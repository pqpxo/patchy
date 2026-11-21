"""GitHub repository discovery.

Uses the GitHub REST API and raw file downloads only: nothing is cloned, extracted, built or executed.
File paths come from GitHub's tree listing and are only ever used as strings (never written to disk).
"""
from __future__ import annotations

import posixpath
import re
import time
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from . import parsers
from .config import settings
from .db import utcnow
from .inventory import sync_components
from .models import Repository, ScanRun
from .security import scrub

OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
URL_RE = re.compile(r"^https://github\.com/([^/\s]+)/([^/\s]+?)(?:\.git)?/?$")
GITHUB_API = "https://api.github.com"


class ScanError(Exception):
    pass


def parse_github_url(url: str) -> tuple[str, str]:
    m = URL_RE.match(url.strip())
    if not m or not OWNER_RE.match(m.group(1)) or not REPO_RE.match(m.group(2)) or m.group(2) in (".", ".."):
        raise ValueError("Enter a repository URL like https://github.com/owner/repo")
    return m.group(1), m.group(2)


def validate_branch(branch: str | None) -> str | None:
    if not branch:
        return None
    if not BRANCH_RE.match(branch) or ".." in branch or branch.startswith("/") or branch.endswith("/"):
        raise ValueError("Branch name contains unsupported characters.")
    return branch


def safe_repo_path(path: str) -> bool:
    if not path or len(path) > 1024 or path.startswith("/") or "\\" in path or "\x00" in path:
        return False
    return posixpath.normpath(path) == path and not any(p in ("..", ".") for p in path.split("/"))


def github_client(transport=None) -> httpx.Client:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "Patchy/0.1"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return httpx.Client(timeout=30, headers=headers, follow_redirects=True, transport=transport)


def _get(client: httpx.Client, url: str, **kw) -> httpx.Response:
    r = client.get(url, **kw)
    if r.status_code == 404:
        raise ScanError("Repository, branch or file not found. Private repositories need GITHUB_TOKEN "
                        "configured on the server.")
    if r.status_code in (401, 403, 429):
        hint = "rate limit reached" if r.headers.get("x-ratelimit-remaining") == "0" else "access denied"
        raise ScanError(f"GitHub returned {r.status_code} ({hint}). Configure GITHUB_TOKEN for higher limits "
                        "or private repositories.")
    r.raise_for_status()
    return r


def _fetch_file(client: httpx.Client, owner: str, repo: str, sha: str, path: str, limit: int) -> bytes:
    """Stream a file with a hard byte cap. API raw endpoint so a token (if any) applies."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{quote(path)}"
    with client.stream("GET", url, params={"ref": sha}, headers={"Accept": "application/vnd.github.raw"}) as r:
        if r.status_code >= 400:
            raise ScanError(f"HTTP {r.status_code}")
        buf = bytearray()
        for chunk in r.iter_bytes():
            buf += chunk
            if len(buf) > limit:
                raise ScanError("file exceeds size limit")
        return bytes(buf)


def scan_repository(db: Session, run: ScanRun, client: httpx.Client, clock=time.monotonic) -> dict:
    repo: Repository = run.repository
    deadline = clock() + settings.repo_scan_timeout
    owner, name = repo.owner, repo.name

    def progress(msg):
        run.progress = msg
        db.commit()

    progress("Reading repository metadata")
    meta = _get(client, f"{GITHUB_API}/repos/{owner}/{name}").json()
    branch = repo.branch or meta.get("default_branch") or "main"
    repo.is_private = bool(meta.get("private"))
    languages = _get(client, f"{GITHUB_API}/repos/{owner}/{name}/languages").json()
    sha = _get(client, f"{GITHUB_API}/repos/{owner}/{name}/commits/{quote(branch, safe='')}",
               headers={"Accept": "application/vnd.github.sha"}).text.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ScanError("Could not resolve the branch to a commit.")
    run.revision = sha
    progress(f"Listing files at {sha[:10]}")
    tree = _get(client, f"{GITHUB_API}/repos/{owner}/{name}/git/trees/{sha}", params={"recursive": "1"}).json()

    skipped, candidates = [], []
    for entry in tree.get("tree", []):
        path = entry.get("path", "")
        if entry.get("type") != "blob" or not parsers.parser_for(path):
            continue
        if not safe_repo_path(path):
            skipped.append({"path": path[:200], "reason": "unsafe path"})
        elif "node_modules/" in path or "/vendor/" in f"/{path}":
            continue  # vendored third-party trees: not this repo's own declarations
        elif (entry.get("size") or 0) > settings.repo_max_file_bytes:
            skipped.append({"path": path, "reason": "larger than REPO_MAX_FILE_BYTES"})
        else:
            candidates.append(path)
    if len(candidates) > settings.repo_max_manifests:
        skipped += [{"path": p, "reason": "over REPO_MAX_MANIFESTS"} for p in candidates[settings.repo_max_manifests:]]
        candidates = candidates[: settings.repo_max_manifests]

    items, manifests, total = [], [], 0
    for i, path in enumerate(candidates, 1):
        if clock() > deadline:
            skipped += [{"path": p, "reason": "scan time limit reached"} for p in candidates[i - 1:]]
            break
        if total > settings.repo_max_total_bytes:
            skipped += [{"path": p, "reason": "total size limit reached"} for p in candidates[i - 1:]]
            break
        progress(f"Parsing manifests {i}/{len(candidates)}")
        try:
            raw = _fetch_file(client, owner, name, sha, path, settings.repo_max_file_bytes)
            total += len(raw)
            found = parsers.parser_for(path)(raw.decode("utf-8", errors="replace"))
        except ScanError as e:
            skipped.append({"path": path, "reason": str(e)})
            continue
        except Exception as e:  # untrusted input: never echo content, only the error type
            skipped.append({"path": path, "reason": f"could not parse ({type(e).__name__})"})
            continue
        manifests.append({"path": path, "components": len(found)})
        for p in found:
            p.path = path
        items += found

    items = parsers.drop_constraints_covered_by_lockfiles(items)
    rows = [{
        "identity": f"{p.path}|{p.ecosystem or '-'}|{p.name}",
        "name": p.name[:300], "component_type": p.component_type, "ecosystem": p.ecosystem,
        "version": (p.version or None) and p.version[:200], "version_status": p.version_status,
        "version_spec": (p.version_spec or None) and p.version_spec[:300], "details": p.details or None,
        "paths": [(p.path, p.path_kind)],
    } for p in items]
    for lang, size in languages.items():
        rows.append({"identity": f"language|{lang}", "name": lang, "component_type": "language",
                     "ecosystem": None, "version": None, "version_status": "unknown",
                     "details": {"bytes": size, "note": "from GitHub language statistics"}, "paths": []})
    ids = sync_components(db, run, f"repo:{repo.id}", rows, source="repo", repository_id=repo.id)
    repo.languages = languages
    repo.last_revision = sha
    repo.last_scanned_at = utcnow()
    return {"component_ids": ids, "branch": branch, "revision": sha, "tree_truncated": bool(tree.get("truncated")),
            "manifests": manifests, "components": len(rows), "skipped": skipped[:200],
            "partial": bool(skipped) or bool(tree.get("truncated"))}


def error_text(e: Exception) -> str:
    if isinstance(e, ScanError):
        return str(e)
    if isinstance(e, httpx.HTTPError):
        return scrub(f"Network error talking to GitHub ({type(e).__name__}).")
    return "Unexpected error during scan. See server logs."
