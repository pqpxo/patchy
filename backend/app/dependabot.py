"""Cross-check GitHub Dependabot alerts against Patchy's own findings for scanned repositories.

Read-only: lists open alerts with the server-side GITHUB_TOKEN (needs 'Dependabot alerts: read').
Nothing is written to GitHub. Each repository's latest result is kept on repositories.dependabot.
"""
from __future__ import annotations

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import utcnow
from .models import Advisory, Component, Finding, Repository
from .repo_scanner import GITHUB_API

MAX_PAGES = 10
ERRORS = {
    401: "GitHub rejected the token.",
    403: "Token lacks the 'Dependabot alerts: read' permission, or the repository is not covered by it.",
    404: "Dependabot alerts are not enabled for this repository (or it is not visible to the token).",
}


def _alerts(client: httpx.Client, owner: str, name: str) -> list[dict]:
    url, params, out = f"{GITHUB_API}/repos/{owner}/{name}/dependabot/alerts", {"state": "open", "per_page": 100}, []
    for _ in range(MAX_PAGES):
        r = client.get(url, params=params)
        if r.status_code in ERRORS:
            raise PermissionError(ERRORS[r.status_code])
        r.raise_for_status()
        out += r.json()
        nxt = r.links.get("next", {}).get("url")
        if not nxt or not nxt.startswith(GITHUB_API + "/"):
            break
        url, params = nxt, None
    return out


def patchy_ids(db: Session, repo_id: int) -> set[str]:
    """Advisory ids and aliases of this repository's currently matching findings."""
    rows = db.execute(select(Advisory.id, Advisory.aliases).join(Finding).join(Component).where(
        Component.repository_id == repo_id, Finding.currently_matching.is_(True))).all()
    return {i for aid, aliases in rows for i in [aid, *(aliases or [])]}


def check_repo(db: Session, client: httpx.Client, repo: Repository) -> dict:
    ids = patchy_ids(db, repo.id)
    alerts = []
    for a in _alerts(client, repo.owner, repo.name):
        adv, vuln, dep = a.get("security_advisory") or {}, a.get("security_vulnerability") or {}, a.get("dependency") or {}
        ghsa, cve = adv.get("ghsa_id"), adv.get("cve_id")
        url = a.get("html_url") if str(a.get("html_url", "")).startswith("https://github.com/") else None
        alerts.append({
            "number": a.get("number"), "url": url, "ghsa": ghsa, "cve": cve, "summary": (adv.get("summary") or "")[:300],
            "severity": (vuln.get("severity") or adv.get("severity") or "unknown").lower(),
            "package": (dep.get("package") or {}).get("name"), "ecosystem": (dep.get("package") or {}).get("ecosystem"),
            "manifest": dep.get("manifest_path"), "vulnerable_range": vuln.get("vulnerable_version_range"),
            "patched": (vuln.get("first_patched_version") or {}).get("identifier"),
            "in_patchy": bool({ghsa, cve} & ids - {None}),
        })
    return {"checked_at": utcnow().isoformat(), "error": None, "alerts": alerts[:500],
            "total": len(alerts), "also_in_patchy": sum(a["in_patchy"] for a in alerts)}


def refresh_dependabot(db: Session, client: httpx.Client) -> dict:
    checked = failed = 0
    for repo in db.scalars(select(Repository).where(Repository.is_demo.is_(False))).all():
        try:
            repo.dependabot = check_repo(db, client, repo)
            checked += 1
        except (PermissionError, httpx.HTTPError, ValueError) as e:
            msg = str(e) if isinstance(e, PermissionError) else f"Could not read alerts ({type(e).__name__})."
            repo.dependabot = {"checked_at": utcnow().isoformat(), "error": msg, "alerts": [], "total": 0}
            failed += 1
        db.flush()
    if failed and not checked:
        raise ValueError(f"Dependabot alerts could not be read for any of {failed} repositories.")
    return {"repositories_checked": checked, "repositories_failed": failed}


def for_finding(f: Finding) -> dict | None:
    """The repository's Dependabot alert for this finding's advisory, if any."""
    repo = f.component.repository
    if not repo or not repo.dependabot:
        return None
    ids = {f.advisory.id, *(f.advisory.aliases or [])}
    return next((a for a in repo.dependabot.get("alerts") or [] if {a.get("ghsa"), a.get("cve")} & ids), None)
