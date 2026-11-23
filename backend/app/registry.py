"""Optional check for newer container images: does a running container's tag now point at a different build?

Off by default (it contacts public registries, and Diun or Watchtower may already do this). Only well-known public
registries are contacted, anonymously, so an image name reported by an agent can't make the server call anything
else. A HEAD request finds out whether a tag moved; the manifest is only downloaded when it has.
"""
from __future__ import annotations

import re

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import utcnow
from .models import AppSetting, Host
from .vulns import USER_AGENT

REGISTRIES = {"docker.io": "registry-1.docker.io", "ghcr.io": "ghcr.io", "lscr.io": "lscr.io", "quay.io": "quay.io",
              "gcr.io": "gcr.io", "mcr.microsoft.com": "mcr.microsoft.com", "registry.gitlab.com": "registry.gitlab.com",
              "public.ecr.aws": "public.ecr.aws", "registry.k8s.io": "registry.k8s.io"}
ACCEPT = ", ".join(["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"])
PLATFORMS = {"x86_64": ("amd64", None), "amd64": ("amd64", None), "aarch64": ("arm64", None), "arm64": ("arm64", None),
             "armv7l": ("arm", "v7"), "armv6l": ("arm", "v6")}
MAX_BYTES = 1_000_000
_NAME = re.compile(r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*$")


def parse_ref(image: str) -> tuple[str, str, str] | None:
    """'nginx:1.27' -> ('docker.io', 'library/nginx', '1.27'). None for digests, unknown registries or odd names."""
    if "@" in image:
        return None  # pinned to a digest: it can't move
    first, _, rest = image.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = "docker.io", image
    name, _, tag = path.rpartition(":") if ":" in path else (path, "", "latest")
    if registry == "docker.io" and "/" not in name:
        name = f"library/{name}"
    if registry not in REGISTRIES or not _NAME.match(name) or not re.match(r"^[\w][\w.-]{0,127}$", tag):
        return None
    return registry, name, tag


def _token(client: httpx.Client, r: httpx.Response) -> str | None:
    """Anonymous pull token from a 401's 'WWW-Authenticate: Bearer realm=...,service=...,scope=...'."""
    h = r.headers.get("www-authenticate", "")
    if not h.lower().startswith("bearer "):
        return None
    params = dict(re.findall(r'(\w+)="([^"]*)"', h))
    realm = params.pop("realm", "")
    if not realm.startswith("https://"):
        return None
    t = client.get(realm, params=params)
    t.raise_for_status()
    return t.json().get("token") or t.json().get("access_token")


def _request(client: httpx.Client, method: str, url: str, auth: dict) -> httpx.Response:
    headers = {"Accept": ACCEPT, **({"Authorization": f"Bearer {auth['token']}"} if auth.get("token") else {})}
    r = client.request(method, url, headers=headers)
    if r.status_code == 401 and "token" not in auth:
        auth["token"] = _token(client, r)
        if auth["token"]:
            r = client.request(method, url, headers={**headers, "Authorization": f"Bearer {auth['token']}"})
    r.raise_for_status()
    if r.url.scheme != "https" or len(r.content) > MAX_BYTES:
        raise ValueError("unexpected registry response")
    return r


def check(client: httpx.Client, image: str, arch: str | None, known_digest: str | None = None) -> dict | None:
    """{'digest': tag's digest, 'current': digests a container of the current build can have}.

    'current' holds the index, platform manifest and config digests, because an image ID is the config digest
    with Docker's classic store and the index digest with the containerd store. Returns None when the tag hasn't
    moved since `known_digest`.
    """
    ref = parse_ref(image)
    if not ref:
        raise ValueError("not a public registry image")
    registry, name, tag = ref
    base, auth = f"https://{REGISTRIES[registry]}/v2/{name}/manifests/", {}
    digest = _request(client, "HEAD", base + tag, auth).headers.get("docker-content-digest")
    if digest and digest == known_digest:
        return None
    r = _request(client, "GET", base + tag, auth)
    digest = r.headers.get("docker-content-digest") or digest
    doc, current = r.json(), {digest}
    if "manifests" in doc:  # an index: pick this host's platform
        want, variant = PLATFORMS.get((arch or "").lower(), ("amd64", None))
        m = next((m for m in doc["manifests"] if (m.get("platform") or {}).get("os") == "linux"
                  and m["platform"].get("architecture") == want
                  and (not variant or m["platform"].get("variant") in (variant, None))), None)
        if not m:
            raise ValueError(f"no linux/{want} build")
        current.add(m["digest"])
        doc = _request(client, "GET", base + m["digest"], auth).json()
    if (doc.get("config") or {}).get("digest"):
        current.add(doc["config"]["digest"])
    return {"digest": digest, "current": sorted(d for d in current if d)}


def _built_here(c: dict) -> bool:
    """Compose names images it builds '<project>-<service>'; those aren't on any registry, so don't ask."""
    p, s = c.get("compose_project"), c.get("compose_service")
    return bool(p and s and c.get("image") in (f"{p}-{s}", f"{p}_{s}"))


def http_client() -> httpx.Client:
    return httpx.Client(timeout=20, headers={"User-Agent": USER_AGENT}, follow_redirects=True, max_redirects=3)


def refresh(db: Session, client: httpx.Client | None = None) -> dict:
    """Check every running container's image tag. Results are kept per image and platform."""
    wanted: dict[tuple[str, str], set[str]] = {}
    for h in db.scalars(select(Host)):
        for c in h.containers or []:
            if c.get("image_id") and c.get("image") and not _built_here(c) and parse_ref(c["image"]):
                wanted.setdefault((c["image"], h.arch or ""), set()).add(c["image_id"])
    row = db.get(AppSetting, "image_updates")
    old, new = (row.value or {}) if row else {}, {}
    checked = failed = 0
    with (client or http_client()) as cl:
        for (image, arch), local in sorted(wanted.items()):
            key = f"{image}|{arch}"
            prev = old.get(key) or {}
            try:
                got = check(cl, image, arch, prev.get("digest"))
                checked += 1
            except (httpx.HTTPError, ValueError, KeyError) as e:
                failed += 1
                status = getattr(getattr(e, "response", None), "status_code", None)
                new[key] = {**prev, "error": f"HTTP {status}" if status else type(e).__name__}
                continue
            e = {**prev, **(got or {}), "checked_at": utcnow().isoformat(), "error": None}
            # Remember which local builds were already out of date, so a fresh pull isn't flagged before the next check.
            e["outdated"] = sorted(set(prev.get("outdated", [])) | {i for i in local if i not in e["current"]})[-50:]
            new[key] = e
    if wanted and failed == len(wanted):
        raise RuntimeError(f"no registry could be reached ({failed} images)")
    db.merge(AppSetting(key="image_updates", value=new))
    db.flush()
    return {"images": len(wanted), "checked": checked, "failed": failed,
            "newer": sum(1 for (i, a), local in wanted.items() if local & set(new[f"{i}|{a}"].get("outdated", [])))}


def newer(db: Session, host: Host) -> dict[str, dict]:
    """{container name: {'checked_at'}} for this host's containers running an out-of-date build."""
    row = db.get(AppSetting, "image_updates")
    v = (row.value or {}) if row else {}
    out = {}
    for c in host.containers or []:
        e = v.get(f"{c.get('image')}|{host.arch or ''}")
        if e and c.get("image_id") in e.get("outdated", []) and c.get("image_id") not in e.get("current", []):
            out[c.get("name") or c.get("image")] = {"checked_at": e.get("checked_at")}
    return out
