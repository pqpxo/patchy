"""End-of-life tracking from endoflife.date, applied to components and host operating systems.

A component only gets an EOL state when its product and release cycle are identified exactly
(package URL, CPE or product name, then the longest release name the version starts with).
Distro packages are skipped: the distro supports them for the life of the OS release, and the
host's OS end-of-life covers that.
"""
from __future__ import annotations

import re
from datetime import date, timedelta
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import matching as m
from .config import settings
from .models import Component, FeedStatus, Host

SOON_DAYS = 90
PURL_TYPES = {"PyPI": "pypi", "npm": "npm", "Maven": "maven", "Packagist": "composer", "RubyGems": "gem",
              "crates.io": "cargo", "Go": "golang", "NuGet": "nuget"}
DISTRO = {"Debian", "Ubuntu", "Alpine", "Rocky Linux", "AlmaLinux"}
NAME_ALIASES = {"python3": "python", "apache2": "apache-http-server", "httpd": "apache-http-server",
                "docker": "docker-engine", "node": "nodejs", "postgres": "postgresql"}
OS_PRODUCTS = {"debian": "debian", "raspbian": "debian", "ubuntu": "ubuntu", "alpine": "alpine-linux",
               "rocky": "rocky-linux", "almalinux": "almalinux", "centos": "centos", "rhel": "rhel",
               "fedora": "fedora", "linuxmint": "linuxmint", "opensuse-leap": "opensuse"}


def refresh_eol(db: Session, client: httpx.Client) -> dict:
    r = client.get(f"{settings.eol_api}/products/full")
    r.raise_for_status()
    products, index, cpes = {}, {}, {}
    for p in r.json().get("result") or []:
        slug = p.get("name")
        if not slug:
            continue
        products[slug] = {"label": p.get("label") or slug, "releases": [
            {"name": str(x.get("name")), "label": x.get("label"), "is_eol": bool(x.get("isEol")),
             "eol_from": x.get("eolFrom"), "is_lts": bool(x.get("isLts")),
             "latest": (x.get("latest") or {}).get("name"), "link": (x.get("latest") or {}).get("link")}
            for x in p.get("releases") or [] if x.get("name")]}
        for key in [slug, *(p.get("aliases") or [])]:
            index.setdefault(f"name:{key.lower()}", slug)
        for ident in p.get("identifiers") or []:
            iid = str(ident.get("id", "")).lower()
            if ident.get("type") == "purl":
                index.setdefault(f"purl:{iid.split('@')[0].split('?')[0]}", slug)
            elif ident.get("type") == "cpe" and iid.startswith("cpe:2.3:"):
                parts = iid.split(":")
                if len(parts) > 4:
                    index.setdefault(f"cpe:{parts[3]}:{parts[4]}", slug)
                    if parts[2] == "a":
                        cpes.setdefault(slug, []).append(f"{parts[3]}:{parts[4]}")
    f = db.get(FeedStatus, "eol") or FeedStatus(source="eol")
    f.detail = {"products": products, "index": index, "cpes": cpes, "count": len(products)}
    db.add(f)
    db.flush()
    return {"products": len(products)}


def load(db: Session) -> dict | None:
    f = db.get(FeedStatus, "eol")
    return f.detail if f and f.detail and f.detail.get("products") else None


def _cycle(releases: list[dict], version: str | None) -> dict | None:
    """Release whose name is the longest dotted prefix of the version, eg 3.11 for 3.11.4."""
    if not version:
        return None
    v = re.match(r"v?(\d+(?:\.\d+)*)", version.strip())
    if not v:
        return None
    v = v.group(1)
    best = None
    for rel in releases:
        n = rel["name"]
        if (v == n or v.startswith(n + ".")) and (not best or len(n) > len(best["name"])):
            best = rel
    return best


def state_for(product: str, label: str, releases: list[dict], version: str | None, today: date) -> dict | None:
    rel = _cycle(releases, version)
    if not rel:
        return None
    eol_from = rel.get("eol_from")
    try:
        eol_day = date.fromisoformat(eol_from) if eol_from else None
    except ValueError:
        eol_day = None
    if rel["is_eol"] or (eol_day and eol_day <= today):
        state = "eol"
    elif eol_day and eol_day <= today + timedelta(days=SOON_DAYS):
        state = "eol_soon"
    else:
        state = "supported"
    newest = next((r for r in releases if not r["is_eol"]), None)
    return {"state": state, "product": product, "label": label, "cycle": rel["name"], "eol_from": eol_from,
            "latest_in_cycle": rel.get("latest"),
            "newest_supported": newest["name"] if newest else None,
            "newest_supported_latest": newest.get("latest") if newest else None,
            "link": f"https://endoflife.date/{product}"}


def keys_for(c: Component) -> list[str]:
    eco = m.ecosystem_base(c.ecosystem or "")
    if eco in DISTRO:
        return []
    keys = []
    if c.cpe and ":" in c.cpe:
        keys.append(f"cpe:{c.cpe.lower()}")
    name = (c.name or "").lower()
    if eco in PURL_TYPES:
        n = name.replace(":", "/") if eco == "Maven" else m.normalize_name(c.ecosystem, c.name).lower()
        keys.append(f"purl:pkg:{PURL_TYPES[eco]}/{quote(n, safe='/')}")
        return keys  # libraries only match by package URL, never by a similar product name
    if c.component_type == "container_image":
        image = name.split("@")[0]
        for prefix in ("docker.io/", "index.docker.io/"):
            image = image.removeprefix(prefix)
        keys.append(f"purl:pkg:docker/{image if '/' in image else 'library/' + image}")
        return keys
    keys += [f"name:{NAME_ALIASES.get(name, name)}"]
    return keys


def distro_managed(c: Component, host_packages: dict[int, list[Component]]) -> bool:
    """True when an agent-probed binary comes from a distro package Patchy already checks via OSV."""
    if c.source != "agent" or c.component_type == "os_package" or not c.host_id:
        return False
    for p in host_packages.get(c.host_id, []):
        binaries = set((p.details or {}).get("binaries") or [])
        if c.name in binaries or p.name == c.name or f"{c.name}-server" in binaries:
            return True
    return False


def host_packages(db: Session, host_ids) -> dict[int, list[Component]]:
    out: dict[int, list[Component]] = {}
    if not host_ids:
        return out
    for p in db.scalars(select(Component).where(Component.host_id.in_(set(host_ids)),
                                                Component.component_type == "os_package",
                                                Component.missing_since.is_(None))):
        if m.supports_osv(p.ecosystem):
            out.setdefault(p.host_id, []).append(p)
    return out


def apply(db: Session, components: list[Component], today: date | None = None) -> int:
    """Set eol_state/eol on components and their hosts. Returns how many components are EOL or near it."""
    data = load(db)
    if not data:
        return 0
    today = today or date.today()
    products, index = data["products"], data["index"]
    pkgs = host_packages(db, [c.host_id for c in components if c.host_id])
    flagged = 0
    for c in components:
        info = None
        if c.missing_since is None and not distro_managed(c, pkgs):
            slug = next((index[k] for k in keys_for(c) if k in index), None)
            if slug:
                p = products[slug]
                info = state_for(slug, p["label"], p["releases"], c.version, today)
        c.eol, c.eol_state = info, info["state"] if info else None
        flagged += bool(info and info["state"] != "supported")
    host_ids = {c.host_id for c in components if c.host_id}
    for h in db.scalars(select(Host).where(Host.id.in_(host_ids))) if host_ids else []:
        apply_host(h, products, today)
    db.flush()
    return flagged


def apply_host(h: Host, products: dict, today: date) -> None:
    slug = OS_PRODUCTS.get((h.os_id or "").lower())
    info = None
    if slug and slug in products:
        version = h.os_version
        if slug == "debian" and version:
            version = version.split(".")[0]
        info = state_for(slug, products[slug]["label"], products[slug]["releases"], version, today)
    h.os_eol, h.os_eol_state = info, info["state"] if info else None


def apply_all(db: Session) -> int:
    n = apply(db, db.scalars(select(Component)).all())
    data = load(db)
    if data:
        for h in db.scalars(select(Host)):
            apply_host(h, data["products"], date.today())
    return n
