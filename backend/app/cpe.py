"""NVD product (CPE) matching for components OSV can't check: servers, runtimes and manual assets.

NVD evaluates the version ranges itself (virtualMatchString with a version). Results are recorded
as 'possible' matches, because distro and vendor builds often backport fixes without changing the
upstream version. Container images and libraries with an OSV ecosystem are never sent here.
"""
from __future__ import annotations

import re
import time

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import eol
from . import matching as m
from .config import settings
from .db import utcnow
from .models import Advisory, AdvisoryPackage, Component, OsvQuery

ECOSYSTEM = "CPE"
# Products whose CPE names are stable and unambiguous. endoflife.date identifiers cover many more.
CURATED = {
    "nginx": ["f5:nginx", "nginx:nginx"], "apache2": ["apache:http_server"], "httpd": ["apache:http_server"],
    "openssh": ["openbsd:openssh"], "openssl": ["openssl:openssl"], "node": ["nodejs:node.js"],
    "nodejs": ["nodejs:node.js"], "python": ["python:python"], "python3": ["python:python"],
    "caddy": ["caddyserver:caddy"], "postgresql": ["postgresql:postgresql"], "postgres": ["postgresql:postgresql"],
    "redis": ["redis:redis"], "mariadb": ["mariadb:mariadb"], "mysql": ["oracle:mysql"], "php": ["php:php"],
    "ruby": ["ruby-lang:ruby"], "go": ["golang:go"], "grafana": ["grafana:grafana"],
}
VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+){0,3})(?:(p\d+))?$")


def products_for(c: Component, eol_data: dict | None) -> list[str]:
    if c.cpe:
        return [c.cpe.lower()]
    name = (c.name or "").lower()
    if name in CURATED:
        return CURATED[name]
    if eol_data:
        slug = next((eol_data["index"][k] for k in eol.keys_for(c) if k in eol_data["index"]), None)
        return (eol_data.get("cpes") or {}).get(slug, [])[:2]
    return []


def targets_for(c: Component, pkgs: dict, eol_data: dict | None) -> list[tuple[str, str]]:
    """[(vendor:product, cpe version)] to look up, or [] when the component isn't CPE-checkable."""
    if (m.supports_osv(c.ecosystem) or c.component_type in ("container_image", "os_package")
            or c.version_status != "exact" or not c.version or c.missing_since or eol.distro_managed(c, pkgs)):
        return []
    v = VERSION_RE.match(c.version.strip())
    if not v:
        return []
    version = v.group(1) + (f":{v.group(2)}" if v.group(2) else "")
    return [(p, version) for p in products_for(c, eol_data) if re.fullmatch(r"[a-z0-9_.\-]+:[a-z0-9_.\-]+", p)]


def all_targets(db: Session) -> set[tuple[str, str]]:
    comps = db.scalars(select(Component).where(Component.missing_since.is_(None))).all()
    pkgs = eol.host_packages(db, [c.host_id for c in comps if c.host_id])
    data = eol.load(db)
    return {t for c in comps for t in targets_for(c, pkgs, data)}


def ranges_for(cve: dict, product: str) -> list[dict]:
    vendor, prod = product.split(":", 1)
    out = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                parts = str(cm.get("criteria", "")).split(":")
                if not cm.get("vulnerable") or len(parts) < 6 or parts[3] != vendor or parts[4] != prod:
                    continue
                r = {k: cm[src] for k, src in (("start_incl", "versionStartIncluding"),
                                               ("start_excl", "versionStartExcluding"),
                                               ("end_incl", "versionEndIncluding"),
                                               ("end_excl", "versionEndExcluding")) if cm.get(src)}
                if parts[5] not in ("*", "-"):
                    r["version"] = parts[5] + (f":{parts[6]}" if len(parts) > 6 and parts[6] not in ("*", "-") else "")
                out.append(r)
    return out[:50]


def covers(r: dict, version: str) -> bool:
    """Whether one NVD range includes the version. Unparseable comparisons trust NVD's own match."""
    current = version.split(":")[0]

    def cmp(other):
        return m.compare("PyPI", current, other.split(":")[0])
    if "version" in r:
        c = cmp(r["version"])
        return c is None or c == 0
    checks = [("start_incl", lambda c: c >= 0), ("start_excl", lambda c: c > 0),
              ("end_incl", lambda c: c <= 0), ("end_excl", lambda c: c < 0)]
    for key, ok in checks:
        if key in r:
            c = cmp(r[key])
            if c is not None and not ok(c):
                return False
    return True


def describe(r: dict) -> str:
    if "version" in r:
        return f"= {r['version']}"
    bits = [f">= {r['start_incl']}" if "start_incl" in r else f"> {r['start_excl']}" if "start_excl" in r else "",
            f"< {r['end_excl']}" if "end_excl" in r else f"<= {r['end_incl']}" if "end_incl" in r else ""]
    return ", ".join(b for b in bits if b) or "all versions"


def nvd_metrics(cve: dict) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            d = metrics[key][0]["cvssData"]
            return d.get("baseScore"), d.get("vectorString")
    return None, None


def upsert_cve(db: Session, cve: dict, product: str) -> Advisory:
    from .vulns import _apply_kev, _dt, kev_entries  # local import: vulns imports this module
    cid = cve["id"]
    adv = db.get(Advisory, cid)
    if adv is None:
        adv = Advisory(id=cid, source="nvd", aliases=[], cve_ids=[cid], references=[], affected=[])
    if adv.source == "nvd":  # OSV records stay authoritative for their own fields
        desc = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
        adv.summary = (desc.split(". ")[0][:300] or None) if desc else None
        adv.details = desc[:20000] or None
        adv.published, adv.modified = _dt(cve.get("published")), _dt(cve.get("lastModified"))
        adv.withdrawn = utcnow() if cve.get("vulnStatus") == "Rejected" else None
        score, vector = nvd_metrics(cve)
        if score is not None:
            adv.cvss_score, adv.cvss_vector = score, (vector or "")[:200] or None
            adv.severity, adv.severity_source = m.severity_from_score(score), "NVD"
        adv.references = [{"type": "WEB", "url": r["url"]} for r in cve.get("references") or []
                          if str(r.get("url", "")).startswith(("https://", "http://"))][:100]
    entry = {"package": {"ecosystem": ECOSYSTEM, "name": product}, "cpe_ranges": ranges_for(cve, product)}
    adv.affected = [a for a in adv.affected or [] if (a.get("package") or {}) != entry["package"]] + [entry]
    adv.fetched_at = utcnow()
    db.add(adv)
    db.flush()
    if not db.scalar(select(AdvisoryPackage.id).where(AdvisoryPackage.advisory_id == cid,
                                                      AdvisoryPackage.ecosystem == ECOSYSTEM,
                                                      AdvisoryPackage.name == product)):
        db.add(AdvisoryPackage(advisory_id=cid, ecosystem=ECOSYSTEM, name=product[:300]))
    _apply_kev(adv, kev_entries(db))
    return adv


def refresh_cpe(db: Session, client: httpx.Client, mode: str = "full", sleep=time.sleep) -> dict:
    targets = all_targets(db)
    cached = {(q.name, q.version): q for q in db.scalars(select(OsvQuery).where(OsvQuery.ecosystem == ECOSYSTEM))}
    todo = [t for t in targets if t not in cached] if mode == "pending" else \
        sorted(targets, key=lambda t: (t in cached, cached[t].queried_at if t in cached else utcnow()))
    todo = todo[: settings.nvd_cpe_max_per_refresh]
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    delay = 0.7 if settings.nvd_api_key else 6.5  # NVD allows 50 (key) or 5 requests per 30 seconds
    found = 0
    for i, (product, version) in enumerate(todo):
        if i:
            sleep(delay)
        r = client.get(settings.nvd_api, headers=headers,
                       params={"virtualMatchString": f"cpe:2.3:a:{product}:{version}", "resultsPerPage": 2000})
        r.raise_for_status()
        data = r.json()
        ids = []
        for v in data.get("vulnerabilities") or []:
            cve = v.get("cve") or {}
            # NVD also matches CVEs where this product is only the platform (eg a Django flaw "on Python").
            # Keep a CVE only when the product itself is vulnerable and a range covers this version.
            if cve.get("id", "").startswith("CVE-") and any(covers(r, version) for r in ranges_for(cve, product)):
                upsert_cve(db, cve, product)
                ids.append(cve["id"])
        q = cached.get((product, version)) or OsvQuery(ecosystem=ECOSYSTEM, name=product, version=version)
        q.vuln_ids, q.truncated, q.queried_at = ids, data.get("totalResults", 0) > len(ids), utcnow()
        db.add(q)
        db.flush()
        found += len(ids)
    return {"products_checked": len(todo), "targets": len(targets), "cves_found": found,
            "not_checked_over_cap": max(0, len(targets) - len(todo)) if mode == "full" else 0}


def match(c: Component, adv: Advisory, cpe_version: str, product: str) -> m.MatchResult:
    entry = next((a for a in adv.affected or [] if (a.get("package") or {}).get("name") == product), {})
    ranges = entry.get("cpe_ranges") or []
    current = cpe_version.split(":")[0]
    fixed = [r["end_excl"] for r in ranges if "end_excl" in r]
    fixed = [f for f in m.sort_versions("PyPI", set(fixed))
             if (r := m.compare("PyPI", f, current)) is None or r > 0]
    return m.MatchResult(
        m.POSSIBLE,
        f"NVD lists cpe:2.3:a:{product}:{cpe_version} as affected. Distro and vendor builds often backport "
        "fixes without changing the version number, so check your vendor's security tracker before acting.",
        [describe(r) for r in ranges][:20], fixed)
