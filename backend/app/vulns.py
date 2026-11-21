"""Feed integration (OSV, CISA KEV, NVD) and finding maintenance.

Network access goes through an injectable httpx.Client so tests use httpx.MockTransport.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import matching as m
from .config import settings
from .db import utcnow
from .models import Advisory, AdvisoryPackage, Component, FeedStatus, Finding, OsvQuery
from .security import audit, scrub

log = logging.getLogger("patchy.feeds")
USER_AGENT = "Patchy/0.1 (self-hosted vulnerability tracker)"


def http_client() -> httpx.Client:
    return httpx.Client(timeout=30, headers={"User-Agent": USER_AGENT}, follow_redirects=False)


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def feed(db: Session, source: str) -> FeedStatus:
    f = db.get(FeedStatus, source)
    if not f:
        f = FeedStatus(source=source)
        db.add(f)
    return f


def feed_is_stale(db: Session) -> bool:
    f = db.get(FeedStatus, "osv")
    return not f or not f.last_success_at or f.last_success_at < utcnow() - timedelta(hours=settings.feed_stale_hours)


# ---------- component -> OSV identity ----------

def match_identity(c: Component) -> tuple[str, str, str | None] | None:
    """(ecosystem, package name, version) used for matching, or None if not checkable."""
    if not m.supports_osv(c.ecosystem):
        return None
    name = c.source_package or c.name
    version = c.source_version or c.version if c.version_status == "exact" else None
    return c.ecosystem, m.normalize_name(c.ecosystem, name), version


def osv_targets(db: Session) -> set[tuple[str, str, str]]:
    out = set()
    for c in db.scalars(select(Component).where(Component.missing_since.is_(None))):
        ident = match_identity(c)
        if ident:
            out.add((ident[0], ident[1], ident[2] or ""))
    return out


# ---------- OSV ----------

def query_osv(client: httpx.Client, targets: list[tuple[str, str, str]]) -> dict:
    """Batch query OSV. Returns {target: (ids, truncated)}."""
    results = {}
    cap = settings.osv_max_vulns_per_package
    pending = [(t, None) for t in targets]
    for _ in range(10):  # bounded pagination rounds
        if not pending:
            break
        next_round = []
        for i in range(0, len(pending), 1000):
            chunk = pending[i:i + 1000]
            queries = []
            for (eco, name, ver), token in chunk:
                q = {"package": {"ecosystem": eco, "name": name}}
                if ver:
                    q["version"] = ver
                if token:
                    q["page_token"] = token
                queries.append(q)
            r = client.post(f"{settings.osv_api}/v1/querybatch", json={"queries": queries})
            r.raise_for_status()
            for (target, _), res in zip(chunk, r.json().get("results", [])):
                ids, trunc = results.get(target, ([], False))
                ids = ids + [v["id"] for v in res.get("vulns") or []]
                token = res.get("next_page_token")
                if len(ids) >= cap:
                    ids, trunc, token = ids[:cap], True, None
                results[target] = (ids, trunc)
                if token:
                    next_round.append((target, token))
        pending = next_round
    for t, _ in pending:
        results[t] = (results[t][0], True)
    return results


def upsert_advisory(db: Session, rec: dict, source: str = "osv") -> Advisory:
    adv = db.get(Advisory, rec["id"]) or Advisory(id=rec["id"])
    label, score, vector, sev_src = m.severity_from_osv(rec)
    aliases = rec.get("aliases") or []
    cves = sorted({x for x in [rec["id"], *aliases, *(rec.get("upstream") or [])] if x.startswith("CVE-")})
    adv.source = source
    adv.aliases = aliases
    adv.cve_ids = cves
    adv.summary = (rec.get("summary") or "")[:1000] or None
    adv.details = (rec.get("details") or "")[:20000] or None
    adv.published, adv.modified, adv.withdrawn = _dt(rec.get("published")), _dt(rec.get("modified")), _dt(rec.get("withdrawn"))
    if adv.severity_source != "NVD" or label != "unknown":
        adv.severity, adv.cvss_score, adv.severity_source = label, score, sev_src
        adv.cvss_vector = vector[:200] if vector else None
    adv.references = [{"type": r.get("type"), "url": r.get("url")} for r in rec.get("references") or []
                      if str(r.get("url", "")).startswith(("https://", "http://"))][:100]
    adv.affected = [{k: a.get(k) for k in ("package", "ranges", "versions") if a.get(k)}
                    for a in rec.get("affected") or []]
    adv.fetched_at = utcnow()
    db.add(adv)
    db.flush()
    db.execute(delete(AdvisoryPackage).where(AdvisoryPackage.advisory_id == adv.id))
    seen = set()
    for a in adv.affected:
        pkg = a.get("package") or {}
        key = (pkg.get("ecosystem", ""), m.normalize_name(pkg.get("ecosystem", ""), pkg.get("name", "")))
        if key[0] and key[1] and key not in seen:
            seen.add(key)
            db.add(AdvisoryPackage(advisory_id=adv.id, ecosystem=key[0][:64], name=key[1][:300]))
    kev = (db.get(FeedStatus, "kev").detail or {}).get("entries", {}) if db.get(FeedStatus, "kev") else {}
    _apply_kev(adv, kev)
    return adv


def refresh_osv(db: Session, client: httpx.Client, mode: str = "full") -> dict:
    targets = osv_targets(db)
    cached = {(q.ecosystem, q.name, q.version): q for q in db.scalars(select(OsvQuery))}
    if mode == "pending":
        targets = {t for t in targets if t not in cached}
    targets = sorted(targets)[: settings.osv_max_queries]
    answers = query_osv(client, targets) if targets else {}
    want = {vid for ids, _ in answers.values() for vid in ids}
    have = {a.id for a in db.scalars(select(Advisory).where(Advisory.id.in_(want)))} if want else set()
    # Re-fetch existing advisories on full refresh (cheap enough within cap); new ones always.
    to_fetch = sorted(want - have) + (sorted(have) if mode == "full" else [])
    skipped = max(0, len(to_fetch) - settings.osv_max_fetch)
    to_fetch = to_fetch[: settings.osv_max_fetch]

    def get(vid):
        r = client.get(f"{settings.osv_api}/v1/vulns/{vid}")
        r.raise_for_status()
        return r.json()

    errors = 0
    with ThreadPoolExecutor(max_workers=4) as pool:
        for vid, rec in zip(to_fetch, pool.map(lambda v: _safe(get, v), to_fetch)):
            if rec is None:
                errors += 1
            else:
                upsert_advisory(db, rec)
    now = utcnow()
    for (eco, name, ver), (ids, trunc) in answers.items():
        q = cached.get((eco, name, ver)) or OsvQuery(ecosystem=eco, name=name, version=ver)
        q.vuln_ids, q.truncated, q.queried_at = ids, trunc, now
        db.add(q)
    db.flush()
    return {"queries": len(targets), "advisories_fetched": len(to_fetch) - errors,
            "fetch_errors": errors, "not_fetched_over_cap": skipped,
            "truncated_packages": sum(1 for _, t in answers.values() if t)}


def _safe(fn, arg):
    try:
        return fn(arg)
    except (httpx.HTTPError, ValueError) as e:
        log.warning("OSV fetch failed for %s: %s", arg, type(e).__name__)
        return None


# ---------- KEV ----------

def _apply_kev(adv: Advisory, entries: dict) -> None:
    hit = next((entries[c] for c in adv.cve_ids or [] if c in entries), None)
    adv.kev = bool(hit)
    adv.kev_date_added = hit.get("dateAdded") if hit else None
    adv.kev_due_date = hit.get("dueDate") if hit else None
    adv.kev_required_action = hit.get("requiredAction") if hit else None


def refresh_kev(db: Session, client: httpx.Client) -> dict:
    r = client.get(settings.kev_url)
    r.raise_for_status()
    data = r.json()
    entries = {v["cveID"]: {k: v.get(k) for k in ("dateAdded", "dueDate", "requiredAction")}
               for v in data.get("vulnerabilities", []) if v.get("cveID")}
    f = feed(db, "kev")
    f.detail = {"catalog_version": data.get("catalogVersion"), "count": len(entries), "entries": entries}
    for adv in db.scalars(select(Advisory)):
        _apply_kev(adv, entries)
    db.flush()
    return {"kev_entries": len(entries)}


# ---------- NVD (optional) ----------

def refresh_nvd(db: Session, client: httpx.Client, sleep=time.sleep) -> dict:
    """Fill in CVSS for advisories with unknown severity that have findings. Bounded and rate-limited."""
    q = (select(Advisory).join(Finding, Finding.advisory_id == Advisory.id)
         .where(Advisory.severity == "unknown", Advisory.nvd_checked_at.is_(None))
         .distinct().limit(settings.nvd_max_per_refresh))
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    delay = 0.7 if settings.nvd_api_key else 6.5  # NVD: 50 or 5 requests per 30s
    done = 0
    for adv in db.scalars(q).all():
        if not adv.cve_ids:
            adv.nvd_checked_at = utcnow()
            continue
        r = client.get(settings.nvd_api, params={"cveId": adv.cve_ids[0]}, headers=headers)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities") or []
        metrics = (vulns[0]["cve"].get("metrics") or {}) if vulns else {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            if metrics.get(key):
                d = metrics[key][0]["cvssData"]
                adv.cvss_score = d.get("baseScore")
                adv.cvss_vector = d.get("vectorString")
                adv.severity = m.severity_from_score(adv.cvss_score)
                adv.severity_source = "NVD"
                break
        adv.nvd_checked_at = utcnow()
        done += 1
        sleep(delay)
    db.flush()
    return {"nvd_lookups": done}


# ---------- matching / findings ----------

def remediation_text(c: Component, adv: Advisory, fixed: list[str], ranges: list[str]) -> str:
    name = c.source_package or c.name
    base = m.ecosystem_base(c.ecosystem or "")
    current = c.source_version or c.version

    def is_newer(f):
        r = m.compare(c.ecosystem, f, current) if current else None
        return r is None or r > 0
    newer = [f for f in fixed if is_newer(f)] or fixed
    lines = []
    if newer:
        target = ", ".join(newer[:5])
        lines.append(f"The advisory lists fixed version(s): {target}. Upgrade {name} to a fixed version "
                     "that matches your release line, or later.")
        binaries = (c.details or {}).get("binaries") or [c.name]
        cmd = {
            "PyPI": f"pip install --upgrade '{name}>={newer[0]}' (then update the pinned version in your manifest)",
            "npm": f"npm install {name}@{newer[0]} (then commit the updated lockfile)",
            "Go": f"go get {name}@{newer[0] if newer[0].startswith('v') else 'v' + newer[0]} && go mod tidy",
            "crates.io": f"cargo update -p {name} (or raise the version in Cargo.toml)",
            "Packagist": f"composer require {name}:^{newer[0]}",
            "RubyGems": f"bundle update {name}",
            "Maven": "Raise the dependency version in pom.xml or build.gradle and rebuild.",
            "Debian": "sudo apt update && sudo apt install --only-upgrade " + " ".join(binaries[:10]),
            "Ubuntu": "sudo apt update && sudo apt install --only-upgrade " + " ".join(binaries[:10]),
            "Alpine": "apk update && apk upgrade " + " ".join(binaries[:10]),
        }.get(base)
        if cmd:
            lines.append(f"Typical step: {cmd}")
    else:
        lines.append("The advisory does not list a fixed version. Follow the advisory link for "
                     "mitigations or vendor guidance; Patchy will not guess a fix.")
    if adv.kev and adv.kev_required_action:
        lines.append(f"CISA KEV required action: {adv.kev_required_action}")
    lines.append("Test updates before deploying. Patchy cannot guarantee an update is safe or complete.")
    return "\n".join(lines)


def rematch(db: Session, component_ids: list[int] | None = None) -> dict:
    """Recompute findings. Auto-resolves findings that no longer match; reopens auto-resolved ones."""
    q = select(Component)
    if component_ids is not None:
        if not component_ids:
            return {"components": 0}
        q = q.where(Component.id.in_(component_ids))
    now = utcnow()
    cache = {(o.ecosystem, o.name, o.version): o for o in db.scalars(select(OsvQuery))}
    stats = {"components": 0, "new": 0, "auto_resolved": 0, "reopened": 0}
    for c in db.scalars(q).all():
        stats["components"] += 1
        existing = {f.advisory_id: f for f in db.scalars(select(Finding).where(Finding.component_id == c.id))}
        matched = {}
        ident = match_identity(c)
        if ident and c.missing_since is None:
            eco, name, version = ident
            cached = cache.get((eco, name, version or ""))
            c.vuln_checked_at = cached.queried_at if cached else None
            adv_ids = db.scalars(select(AdvisoryPackage.advisory_id).where(
                AdvisoryPackage.name == name,
                AdvisoryPackage.ecosystem.in_({eco, m.ecosystem_base(eco)}))).all()
            for adv in db.scalars(select(Advisory).where(Advisory.id.in_(adv_ids), Advisory.withdrawn.is_(None))):
                osv_hit = (adv.id in cached.vuln_ids) if (cached and version) else None
                res = m.evaluate(adv.affected, eco, name, version or c.version_spec,
                                 "exact" if version else c.version_status, osv_hit)
                if res and res.status != m.NOT_AFFECTED:
                    matched[adv.id] = (adv, res)
        for adv_id, (adv, res) in matched.items():
            f = existing.get(adv_id)
            if not f:
                f = Finding(component_id=c.id, advisory_id=adv_id, first_detected_at=now)
                db.add(f)
                stats["new"] += 1
            elif f.status == "resolved" and f.status_changed_by == "system":
                f.status, f.status_note, f.status_changed_at = "open", "Reopened automatically: matches again.", now
                stats["reopened"] += 1
            f.match_status, f.evidence = res.status, res.evidence
            f.affected_ranges, f.fixed_versions = res.affected_ranges, res.fixed_versions
            f.remediation = remediation_text(c, adv, res.fixed_versions, res.affected_ranges)
            f.currently_matching, f.last_checked_at = True, now
        for adv_id, f in existing.items():
            if adv_id in matched:
                continue
            f.currently_matching, f.last_checked_at = False, now
            if f.status in ("open", "acknowledged"):
                why = "component no longer present in latest scan" if c.missing_since else \
                    f"version {c.version or 'unknown'} no longer matches the advisory"
                f.status, f.status_note = "resolved", f"Resolved automatically: {why}."
                f.status_changed_at, f.status_changed_by = now, "system"
                audit(db, "system", "finding.auto_resolved", "finding", f.id, {"reason": why})
                stats["auto_resolved"] += 1
    db.flush()
    return stats


# ---------- orchestration ----------

def run_feed_refresh(db: Session, client: httpx.Client, mode: str = "full") -> dict:
    """Refresh each enabled source independently; one failing source does not block the others."""
    summary, failed = {"mode": mode}, []
    if mode == "pending":
        # Only new inventory; doesn't count as a feed refresh, so freshness timestamps stay honest.
        if settings.osv_enabled:
            try:
                summary["osv"] = refresh_osv(db, client, "pending")
                db.commit()
            except (httpx.HTTPError, ValueError, KeyError) as e:
                db.rollback()
                summary["osv_error"] = scrub(f"{type(e).__name__}: {e}")
                failed.append("osv")
        summary["match"] = rematch(db)
        db.commit()
        summary["failed_sources"] = failed
        return summary
    steps = [("kev", settings.kev_enabled and mode == "full", lambda: refresh_kev(db, client)),
             ("osv", settings.osv_enabled, lambda: refresh_osv(db, client, mode))]
    for source, enabled, fn in steps:
        if not enabled:
            continue
        f = feed(db, source)
        f.last_attempt_at = utcnow()
        try:
            summary[source] = fn()
            f.last_success_at, f.last_error = utcnow(), None
            if source == "osv":
                f.detail = summary[source]
            db.commit()
        except (httpx.HTTPError, ValueError, KeyError) as e:
            db.rollback()
            f = feed(db, source)
            f.last_attempt_at, f.last_error = utcnow(), scrub(f"{type(e).__name__}: {e}")
            db.commit()
            failed.append(source)
    summary["match"] = rematch(db)
    db.commit()
    if settings.nvd_enabled and mode == "full":
        f = feed(db, "nvd")
        f.last_attempt_at = utcnow()
        try:
            summary["nvd"] = refresh_nvd(db, client)
            f.last_success_at, f.last_error = utcnow(), None
        except (httpx.HTTPError, ValueError, KeyError) as e:
            f.last_error = scrub(f"{type(e).__name__}: {e}")
            failed.append("nvd")
        db.commit()
    summary["failed_sources"] = failed
    return summary


def counts_by_severity(db: Session) -> dict:
    rows = db.execute(select(Advisory.severity, func.count()).join(Finding).where(
        Finding.status.in_(["open", "acknowledged"]), Finding.match_status != "unknown_version",
        Finding.currently_matching.is_(True)).group_by(Advisory.severity)).all()
    return dict(rows)
