"""Idempotent upsert of discovered components for one host or repository scan."""
from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import utcnow
from .models import Component, ComponentObservation, ComponentPath, ScanRun

FIELDS = ("name", "component_type", "vendor", "ecosystem", "version", "version_status", "version_spec",
          "source_package", "source_version", "listen_ip", "port", "protocol", "install_path", "details")


def sync_components(db: Session, run: ScanRun, scope: str, items: list[dict], *, source: str,
                    host_id: int | None = None, repository_id: int | None = None) -> list[int]:
    """items: dicts with FIELDS plus 'identity' (stable within scope) and 'paths' [(path, kind)].

    Components in this scope that are not in `items` get missing_since set (their findings then
    auto-resolve on the next match). Re-sending the same report is a no-op apart from timestamps.
    """
    now = utcnow()
    counts = Counter(i["identity"] for i in items)
    keyed = {}
    for i in items:
        key = f"{scope}|{i['identity']}"
        if counts[i["identity"]] > 1:  # same package twice at one location, eg two lockfile versions
            key += f"|{i.get('version') or ''}"
        keyed[key[:800]] = i

    q = select(Component).where(Component.source == source)
    q = q.where(Component.host_id == host_id) if host_id else q.where(Component.repository_id == repository_id)
    existing = {c.dedupe_key: c for c in db.scalars(q)}
    ids = []
    for key, item in keyed.items():
        c = existing.get(key)
        if c is None:
            c = Component(dedupe_key=key, source=source, detection="detected", host_id=host_id,
                          repository_id=repository_id)
            db.add(c)
        for f in FIELDS:
            if f in item:
                setattr(c, f, item[f])
        c.missing_since = None
        c.last_scan_run_id = run.id
        c.last_scanned_at = now
        db.flush()
        known = {p.path for p in c.paths}
        for path, kind in item.get("paths") or []:
            if path and path not in known:
                c.paths.append(ComponentPath(path=path[:1024], kind=kind))
                known.add(path)
        db.add(ComponentObservation(component_id=c.id, scan_run_id=run.id, version=c.version))
        ids.append(c.id)
    for key, c in existing.items():
        if key not in keyed and c.missing_since is None:
            c.missing_since = now
            ids.append(c.id)
    db.flush()
    return ids
