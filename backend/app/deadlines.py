"""Fix-by deadlines: how long each severity may stay open, counted from when Patchy first found it.

Known-exploited (CISA KEV) findings get the critical deadline whatever their severity, counted from when Patchy found
them or when CISA listed them, whichever is later. 0 days turns a deadline off.
"""
from __future__ import annotations

import statistics
from datetime import datetime, time, timedelta, timezone

from sqlalchemy import and_, false, or_, select, true
from sqlalchemy.orm import Session

from .db import utcnow
from .models import Advisory, AppSetting, Finding

DEFAULTS = {"critical": 7, "high": 30, "medium": 90, "low": 180}


def config(db: Session) -> dict:
    if "deadlines" not in db.info:  # read once per request: a missing row isn't cached by the session
        row = db.get(AppSetting, "deadlines")
        db.info["deadlines"] = {**DEFAULTS, **{k: v for k, v in (row.value if row else {}).items() if k in DEFAULTS}}
    return db.info["deadlines"]


def save(db: Session, changes: dict) -> dict:
    row = db.get(AppSetting, "deadlines") or AppSetting(key="deadlines", value={})
    row.value = {**(row.value or {}), **changes}  # reassign so the JSON column is marked dirty
    db.add(row)
    db.flush()
    db.info.pop("deadlines", None)
    return config(db)


def _utc(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)  # SQLite hands back naive UTC


def _listed(kev_date_added: str | None) -> datetime | None:
    try:
        return datetime.combine(datetime.fromisoformat(kev_date_added).date(), time(), timezone.utc)
    except (TypeError, ValueError):
        return None


def due_at(cfg: dict, severity: str, kev: bool, kev_date_added: str | None, detected: datetime) -> datetime | None:
    detected = _utc(detected)
    if kev and cfg["critical"]:
        return max(detected, _listed(kev_date_added) or detected) + timedelta(days=cfg["critical"])
    days = cfg.get(severity)
    return detected + timedelta(days=days) if days else None


def overdue(cfg: dict, now: datetime | None = None):
    """SQL condition for findings past their deadline. Needs Advisory joined. Matches due_at()."""
    now = now or utcnow()
    crit = cfg["critical"]
    not_kev = Advisory.kev.is_(False) if crit else true()  # with no critical deadline, KEV uses its severity
    parts = [and_(not_kev, Advisory.severity == sev, Finding.first_detected_at < now - timedelta(days=days))
             for sev, days in cfg.items() if days]
    if crit:
        cutoff = now - timedelta(days=crit)
        parts.append(and_(Advisory.kev.is_(True), Finding.first_detected_at < cutoff,
                          or_(Advisory.kev_date_added.is_(None), Advisory.kev_date_added <= cutoff.date().isoformat())))
    return or_(*parts) if parts else false()


def time_to_fix(db: Session, days: int = 90) -> dict:
    """Findings resolved in the last `days`: how many, the median days they were open, and the share fixed on time."""
    cfg = config(db)
    rows = db.execute(select(Finding.first_detected_at, Finding.status_changed_at, Advisory.severity, Advisory.kev,
                             Advisory.kev_date_added).join(Advisory)
                      .where(Finding.status == "resolved", Finding.status_changed_at >= utcnow() - timedelta(days=days)))
    spans, on_time = [], []
    for detected, fixed, *adv in rows:
        detected, fixed = _utc(detected), _utc(fixed)
        spans.append((fixed - detected).total_seconds())
        if due := due_at(cfg, *adv, detected):
            on_time.append(fixed <= due)
    return {"days": days, "fixed": len(spans),
            "median_days": round(statistics.median(spans) / 86400, 1) if spans else None,
            "on_time_pct": round(100 * sum(on_time) / len(on_time)) if on_time else None}
