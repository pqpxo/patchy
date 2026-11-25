"""Pending apt updates and Run upgrade.

Patchy never runs anything on a host. Run upgrade queues a request; the agent picks it up at its next check-in
and hands it to the host's own root service, which exists only if the host allowed upgrades at install time
and only ever runs `apt-get update && apt-get upgrade`. The result comes back with the next report.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import matching as m
from .db import utcnow
from .models import Component, Finding, Host, UpgradeRun

OPEN = ("open", "acknowledged")
WAITING = ("queued", "sent")
QUEUED_FOR = timedelta(days=1)  # an agent that never checks in
SENT_FOR = timedelta(hours=2)  # handed over, but no result (apt waits up to 10 minutes for its lock)
REFUSED = "This host doesn't allow upgrades from Patchy, so nothing ran. Re-run the installer to allow them."


def can_upgrade(host: Host) -> bool:
    return bool((host.updates or {}).get("can_upgrade")) and bool(host.agent and not host.agent.revoked_at)


def expire(db: Session, host_id: int) -> None:
    now = utcnow()
    for run in db.scalars(select(UpgradeRun).where(UpgradeRun.host_id == host_id, UpgradeRun.status.in_(WAITING))):
        if run.status == "queued" and run.requested_at < now - QUEUED_FOR:
            run.status, run.finished_at, run.note = "failed", now, "The host's agent didn't check in for a day."
        elif run.status == "sent" and (run.sent_at or run.requested_at) < now - SENT_FOR:
            run.status, run.finished_at, run.note = "failed", now, "No result from the host within 2 hours."


def hand_out(db: Session, host: Host) -> int | None:
    """At an agent check-in: the queued upgrade to pass on, if this host allows them."""
    if not can_upgrade(host):
        return None
    run = db.scalar(select(UpgradeRun).where(UpgradeRun.host_id == host.id, UpgradeRun.status == "queued")
                    .order_by(UpgradeRun.id))
    if run:
        run.status, run.sent_at = "sent", utcnow()
    return run.id if run else None


def _when(s: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None
    except ValueError:
        return None


def record(db: Session, host: Host, report, now: datetime) -> None:
    """Store a report's pending updates and any upgrade result it carries."""
    host.updates = {**report.updates.model_dump(), "reported_at": now.isoformat()} if report.updates else None
    r = report.upgrade_result
    run = db.get(UpgradeRun, r.id) if r else None
    if run and run.host_id == host.id and run.output is None:  # a late result still beats "no result"
        run.status = "succeeded" if r.exit_code == 0 else "failed"
        run.exit_code, run.output, run.note = r.exit_code, r.output, None if r.exit_code is not None else "No exit code."
        run.started_at, run.finished_at = _when(r.started_at), _when(r.finished_at) or now
    if report.updates and not report.updates.can_upgrade:  # the host said no (a report without updates says nothing)
        for run in db.scalars(select(UpgradeRun).where(UpgradeRun.host_id == host.id, UpgradeRun.status.in_(WAITING))):
            run.status, run.finished_at, run.note = "failed", now, REFUSED


def pending(db: Session, host: Host) -> tuple[list[dict], int]:
    """Pending updates, each with how many open findings on this host it fixes, and the total fixed."""
    pkgs = [dict(p) for p in (host.updates or {}).get("packages") or []]
    by_binary: dict[str, int] = {}
    for cid, details in db.execute(select(Component.id, Component.details).where(
            Component.host_id == host.id, Component.source == "agent", Component.component_type == "os_package",
            Component.missing_since.is_(None))):
        for b in (details or {}).get("binaries") or []:
            by_binary.setdefault(b, cid)
    wanted = {by_binary[p["name"]] for p in pkgs if p.get("name") in by_binary}
    by_comp: dict[int, list] = {}
    if wanted:
        for fid, cid, fixed in db.execute(select(Finding.id, Finding.component_id, Finding.fixed_versions).where(
                Finding.component_id.in_(wanted), Finding.status.in_(OPEN), Finding.currently_matching.is_(True))):
            by_comp.setdefault(cid, []).append((fid, fixed or []))
    total: set[int] = set()
    for p in pkgs:
        ids = {fid for fid, fixed in by_comp.get(by_binary.get(p.get("name")), [])
               if any((c := m.cmp_dpkg(v, p.get("available") or "")) is not None and c <= 0 for v in fixed)}
        p["fixes"] = len(ids)
        total |= ids
    pkgs.sort(key=lambda p: (not p.get("security"), -p["fixes"], p.get("name") or ""))
    return pkgs, len(total)
