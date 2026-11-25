"""Accepted-risk rules: matching findings leave the open counts until the rule expires or is revoked."""
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from .db import utcnow
from .models import Advisory, Component, Finding, RiskRule
from .security import audit

OPEN = ("open", "acknowledged")


def findings_for(r: RiskRule):
    """Findings a rule covers. The advisory may be the finding's own id or a CVE it lists."""
    q = select(Finding).join(Advisory).join(Component)
    if r.advisory:
        a = r.advisory  # validated to [A-Za-z0-9.:-], so safe inside LIKE
        q = q.where(or_(Finding.advisory_id == a, Finding.advisory_id.like(f"%-{a}"),
                        cast(Advisory.cve_ids, String).like(f'%"{a}"%'), cast(Advisory.aliases, String).like(f'%"{a}"%')))
    if r.package:
        p = r.package.lower()
        q = q.where(or_(func.lower(Component.name) == p, func.lower(Component.source_package) == p))
    if r.host_id:
        q = q.where(Component.host_id == r.host_id)
    return q


def apply(db: Session) -> dict:
    """Release findings whose rule has ended, then accept open ones that an active rule covers."""
    now = utcnow()
    rules = {r.id: r for r in db.scalars(select(RiskRule).where(RiskRule.revoked_at.is_(None), RiskRule.expires_at > now))}
    released = accepted = 0
    for f in db.scalars(select(Finding).where(Finding.status == "risk_accepted")):
        rid = (f.status_changed_by or "").removeprefix("rule:")
        if not (rid.isdigit() and int(rid) in rules):
            note = "Reopened automatically: the accepted-risk rule expired or was revoked."
            audit(db, "system", "finding.auto_status", "finding", f.id, {"from": f.status, "to": "open", "note": note})
            f.status, f.status_changed_by, f.status_changed_at, f.status_note = "open", "system", now, note
            released += 1
    for r in rules.values():
        for f in db.scalars(findings_for(r).where(Finding.status.in_(OPEN))):
            note = f"Risk accepted by {r.created_by} until {r.expires_at:%d %b %Y}: {r.reason}"
            audit(db, f"rule:{r.id}", "finding.auto_status", "finding", f.id, {"from": f.status, "to": "risk_accepted", "note": note})
            f.status, f.status_changed_by, f.status_changed_at, f.status_note = "risk_accepted", f"rule:{r.id}", now, note
            accepted += 1
    db.flush()
    return {"risk_accepted": accepted, "risk_released": released}
