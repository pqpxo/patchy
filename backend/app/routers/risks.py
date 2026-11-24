"""Accepted-risk rules: create, list and revoke. Every rule has an expiry date."""
from datetime import date, datetime, time, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import risk
from ..db import get_db, utcnow
from ..models import Finding, Host, RiskRule, User
from ..security import audit, client_ip, require_user

router = APIRouter(prefix="/api/risks", tags=["risks"])
MAX_DAYS = 365


class RiskRuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    advisory: str | None = Field(None, max_length=128, pattern=r"^[A-Za-z0-9.:-]+$")
    package: str | None = Field(None, max_length=300, pattern=r"^[^\x00-\x1f]+$")
    host_id: int | None = None
    reason: str = Field(min_length=3, max_length=1000)
    expires_on: date


def _out(r: RiskRule, counts: dict) -> dict:
    return {"id": r.id, "advisory": r.advisory, "package": r.package, "host_id": r.host_id,
            "host_name": r.host.name if r.host else None, "reason": r.reason, "expires_at": r.expires_at,
            "created_by": r.created_by, "created_at": r.created_at, "revoked_at": r.revoked_at,
            "active": not r.revoked_at and r.expires_at > utcnow(), "findings": counts.get(f"rule:{r.id}", 0)}


@router.get("")
def list_rules(db: Session = Depends(get_db), _: User = Depends(require_user)) -> list[dict]:
    counts = dict(db.execute(select(Finding.status_changed_by, func.count()).where(Finding.status == "risk_accepted")
                             .group_by(Finding.status_changed_by)).all())
    return [_out(r, counts) for r in db.scalars(select(RiskRule).order_by(RiskRule.id.desc()))]


@router.post("", status_code=201)
def create_rule(body: RiskRuleIn, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_user)) -> dict:
    if not (body.advisory or (body.package or "").strip()):
        raise HTTPException(422, "Give an advisory, a package, or both.")
    today = utcnow().date()
    if not today < body.expires_on <= today + timedelta(days=MAX_DAYS):
        raise HTTPException(422, f"The expiry date must be after today and within {MAX_DAYS} days.")
    if body.host_id and not db.get(Host, body.host_id):
        raise HTTPException(422, "Unknown host.")
    r = RiskRule(advisory=body.advisory, package=(body.package or "").strip() or None, host_id=body.host_id,
                 reason=body.reason.strip(), created_by=user.username,
                 expires_at=datetime.combine(body.expires_on, time(23, 59, 59), tzinfo=timezone.utc))
    db.add(r)
    db.flush()
    stats = risk.apply(db)
    audit(db, user.username, "risk.accept", "risk_rule", r.id,
          {"advisory": r.advisory, "package": r.package, "host_id": r.host_id, "expires_on": str(body.expires_on),
           "reason": r.reason, "findings": stats["risk_accepted"]}, client_ip(request))
    db.commit()
    return _out(r, {f"rule:{r.id}": stats["risk_accepted"]})


@router.delete("/{rule_id}", status_code=204)
def revoke_rule(rule_id: int, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_user)) -> None:
    r = db.get(RiskRule, rule_id)
    if not r:
        raise HTTPException(404, "Not found.")
    if not r.revoked_at:
        r.revoked_at = utcnow()
        stats = risk.apply(db)
        audit(db, user.username, "risk.revoke", "risk_rule", r.id, {"findings_reopened": stats["risk_released"]},
              client_ip(request))
        db.commit()
