"""Read-only API tokens and the summary they can read, for Home Assistant and other dashboards."""
import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import __version__, alerts, deadlines, registry, vulns
from ..db import get_db, utcnow
from ..models import Advisory, Agent, ApiToken, Component, Finding, Host, User
from ..security import audit, client_ip, current_session, limiter, require_user, sha256
from .common import OPEN

router = APIRouter(prefix="/api", tags=["integrations"])


class TokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100, pattern=r"^[^\x00-\x1f]+$")


def _out(t: ApiToken) -> dict:
    return {"id": t.id, "name": t.name, "hint": t.token_hint, "created_at": t.created_at, "created_by": t.created_by,
            "last_used_at": t.last_used_at, "last_ip": t.last_ip, "revoked_at": t.revoked_at}


def reader(request: Request, db: Session = Depends(get_db)) -> str:
    """A signed-in user, or a read-only API token sent as 'Authorization: Bearer pt_...'. Returns who it is."""
    auth = request.headers.get("authorization", "")
    if not auth:
        return require_user(current_session(request, db)).username
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    try:
        _, tid, _ = token.split("_", 2)
        t = db.get(ApiToken, int(tid))
    except ValueError:
        t = None
    if not t or t.revoked_at or not secrets.compare_digest(t.token_hash, sha256(token)):
        limiter.check(f"token-fail:{client_ip(request)}", 10, 300)  # slow down guessing
        raise HTTPException(401, "Invalid or revoked API token.")
    now = utcnow()
    if not t.last_used_at or t.last_used_at < now - timedelta(minutes=5):  # not a write on every poll
        t.last_used_at, t.last_ip = now, client_ip(request)
        db.commit()
    return f"token:{t.name}"


@router.get("/integrations/summary")
def summary(db: Session = Depends(get_db), _: str = Depends(reader)) -> dict:
    """Counts for a dashboard. Stable keys: new ones may be added, existing ones keep their meaning."""
    active = (Finding.status.in_(OPEN), Finding.currently_matching.is_(True), Finding.match_status != "unknown_version")
    sev = dict(db.execute(select(Advisory.severity, func.count()).select_from(Finding).join(Advisory)
                          .where(*active).group_by(Advisory.severity)).all())
    count = lambda *where: db.scalar(select(func.count()).select_from(Finding).join(Advisory).join(Component)  # noqa: E731
                                     .where(*active, *where))
    eol = lambda state: (  # noqa: E731
        db.scalar(select(func.count()).select_from(Component).where(Component.missing_since.is_(None),
                                                                   Component.eol_state == state))
        + db.scalar(select(func.count()).select_from(Host).where(Host.os_eol_state == state)))
    cutoff = utcnow() - timedelta(hours=alerts.config(db)["silent_hours"] or 24)
    hosts = db.scalars(select(Host).where(Host.is_demo.is_(False))).all()
    silent = db.scalar(select(func.count()).select_from(Host).join(Agent, Agent.host_id == Host.id).where(
        Agent.revoked_at.is_(None), Host.is_demo.is_(False), Host.last_report_at < cutoff))  # as the alert counts it
    return {
        "open": sum(sev.values()), **{k: sev.get(k, 0) for k in ("critical", "high", "medium", "low")},
        "kev": count(Advisory.kev.is_(True)),
        "overdue": count(deadlines.overdue(deadlines.config(db))),
        "network_exposed": count(Component.exposure == "network"),
        "eol": eol("eol"), "eol_soon": eol("eol_soon"),
        "hosts": len(hosts), "hosts_not_reporting": silent,
        "newer_images": sum(len(registry.newer(db, h)) for h in hosts),
        "feeds_stale": vulns.feed_is_stale(db), "alerts_paused": alerts.config(db)["paused"],
        "version": __version__, "generated_at": utcnow().isoformat(),
    }


@router.get("/settings/tokens")
def list_tokens(db: Session = Depends(get_db), _: User = Depends(require_user)) -> list[dict]:
    return [_out(t) for t in db.scalars(select(ApiToken).order_by(ApiToken.id.desc()))]


@router.post("/settings/tokens", status_code=201)
def create_token(body: TokenIn, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_user)) -> dict:
    """The token is in this response only; Patchy keeps a SHA-256 of it."""
    if db.scalar(select(func.count()).select_from(ApiToken).where(ApiToken.revoked_at.is_(None))) >= 20:
        raise HTTPException(409, "Up to 20 active tokens. Revoke one first.")
    t = ApiToken(name=body.name.strip(), token_hash="", token_hint="", created_by=user.username)
    db.add(t)
    db.flush()
    token = f"pt_{t.id}_{secrets.token_urlsafe(32)}"
    t.token_hash, t.token_hint = sha256(token), "..." + token[-4:]
    audit(db, user.username, "token.create", "api_token", t.id, {"name": t.name}, client_ip(request))
    db.commit()
    return {**_out(t), "token": token}


@router.delete("/settings/tokens/{token_id}", status_code=204)
def revoke_token(token_id: int, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_user)) -> None:
    t = db.get(ApiToken, token_id)
    if not t:
        raise HTTPException(404, "Not found.")
    if not t.revoked_at:
        t.revoked_at = utcnow()
        audit(db, user.username, "token.revoke", "api_token", t.id, {"name": t.name}, client_ip(request))
        db.commit()
