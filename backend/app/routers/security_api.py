"""Findings, dashboard, feeds, settings, audit log, and the agent-facing endpoints."""
import json
import pathlib
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import ValidationError
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from .. import matching as m
from .. import vulns
from ..agent_ingest import Report, ingest
from ..config import settings
from ..db import get_db, utcnow
from ..models import Advisory, AuditLog, Component, FeedStatus, Finding, Host, Repository, ScanRun, User
from ..schemas import AuditOut, FeedOut, FindingOut, FindingStatusIn, Page, ScanRunOut
from ..security import audit, authenticate_agent, client_ip, limiter, require_user
from ..worker import enqueue
from .common import OPEN, finding_out, paginate, repo_label

router = APIRouter(prefix="/api", tags=["vulnerabilities"])
agent_router = APIRouter(prefix="/api/agent", tags=["agent"])
AGENT_DIR = pathlib.Path(__file__).resolve().parents[3] / "agent"
AGENT_FILES = {"patchy_agent.py", "install.sh", "uninstall.sh", "config.example.json"}

SEV_RANK = case({"critical": 5, "high": 4, "medium": 3, "low": 2, "none": 1}, value=Advisory.severity, else_=0)


# ---------------- findings ----------------

@router.get("/findings", response_model=Page[FindingOut])
def list_findings(db: Session = Depends(get_db), _: User = Depends(require_user),
                  severity: list[Literal["critical", "high", "medium", "low", "none", "unknown"]] = Query(None),
                  status: list[Literal["open", "acknowledged", "resolved", "false_positive"]] = Query(None),
                  match_status: list[Literal["confirmed", "possible", "unknown_version"]] = Query(None),
                  kev: bool | None = None, host_id: int | None = None, repository_id: int | None = None,
                  component_id: int | None = None, q: str | None = Query(None, max_length=200),
                  include_stale_matches: bool = False,
                  sort: Literal["severity", "published", "component", "status", "detected"] = "severity",
                  order: Literal["asc", "desc"] = "desc",
                  page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    query = select(Finding).join(Advisory).join(Component)
    if severity:
        query = query.where(Advisory.severity.in_(severity))
    if status:
        query = query.where(Finding.status.in_(status))
    if match_status:
        query = query.where(Finding.match_status.in_(match_status))
    if kev is not None:
        query = query.where(Advisory.kev.is_(kev))
    for col, val in ((Component.host_id, host_id), (Component.repository_id, repository_id),
                     (Finding.component_id, component_id)):
        if val is not None:
            query = query.where(col == val)
    if q:
        query = query.where(Component.name.icontains(q, autoescape=True) | Advisory.id.icontains(q, autoescape=True))
    if not include_stale_matches:
        query = query.where(Finding.currently_matching.is_(True) | Finding.status.in_(["resolved", "false_positive"]))
    col = {"severity": SEV_RANK, "published": Advisory.published, "component": Component.name,
           "status": Finding.status, "detected": Finding.first_detected_at}[sort]
    query = query.order_by(col.desc() if order == "desc" else col.asc(), Advisory.kev.desc(), Finding.id)
    items, total = paginate(db, query, page, page_size)
    return Page(items=[finding_out(f) for f in items], total=total, page=page, page_size=page_size)


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db), _: User = Depends(require_user)) -> dict:
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Not found.")
    history = db.scalars(select(AuditLog).where(AuditLog.target_type == "finding",
                                                AuditLog.target_id == str(f.id)).order_by(AuditLog.id.desc())).all()
    return {"finding": finding_out(f), "history": [AuditOut.model_validate(h) for h in history],
            "feed_stale": vulns.feed_is_stale(db)}


@router.post("/findings/{finding_id}/status", response_model=FindingOut)
def set_finding_status(finding_id: int, body: FindingStatusIn, request: Request, db: Session = Depends(get_db),
                       user: User = Depends(require_user)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Not found.")
    old = f.status
    f.status, f.status_note = body.status, body.note
    f.status_changed_at, f.status_changed_by = utcnow(), user.username
    audit(db, user.username, "finding.status", "finding", f.id,
          {"from": old, "to": body.status, "note": body.note, "advisory": f.advisory_id}, client_ip(request))
    db.commit()
    return finding_out(f)


# ---------------- dashboard ----------------

@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), _: User = Depends(require_user)) -> dict:
    active = (Finding.status.in_(OPEN), Finding.currently_matching.is_(True))
    by_sev = dict(db.execute(select(Advisory.severity, func.count()).join(Finding).where(
        *active, Finding.match_status != "unknown_version").group_by(Advisory.severity)).all())
    by_match = dict(db.execute(select(Finding.match_status, func.count()).where(*active)
                               .group_by(Finding.match_status)).all())
    by_status = dict(db.execute(select(Finding.status, func.count()).group_by(Finding.status)).all())
    kev = db.scalar(select(func.count()).select_from(Finding).join(Advisory).where(*active, Advisory.kev.is_(True)))
    top = db.execute(
        select(Component.id, Component.name, Component.version, Host.name, Repository.owner, Repository.name,
               func.count(Finding.id), func.max(SEV_RANK))
        .select_from(Finding).join(Advisory).join(Component).outerjoin(Host, Component.host_id == Host.id)
        .outerjoin(Repository, Component.repository_id == Repository.id)
        .where(*active, Finding.match_status != "unknown_version")
        .group_by(Component.id, Component.name, Component.version, Host.name, Repository.owner, Repository.name)
        .order_by(func.max(SEV_RANK).desc(), func.count(Finding.id).desc()).limit(10)).all()
    rank_name = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "none", 0: "unknown"}
    comps = db.scalars(select(Component).where(Component.missing_since.is_(None))).all()
    checkable = [c for c in comps if m.supports_osv(c.ecosystem)]
    coverage = {
        "total": len(comps),
        "not_checkable": len(comps) - len(checkable),
        "version_unknown": sum(1 for c in checkable if c.version_status != "exact"),
        "not_checked_yet": sum(1 for c in checkable if c.version_status == "exact" and not c.vuln_checked_at),
        "checked": sum(1 for c in checkable if c.version_status == "exact" and c.vuln_checked_at),
    }
    recent = db.scalars(select(ScanRun).where(ScanRun.kind != "feed").order_by(ScanRun.id.desc()).limit(8)).all()
    return {
        "severity": by_sev, "match_status": by_match, "status": by_status, "kev_open": kev,
        "top_assets": [{"id": r[0], "name": r[1], "version": r[2], "location": r[3] or (f"{r[4]}/{r[5]}" if r[4] else None),
                        "open": r[6], "max_severity": rank_name.get(r[7], "unknown")} for r in top],
        "coverage": coverage, "feeds": feeds_status(db), "feed_stale": vulns.feed_is_stale(db),
        "recent_scans": [{"id": r.id, "kind": r.kind, "status": r.status, "finished_at": r.finished_at,
                          "created_at": r.created_at,
                          "target": repo_label(r.repository) if r.repository else (r.host.name if r.host else None)}
                         for r in recent],
        "hosts": db.scalar(select(func.count()).select_from(Host)),
        "repositories": db.scalar(select(func.count()).select_from(Repository)),
        "demo_data": bool(db.scalar(select(func.count()).select_from(Host).where(Host.is_demo.is_(True)))),
    }


# ---------------- feeds, settings, audit ----------------

def feeds_status(db: Session) -> list[FeedOut]:
    enabled = {"osv": settings.osv_enabled, "kev": settings.kev_enabled, "nvd": settings.nvd_enabled}
    out = []
    for source in ("osv", "kev", "nvd"):
        f = db.get(FeedStatus, source)
        last = f.last_success_at if f else None
        detail = dict(f.detail or {}) if f else None
        if detail:
            detail.pop("entries", None)  # KEV catalogue is large; keep the response small
        out.append(FeedOut(source=source, enabled=enabled[source], last_attempt_at=f.last_attempt_at if f else None,
                           last_success_at=last, last_error=f.last_error if f else None, detail=detail,
                           stale=enabled[source] and (not last or last < utcnow() - timedelta(hours=settings.feed_stale_hours))))
    return out


@router.get("/feeds", response_model=list[FeedOut])
def get_feeds(db: Session = Depends(get_db), _: User = Depends(require_user)):
    return feeds_status(db)


@router.post("/feeds/refresh", response_model=ScanRunOut, status_code=202)
def refresh_feeds(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    limiter.check("feed-refresh", 6, 3600)
    run, created = enqueue(db, "feed", params={"mode": "full"})
    if created:
        audit(db, user.username, "feed.refresh", "scan_run", run.id, None, client_ip(request))
    db.commit()
    return ScanRunOut.model_validate(run)


@router.get("/settings")
def get_settings(_: User = Depends(require_user)) -> dict:
    """Non-secret configuration only. Secrets are reported as configured yes/no."""
    return {
        "github_token_configured": bool(settings.github_token),
        "nvd_api_key_configured": bool(settings.nvd_api_key),
        "osv_enabled": settings.osv_enabled, "kev_enabled": settings.kev_enabled, "nvd_enabled": settings.nvd_enabled,
        "feed_refresh_hours": settings.feed_refresh_hours, "feed_stale_hours": settings.feed_stale_hours,
        "repo_limits": {"max_file_bytes": settings.repo_max_file_bytes, "max_total_bytes": settings.repo_max_total_bytes,
                        "max_manifests": settings.repo_max_manifests, "timeout_seconds": settings.repo_scan_timeout},
        "cookie_secure": settings.cookie_secure,
        "coverage": {
            "local_version_comparison": sorted(m.ECOSYSTEM_COMPARATORS),
            "osv_queried": sorted(m.OSV_ECOSYSTEMS),
            "inventory_only": ["container images", "language runtimes", "web server configs", "agent version probes",
                               "RPM distros other than Rocky/Alma", "NuGet (no manifest parser yet)"],
        },
    }


@router.get("/audit", response_model=Page[AuditOut])
def list_audit(db: Session = Depends(get_db), _: User = Depends(require_user), action: str | None = None,
               page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    query = select(AuditLog).order_by(AuditLog.id.desc())
    if action:
        query = query.where(AuditLog.action.startswith(action, autoescape=True))
    items, total = paginate(db, query, page, page_size)
    return Page(items=[AuditOut.model_validate(a) for a in items], total=total, page=page, page_size=page_size)


# ---------------- agent-facing (bearer token, no session/CSRF) ----------------

@agent_router.get("/ping")
def agent_ping(request: Request, db: Session = Depends(get_db)) -> dict:
    limiter.check(f"agent:{client_ip(request)}", 60, 60)
    agent = authenticate_agent(db, request)
    return {"ok": True, "host": agent.host.name}


@agent_router.post("/report")
async def agent_report(request: Request, db: Session = Depends(get_db)) -> dict:
    ip = client_ip(request)
    limiter.check(f"agent:{ip}", 30, 60)
    agent = authenticate_agent(db, request)
    if not request.headers.get("content-type", "").startswith("application/json"):
        raise HTTPException(415, "Send the report as application/json.")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > settings.agent_max_report_bytes:
            raise HTTPException(413, "Report too large.")
    try:
        report = Report.model_validate(json.loads(body))
    except (ValueError, ValidationError) as e:
        n = len(e.errors()) if isinstance(e, ValidationError) else 1
        raise HTTPException(422, f"Report failed validation ({n} error(s)).")
    run, duplicate, ids = ingest(db, agent, report, ip)
    if not duplicate:
        vulns.rematch(db, ids)
        enqueue(db, "feed", params={"mode": "pending"})
        audit(db, f"agent:{agent.id}", "agent.report", "host", agent.host_id,
              {"scan_run_id": run.id, "packages": len(report.packages)}, ip)
    db.commit()
    return {"scan_run_id": run.id, "duplicate": duplicate, "status": run.status}


@agent_router.get("/files/{name}", include_in_schema=False)
def agent_file(name: str):
    """Agent scripts for download (no secrets in them). Strict allowlist, no path input reaches the filesystem."""
    if name not in AGENT_FILES:
        raise HTTPException(404, "Not found.")
    return FileResponse(AGENT_DIR / name, media_type="text/plain; charset=utf-8")
