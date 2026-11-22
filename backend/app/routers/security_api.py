"""Findings, dashboard, feeds, settings, audit log, and the agent-facing endpoints."""
import json
import pathlib
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import ValidationError
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from .. import __version__, dependabot, fixplan, sources, vulns
from .. import matching as m
from ..agent_ingest import Report, ingest
from ..config import settings
from ..db import get_db, utcnow
from ..models import Advisory, AppSetting, AuditLog, Component, FeedStatus, Finding, Host, Repository, ScanRun, User
from ..schemas import AuditOut, FeedOut, FindingOut, FindingStatusIn, Page, RefreshIn, ScanRunOut, SourceIn
from ..security import audit, authenticate_agent, client_ip, limiter, require_user
from ..worker import enqueue
from .common import OPEN, bundled_agent_version, finding_out, paginate, repo_label

router = APIRouter(prefix="/api", tags=["vulnerabilities"])
agent_router = APIRouter(prefix="/api/agent", tags=["agent"])
AGENT_DIR = pathlib.Path(__file__).resolve().parents[3] / "agent"
AGENT_FILES = {"patchy_agent.py", "install.sh", "uninstall.sh", "config.example.json"}
CHANGELOG = pathlib.Path(__file__).resolve().parents[3] / "CHANGELOG.md"

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
                  sort: Literal["priority", "severity", "epss", "cvss", "published", "component", "location",
                                "match", "status", "detected"] = "severity",
                  order: Literal["asc", "desc"] = "desc",
                  page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    query = (select(Finding).join(Advisory).join(Component).outerjoin(Host, Component.host_id == Host.id)
             .outerjoin(Repository, Component.repository_id == Repository.id))
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
    match_rank = case({"confirmed": 0, "possible": 1}, value=Finding.match_status, else_=2)
    if sort == "priority":  # what to fix first: known exploited, then likely exploited, then severity
        keys = [Advisory.kev.desc(), func.coalesce(Advisory.epss, -1).desc(), SEV_RANK.desc()]
        if order == "asc":
            keys = [k.element.asc() for k in keys]
        query = query.order_by(*keys, match_rank, Finding.id)
    else:
        col = {"severity": SEV_RANK, "epss": func.coalesce(Advisory.epss, -1),
               "cvss": func.coalesce(Advisory.cvss_score, -1), "published": Advisory.published,
               "component": Component.name, "location": func.coalesce(Host.name, Repository.name), "match": match_rank,
               "status": Finding.status, "detected": Finding.first_detected_at}[sort]
        query = query.order_by(col.desc() if order == "desc" else col.asc(), Advisory.kev.desc(), match_rank,
                               Finding.id)
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
            "feed_stale": vulns.feed_is_stale(db), "dependabot": dependabot.for_finding(f)}


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
    osv = [c for c in comps if m.supports_osv(c.ecosystem)]
    checked = sum(1 for c in comps if c.version_status == "exact" and c.vuln_checked_at)
    coverage = {
        "total": len(comps),
        "checked": checked,
        "version_unknown": sum(1 for c in osv if c.version_status != "exact"),
        "not_checked_yet": sum(1 for c in osv if c.version_status == "exact" and not c.vuln_checked_at),
    }
    coverage["not_checkable"] = len(comps) - sum(coverage[k] for k in ("checked", "version_unknown", "not_checked_yet"))
    end_of_life = {"eol": sum(1 for c in comps if c.eol_state == "eol"),
                   "eol_soon": sum(1 for c in comps if c.eol_state == "eol_soon"),
                   "hosts_eol": db.scalar(select(func.count()).select_from(Host).where(Host.os_eol_state == "eol")),
                   "hosts_eol_soon": db.scalar(select(func.count()).select_from(Host)
                                               .where(Host.os_eol_state == "eol_soon"))}
    likely = db.scalars(select(Finding).join(Advisory).where(*active, Advisory.epss.is_not(None))
                        .order_by(Advisory.kev.desc(), Advisory.epss.desc()).limit(6)).all()
    recent = db.scalars(select(ScanRun).where(ScanRun.kind != "feed").order_by(ScanRun.id.desc()).limit(8)).all()
    return {
        "severity": by_sev, "match_status": by_match, "status": by_status, "kev_open": kev,
        "top_assets": [{"id": r[0], "name": r[1], "version": r[2], "location": r[3] or (f"{r[4]}/{r[5]}" if r[4] else None),
                        "open": r[6], "max_severity": rank_name.get(r[7], "unknown")} for r in top],
        "coverage": coverage, "feeds": feeds_status(db), "feed_stale": vulns.feed_is_stale(db),
        "end_of_life": end_of_life, "likely_exploited": [finding_out(f) for f in likely],
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
    out = []
    for source, s in sources.schedule(db).items():
        f = db.get(FeedStatus, source)
        last = f.last_success_at if f else None
        detail = {k: v for k, v in (f.detail or {}).items() if k not in ("entries", "products", "index", "cpes")} \
            if f and f.detail else None
        stale_after = max(settings.feed_stale_hours, s["hours"] * 2)
        out.append(FeedOut(source=source, label=s["label"], about=s["about"], hours=s["hours"],
                           unavailable=s["unavailable"], enabled=s["enabled"],
                           last_attempt_at=f.last_attempt_at if f else None, last_success_at=last,
                           last_error=f.last_error if f else None, detail=detail,
                           stale=s["enabled"] and (not last or last < utcnow() - timedelta(hours=stale_after))))
    return out


@router.get("/feeds", response_model=list[FeedOut])
def get_feeds(db: Session = Depends(get_db), _: User = Depends(require_user)):
    return feeds_status(db)


@router.post("/feeds/refresh", response_model=ScanRunOut, status_code=202)
def refresh_feeds(request: Request, body: RefreshIn | None = None, db: Session = Depends(get_db),
                  user: User = Depends(require_user)):
    limiter.check("feed-refresh", 12, 3600)
    only = body.sources if body and body.sources else None
    run, created = enqueue(db, "feed", params={"mode": "full", **({"only": only} if only else {})})
    if created:
        audit(db, user.username, "feed.refresh", "scan_run", run.id, {"sources": only}, client_ip(request))
    db.commit()
    return ScanRunOut.model_validate(run)


@router.get("/settings")
def get_settings(db: Session = Depends(get_db), _: User = Depends(require_user)) -> dict:
    """Non-secret configuration only. Secrets are reported as configured yes/no."""
    return {
        "github_token_configured": bool(settings.github_token),
        "nvd_api_key_configured": bool(settings.nvd_api_key),
        "sources": sources.schedule(db), "hour_choices": list(sources.HOUR_CHOICES),
        "feed_stale_hours": settings.feed_stale_hours, "version": __version__,
        "worker": (w.value if (w := db.get(AppSetting, "worker")) else None),
        "repo_limits": {"max_file_bytes": settings.repo_max_file_bytes, "max_total_bytes": settings.repo_max_total_bytes,
                        "max_manifests": settings.repo_max_manifests, "timeout_seconds": settings.repo_scan_timeout},
        "cookie_secure": settings.cookie_secure,
        "coverage": {
            "local_version_comparison": sorted(m.ECOSYSTEM_COMPARATORS),
            "osv_queried": sorted(m.OSV_ECOSYSTEMS),
            "nvd_products": "Servers, runtimes and manual assets with a known CPE (possible matches)",
            "inventory_only": ["container images (end-of-life only)", "web server configs",
                               "RPM distros other than Rocky/Alma", "NuGet (no manifest parser yet)"],
        },
    }


@router.put("/settings/sources")
def update_sources(body: dict[str, SourceIn], request: Request, db: Session = Depends(get_db),
                   user: User = Depends(require_user)) -> dict:
    unknown = set(body) - set(sources.INFO)
    if unknown:
        raise HTTPException(422, "Unknown source.")
    changes = {k: v.model_dump(exclude_none=True) for k, v in body.items()}
    for k, c in changes.items():
        if c.get("enabled") and sources.unavailable_reason(k):
            raise HTTPException(422, sources.unavailable_reason(k))
    result = sources.save(db, changes)
    audit(db, user.username, "settings.sources", "settings", "sources", changes, client_ip(request))
    db.commit()
    return result


@router.get("/version")
def version(_: User = Depends(require_user)) -> dict:
    return {"version": __version__, "agent_version": bundled_agent_version(),
            "changelog": CHANGELOG.read_text(encoding="utf-8") if CHANGELOG.is_file() else ""}


@router.get("/fix-plan")
def fix_plan(host_id: int | None = None, repository_id: int | None = None, db: Session = Depends(get_db),
             _: User = Depends(require_user)) -> dict:
    return fixplan.build(db, host_id=host_id, repository_id=repository_id)


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


@agent_router.get("/poll")
def agent_poll(request: Request, db: Session = Depends(get_db)) -> dict:
    """Agents 1.2+ ask every few minutes whether someone pressed Rescan. It only ever triggers a normal report."""
    ip = client_ip(request)
    limiter.check(f"agent:{ip}", 60, 60)
    agent = authenticate_agent(db, request)
    agent.last_seen_at, agent.last_ip = utcnow(), ip
    want = agent.host.rescan_requested_at is not None
    db.commit()
    return {"report": want}


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
    # Big reports (container image packages) take seconds of database work. Off the event loop, so the
    # single app process keeps answering health checks and the UI meanwhile.
    return await run_in_threadpool(_store_report, db, agent, bytes(body), ip)


def _store_report(db: Session, agent, body: bytes, ip: str) -> dict:
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
