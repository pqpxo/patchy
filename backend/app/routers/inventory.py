"""Assets (components), hosts + agent credentials, repositories, scans."""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import repo_scanner, vulns
from ..db import get_db, utcnow
from ..models import (Agent, Component, ComponentObservation, ComponentPath, Finding, Host, HostPath, HostService, Repository,
                      ScanRun, User)
from ..schemas import (AgentOut, AgentTokenOut, AssetIn, ComponentDetail, ComponentOut, HostIn, HostOut,
                       HostPathOut, ObservationOut, Page, RepoIn, RepoOut, ScanRunOut, ServiceOut)
from ..security import audit, client_ip, new_agent_token, require_user, sha256
from ..worker import enqueue
from .common import OPEN, component_out, finding_out, finding_stats, paginate, repo_label

router = APIRouter(prefix="/api", tags=["inventory"])


def _404(obj, what="Not found."):
    if obj is None:
        raise HTTPException(404, what)
    return obj


def _open_counts(db, column, ids):
    if not ids:
        return {}
    rows = db.execute(select(column, func.count()).select_from(Finding).join(Component).where(
        column.in_(ids), Finding.status.in_(OPEN), Finding.currently_matching.is_(True)).group_by(column)).all()
    return dict(rows)


def _comp_counts(db, column, ids):
    if not ids:
        return {}
    return dict(db.execute(select(column, func.count()).where(column.in_(ids), Component.missing_since.is_(None))
                           .group_by(column)).all())


# ---------------- assets ----------------

@router.get("/assets", response_model=Page[ComponentOut])
def list_assets(db: Session = Depends(get_db), _: User = Depends(require_user),
                q: str | None = Query(None, max_length=200), component_type: str | None = None,
                source: str | None = None, ecosystem: str | None = None, host_id: int | None = None,
                repository_id: int | None = None, include_missing: bool = False, vulnerable_only: bool = False,
                sort: Literal["name", "type", "updated", "version"] = "name", order: Literal["asc", "desc"] = "asc",
                page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    query = select(Component)
    if q:
        query = query.where(Component.name.icontains(q, autoescape=True))
    for col, val in ((Component.component_type, component_type), (Component.source, source),
                     (Component.ecosystem, ecosystem), (Component.host_id, host_id),
                     (Component.repository_id, repository_id)):
        if val is not None:
            query = query.where(col == val)
    if not include_missing:
        query = query.where(Component.missing_since.is_(None))
    if vulnerable_only:
        query = query.where(Component.id.in_(select(Finding.component_id).where(
            Finding.status.in_(OPEN), Finding.currently_matching.is_(True))))
    col = {"name": Component.name, "type": Component.component_type, "updated": Component.updated_at,
           "version": Component.version}[sort]
    query = query.order_by(col.desc() if order == "desc" else col.asc(), Component.id)
    items, total = paginate(db, query, page, page_size)
    stats, stale = finding_stats(db, [c.id for c in items]), vulns.feed_is_stale(db)
    return Page(items=[component_out(c, stats, stale) for c in items], total=total, page=page, page_size=page_size)


def _apply_asset(db: Session, c: Component, body: AssetIn) -> None:
    for f in ("name", "component_type", "vendor", "ecosystem", "listen_ip", "port", "protocol", "install_path",
              "notes"):
        setattr(c, f, getattr(body, f))
    c.version = body.version
    c.version_status = body.version_status if body.version else "unknown"
    c.version_spec = body.version if body.version_status == "constraint" else None
    if body.host_name:
        host = db.scalar(select(Host).where(Host.name == body.host_name))
        if not host:
            host = Host(name=body.host_name)
            db.add(host)
        if body.host_ip:
            host.ip = body.host_ip
        c.host = host
    else:
        c.host = None
    if body.repository_url:
        try:
            owner, name = repo_scanner.parse_github_url(body.repository_url)
            branch = repo_scanner.validate_branch(body.branch)
        except ValueError as e:
            raise HTTPException(422, str(e))
        repo = db.scalar(select(Repository).where(Repository.owner == owner, Repository.name == name,
                                                  Repository.branch.is_(branch) if branch is None
                                                  else Repository.branch == branch))
        if not repo:
            repo = Repository(url=f"https://github.com/{owner}/{name}", owner=owner, name=name, branch=branch)
            db.add(repo)
        c.repository = repo
    else:
        c.repository = None
    c.paths.clear()
    if body.install_path:
        c.paths.append(ComponentPath(path=body.install_path, kind="install"))


@router.post("/assets", response_model=ComponentOut, status_code=201)
def create_asset(body: AssetIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    c = Component(source="manual", detection="manual")
    db.add(c)
    _apply_asset(db, c, body)
    db.flush()
    vulns.rematch(db, [c.id])
    enqueue(db, "feed", params={"mode": "pending"})
    audit(db, user.username, "asset.create", "component", c.id, {"name": c.name, "version": c.version},
          client_ip(request))
    db.commit()
    return component_out(c, finding_stats(db, [c.id]), vulns.feed_is_stale(db))


@router.get("/assets/{asset_id}", response_model=ComponentDetail)
def get_asset(asset_id: int, db: Session = Depends(get_db), _: User = Depends(require_user)):
    c = _404(db.get(Component, asset_id))
    hist = db.execute(select(ComponentObservation, ScanRun).join(ScanRun).where(
        ComponentObservation.component_id == c.id).order_by(ComponentObservation.id.desc()).limit(50)).all()
    findings = db.scalars(select(Finding).where(Finding.component_id == c.id)).all()
    return component_out(
        c, finding_stats(db, [c.id]), vulns.feed_is_stale(db), ComponentDetail,
        paths=[{"path": p.path, "kind": p.kind} for p in c.paths],
        history=[ObservationOut(scan_run_id=o.scan_run_id, version=o.version, seen_at=o.seen_at,
                                kind=r.kind, status=r.status) for o, r in hist],
        findings=sorted([finding_out(f) for f in findings], key=lambda f: (not f.currently_matching, f.status)),
    )


@router.put("/assets/{asset_id}", response_model=ComponentOut)
def update_asset(asset_id: int, body: AssetIn, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_user)):
    c = _404(db.get(Component, asset_id))
    if c.source != "manual":
        # Detected assets: only notes are editable; the next scan would overwrite anything else.
        c.notes = body.notes
    else:
        _apply_asset(db, c, body)
    db.flush()
    vulns.rematch(db, [c.id])
    enqueue(db, "feed", params={"mode": "pending"})
    audit(db, user.username, "asset.update", "component", c.id, {"name": c.name, "version": c.version},
          client_ip(request))
    db.commit()
    return component_out(c, finding_stats(db, [c.id]), vulns.feed_is_stale(db))


@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    c = _404(db.get(Component, asset_id))
    audit(db, user.username, "asset.delete", "component", c.id, {"name": c.name}, client_ip(request))
    db.delete(c)
    db.commit()


# ---------------- hosts + agents ----------------

def _host_out(db, h: Host, comps=None, opens=None) -> HostOut:
    return HostOut.model_validate({**{k: getattr(h, k) for k in HostOut.model_fields if hasattr(h, k)},
                                   "agent": AgentOut.model_validate(h.agent) if h.agent else None,
                                   "component_count": (comps or {}).get(h.id, 0),
                                   "open_findings": (opens or {}).get(h.id, 0)})


@router.get("/hosts", response_model=Page[HostOut])
def list_hosts(db: Session = Depends(get_db), _: User = Depends(require_user),
               q: str | None = Query(None, max_length=200),
               page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    query = select(Host).order_by(Host.name)
    if q:
        query = query.where(Host.name.icontains(q, autoescape=True))
    items, total = paginate(db, query, page, page_size)
    ids = [h.id for h in items]
    comps, opens = _comp_counts(db, Component.host_id, ids), _open_counts(db, Component.host_id, ids)
    return Page(items=[_host_out(db, h, comps, opens) for h in items], total=total, page=page, page_size=page_size)


@router.post("/hosts", response_model=HostOut, status_code=201)
def create_host(body: HostIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    h = Host(name=body.name, ip=body.ip, notes=body.notes)
    db.add(h)
    try:
        db.flush()
    except IntegrityError:
        raise HTTPException(409, "A host with that name already exists.")
    audit(db, user.username, "host.create", "host", h.id, {"name": h.name}, client_ip(request))
    db.commit()
    return _host_out(db, h)


@router.get("/hosts/{host_id}")
def get_host(host_id: int, db: Session = Depends(get_db), _: User = Depends(require_user)) -> dict:
    h = _404(db.get(Host, host_id))
    services = db.scalars(select(HostService).where(HostService.host_id == h.id)
                          .order_by(HostService.port.is_(None), HostService.port)).all()
    paths = db.scalars(select(HostPath).where(HostPath.host_id == h.id).order_by(HostPath.path).limit(2000)).all()
    runs = db.scalars(select(ScanRun).where(ScanRun.host_id == h.id).order_by(ScanRun.id.desc()).limit(20)).all()
    return {"host": _host_out(db, h, _comp_counts(db, Component.host_id, [h.id]),
                              _open_counts(db, Component.host_id, [h.id])),
            "services": [ServiceOut.model_validate(s) for s in services],
            "paths": [HostPathOut.model_validate(p) for p in paths],
            "runs": [ScanRunOut.model_validate(r) for r in runs]}


@router.put("/hosts/{host_id}", response_model=HostOut)
def update_host(host_id: int, body: HostIn, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_user)):
    h = _404(db.get(Host, host_id))
    h.name, h.ip, h.notes = body.name, body.ip, body.notes
    try:
        db.flush()
    except IntegrityError:
        raise HTTPException(409, "A host with that name already exists.")
    audit(db, user.username, "host.update", "host", h.id, {"name": h.name}, client_ip(request))
    db.commit()
    return _host_out(db, h)


@router.delete("/hosts/{host_id}", status_code=204)
def delete_host(host_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    h = _404(db.get(Host, host_id))
    audit(db, user.username, "host.delete", "host", h.id, {"name": h.name}, client_ip(request))
    db.delete(h)
    db.commit()


def _issue_token(db: Session, h: Host, action: str, user: User, ip: str) -> AgentTokenOut:
    agent = h.agent
    if agent is None:
        agent = Agent(host_id=h.id, token_hash="pending", token_hint="")
        db.add(agent)
        db.flush()
    elif action == "enroll" and not agent.revoked_at:
        raise HTTPException(409, "This host already has an active agent credential. Rotate or revoke it.")
    token = new_agent_token(agent.id)
    agent.token_hash, agent.token_hint = sha256(token), token[-4:]
    agent.revoked_at = None
    if action == "rotate":
        agent.rotated_at = utcnow()
    audit(db, user.username, f"agent.{action}", "host", h.id, {"agent_id": agent.id, "hint": agent.token_hint}, ip)
    db.commit()
    return AgentTokenOut(agent=AgentOut.model_validate(agent), token=token)


@router.post("/hosts/{host_id}/agent", response_model=AgentTokenOut, status_code=201)
def enroll_agent(host_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    return _issue_token(db, _404(db.get(Host, host_id)), "enroll", user, client_ip(request))


@router.post("/hosts/{host_id}/agent/rotate", response_model=AgentTokenOut)
def rotate_agent(host_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    h = _404(db.get(Host, host_id))
    _404(h.agent, "This host has no agent credential yet.")
    return _issue_token(db, h, "rotate", user, client_ip(request))


@router.post("/hosts/{host_id}/agent/revoke", response_model=AgentOut)
def revoke_agent(host_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    h = _404(db.get(Host, host_id))
    agent = _404(h.agent, "This host has no agent credential.")
    agent.revoked_at = utcnow()
    agent.token_hash = sha256("revoked:" + agent.token_hash)  # old token can never match again
    audit(db, user.username, "agent.revoke", "host", h.id, {"agent_id": agent.id}, client_ip(request))
    db.commit()
    return AgentOut.model_validate(agent)


# ---------------- repositories ----------------

def _repo_out(db, r: Repository, comps=None, opens=None) -> RepoOut:
    last = db.scalar(select(ScanRun.status).where(ScanRun.repository_id == r.id).order_by(ScanRun.id.desc()).limit(1))
    return RepoOut.model_validate({**{k: getattr(r, k) for k in RepoOut.model_fields if hasattr(r, k)},
                                   "component_count": (comps or {}).get(r.id, 0),
                                   "open_findings": (opens or {}).get(r.id, 0), "last_scan_status": last})


@router.get("/repositories", response_model=Page[RepoOut])
def list_repos(db: Session = Depends(get_db), _: User = Depends(require_user),
               page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    items, total = paginate(db, select(Repository).order_by(Repository.owner, Repository.name), page, page_size)
    ids = [r.id for r in items]
    comps, opens = _comp_counts(db, Component.repository_id, ids), _open_counts(db, Component.repository_id, ids)
    return Page(items=[_repo_out(db, r, comps, opens) for r in items], total=total, page=page, page_size=page_size)


@router.post("/repositories", response_model=RepoOut, status_code=201)
def create_repo(body: RepoIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    try:
        owner, name = repo_scanner.parse_github_url(body.url)
        branch = repo_scanner.validate_branch(body.branch)
    except ValueError as e:
        raise HTTPException(422, str(e))
    r = Repository(url=f"https://github.com/{owner}/{name}", owner=owner, name=name, branch=branch, notes=body.notes)
    db.add(r)
    try:
        db.flush()
    except IntegrityError:
        raise HTTPException(409, "That repository and branch are already tracked.")
    audit(db, user.username, "repository.create", "repository", r.id, {"repo": repo_label(r)}, client_ip(request))
    db.commit()
    return _repo_out(db, r)


@router.get("/repositories/{repo_id}")
def get_repo(repo_id: int, db: Session = Depends(get_db), _: User = Depends(require_user)) -> dict:
    r = _404(db.get(Repository, repo_id))
    runs = db.scalars(select(ScanRun).where(ScanRun.repository_id == r.id).order_by(ScanRun.id.desc()).limit(20)).all()
    return {"repository": _repo_out(db, r, _comp_counts(db, Component.repository_id, [r.id]),
                                    _open_counts(db, Component.repository_id, [r.id])),
            "runs": [ScanRunOut.model_validate(x) for x in runs]}


@router.delete("/repositories/{repo_id}", status_code=204)
def delete_repo(repo_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    r = _404(db.get(Repository, repo_id))
    audit(db, user.username, "repository.delete", "repository", r.id, {"repo": repo_label(r)}, client_ip(request))
    db.delete(r)
    db.commit()


@router.post("/repositories/{repo_id}/scan", response_model=ScanRunOut, status_code=202)
def scan_repo(repo_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    r = _404(db.get(Repository, repo_id))
    if r.is_demo:
        raise HTTPException(400, "Demo repositories cannot be scanned.")
    run, created = enqueue(db, "repo", repository_id=r.id)
    if created:
        audit(db, user.username, "scan.launch", "repository", r.id, {"scan_run_id": run.id}, client_ip(request))
    db.commit()
    return _run_out(run)


# ---------------- scans ----------------

def _run_out(r: ScanRun) -> ScanRunOut:
    label = repo_label(r.repository) if r.repository else (r.host.name if r.host else None)
    return ScanRunOut.model_validate({**{k: getattr(r, k) for k in ScanRunOut.model_fields if hasattr(r, k)},
                                      "target_label": label or ("Vulnerability feeds" if r.kind == "feed" else None)})


@router.get("/scans", response_model=Page[ScanRunOut])
def list_scans(db: Session = Depends(get_db), _: User = Depends(require_user),
               kind: Literal["repo", "agent", "feed"] | None = None,
               status: Literal["queued", "running", "succeeded", "partial", "failed"] | None = None,
               host_id: int | None = None, repository_id: int | None = None,
               page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    query = select(ScanRun).order_by(ScanRun.id.desc())
    for col, val in ((ScanRun.kind, kind), (ScanRun.status, status), (ScanRun.host_id, host_id),
                     (ScanRun.repository_id, repository_id)):
        if val is not None:
            query = query.where(col == val)
    items, total = paginate(db, query, page, page_size)
    return Page(items=[_run_out(r) for r in items], total=total, page=page, page_size=page_size)


@router.get("/scans/{run_id}")
def get_scan(run_id: int, db: Session = Depends(get_db), _: User = Depends(require_user)) -> dict:
    r = _404(db.get(ScanRun, run_id))
    comps = db.scalars(select(Component).join(ComponentObservation).where(
        ComponentObservation.scan_run_id == r.id).order_by(Component.name).limit(500)).all()
    stats = finding_stats(db, [c.id for c in comps])
    stale = vulns.feed_is_stale(db)
    return {"run": _run_out(r), "components": [component_out(c, stats, stale) for c in comps]}
