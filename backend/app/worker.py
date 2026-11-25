"""DB-backed job worker. Run as `python -m app.worker` (the `worker` compose service)."""
from __future__ import annotations

import logging
import pathlib
import signal
import time

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from . import __version__, alerts, news, repo_scanner, risk, sources, vulns
from .db import SessionLocal, utcnow
from .models import AppSetting, ScanRun

log = logging.getLogger("patchy.worker")
HEARTBEAT = pathlib.Path("/tmp/patchy-worker-heartbeat")
ALERT_EVERY = 300  # seconds between alert checks
NEWS_EVERY = 3600  # seconds between news feed fetches


def enqueue(db: Session, kind: str, *, repository_id=None, params=None) -> tuple[ScanRun, bool]:
    """Queue a job unless an identical one is already queued/running. Returns (run, created)."""
    q = select(ScanRun).where(ScanRun.kind == kind, ScanRun.status.in_(["queued", "running"]))
    if repository_id:
        q = q.where(ScanRun.repository_id == repository_id)
    if kind == "feed":
        mode = (params or {}).get("mode", "full")
        dupes = [r for r in db.scalars(q) if (r.params or {}).get("mode") in (mode, "full")]
    else:
        dupes = db.scalars(q).all()
    if dupes:
        return dupes[0], False
    run = ScanRun(kind=kind, repository_id=repository_id, params=params, status="queued", progress="Queued")
    db.add(run)
    db.flush()
    return run, True


def claim(db: Session) -> ScanRun | None:
    for run in db.scalars(select(ScanRun).where(ScanRun.status == "queued",
                                                ScanRun.kind.in_(["repo", "feed"])).order_by(ScanRun.id).limit(5)):
        # Atomic claim: only one worker wins the UPDATE.
        res = db.execute(update(ScanRun).where(ScanRun.id == run.id, ScanRun.status == "queued")
                         .values(status="running", started_at=utcnow()))
        db.commit()
        if res.rowcount == 1:
            db.refresh(run)
            return run
    return None


def execute(db: Session, run: ScanRun, gh_client=None, feed_client=None) -> None:
    try:
        if run.kind == "repo":
            with (gh_client or repo_scanner.github_client()) as client:
                summary = repo_scanner.scan_repository(db, run, client)
            ids = summary.pop("component_ids")
            vulns.rematch(db, ids)
            run.summary = summary
            run.status = "partial" if summary["partial"] else "succeeded"
            enqueue(db, "feed", params={"mode": "pending"})
        elif run.kind == "feed":
            with (feed_client or vulns.http_client()) as client:
                params = run.params or {}
                summary = vulns.run_feed_refresh(db, client, params.get("mode", "full"), params.get("only"))
            run.summary = summary
            run.status = "partial" if summary["failed_sources"] else "succeeded"
        run.progress = "Done"
    except Exception as e:  # record and continue; never crash the worker loop
        db.rollback()
        log.exception("job %s failed", run.id)
        run = db.get(ScanRun, run.id)
        run.status, run.progress = "failed", "Failed"
        run.error = repo_scanner.error_text(e) if run.kind == "repo" else vulns.scrub(f"{type(e).__name__}")
    run.finished_at = utcnow()
    db.commit()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    stop = False

    def _stop(*_):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    with SessionLocal() as db:  # jobs left running by a crash/restart
        db.execute(update(ScanRun).where(ScanRun.status == "running", ScanRun.kind.in_(["repo", "feed"]))
                   .values(status="failed", error="Worker restarted while job was running.", finished_at=utcnow()))
        db.merge(AppSetting(key="worker", value={"version": __version__, "started_at": utcnow().isoformat()}))
        db.commit()
    log.info("worker %s started", __version__)
    next_alert = next_news = 0.0
    while not stop:
        HEARTBEAT.touch()
        with SessionLocal() as db:
            if time.monotonic() >= next_news or news.pending(db):  # pending: the feed list was just changed
                next_news = time.monotonic() + NEWS_EVERY
                try:
                    news.refresh(db)
                except Exception:  # news is a nicety; never let it stop scans
                    db.rollback()
                    log.exception("news fetch failed")
        if time.monotonic() >= next_alert:
            next_alert = time.monotonic() + ALERT_EVERY
            with SessionLocal() as db:
                try:
                    if (s := risk.apply(db))["risk_released"]:  # rules that expired since the last check
                        log.info("reopened %s finding(s) whose accepted risk ended", s["risk_released"])
                    db.commit()
                    if n := alerts.run(db):
                        log.info("sent an alert covering %s item(s)", n)
                    if alerts.run_digest(db):
                        log.info("sent the weekly digest")
                except Exception:  # an alert problem must never stop scans
                    db.rollback()
                    log.exception("alert check failed")
        with SessionLocal() as db:
            due = sources.due(db)
            if due:
                enqueue(db, "feed", params={"mode": "full", "only": due})
                db.commit()
            run = claim(db)
            if run:
                log.info("running job %s (%s)", run.id, run.kind)
                execute(db, run)
                continue
        time.sleep(3)


if __name__ == "__main__":
    main()
