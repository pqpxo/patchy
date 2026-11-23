"""Alerts: tell someone when something changes, without them opening Patchy.

The worker calls run() every few minutes. It looks for alert-worthy things (an exploited or critical finding, a host
that stopped reporting, end of life), drops any already alerted (alerts_sent), and sends the rest as one digest to
every destination set in .env. Destinations are secrets (webhook IDs, tokens, SMTP password), so they live in
environment variables only; which events alert is saved from the Settings page.
"""
from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from datetime import timedelta
from email.message import EmailMessage

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .config import settings
from .db import utcnow
from .models import Agent, AlertSent, AppSetting, Component, Finding, Host

log = logging.getLogger("patchy.alerts")
SILENT_CHOICES = (0, 6, 12, 24, 48, 72)  # 0 = off
DEFAULTS = {"kev": True, "critical": True, "eol": True, "silent_hours": 24}
HEADINGS = {"kev": "Known exploited (CISA KEV)", "critical": "Critical", "silent": "Hosts not reporting",
            "eol": "End of life"}
PER_GROUP = 10


@dataclass
class Item:
    key: str
    kind: str  # kev|critical|silent|eol
    text: str
    path: str  # page in Patchy


def config(db: Session) -> dict:
    row = db.get(AppSetting, "alerts")
    return {**DEFAULTS, **{k: v for k, v in (row.value if row else {}).items() if k in DEFAULTS}}


def save(db: Session, changes: dict) -> dict:
    row = db.get(AppSetting, "alerts") or AppSetting(key="alerts", value={})
    row.value = {**(row.value or {}), **changes}  # reassign so the JSON column is marked dirty
    db.add(row)
    db.flush()
    return config(db)


def destinations() -> dict[str, bool]:
    return {"webhook": bool(settings.alert_webhook_url), "ntfy": bool(settings.alert_ntfy_url),
            "email": bool(settings.smtp_host and settings.alert_email_to)}


def status(db: Session) -> dict | None:
    row = db.get(AppSetting, "alerts_status")
    return row.value if row else None


def _where(c: Component) -> str:
    if c.host:
        return c.host.name
    r = c.repository
    return f"{r.owner}/{r.name}" if r else "a manual asset"


def collect(db: Session, cfg: dict) -> list[Item]:
    items: list[Item] = []
    rows = db.scalars(select(Finding).options(joinedload(Finding.advisory), joinedload(Finding.component)
                                              .joinedload(Component.host), joinedload(Finding.component)
                                              .joinedload(Component.repository))
                      .where(Finding.status == "open", Finding.currently_matching.is_(True))).unique()
    for f in rows:
        a, c = f.advisory, f.component
        if (c.host and c.host.is_demo) or (c.repository and c.repository.is_demo) or c.missing_since:
            continue
        # KEV alerts include possible matches (NVD product ranges): an exploited flaw is worth a look either way.
        # A critical KEV finding still goes out as critical when only KEV alerts are off.
        is_kev = a.kev and f.match_status in ("confirmed", "possible")
        is_critical = a.severity == "critical" and f.match_status == "confirmed"
        if is_kev and (cfg["kev"] or not is_critical):
            kind = "kev"
        elif is_critical:
            kind = "critical"
        else:
            continue
        cve = next(iter(a.cve_ids or []), None)
        name = a.id if not cve or cve == a.id else f"{cve} ({a.id})"
        what = f"{c.name} {c.version}" if c.version else c.name
        items.append(Item(f"finding:{f.id}", kind, f"{name} in {what} on {_where(c)}", f"/vulnerabilities/{f.id}"))

    # While this alert is off, still collect at the shortest choice so outages are marked seen and not
    # replayed when it's turned back on (run() doesn't send silent items when silent_hours is 0).
    cutoff = utcnow() - timedelta(hours=cfg["silent_hours"] or min(h for h in SILENT_CHOICES if h))
    for h in db.scalars(select(Host).join(Agent, Agent.host_id == Host.id).where(
            Agent.revoked_at.is_(None), Host.is_demo.is_(False), Host.last_report_at < cutoff)):
        hours = int((utcnow() - h.last_report_at).total_seconds() // 3600)
        items.append(Item(f"silent:{h.id}:{h.last_report_at.isoformat()}", "silent",
                          f"{h.name} last reported {hours} hours ago", f"/hosts/{h.id}"))

    def eol_item(key, eol, what, path):
        when = "reached end of life" if eol["state"] == "eol" else f"reaches end of life on {eol['eol_from']}"
        return Item(f"{key}:{eol['cycle']}:{eol['state']}", "eol", f"{eol['label']} {eol['cycle']} on {what} {when}",
                    path)
    for h in db.scalars(select(Host).where(Host.os_eol_state.in_(["eol", "eol_soon"]), Host.is_demo.is_(False))):
        items.append(eol_item(f"eol:host:{h.id}", h.os_eol, h.name, f"/hosts/{h.id}"))
    for c in db.scalars(select(Component).options(joinedload(Component.host), joinedload(Component.repository))
                        .where(Component.eol_state.in_(["eol", "eol_soon"]), Component.missing_since.is_(None))):
        if (c.host and c.host.is_demo) or (c.repository and c.repository.is_demo):
            continue
        items.append(eol_item(f"eol:c:{c.id}", c.eol, _where(c), f"/assets/{c.id}"))
    return items


def compose(items: list[Item]) -> tuple[str, str]:
    counts = {k: sum(i.kind == k for i in items) for k in HEADINGS}
    words = {"kev": "exploited vulnerability", "critical": "critical vulnerability", "silent": "host not reporting",
             "eol": "end-of-life item"}
    plural = {"kev": "exploited vulnerabilities", "critical": "critical vulnerabilities",
              "silent": "hosts not reporting", "eol": "end-of-life items"}
    title = "Patchy: " + ", ".join(f"{n} {words[k] if n == 1 else plural[k]}" for k, n in counts.items() if n)
    lines = []
    for k, heading in HEADINGS.items():
        group = [i for i in items if i.kind == k]
        if not group:
            continue
        lines.append(f"{heading}:")
        lines += [f"- {i.text}" for i in group[:PER_GROUP]]
        if len(group) > PER_GROUP:
            lines.append(f"- and {len(group) - PER_GROUP} more")
        lines.append("")
    if settings.patchy_url:
        lines.append(settings.patchy_url)
    return title, "\n".join(lines).strip()


def _link(path: str) -> str | None:
    return settings.patchy_url.rstrip("/") + path if settings.patchy_url else None


def _error(e: Exception) -> str:
    """Short and secret-free: never the URL (a Home Assistant webhook ID is a password) or the SMTP login."""
    if isinstance(e, httpx.HTTPStatusError):
        return f"HTTP {e.response.status_code}"
    if isinstance(e, smtplib.SMTPResponseException):
        return f"SMTP {e.smtp_code}"
    return type(e).__name__


def send(title: str, message: str, items: list[Item]) -> dict[str, str | None]:
    """Send to every configured destination. Returns {destination: error or None}."""
    out: dict[str, str | None] = {}
    if settings.alert_webhook_url:
        try:
            httpx.post(settings.alert_webhook_url, timeout=15, json={
                "title": title, "message": message, "url": settings.patchy_url or None,
                "items": [{"kind": i.kind, "text": i.text, "url": _link(i.path)} for i in items],
            }).raise_for_status()
            out["webhook"] = None
        except Exception as e:  # noqa: BLE001 - one bad destination must not stop the others
            out["webhook"] = _error(e)
    if settings.alert_ntfy_url:
        headers = {"Title": title.encode("ascii", "replace").decode(), "Tags": "warning",
                   "Priority": "high" if any(i.kind == "kev" for i in items) else "default"}
        if settings.patchy_url:
            headers["Click"] = settings.patchy_url
        if settings.alert_ntfy_token:
            headers["Authorization"] = f"Bearer {settings.alert_ntfy_token}"
        try:
            httpx.post(settings.alert_ntfy_url, content=message.encode(), headers=headers, timeout=15).raise_for_status()
            out["ntfy"] = None
        except Exception as e:  # noqa: BLE001
            out["ntfy"] = _error(e)
    if settings.smtp_host and settings.alert_email_to:
        msg = EmailMessage()
        msg["Subject"], msg["From"] = title, settings.smtp_from or settings.smtp_user
        msg["To"] = settings.alert_email_to
        msg.set_content(message)
        try:
            cls = smtplib.SMTP_SSL if settings.smtp_port == 465 else smtplib.SMTP
            with cls(settings.smtp_host, settings.smtp_port, timeout=20) as s:
                if cls is smtplib.SMTP and settings.smtp_starttls:
                    s.starttls()
                if settings.smtp_user:
                    s.login(settings.smtp_user, settings.smtp_password)
                s.send_message(msg)
            out["email"] = None
        except Exception as e:  # noqa: BLE001
            out["email"] = _error(e)
    return out


def record(db: Session, title: str, results: dict[str, str | None]) -> None:
    errors = [f"{d}: {err}" for d, err in results.items() if err]
    prev = status(db) or {}
    ok = len(errors) < len(results)
    db.merge(AppSetting(key="alerts_status", value={
        **prev, "last_attempt_at": utcnow().isoformat(), "last_error": "; ".join(errors) or None,
        **({"last_sent_at": utcnow().isoformat(), "last_title": title} if ok else {})}))


def run(db: Session) -> int:
    """One check. Returns how many items were sent. The first check only records what is already there."""
    cfg = config(db)
    items = collect(db, cfg)
    keys = [i.key for i in items]
    seen = set()
    for n in range(0, len(keys), 500):
        seen.update(db.scalars(select(AlertSent.key).where(AlertSent.key.in_(keys[n:n + 500]))))
    new = [i for i in items if i.key not in seen]
    first = (status(db) or {}).get("baseline_at") is None
    wanted = [] if first else [i for i in new if cfg.get("silent_hours" if i.kind == "silent" else i.kind)]
    sent = 0
    if wanted and any(destinations().values()):
        title, message = compose(wanted)
        results = send(title, message, wanted)
        record(db, title, results)
        if all(results.values()):  # every destination failed: try again at the next check
            db.commit()
            log.warning("alerts not sent: %s", results)
            return 0
        sent = len(wanted)
    # Disabled kinds, and everything when nothing is set up, are marked seen too, so turning them on later
    # alerts what happens from then on rather than replaying the backlog.
    db.add_all(AlertSent(key=i.key) for i in new)
    if first:
        db.merge(AppSetting(key="alerts_status", value={**(status(db) or {}), "baseline_at": utcnow().isoformat()}))
    db.commit()
    return sent
