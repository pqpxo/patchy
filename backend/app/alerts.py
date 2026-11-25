"""Alerts: tell someone when something changes, without them opening Patchy.

The worker calls run() every few minutes. It looks for alert-worthy things (an exploited or critical finding, a host
that stopped reporting, end of life), drops any already alerted (alerts_sent), and sends the rest as one digest to
every destination that is set up. Destinations come from .env or from Settings > Alerts; a variable set in .env
wins and is locked in the UI. Secret fields (webhook URLs, tokens, the SMTP password) are write-only: the API says
whether they are set, never what they are.
"""
from __future__ import annotations

import logging
import os
import smtplib
from dataclasses import dataclass
from datetime import timedelta
from email.message import EmailMessage

import httpx
from sqlalchemy import and_, false, or_, select
from sqlalchemy.orm import Session

from . import deadlines
from .db import utcnow
from .models import Advisory, Agent, AlertSent, AppSetting, Component, Finding, Host, Repository

log = logging.getLogger("patchy.alerts")
SILENT_CHOICES = (0, 6, 12, 24, 48, 72)  # 0 = off
DEFAULTS = {"kev": True, "critical": True, "overdue": False, "eol": True, "silent_hours": 24, "paused": False}
HEADINGS = {"kev": "Known exploited (CISA KEV)", "critical": "Critical", "overdue": "Past the fix-by deadline",
            "silent": "Hosts not reporting", "eol": "End of life"}
PER_GROUP = 10
PUSHOVER_API = "https://api.pushover.net/1/messages.json"
# name: (environment variable, secret, default)
FIELDS = {
    "patchy_url": ("PATCHY_URL", False, ""),
    "webhook_url": ("ALERT_WEBHOOK_URL", True, ""),
    "ntfy_url": ("ALERT_NTFY_URL", True, ""),
    "ntfy_token": ("ALERT_NTFY_TOKEN", True, ""),
    "pushover_token": ("PUSHOVER_TOKEN", True, ""),
    "pushover_user": ("PUSHOVER_USER", True, ""),
    "smtp_host": ("SMTP_HOST", False, ""),
    "smtp_port": ("SMTP_PORT", False, "587"),
    "smtp_starttls": ("SMTP_STARTTLS", False, "true"),
    "smtp_user": ("SMTP_USER", False, ""),
    "smtp_password": ("SMTP_PASSWORD", True, ""),
    "smtp_from": ("SMTP_FROM", False, ""),
    "email_to": ("ALERT_EMAIL_TO", False, ""),
}


@dataclass
class Item:
    key: str
    kind: str  # kev|critical|overdue|silent|eol
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


def _saved(db: Session) -> dict:
    row = db.get(AppSetting, "alert_destinations")
    return dict(row.value) if row else {}


def values(db: Session) -> dict[str, str]:
    """Destination settings in effect: .env first, then what was saved in Settings, then the default."""
    saved = _saved(db)
    return {k: os.getenv(var, "").strip() or saved.get(k) or default for k, (var, _, default) in FIELDS.items()}


def fields(db: Session) -> dict[str, dict]:
    """For the Settings page. Secret values never leave the server."""
    saved = _saved(db)
    out = {}
    for k, (var, secret, default) in FIELDS.items():
        env = os.getenv(var, "").strip()
        value = env or saved.get(k) or ""
        out[k] = {"env": var, "secret": secret, "source": "env" if env else "ui" if saved.get(k) else None,
                  "value": None if secret else (value or default)}
    return out


def save_destinations(db: Session, changes: dict[str, str | None]) -> None:
    """Empty or None removes a saved value. Fields set in .env can't be changed here."""
    locked = [k for k in changes if os.getenv(FIELDS[k][0], "").strip()]
    if locked:
        raise ValueError(f"Set in .env, so it can't be changed here: {', '.join(FIELDS[k][0] for k in locked)}")
    row = db.get(AppSetting, "alert_destinations") or AppSetting(key="alert_destinations", value={})
    value = dict(row.value or {})
    for k, v in changes.items():
        if v:
            value[k] = v
        else:
            value.pop(k, None)
    row.value = value  # reassign so the JSON column is marked dirty
    db.add(row)
    db.flush()


def destinations(v: dict[str, str]) -> dict[str, bool]:
    return {"webhook": bool(v["webhook_url"]), "ntfy": bool(v["ntfy_url"]),
            "pushover": bool(v["pushover_token"] and v["pushover_user"]),
            "email": bool(v["smtp_host"] and v["email_to"])}


def status(db: Session) -> dict | None:
    row = db.get(AppSetting, "alerts_status")
    return row.value if row else None


# Only the columns alerts need, and only rows that can alert. Loading whole findings with their advisories
# (each carrying its full affected-version list) took gigabytes on a host with many container images.
WHERE = (Host.name, Repository.owner, Repository.name)
NOT_DEMO = (or_(Host.is_demo.is_(None), Host.is_demo == false()),
            or_(Repository.is_demo.is_(None), Repository.is_demo == false()))


def _where(host, owner, repo) -> str:
    return host or (f"{owner}/{repo}" if owner else "a manual asset")


def collect(db: Session, cfg: dict) -> list[Item]:
    items: list[Item] = []
    rows = db.execute(
        select(Finding.id, Finding.match_status, Advisory.id, Advisory.cve_ids, Advisory.kev, Advisory.severity,
               Component.name, Component.version, *WHERE)
        .join(Advisory, Finding.advisory_id == Advisory.id).join(Component, Finding.component_id == Component.id)
        .outerjoin(Host, Component.host_id == Host.id).outerjoin(Repository, Component.repository_id == Repository.id)
        .where(Finding.status == "open", Finding.currently_matching.is_(True), Component.missing_since.is_(None),
               *NOT_DEMO,
               or_(and_(Advisory.kev.is_(True), Finding.match_status.in_(["confirmed", "possible"])),
                   and_(Advisory.severity == "critical", Finding.match_status == "confirmed"))))
    for fid, status, adv_id, cve_ids, kev, severity, cname, cversion, *where in rows:
        # KEV alerts include possible matches (NVD product ranges): an exploited flaw is worth a look either way.
        # A critical KEV finding still goes out as critical when only KEV alerts are off.
        is_kev = kev and status in ("confirmed", "possible")
        is_critical = severity == "critical" and status == "confirmed"
        kind = "kev" if is_kev and (cfg["kev"] or not is_critical) else "critical"
        cve = next(iter(cve_ids or []), None)
        name = adv_id if not cve or cve == adv_id else f"{cve} ({adv_id})"
        what = f"{cname} {cversion}" if cversion else cname
        items.append(Item(f"finding:{fid}", kind, f"{name} in {what} on {_where(*where)}", f"/vulnerabilities/{fid}"))

    # Overdue: one alert per finding when it passes its deadline. Collected while off too, so it's marked seen.
    for fid, adv_id, cve_ids, cname, cversion, sev, kev, added, detected, *where in db.execute(
            select(Finding.id, Advisory.id, Advisory.cve_ids, Component.name, Component.version, Advisory.severity,
                   Advisory.kev, Advisory.kev_date_added, Finding.first_detected_at, *WHERE)
            .join(Advisory, Finding.advisory_id == Advisory.id).join(Component, Finding.component_id == Component.id)
            .outerjoin(Host, Component.host_id == Host.id).outerjoin(Repository, Component.repository_id == Repository.id)
            .where(Finding.status == "open", Finding.currently_matching.is_(True), Component.missing_since.is_(None),
                   Finding.match_status.in_(["confirmed", "possible"]), *NOT_DEMO,
                   deadlines.overdue(deadlines.config(db)))):
        cve = next(iter(cve_ids or []), None)
        name = adv_id if not cve or cve == adv_id else f"{cve} ({adv_id})"
        what = f"{cname} {cversion}" if cversion else cname
        due = deadlines.due_at(deadlines.config(db), sev, kev, added, detected)
        items.append(Item(f"overdue:{fid}", "overdue", f"{name} in {what} on {_where(*where)}, due {due:%d %b %Y}",
                          f"/vulnerabilities/{fid}"))

    # While this alert is off, still collect at the shortest choice so outages are marked seen and not
    # replayed when it's turned back on (run() doesn't send silent items when silent_hours is 0).
    cutoff = utcnow() - timedelta(hours=cfg["silent_hours"] or min(h for h in SILENT_CHOICES if h))
    for hid, name, last in db.execute(select(Host.id, Host.name, Host.last_report_at).join(Agent, Agent.host_id == Host.id)
                                      .where(Agent.revoked_at.is_(None), Host.is_demo.is_(False),
                                             Host.last_report_at < cutoff)):
        hours = int((utcnow() - last).total_seconds() // 3600)
        items.append(Item(f"silent:{hid}:{last.isoformat()}", "silent", f"{name} last reported {hours} hours ago",
                          f"/hosts/{hid}"))

    def eol_item(key, eol, what, path):
        when = "reached end of life" if eol["state"] == "eol" else f"reaches end of life on {eol['eol_from']}"
        return Item(f"{key}:{eol['cycle']}:{eol['state']}", "eol", f"{eol['label']} {eol['cycle']} on {what} {when}",
                    path)
    for hid, name, eol in db.execute(select(Host.id, Host.name, Host.os_eol).where(
            Host.os_eol_state.in_(["eol", "eol_soon"]), Host.is_demo.is_(False))):
        items.append(eol_item(f"eol:host:{hid}", eol, name, f"/hosts/{hid}"))
    for cid, eol, *where in db.execute(
            select(Component.id, Component.eol, *WHERE)
            .outerjoin(Host, Component.host_id == Host.id).outerjoin(Repository, Component.repository_id == Repository.id)
            .where(Component.eol_state.in_(["eol", "eol_soon"]), Component.missing_since.is_(None), *NOT_DEMO)):
        items.append(eol_item(f"eol:c:{cid}", eol, _where(*where), f"/assets/{cid}"))
    return items


def compose(items: list[Item], patchy_url: str = "") -> tuple[str, str]:
    counts = {k: sum(i.kind == k for i in items) for k in HEADINGS}
    words = {"kev": "exploited vulnerability", "critical": "critical vulnerability", "overdue": "overdue finding",
             "silent": "host not reporting", "eol": "end-of-life item"}
    plural = {"kev": "exploited vulnerabilities", "critical": "critical vulnerabilities", "overdue": "overdue findings",
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
    if patchy_url:
        lines.append(patchy_url)
    return title, "\n".join(lines).strip()


def _error(e: Exception) -> str:
    """Short and secret-free: never the URL (a Home Assistant webhook ID is a password) or the SMTP login."""
    if isinstance(e, httpx.HTTPStatusError):
        return f"HTTP {e.response.status_code}"
    if isinstance(e, smtplib.SMTPResponseException):
        return f"SMTP {e.smtp_code}"
    return type(e).__name__


def send(title: str, message: str, items: list[Item], v: dict[str, str]) -> dict[str, str | None]:
    """Send to every configured destination (v from values()). Returns {destination: error or None}."""
    out: dict[str, str | None] = {}
    url = v["patchy_url"]
    if v["webhook_url"]:
        try:
            httpx.post(v["webhook_url"], timeout=15, json={
                "title": title, "message": message, "url": url or None,
                "items": [{"kind": i.kind, "text": i.text, "url": url.rstrip("/") + i.path if url else None}
                          for i in items],
            }).raise_for_status()
            out["webhook"] = None
        except Exception as e:  # noqa: BLE001 - one bad destination must not stop the others
            out["webhook"] = _error(e)
    if v["ntfy_url"]:
        headers = {"Title": title.encode("ascii", "replace").decode(), "Tags": "warning",
                   "Priority": "high" if any(i.kind == "kev" for i in items) else "default"}
        if url:
            headers["Click"] = url
        if v["ntfy_token"]:
            headers["Authorization"] = f"Bearer {v['ntfy_token']}"
        try:
            httpx.post(v["ntfy_url"], content=message.encode(), headers=headers, timeout=15).raise_for_status()
            out["ntfy"] = None
        except Exception as e:  # noqa: BLE001
            out["ntfy"] = _error(e)
    if v["pushover_token"] and v["pushover_user"]:
        data = {"token": v["pushover_token"], "user": v["pushover_user"], "title": title[:250],
                "message": message[:1024], "priority": 1 if any(i.kind == "kev" for i in items) else 0}
        if url:
            data |= {"url": url, "url_title": "Open Patchy"}
        try:
            httpx.post(PUSHOVER_API, data=data, timeout=15).raise_for_status()
            out["pushover"] = None
        except Exception as e:  # noqa: BLE001
            out["pushover"] = _error(e)
    if v["smtp_host"] and v["email_to"]:
        msg = EmailMessage()
        msg["Subject"], msg["From"] = title, v["smtp_from"] or v["smtp_user"]
        msg["To"] = v["email_to"]
        msg.set_content(message)
        try:
            port = int(v["smtp_port"])
            cls = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
            with cls(v["smtp_host"], port, timeout=20) as s:
                if cls is smtplib.SMTP and v["smtp_starttls"].lower() in ("1", "true", "yes", "on"):
                    s.starttls()
                if v["smtp_user"]:
                    s.login(v["smtp_user"], v["smtp_password"])
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
    wanted = [] if first or cfg["paused"] else [i for i in new if cfg.get("silent_hours" if i.kind == "silent" else i.kind)]
    sent, v = 0, values(db)
    if wanted and any(destinations(v).values()):
        title, message = compose(wanted, v["patchy_url"])
        results = send(title, message, wanted, v)
        record(db, title, results)
        if all(results.values()):  # every destination failed: try again at the next check
            db.commit()
            log.warning("alerts not sent: %s", results)
            return 0
        sent = len(wanted)
    # Disabled kinds, everything while paused, and everything when nothing is set up, are marked seen too, so turning them on later
    # alerts what happens from then on rather than replaying the backlog.
    db.add_all(AlertSent(key=i.key) for i in new)
    if first:
        db.merge(AppSetting(key="alerts_status", value={**(status(db) or {}), "baseline_at": utcnow().isoformat()}))
    db.commit()
    return sent
