from datetime import timedelta

import httpx

from app import alerts
from app.config import settings
from app.db import utcnow
from app.models import Advisory, Agent, Component, Finding, Host


def _finding(db, host, adv_id, **adv):
    db.add(Advisory(id=adv_id, cve_ids=["CVE-2026-0001"], affected=[], **adv))
    c = Component(name="openssl", version="3.0.1", component_type="library", source="agent", host_id=host.id)
    db.add(c)
    db.flush()
    db.add(Finding(component_id=c.id, advisory_id=adv_id, match_status="confirmed", evidence="e", remediation="r"))
    db.commit()


def test_each_thing_alerts_once_after_the_first_check(db, host, monkeypatch):
    monkeypatch.setattr(settings, "alert_webhook_url", "http://hook.invalid/secret-id")
    sent = []
    monkeypatch.setattr(alerts, "send", lambda title, message, items: sent.append((title, message)) or {"webhook": None})
    _finding(db, host, "GHSA-old", severity="critical")

    assert alerts.run(db) == 0 and sent == []  # first check: what's already there is the baseline
    _finding(db, host, "GHSA-new", kev=True, severity="high")
    assert alerts.run(db) == 1
    title, message = sent[0]
    assert title == "Patchy: 1 exploited vulnerability"
    assert "CVE-2026-0001 (GHSA-new) in openssl 3.0.1 on pi4" in message
    assert alerts.run(db) == 0 and len(sent) == 1  # not repeated
    assert alerts.status(db)["last_title"] == title


def test_failed_sends_retry_and_switched_off_events_dont_replay(db, host, monkeypatch):
    monkeypatch.setattr(settings, "alert_webhook_url", "http://hook.invalid/secret-id")
    alerts.run(db)
    result = {"webhook": "HTTP 500"}
    monkeypatch.setattr(alerts, "send", lambda *a: dict(result))
    _finding(db, host, "GHSA-crit", severity="critical")
    assert alerts.run(db) == 0 and alerts.status(db)["last_error"] == "webhook: HTTP 500"
    result["webhook"] = None
    assert alerts.run(db) == 1  # retried at the next check

    alerts.save(db, {"critical": False})
    _finding(db, host, "GHSA-crit2", severity="critical")
    assert alerts.run(db) == 0
    alerts.save(db, {"critical": True})
    assert alerts.run(db) == 0  # skipped while off, not replayed when turned back on


def test_host_that_stops_reporting_alerts(db, host, monkeypatch):
    monkeypatch.setattr(settings, "alert_ntfy_url", "http://ntfy.invalid/topic")
    alerts.run(db)
    host.last_report_at = utcnow() - timedelta(hours=30)
    db.add(Agent(host_id=host.id, token_hash="x" * 64, token_hint="abcd"))
    db.add(Host(name="demo", is_demo=True, last_report_at=utcnow() - timedelta(days=5)))
    db.commit()
    items = [i for i in alerts.collect(db, alerts.config(db)) if i.kind == "silent"]
    assert [i.text for i in items] == ["pi4 last reported 30 hours ago"]
    assert alerts.collect(db, {**alerts.config(db), "silent_hours": 48}) == []


def test_send_keeps_secrets_out_of_errors(monkeypatch):
    monkeypatch.setattr(settings, "alert_webhook_url", "http://hook.invalid/secret-id")
    monkeypatch.setattr(settings, "alert_ntfy_url", "http://ntfy.invalid/topic")
    calls = []

    def post(url, **kw):
        calls.append((url, kw))
        return httpx.Response(403 if "ntfy" in url else 200, request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    item = alerts.Item("finding:1", "kev", "CVE-1 in x on pi4", "/vulnerabilities/1")
    assert alerts.send("Patchy: t", "m", [item]) == {"webhook": None, "ntfy": "HTTP 403"}
    assert calls[0][1]["json"]["items"][0]["text"] == "CVE-1 in x on pi4"
    assert calls[1][1]["headers"]["Priority"] == "high"


def test_alert_settings_api(auth_client, monkeypatch):
    s = auth_client.get("/api/settings").json()["alerts"]
    assert s["destinations"] == {"webhook": False, "ntfy": False, "email": False}
    assert s["events"] == {"kev": True, "critical": True, "eol": True, "silent_hours": 24}
    assert auth_client.post("/api/alerts/test").status_code == 409
    assert auth_client.put("/api/settings/alerts", json={"silent_hours": 5}).status_code == 422
    assert auth_client.put("/api/settings/alerts", json={"eol": False, "silent_hours": 0}).json()["eol"] is False

    monkeypatch.setattr(settings, "alert_webhook_url", "http://hook.invalid/secret-id")
    monkeypatch.setattr(alerts, "send", lambda *a: {"webhook": None})
    assert auth_client.post("/api/alerts/test").json() == {"results": {"webhook": None}}
    assert "secret-id" not in auth_client.get("/api/settings").text
