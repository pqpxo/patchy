from datetime import timedelta

import httpx

from app import alerts
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
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "http://hook.invalid/secret-id")
    sent = []
    monkeypatch.setattr(alerts, "send", lambda title, message, items, v: sent.append((title, message)) or {"webhook": None})
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
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "http://hook.invalid/secret-id")
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

    alerts.save(db, {"kev": False})  # a critical KEV finding still goes out as critical
    _finding(db, host, "GHSA-crit-kev", severity="critical", kev=True)
    assert [i.kind for i in alerts.collect(db, alerts.config(db)) if i.text.startswith("CVE-2026-0001 (GHSA-crit-kev)")] == ["critical"]
    assert alerts.run(db) == 1


def test_host_that_stops_reporting_alerts(db, host, monkeypatch):
    monkeypatch.setenv("ALERT_NTFY_URL", "http://ntfy.invalid/topic")
    alerts.run(db)
    host.last_report_at = utcnow() - timedelta(hours=30)
    db.add(Agent(host_id=host.id, token_hash="x" * 64, token_hint="abcd"))
    db.add(Host(name="demo", is_demo=True, last_report_at=utcnow() - timedelta(days=5)))
    db.commit()
    items = [i for i in alerts.collect(db, alerts.config(db)) if i.kind == "silent"]
    assert [i.text for i in items] == ["pi4 last reported 30 hours ago"]
    assert alerts.collect(db, {**alerts.config(db), "silent_hours": 48}) == []

    sent = []
    monkeypatch.setattr(alerts, "send", lambda title, message, items, v: sent.append(title) or {"ntfy": None})
    alerts.save(db, {"silent_hours": 0})
    assert alerts.run(db) == 0 and sent == []  # an outage while the alert is off is recorded, not sent
    alerts.save(db, {"silent_hours": 24})
    assert alerts.run(db) == 0 and sent == []  # and not replayed when it's turned back on


def test_send_keeps_secrets_out_of_errors(db, monkeypatch):
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "http://hook.invalid/secret-id")
    monkeypatch.setenv("ALERT_NTFY_URL", "http://ntfy.invalid/topic")
    calls = []

    def post(url, **kw):
        calls.append((url, kw))
        return httpx.Response(403 if "ntfy" in url else 200, request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    item = alerts.Item("finding:1", "kev", "CVE-1 in x on pi4", "/vulnerabilities/1")
    assert alerts.send("Patchy: t", "m", [item], alerts.values(db)) == {"webhook": None, "ntfy": "HTTP 403"}
    assert calls[0][1]["json"]["items"][0]["text"] == "CVE-1 in x on pi4"
    assert calls[1][1]["headers"]["Priority"] == "high"


def test_pushover(db, monkeypatch):
    monkeypatch.setenv("PUSHOVER_TOKEN", "app-token")
    monkeypatch.setenv("PUSHOVER_USER", "user-key")
    monkeypatch.setenv("PATCHY_URL", "https://patchy.lan")
    calls = []

    def post(url, **kw):
        calls.append((url, kw["data"]))
        return httpx.Response(400 if kw["data"]["token"] == "bad" else 200, request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", post)
    item = alerts.Item("finding:1", "kev", "CVE-1 in x on pi4", "/vulnerabilities/1")
    assert alerts.send("Patchy: t", "m" * 2000, [item], alerts.values(db)) == {"pushover": None}
    url, data = calls[0]
    assert url == alerts.PUSHOVER_API and data["priority"] == 1 and len(data["message"]) == 1024
    assert (data["user"], data["url"]) == ("user-key", "https://patchy.lan")
    monkeypatch.setenv("PUSHOVER_TOKEN", "bad")
    assert alerts.send("Patchy: t", "m", [], alerts.values(db)) == {"pushover": "HTTP 400"}


def test_alert_settings_api(auth_client, monkeypatch):
    s = auth_client.get("/api/settings").json()["alerts"]
    assert s["destinations"] == {"webhook": False, "ntfy": False, "pushover": False, "email": False}
    assert s["events"] == {"kev": True, "critical": True, "eol": True, "silent_hours": 24}
    assert auth_client.post("/api/alerts/test").status_code == 409
    assert auth_client.put("/api/settings/alerts", json={"silent_hours": 5}).status_code == 422
    assert auth_client.put("/api/settings/alerts", json={"eol": False, "silent_hours": 0}).json()["eol"] is False

    monkeypatch.setenv("ALERT_WEBHOOK_URL", "http://hook.invalid/secret-id")
    monkeypatch.setattr(alerts, "send", lambda *a: {"webhook": None})
    assert auth_client.post("/api/alerts/test").json() == {"results": {"webhook": None}}
    assert "secret-id" not in auth_client.get("/api/settings").text


def test_destinations_set_from_settings(auth_client, db, monkeypatch):
    put = lambda body: auth_client.put("/api/settings/alerts/destinations", json=body)  # noqa: E731
    r = put({"pushover_token": "abc123", "pushover_user": "u1", "smtp_host": "mail.lan", "smtp_password": "pw-secret"})
    assert r.status_code == 200 and r.json()["destinations"]["pushover"] is True
    f = r.json()["fields"]
    assert f["pushover_token"] == {"env": "PUSHOVER_TOKEN", "secret": True, "source": "ui", "value": None}
    assert f["smtp_host"]["value"] == "mail.lan" and f["smtp_port"]["value"] == "587"
    assert alerts.values(db)["smtp_password"] == "pw-secret"
    for leak in ("abc123", "pw-secret"):
        assert leak not in auth_client.get("/api/settings").text and leak not in auth_client.get("/api/audit").text

    assert put({"email_to": "a@b.lan\nBcc: x@y"}).status_code == 422  # no header injection
    assert put({"webhook_url": "file:///etc/passwd"}).status_code == 422
    assert put({"smtp_port": "70000"}).status_code == 422
    assert put({"email_to": "a@b.lan, c@d.lan"}).status_code == 200
    assert put({"pushover_token": ""}).json()["destinations"]["pushover"] is False  # empty removes

    monkeypatch.setenv("SMTP_HOST", "env-mail.lan")  # .env wins and is locked
    assert alerts.fields(db)["smtp_host"] == {"env": "SMTP_HOST", "secret": False, "source": "env", "value": "env-mail.lan"}
    r = put({"smtp_host": "other.lan"})
    assert r.status_code == 409 and "SMTP_HOST" in r.json()["detail"]


def test_only_alertable_findings_are_read(db, host):
    from app.models import Repository
    repo = Repository(url="https://github.com/me/app", owner="me", name="app")
    demo = Host(name="demo-box", is_demo=True)
    db.add_all([repo, demo])
    db.flush()
    for adv_id, comp, sev, kev in (("GHSA-r", dict(repository_id=repo.id), "critical", False),
                                   ("GHSA-d", dict(host_id=demo.id), "critical", True),
                                   ("GHSA-low", dict(host_id=host.id), "low", False)):
        db.add(Advisory(id=adv_id, cve_ids=[], affected=[{"versions": ["x"] * 1000}], severity=sev, kev=kev))
        c = Component(name="lib", version="1", component_type="library", source="repo", **comp)
        db.add(c)
        db.flush()
        db.add(Finding(component_id=c.id, advisory_id=adv_id, match_status="confirmed", evidence="e", remediation="r"))
    db.commit()
    assert [(i.kind, i.text) for i in alerts.collect(db, alerts.config(db))] == [("critical", "GHSA-r in lib 1 on me/app")]
