"""v1.20: a weekly digest to the alert destinations."""
from datetime import datetime, timedelta, timezone

from app import alerts
from app.db import utcnow
from app.models import Advisory, AppSetting, Component, Finding, Host


def _seed(db, host):
    other = Host(name="nas")
    db.add(other)
    db.flush()
    for i, (h, sev, kev, status, age) in enumerate((
            (host, "critical", True, "open", 2), (host, "high", False, "acknowledged", 30),
            (other, "high", False, "open", 3), (other, "medium", False, "resolved", 20),
            (other, "low", False, "minor", 1))):
        db.add(Advisory(id=f"CVE-D{i}", severity=sev, kev=kev, affected=[]))
        c = Component(name=f"pkg{i}", version="1", component_type="os_package", source="agent", host_id=h.id)
        db.add(c)
        db.flush()
        db.add(Finding(component_id=c.id, advisory_id=f"CVE-D{i}", match_status="confirmed", evidence="e",
                       remediation="r", status=status, currently_matching=True,
                       first_detected_at=utcnow() - timedelta(days=age), status_changed_at=utcnow() - timedelta(days=1)))
    db.commit()


def test_digest_message(db, host):
    _seed(db, host)
    title, message, items = alerts.digest(db, "https://patchy.lan")
    assert title == "Patchy weekly: 3 open, 2 new, 1 fixed"
    assert message.splitlines()[0] == "Open: 3 (1 critical, 2 high)"  # minor and resolved aren't open
    assert "Known exploited: 1." in message and "This week: 2 new and still open, 1 fixed" in message
    assert [i.text for i in items] == ["pi4: 2 open, 1 critical", "nas: 1 open"]  # most critical first
    assert items[0].path == f"/hosts/{host.id}" and message.endswith("https://patchy.lan")


def test_digest_is_due_once_a_week_from_monday_morning(db):
    mon = datetime(2026, 11, 23, 8, 0, tzinfo=timezone.utc)  # a Monday
    assert alerts.digest_due(db, mon)  # never sent
    db.merge(AppSetting(key="alerts_status", value={"digest_sent_at": (mon + timedelta(minutes=5)).isoformat()}))
    db.commit()
    assert not alerts.digest_due(db, mon + timedelta(days=3))
    assert not alerts.digest_due(db, mon + timedelta(days=7, minutes=-1))
    assert alerts.digest_due(db, mon + timedelta(days=7))


def test_worker_sends_it_when_on_and_due(db, host, monkeypatch):
    _seed(db, host)
    sent, result = [], {"ntfy": None}
    monkeypatch.setattr(alerts, "send", lambda title, message, items, v: sent.append(title) or dict(result))
    assert not alerts.run_digest(db)  # off by default
    alerts.save(db, {"digest": True})
    db.commit()
    assert not alerts.run_digest(db)  # nowhere to send it
    monkeypatch.setenv("ALERT_NTFY_URL", "http://ntfy.invalid/topic")
    result["ntfy"] = "HTTP 500"
    assert not alerts.run_digest(db) and alerts.digest_due(db)  # failed: tried again next check
    result["ntfy"] = None
    assert alerts.run_digest(db) and not alerts.run_digest(db)  # then once a week
    assert len(sent) == 2 and sent[-1].startswith("Patchy weekly:")
    assert alerts.status(db)["last_title"] == sent[-1]


def test_digest_api(auth_client, monkeypatch):
    assert auth_client.post("/api/alerts/digest").status_code == 409  # no destination
    r = auth_client.put("/api/settings/alerts", json={"digest": True})
    assert r.status_code == 200 and r.json()["digest"] is True
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "http://hook.invalid/secret-id")
    monkeypatch.setattr(alerts, "send", lambda *a: {"webhook": None})
    assert auth_client.post("/api/alerts/digest").json() == {"results": {"webhook": None}}
    assert auth_client.get("/api/settings").json()["alerts"]["status"]["digest_sent_at"]
