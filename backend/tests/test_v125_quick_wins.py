"""v1.25: bulk status changes, the finding timeline, and the idle session timeout."""
from datetime import timedelta

from app import risk
from app.config import settings
from app.db import utcnow
from app.models import Advisory, AuditLog, Component, Finding, RiskRule, UserSession
from app.routers import security_api
from app.security import audit


def _findings(db, host, n=3, severity="critical"):
    c = Component(name="openssl", version="3.0.1", component_type="os_package", source="agent", host_id=host.id)
    db.add(c)
    db.flush()
    out = []
    for i in range(n):
        db.add(Advisory(id=f"GHSA-{severity}-{i}", severity=severity, cve_ids=[], affected=[]))
        f = Finding(component_id=c.id, advisory_id=f"GHSA-{severity}-{i}", match_status="confirmed", evidence="e",
                    remediation="r", first_detected_at=utcnow() - timedelta(days=3))
        db.add(f)
        out.append(f)
    db.commit()
    return out


def test_bulk_status_follows_the_filters_and_skips_accepted_risk(auth_client, db, host, monkeypatch):
    crit = _findings(db, host)
    low = _findings(db, host, n=1, severity="low")
    crit[2].status = "risk_accepted"
    db.commit()
    params = {"severity": "critical"}
    url = "/api/findings/bulk-status"
    assert auth_client.post(url, params=params, json={"status": "minor", "expected": 3}).status_code == 422  # Patchy's own
    r = auth_client.post(url, params=params, json={"status": "acknowledged", "expected": 2})
    assert r.status_code == 409 and "3 findings match now" in r.json()["detail"]  # the list changed since it was shown
    monkeypatch.setattr(security_api, "BULK_MAX", 2)
    assert auth_client.post(url, params=params, json={"status": "acknowledged", "expected": 3}).status_code == 422
    monkeypatch.undo()

    r = auth_client.post(url, params=params, json={"status": "acknowledged", "note": "Patch window Sunday", "expected": 3})
    assert r.json() == {"changed": 2, "skipped": 1}
    db.expire_all()
    assert [f.status for f in crit] == ["acknowledged", "acknowledged", "risk_accepted"] and low[0].status == "open"
    assert crit[0].status_changed_by == "admin" and crit[0].status_note == "Patch window Sunday"
    logged = db.query(AuditLog).filter_by(action="finding.status").all()
    assert len(logged) == 2 and logged[0].detail["bulk"] is True and logged[0].detail["from"] == "open"
    # Same status and no note: nothing to record.
    assert auth_client.post(url, params={"severity": "critical", "status": "acknowledged"},
                            json={"status": "acknowledged", "expected": 2}).json() == {"changed": 0, "skipped": 2}


def test_timeline_shows_people_and_patchy_oldest_first(auth_client, db, host):
    f = _findings(db, host, n=1)[0]
    auth_client.post(f"/api/findings/{f.id}/status", json={"status": "acknowledged", "note": "Looking"})
    db.expire_all()
    db.add(RiskRule(advisory=f.advisory_id, reason="Not reachable", created_by="admin", expires_at=utcnow() + timedelta(days=30)))
    db.commit()
    risk.apply(db)
    db.commit()
    events = auth_client.get(f"/api/findings/{f.id}").json()["timeline"]
    assert [(e["kind"], e["from"], e["to"]) for e in events] == [
        ("detected", None, "open"), ("status", "open", "acknowledged"), ("status", "acknowledged", "risk_accepted")]
    assert events[1]["actor"] == "admin" and events[1]["note"] == "Looking"
    assert events[2]["actor"].startswith("rule:") and "Not reachable" in events[2]["note"]


def test_timeline_fills_gaps_from_before_changes_were_recorded(auth_client, db, host):
    f = _findings(db, host, n=1)[0]
    audit(db, "system", "finding.auto_resolved", "finding", f.id, {"reason": "the package was removed"})  # pre-1.25 shape
    f.status, f.status_changed_by, f.status_note = "false_positive", "someone", "Set in 1.0"
    db.commit()
    events = auth_client.get(f"/api/findings/{f.id}").json()["timeline"]
    assert [e["to"] for e in events] == ["open", "resolved", "false_positive"]
    assert events[1]["note"] == "the package was removed" and events[2]["actor"] == "someone"


def test_idle_sessions_are_signed_out(auth_client, db, monkeypatch):
    def age(minutes):
        s = db.query(UserSession).one()
        s.last_seen_at = utcnow() - timedelta(minutes=minutes)
        db.commit()

    age(600)
    assert auth_client.get("/api/auth/me").status_code == 200  # off by default
    monkeypatch.setattr(settings, "session_idle_minutes", 30)
    age(5)
    assert auth_client.get("/api/auth/me").status_code == 200
    db.expire_all()
    assert db.query(UserSession).one().last_seen_at > utcnow() - timedelta(minutes=1)  # activity keeps it alive
    age(31)
    r = auth_client.get("/api/auth/me")
    assert r.status_code == 401 and "30 minutes without activity" in r.json()["detail"]
    db.expire_all()
    assert db.query(UserSession).count() == 0
