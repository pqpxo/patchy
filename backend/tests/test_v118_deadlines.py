"""v1.18: fix-by deadlines per severity, overdue counts, the overdue alert and time to fix."""
from datetime import timedelta

from fastapi.testclient import TestClient

from app import alerts, deadlines
from app.db import utcnow
from app.main import app
from app.models import Advisory, Component, Finding


def test_deadlines_overdue_and_time_to_fix(auth_client, db, host):
    now = utcnow()
    c = Component(name="lib", version="1", component_type="library", source="agent", host_id=host.id)
    db.add(c)
    db.add_all([
        Advisory(id="CRIT", severity="critical", affected=[]),  # 10 days old, 7-day deadline: overdue
        Advisory(id="HIGH", severity="high", affected=[]),  # 10 days old, 30-day deadline: not yet
        Advisory(id="KEV-NEW", severity="high", kev=True, affected=[],  # listed 2 days ago: 7 days from then
                 kev_date_added=(now - timedelta(days=2)).date().isoformat()),
        Advisory(id="KEV-OLD", severity="medium", kev=True, affected=[], kev_date_added="2021-11-03"),  # overdue
        Advisory(id="NONE", severity="unknown", affected=[]),  # no deadline
        Advisory(id="DONE", severity="critical", affected=[]),
    ])
    db.flush()
    ages = {"CRIT": 10, "HIGH": 10, "KEV-NEW": 10, "KEV-OLD": 20, "NONE": 400, "DONE": 5}
    for adv, age in ages.items():
        db.add(Finding(component_id=c.id, advisory_id=adv, match_status="confirmed", evidence="e", remediation="r",
                       first_detected_at=now - timedelta(days=age)))
    db.commit()
    done = db.query(Finding).filter_by(advisory_id="DONE").one()
    done.status, done.status_changed_at = "resolved", now
    db.commit()

    d = auth_client.get("/api/dashboard").json()
    assert d["overdue"] == 2
    assert d["time_to_fix"] == {"days": 90, "fixed": 1, "median_days": 5.0, "on_time_pct": 100}
    page = auth_client.get("/api/findings", params={"overdue": "true"}).json()
    assert sorted(i["advisory"]["id"] for i in page["items"]) == ["CRIT", "KEV-OLD"]
    by_id = {i["advisory"]["id"]: i for i in auth_client.get("/api/findings").json()["items"]}
    assert by_id["NONE"]["due_at"] is None
    assert by_id["KEV-NEW"]["due_at"][:10] == (now + timedelta(days=5)).date().isoformat()

    # Python and SQL agree on every finding.
    cfg = deadlines.config(db)
    for f in db.query(Finding).filter(Finding.status == "open"):
        due = deadlines.due_at(cfg, f.advisory.severity, f.advisory.kev, f.advisory.kev_date_added, f.first_detected_at)
        assert (due is not None and due < now) == (f.advisory_id in ("CRIT", "KEV-OLD")), f.advisory_id

    # The overdue alert lists them once it's on; the summary counts them for Home Assistant.
    items = [i for i in alerts.collect(db, {**alerts.DEFAULTS, "overdue": True}) if i.kind == "overdue"]
    assert sorted(i.key for i in items) == sorted(f"overdue:{f.id}" for f in db.query(Finding)
                                                  if f.advisory_id in ("CRIT", "KEV-OLD"))
    assert "due " in items[0].text
    r = auth_client.post("/api/settings/tokens", json={"name": "HA"}).json()
    s = TestClient(app).get("/api/integrations/summary", headers={"Authorization": f"Bearer {r['token']}"}).json()
    assert s["overdue"] == 2

    # Turning the critical deadline off: KEV falls back to its severity, and critical has none.
    assert auth_client.put("/api/settings/deadlines", json={"critical": 0}).json()["critical"] == 0
    assert auth_client.get("/api/dashboard").json()["overdue"] == 0
    assert auth_client.get("/api/settings").json()["deadlines"] == {"critical": 0, "high": 30, "medium": 90, "low": 180}
    assert auth_client.put("/api/settings/deadlines", json={"high": 400}).status_code == 422
