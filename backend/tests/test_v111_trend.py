"""v1.11: open findings per day for the Overview trend, rebuilt from detection and resolution dates."""
from datetime import timedelta

from app.db import utcnow
from app.models import Advisory, Component, Finding


def test_trend_counts_open_findings_at_the_end_of_each_day(auth_client, db, host):
    now = utcnow()
    c = Component(name="lib", version="1", component_type="library", source="agent", host_id=host.id)
    db.add(c)
    db.add_all([Advisory(id=a, severity=s, affected=[]) for a, s in (("A", "critical"), ("B", "high"), ("C", "low"),
                                                                       ("D", "high"), ("E", "low"))])
    db.flush()

    def finding(adv, opened, status="open", closed=None, match="confirmed"):
        db.add(Finding(component_id=c.id, advisory_id=adv, match_status=match, evidence="e", remediation="r",
                       status=status, first_detected_at=now - timedelta(days=opened),
                       status_changed_at=now - timedelta(days=closed if closed is not None else opened)))
    finding("A", 200)  # older than the window: open throughout
    finding("B", 10)
    finding("C", 20, status="resolved", closed=5)  # open from day -20 until it was resolved on day -5
    finding("D", 100, status="false_positive", closed=200)  # closed long ago: not fetched at all
    finding("E", 3, match="unknown_version")  # not counted, like the Overview's other totals
    db.commit()

    days = auth_client.get("/api/trend").json()["days"]
    assert len(days) == 90 and days[-1]["date"] == now.date().isoformat()
    at = lambda n: days[-1 - n]  # noqa: E731  n days ago
    assert at(89) == {**at(89), "total": 1, "critical": 1, "high": 0}
    assert (at(20)["total"], at(10)["total"], at(6)["total"], at(5)["total"], at(0)["total"]) == (2, 3, 3, 2, 2)
    assert (at(0)["critical"], at(0)["high"]) == (1, 1)
    assert len(auth_client.get("/api/trend", params={"days": 7}).json()["days"]) == 7
    assert auth_client.get("/api/trend", params={"days": 1000}).status_code == 422

    # editing the note on a resolved finding, or moving it to another closed status, keeps its closing date
    c_id = db.query(Finding).filter_by(advisory_id="C").one().id
    for status in ("resolved", "false_positive"):
        assert auth_client.post(f"/api/findings/{c_id}/status", json={"status": status, "note": "n"}).status_code == 200
    assert auth_client.get("/api/trend").json()["days"] == days
    assert auth_client.post(f"/api/findings/{c_id}/status", json={"status": "open", "note": "back"}).status_code == 200
    assert auth_client.get("/api/trend").json()["days"][-1]["total"] == 3  # reopening does move it


def test_a_new_install_starts_where_tracking_started(auth_client, db, host):
    c = Component(name="lib", version="1", component_type="library", source="agent", host_id=host.id)
    db.add(c)
    db.add(Advisory(id="A", severity="high", affected=[]))
    db.flush()
    db.add(Finding(component_id=c.id, advisory_id="A", match_status="confirmed", evidence="e", remediation="r",
                   first_detected_at=utcnow() - timedelta(days=12)))
    db.commit()
    days = auth_client.get("/api/trend").json()["days"]
    assert len(days) == 13 and days[0]["total"] == 1
    db.query(Finding).update({"first_detected_at": utcnow()})
    db.commit()
    assert len(auth_client.get("/api/trend").json()["days"]) == 7  # at least a week
