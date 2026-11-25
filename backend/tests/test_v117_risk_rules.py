"""v1.17: accepted-risk rules take findings out of the open counts until they expire or are revoked."""
from datetime import timedelta

from app import risk
from app.db import utcnow
from app.models import Advisory, Component, Finding, RiskRule


def test_accepted_risk_rules(auth_client, db, host):
    c = Component(name="openssl", version="3.0.11", component_type="os_package", source="agent", host_id=host.id)
    other = Component(name="curl", version="7", component_type="os_package", source="agent", host_id=host.id)
    db.add_all([c, other, Advisory(id="DEBIAN-CVE-2023-1", severity="high", cve_ids=[], affected=[]),
                Advisory(id="GHSA-x", severity="critical", cve_ids=["CVE-2023-2"], affected=[])])
    db.flush()
    for comp, adv in ((c, "DEBIAN-CVE-2023-1"), (c, "GHSA-x"), (other, "GHSA-x")):
        db.add(Finding(component_id=comp.id, advisory_id=adv, match_status="confirmed", evidence="e", remediation="r",
                       first_detected_at=utcnow()))
    db.commit()
    soon = str((utcnow() + timedelta(days=30)).date())

    bad = [{"reason": "no scope", "expires_on": soon},
           {"advisory": "CVE-2023-1", "reason": "too long", "expires_on": str((utcnow() + timedelta(days=400)).date())},
           {"advisory": "CVE-2023-1", "reason": "past", "expires_on": str(utcnow().date())},
           {"advisory": "CVE%", "reason": "wildcard", "expires_on": soon}]
    assert [auth_client.post("/api/risks", json=b).status_code for b in bad] == [422] * 4

    # A CVE matches the distro's own advisory id; a package match is scoped to that package.
    r1 = auth_client.post("/api/risks", json={"advisory": "CVE-2023-1", "reason": "Not reachable", "expires_on": soon}).json()
    r2 = auth_client.post("/api/risks", json={"advisory": "CVE-2023-2", "package": "OpenSSL", "host_id": host.id,
                                              "reason": "Behind the VPN", "expires_on": soon}).json()
    assert (r1["findings"], r2["findings"]) == (1, 1)
    status = {(f.component_id, f.advisory_id): f.status for f in db.query(Finding)}
    assert status == {(c.id, "DEBIAN-CVE-2023-1"): "risk_accepted", (c.id, "GHSA-x"): "risk_accepted",
                      (other.id, "GHSA-x"): "open"}
    assert sum(auth_client.get("/api/dashboard").json()["severity"].values()) == 1
    f = db.query(Finding).filter_by(advisory_id="DEBIAN-CVE-2023-1").one()
    assert "Not reachable" in f.status_note and f.status_changed_by == f"rule:{r1['id']}"
    assert auth_client.post(f"/api/findings/{f.id}/status", json={"status": "open"}).status_code == 409
    r = auth_client.post(f"/api/findings/{f.id}/status", json={"status": "risk_accepted", "note": "Reviewed again"})
    assert r.status_code == 200 and r.json()["status_changed_by"] == f"rule:{r1['id']}"  # still tied to its rule
    other_f = db.query(Finding).filter_by(component_id=other.id).one()
    assert auth_client.post(f"/api/findings/{other_f.id}/status", json={"status": "risk_accepted"}).status_code == 422
    assert [x["findings"] for x in auth_client.get("/api/risks").json()] == [1, 1]

    # Revoking reopens; an expired rule reopens on the next check.
    assert auth_client.delete(f"/api/risks/{r1['id']}").status_code == 204
    db.expire_all()
    assert db.get(Finding, f.id).status == "open"
    db.get(RiskRule, r2["id"]).expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    assert risk.apply(db)["risk_released"] == 1
    db.commit()
    assert {f.status for f in db.query(Finding)} == {"open"}
    actions = [a["action"] for a in auth_client.get("/api/audit").json()["items"]]
    assert actions.count("finding.auto_status") == 4  # two findings accepted, then both released (1.25)
    assert [a for a in actions if a != "finding.auto_status"][:4] == ["risk.revoke", "finding.status", "risk.accept", "risk.accept"]
