"""v1.16: findings that Debian rates unimportant (or Ubuntu negligible) are set aside as 'minor'."""
from app import vulns
from app.models import Component, Finding


def _deb(adv_id, urgency, pkg="tar"):
    return {"id": adv_id, "affected": [{
        "package": {"ecosystem": "Debian:12", "name": pkg},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
        "ecosystem_specific": {"urgency": urgency}}]}


def test_minor_findings_are_set_aside_and_come_back(db, auth_client, host):
    ubuntu = vulns.upsert_advisory(db, {"id": "UBUNTU-CVE-1", "severity": [{"type": "Ubuntu", "score": "Negligible"}],
                                        "affected": [{"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "tar"}}]})
    assert ubuntu.affected[0]["priority"] == "negligible"
    minor = vulns.upsert_advisory(db, _deb("DEBIAN-CVE-1", "unimportant"))
    kev = vulns.upsert_advisory(db, _deb("DEBIAN-CVE-2", "unimportant"))
    kev.kev = True
    vulns.upsert_advisory(db, _deb("DEBIAN-CVE-3", "low"))
    assert minor.affected[0]["priority"] == "unimportant"
    c = Component(name="tar", version="1.34", ecosystem="Debian:12", component_type="os_package",
                  version_status="exact", source="agent", host_id=host.id)
    db.add(c)
    db.commit()

    assert vulns.rematch(db)["minor"] == 1
    db.commit()
    f = {x.advisory_id: x for x in db.query(Finding)}
    assert f["DEBIAN-CVE-1"].status == "minor" and "Debian rates this unimportant" in f["DEBIAN-CVE-1"].status_note
    assert f["DEBIAN-CVE-2"].status == "open"  # known exploited is never set aside
    assert f["DEBIAN-CVE-3"].status == "open" and f["DEBIAN-CVE-3"].vendor_priority == "low"
    d = auth_client.get("/api/dashboard").json()
    assert d["status"]["minor"] == 1
    assert sum(d["severity"].values()) == 2  # minor isn't counted as open
    page = auth_client.get("/api/findings", params={"status": "minor"}).json()
    assert [i["advisory"]["id"] for i in page["items"]] == ["DEBIAN-CVE-1"]
    assert page["items"][0]["vendor_priority"] == "unimportant"

    # A person setting it to Open keeps it open; minor itself can't be set by hand.
    fid = f["DEBIAN-CVE-1"].id
    assert auth_client.post(f"/api/findings/{fid}/status", json={"status": "minor"}).status_code == 422
    assert auth_client.post(f"/api/findings/{fid}/status", json={"status": "open"}).status_code == 200
    vulns.rematch(db)
    db.commit()
    db.refresh(f["DEBIAN-CVE-1"])
    assert f["DEBIAN-CVE-1"].status == "open"

    # Raised rating: a minor finding reopens by itself.
    f["DEBIAN-CVE-1"].status, f["DEBIAN-CVE-1"].status_changed_by = "minor", "system"
    vulns.upsert_advisory(db, _deb("DEBIAN-CVE-1", "medium"))
    db.commit()
    vulns.rematch(db)
    db.commit()
    db.refresh(f["DEBIAN-CVE-1"])
    assert f["DEBIAN-CVE-1"].status == "open" and f["DEBIAN-CVE-1"].status_changed_by == "system"
