"""v1.12: findings as CSV, and CycloneDX SBOMs for a host, an image on it, or a repository."""
import csv
import io

from app.db import utcnow
from app.models import Advisory, Component, Finding, Repository
from tests.test_api import _enroll, _report


def _finding(db, comp, adv_id, **adv):
    db.add(Advisory(id=adv_id, affected=[], cve_ids=["CVE-2026-0001"], summary="Bad.", **adv))
    db.add(Finding(component_id=comp.id, advisory_id=adv_id, match_status="confirmed", evidence="e", remediation="r",
                   fixed_versions=["2.0"], currently_matching=True, first_detected_at=utcnow()))


def test_findings_csv_follows_the_list_filters(auth_client, db, host):
    evil = Component(name="=HYPERLINK(\"x\")", version="1.0", component_type="library", ecosystem="npm",
                     source="agent", host_id=host.id, exposure="network")
    other = Component(name="quiet", version="1.0", component_type="library", ecosystem="npm", source="agent",
                      host_id=host.id)
    db.add_all([evil, other])
    db.flush()
    _finding(db, evil, "GHSA-1", severity="critical", kev=True, epss=0.5)
    _finding(db, other, "GHSA-2", severity="low")
    db.commit()

    r = auth_client.get("/api/findings/export", params={"severity": "critical", "host_id": host.id})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert 'filename="patchy-findings-' in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][:3] == ["Advisory", "CVEs", "Severity"] and len(rows) == 2
    row = dict(zip(rows[0], rows[1]))
    assert (row["Advisory"], row["KEV"], row["EPSS"], row["Exposure"]) == ("GHSA-1", "yes", "0.5000", "network")
    assert row["Component"] == "'=HYPERLINK(\"x\")"  # never runs as a spreadsheet formula
    assert (row["Location"], row["Fixed in"], row["Summary"]) == ("pi4", "2.0", "Bad.")
    assert len(list(csv.reader(io.StringIO(auth_client.get("/api/findings/export").text)))) == 3
    assert auth_client.get("/api/audit").json()["items"][0]["detail"] == {"rows": 2}


def test_sbom_for_a_host_an_image_and_a_repository(auth_client, client, host, db):
    token = _enroll(auth_client, host.id)
    assert client.post("/api/agent/report", json=_report(), headers={"Authorization": f"Bearer {token}"}).status_code == 200
    lodash = db.query(Component).filter_by(host_id=host.id, name="lodash").one()
    _finding(db, lodash, "GHSA-lo", severity="high", cvss_score=7.5)
    db.commit()

    r = auth_client.get("/api/sbom", params={"host_id": host.id})
    assert r.status_code == 200 and r.headers["content-type"] == "application/vnd.cyclonedx+json"
    assert 'filename="patchy-sbom-pi4.cdx.json"' in r.headers["content-disposition"]
    bom = r.json()
    assert (bom["bomFormat"], bom["specVersion"], bom["metadata"]["component"]["name"]) == ("CycloneDX", "1.5", "pi4")
    purls = {c["name"]: c.get("purl") for c in bom["components"]}
    assert purls["openssl"].startswith("pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-12")
    assert purls["lodash"] == "pkg:npm/lodash@4.17.20"
    nginx = {c["type"]: c.get("purl") for c in bom["components"] if c["name"] == "nginx"}
    assert nginx == {"library": "pkg:deb/debian/nginx@1.22.1-9?distro=debian-12",
                     "container": "pkg:docker/library/nginx@1.27", "application": None}  # the probe has no purl
    vuln = bom["vulnerabilities"][0]
    assert vuln["id"] == "GHSA-lo" and vuln["ratings"] == [{"severity": "high", "score": 7.5}]
    assert vuln["affects"] == [{"ref": f"component-{lodash.id}"}] and vuln["references"][0]["id"] == "CVE-2026-0001"

    image = auth_client.get("/api/sbom", params={"host_id": host.id, "image": "nginx:1.27"}).json()
    assert image["metadata"]["component"] == {"bom-ref": "subject", "type": "container", "name": "nginx:1.27"}
    assert sorted(c["name"] for c in image["components"]) == ["lodash", "zlib"]

    repo = Repository(url="https://github.com/me/app", owner="me", name="app")
    db.add(repo)
    db.flush()
    db.add(Component(name="Django", version="4.2.1", version_status="exact", component_type="library",
                     ecosystem="PyPI", source="repo", repository_id=repo.id))
    db.commit()
    bom = auth_client.get("/api/sbom", params={"repository_id": repo.id}).json()
    assert [c["purl"] for c in bom["components"]] == ["pkg:pypi/django@4.2.1"]

    assert auth_client.get("/api/sbom").status_code == 422
    assert auth_client.get("/api/sbom", params={"repository_id": repo.id, "image": "x"}).status_code == 422
    assert auth_client.get("/api/sbom", params={"host_id": 999}).status_code == 404
