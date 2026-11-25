"""v1.10: findings in software reachable over the network rank first."""
from app.db import utcnow
from app.models import Advisory, Component, Finding
from tests.test_api import _enroll, _report


def _ingest(auth_client, client, host, **over):
    token = _enroll(auth_client, host.id)
    rep = _report(**over)
    rep["packages"].append({"manager": "dpkg", "name": "postgresql-15", "version": "15.4-0+deb12u1",
                            "source_name": "postgresql-15", "source_version": "15.4-0+deb12u1", "arch": "arm64"})
    rep["listening"].append({"protocol": "tcp", "ip": "127.0.0.1", "port": 5432, "process": "postgresql-15"})
    rep["in_use"].append("postgresql-15")  # it listens, so it runs
    assert client.post("/api/agent/report", json=rep, headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_exposure_comes_from_listeners_and_published_ports(auth_client, client, host, db):
    _ingest(auth_client, client, host)
    comps = {(c.component_type, c.name, (c.details or {}).get("image")): c
             for c in db.query(Component).filter_by(host_id=host.id)}
    probe = comps[("web_server", "nginx", None)]
    assert (probe.exposure, probe.exposure_note) == ("network", "nginx listens on 0.0.0.0:80")
    assert comps[("os_package", "nginx", None)].exposure == "network"  # owns the listening binary
    assert comps[("os_package", "postgresql-15", None)].exposure == "local"  # loopback only
    assert comps[("os_package", "openssl", None)].exposure is None  # a library: nothing listens as it
    image = comps[("container_image", "nginx", None)]
    assert (image.exposure, image.exposure_note) == ("network", "container sample-web publishes 0.0.0.0:8080")
    assert comps[("library", "lodash", "nginx:1.27")].exposure == "network"  # inside that container's image


def test_priority_puts_exposed_findings_first(auth_client, client, host, db):
    _ingest(auth_client, client, host)
    comps = {c.name: c for c in db.query(Component).filter_by(host_id=host.id, component_type="os_package")}
    for adv, comp, epss in (("CVE-A", "openssl", 0.9), ("CVE-B", "nginx", 0.1), ("CVE-C", "postgresql-15", 0.5)):
        db.add(Advisory(id=adv, severity="high", epss=epss, affected=[]))
        db.add(Finding(component_id=comps[comp].id, advisory_id=adv, match_status="confirmed", evidence="e",
                       remediation="r", fixed_versions=["99"], currently_matching=True, first_detected_at=utcnow()))
    db.commit()
    items = auth_client.get("/api/findings", params={"sort": "priority", "order": "desc"}).json()["items"]
    assert [(f["advisory"]["id"], f["exposure"]) for f in items] == [
        ("CVE-B", "network"), ("CVE-C", "local"), ("CVE-A", None)]  # exposure before EPSS
    assert items[0]["exposure_note"] == "nginx listens on 0.0.0.0:80"

    plan = auth_client.get("/api/fix-plan", params={"host_id": host.id}).json()
    items = plan["groups"][0]["items"]
    assert [i["name"] for i in items] == ["nginx", "postgresql-15", "openssl"]
    assert plan["groups"][0]["exposure"] == "network" and plan["groups"][0]["worst"] == "high"
    report = auth_client.get("/api/fix-plan/ai", params={"host_id": host.id}).json()
    assert "| Exposure |" in report["report"] and "network (nginx listens on 0.0.0.0:80)" in report["report"]
    assert "reachable over the network" in report["prompt"]


def test_loopback_is_matched_exactly():
    from app.agent_ingest import _reach
    for ip in ("127.0.0.1", "::1", "[::1]", "::ffff:127.0.0.1", "localhost"):
        assert _reach(ip) == "local", ip
    for ip in ("::10", "::192.0.2.1", "0.0.0.0", "::", None, "192.168.1.2", "fe80::1%eth0", "*"):
        assert _reach(ip) == "network", ip


def test_image_exposure_uses_every_container_not_just_the_first_20():
    from app.agent_ingest import Report, exposure_maps, image_rows
    rep = _report()
    web = next(c for c in rep["containers"] if c["name"] == "sample-web")
    rep["containers"] += [{**web, "name": f"a{i:02}", "ports": []} for i in range(25)]  # sort before sample-web
    report = Report.model_validate(rep)
    rows = image_rows(report, exposure_maps(report)[1])
    lodash = next(r for r in rows if r["name"] == "lodash")
    assert "sample-web" not in lodash["details"]["containers"] and lodash["exposure"] == "network"
