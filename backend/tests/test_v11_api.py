"""v1.1 API: schedules, version, fix plans, sorting, CPE on assets."""
import pytest

from app import fixplan
from app.db import utcnow
from app.models import Advisory, AuditLog, Component, ComponentPath, Finding, Repository


@pytest.mark.parametrize("path,sorts", [
    ("/api/assets", ["name", "type", "updated", "version", "ecosystem", "source", "location", "findings", "severity",
                     "eol", "checked"]),
    ("/api/hosts", ["name", "ip", "os", "last_report", "components", "findings", "eol"]),
    ("/api/repositories", ["name", "last_scanned", "components", "findings"]),
    ("/api/findings", ["priority", "severity", "epss", "cvss", "published", "component", "location", "match",
                       "status", "detected"]),
])
def test_every_sort_works_both_ways(auth_client, db, path, sorts):
    _repo_with_findings(db)
    for sort in sorts:
        for order in ("asc", "desc"):
            r = auth_client.get(path, params={"sort": sort, "order": order})
            assert r.status_code == 200, (sort, order, r.text)
    assert auth_client.get(path, params={"sort": "nope"}).status_code == 422


def test_source_schedule_update_is_validated_and_audited(auth_client, db):
    s = auth_client.get("/api/settings").json()
    assert s["sources"]["osv"]["hours"] == 24 and 168 in s["hour_choices"] and s["version"] == "1.5.0"
    assert auth_client.put("/api/settings/sources", json={"osv": {"hours": 5}}).status_code == 422
    assert auth_client.put("/api/settings/sources", json={"bogus": {"enabled": True}}).status_code == 422
    r = auth_client.put("/api/settings/sources", json={"osv": {"hours": 6}, "epss": {"enabled": False}})
    assert r.status_code == 200 and r.json()["osv"]["hours"] == 6 and not r.json()["epss"]["enabled"]
    feeds = {f["source"]: f for f in auth_client.get("/api/feeds").json()}
    assert feeds["osv"]["hours"] == 6 and not feeds["epss"]["enabled"] and feeds["nvd_cpe"]["label"]
    assert db.query(AuditLog).filter_by(action="settings.sources").count() == 1
    run = auth_client.post("/api/feeds/refresh", json={"sources": ["eol"]}).json()
    assert run["params"] == {"mode": "full", "only": ["eol"]}


def test_version_needs_login(client):
    assert client.get("/api/version").status_code == 401


def test_version_and_changelog(auth_client):
    v = auth_client.get("/api/version").json()
    assert v["version"] == "1.5.0" and v["agent_version"] == "1.4.0" and "## 1.5.0" in v["changelog"]


def test_asset_cpe_is_validated(auth_client):
    base = {"name": "Home Assistant", "component_type": "other", "version": "2024.1.0"}
    assert auth_client.post("/api/assets", json={**base, "cpe": "not a cpe"}).status_code == 422
    r = auth_client.post("/api/assets", json={**base, "cpe": "Home-Assistant:Home-Assistant"})
    assert r.status_code == 201 and r.json()["cpe"] == "home-assistant:home-assistant"


def _repo_with_findings(db):
    repo = Repository(url="https://github.com/octo/app", owner="octo", name="app")
    db.add(repo)
    db.flush()
    advs = [Advisory(id="GHSA-1", severity="high", kev=True, epss=0.9, affected=[]),
            Advisory(id="GHSA-2", severity="medium", affected=[]),
            Advisory(id="GHSA-3", severity="low", affected=[])]
    db.add_all(advs)
    comps = []
    for name, version in (("lodash", "4.17.20"), ("evil;rm -rf ~", "1.0.0")):
        c = Component(name=name, component_type="library", ecosystem="npm", version=version, version_status="exact",
                      source="repo", repository_id=repo.id)
        c.paths.append(ComponentPath(path="web/package-lock.json", kind="manifest"))
        db.add(c)
        comps.append(c)
    db.flush()
    now = utcnow()
    for c, adv, fixed in ((comps[0], "GHSA-1", ["4.17.21"]), (comps[0], "GHSA-2", ["4.17.19", "4.17.22"]),
                          (comps[0], "GHSA-3", []), (comps[1], "GHSA-2", ["1.0.1"])):
        db.add(Finding(component_id=c.id, advisory_id=adv, match_status="confirmed", evidence="e", remediation="r",
                       fixed_versions=fixed, currently_matching=True, first_detected_at=now))
    db.commit()
    return repo


def test_fix_plan_groups_targets_and_never_puts_unsafe_names_in_commands(auth_client, db):
    repo = _repo_with_findings(db)
    plan = auth_client.get("/api/fix-plan", params={"repository_id": repo.id}).json()
    assert plan["summary"]["components"] == 2 and plan["summary"]["upgrade_steps"] == 1
    g = plan["groups"][0]
    assert g["title"] == "web/package-lock.json (npm)" and g["kev"]
    lodash = next(i for i in g["items"] if i["name"] == "lodash")
    assert lodash["target"] == "4.17.22"  # smallest version fixing both fixable advisories (4.17.19 is older)
    assert g["command"] == "npm install lodash@4.17.22"
    assert any("unusual characters" in n and "evil" in n for n in g["notes"])
    assert [i["name"] for i in plan["no_fix"]] == ["lodash"] and plan["no_fix"][0]["unfixed"] == ["GHSA-3"]
    assert auth_client.get("/api/fix-plan", params={"host_id": 999}).json()["summary"]["components"] == 0


def test_repo_list_carries_severity_exposure(auth_client, db):
    _repo_with_findings(db)
    repo = auth_client.get("/api/repositories").json()["items"][0]
    assert repo["open_findings"] == 4
    assert repo["exposure"] == {"total": 4, "high": 1, "medium": 2, "low": 1, "kev": 1}


def test_safe_rejects_shell_metacharacters():
    assert fixplan.safe("@angular/core", "17.0.1", "libssl3", "1:2.36-9+deb12u4")
    for bad in ("a;b", "$(x)", "`x`", "a b", "a|b", "a&b", "-rf", "a'b", 'a"b', "a>b", ""):
        assert not fixplan.safe(bad)
