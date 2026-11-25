"""v1.23: pending apt updates on the host page, and Run upgrade for hosts that allow it."""
from datetime import timedelta

from sqlalchemy import select

from app import demo, upgrades
from app.config import settings
from app.db import utcnow
from app.models import Advisory, AuditLog, Component, Finding, Host, UpgradeRun
from tests.test_api import _enroll, _report, agent_mod

APT = """Reading package lists...
Calculating upgrade...
The following packages have been kept back:
  linux-generic linux-image-generic
The following upgrades have been deferred due to phasing:
  systemd
The following packages will be upgraded:
  curl libssl3
2 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.
Inst libssl3 [3.0.11-1~deb12u1] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [arm64])
Inst curl [7.88.1-10+deb12u5] (7.88.1-10+deb12u8 Debian:12.8/stable [arm64]) []
Inst newdep (1.0-1 Debian:12/stable [all])
Conf libssl3 (3.0.15-1~deb12u1 Debian-Security:12/stable-security [arm64])
"""


def _updates(can_upgrade=True, **over):
    return {"manager": "apt", "packages": [{"name": "libssl3", "installed": "3.0.11-1~deb12u1",
                                            "available": "3.0.15-1~deb12u1", "security": True},
                                           {"name": "nginx", "installed": "1.22.1-9", "available": "1.22.1-9+deb12u1"}],
            "held_back": ["linux-generic"], "lists_at": "2026-11-25T06:00:00Z", "reboot_required": False,
            "reboot_packages": [], "can_upgrade": can_upgrade, **over}


def _send(client, token, **over):
    r = client.post("/api/agent/report", json=_report(**over), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    return r


def test_agent_reads_apt_simulation():
    pkgs, held = agent_mod.parse_apt_simulation(APT)
    assert pkgs == [
        {"name": "libssl3", "installed": "3.0.11-1~deb12u1", "available": "3.0.15-1~deb12u1", "security": True},
        {"name": "curl", "installed": "7.88.1-10+deb12u5", "available": "7.88.1-10+deb12u8", "security": False},
        {"name": "newdep", "installed": None, "available": "1.0-1", "security": False}]
    assert held == ["linux-generic", "linux-image-generic", "systemd"]


def test_agent_hands_over_only_when_allowed_and_reports_each_result_once(tmp_path, monkeypatch):
    state, out = tmp_path / "state", tmp_path / "out"
    state.mkdir(), out.mkdir()
    monkeypatch.setattr(agent_mod, "upgrades_allowed", lambda: False)
    assert agent_mod.start_upgrade(7, str(state)) is False and not list(state.iterdir())
    monkeypatch.setattr(agent_mod, "upgrades_allowed", lambda: True)
    assert agent_mod.start_upgrade(7, str(state)) is True and (state / "upgrade-request").exists()
    assert agent_mod.upgrade_result(str(state), str(out)) is None  # nothing has run yet
    (out / "result.json").write_text('{"exit_code": 0, "started_at": "2000-01-01T00:00:00Z", "finished_at": "x"}')
    assert agent_mod.upgrade_result(str(state), str(out)) is None  # an earlier run's result
    (out / "result.json").write_text('{"exit_code": 100, "started_at": "2999-01-01T00:00:00Z", "finished_at": "2999-01-01T00:05:00Z"}')
    (out / "upgrade.log").write_bytes(b"E: Could not get lock\n")
    assert agent_mod.upgrade_result(str(state), str(out)) == {
        "id": 7, "exit_code": 100, "started_at": "2999-01-01T00:00:00Z", "finished_at": "2999-01-01T00:05:00Z",
        "output": "E: Could not get lock\n"}
    agent_mod.upgrade_reported(str(state))
    assert agent_mod.upgrade_result(str(state), str(out)) is None


def test_updates_tab_counts_the_findings_each_update_fixes(auth_client, client, host, db):
    token = _enroll(auth_client, host.id)
    assert auth_client.get(f"/api/hosts/{host.id}/updates").json()["updates"] is None  # nothing reported yet
    _send(client, token, updates=_updates())
    comp = db.scalar(select(Component).where(Component.host_id == host.id, Component.name == "openssl"))
    for adv, fixed, status in (("CVE-FIXED", "3.0.13-1~deb12u1", "open"), ("CVE-LATER", "3.0.17-1~deb12u1", "open"),
                               ("CVE-DONE", "3.0.13-1~deb12u1", "resolved")):
        db.add(Advisory(id=adv, severity="high", affected=[]))
        db.add(Finding(component_id=comp.id, advisory_id=adv, match_status="confirmed", evidence="e", remediation="r",
                       fixed_versions=[fixed], status=status, currently_matching=True, first_detected_at=utcnow()))
    db.commit()
    d = auth_client.get(f"/api/hosts/{host.id}/updates").json()
    assert [(p["name"], p["fixes"]) for p in d["packages"]] == [("libssl3", 1), ("nginx", 0)]  # security first
    assert d["fixes"] == 1 and d["updates"]["held_back"] == ["linux-generic"] and d["can_upgrade"] is True
    h = auth_client.get(f"/api/hosts/{host.id}").json()["host"]
    assert (h["pending_updates"], h["security_updates"], h["can_upgrade"]) == (2, 1, True)


def test_run_upgrade_goes_through_the_agent_and_records_apts_result(auth_client, client, host, db):
    token = _enroll(auth_client, host.id)
    auth = {"Authorization": f"Bearer {token}"}
    _send(client, token, updates=_updates(can_upgrade=False))
    assert auth_client.post(f"/api/hosts/{host.id}/upgrade").status_code == 409  # the host hasn't allowed it
    _send(client, token, updates=_updates())
    r = auth_client.post(f"/api/hosts/{host.id}/upgrade")
    assert r.status_code == 202 and r.json()["status"] == "queued"
    run_id = r.json()["id"]
    assert auth_client.post(f"/api/hosts/{host.id}/upgrade").status_code == 409  # one at a time
    assert client.get("/api/agent/poll", headers=auth).json()["upgrade"] == run_id
    assert client.get("/api/agent/poll", headers=auth).json()["upgrade"] is None  # handed over once
    assert db.get(UpgradeRun, run_id).status == "sent"
    _send(client, token, updates=_updates(packages=[]), upgrade_result={
        "id": run_id, "exit_code": 0, "started_at": "2026-11-25T10:00:00Z", "finished_at": "2026-11-25T10:02:00Z",
        "output": "2 upgraded, 0 newly installed"})
    d = auth_client.get(f"/api/hosts/{host.id}/updates").json()
    assert d["packages"] == [] and d["runs"][0]["status"] == "succeeded" and "2 upgraded" in d["runs"][0]["output"]
    assert db.scalar(select(AuditLog).where(AuditLog.action == "host.upgrade")).detail == {"upgrade_run_id": run_id}


def test_a_host_that_says_no_fails_the_request_and_stale_ones_expire(auth_client, client, host, db):
    token = _enroll(auth_client, host.id)
    _send(client, token, updates=_updates())
    run_id = auth_client.post(f"/api/hosts/{host.id}/upgrade").json()["id"]
    _send(client, token, updates=_updates(can_upgrade=False))  # the answer was changed on the host
    run = db.get(UpgradeRun, run_id)
    db.refresh(run)
    assert run.status == "failed" and run.note == upgrades.REFUSED
    _send(client, token, updates=_updates())
    db.add(UpgradeRun(host_id=host.id, status="queued", requested_by="admin", requested_at=utcnow() - timedelta(days=2)))
    db.commit()
    assert auth_client.get(f"/api/hosts/{host.id}/updates").json()["runs"][0]["status"] == "failed"
    assert auth_client.post(f"/api/hosts/{host.id}/upgrade").status_code == 202  # the stale one no longer blocks


def test_a_failed_apt_check_keeps_the_last_list_and_old_requests_are_never_handed_out(auth_client, client, host, db,
                                                                                      monkeypatch):
    monkeypatch.setattr(agent_mod, "run_fixed", lambda *a, **k: ("/usr/bin/apt-get", None))
    try:
        agent_mod.apt_updates()
        raise AssertionError("a failed simulation must not look like no updates")
    except RuntimeError:
        pass
    token = _enroll(auth_client, host.id)
    _send(client, token, updates=_updates())
    _send(client, token, updates=None, errors=["updates: RuntimeError"])
    d = auth_client.get(f"/api/hosts/{host.id}/updates").json()
    assert len(d["packages"]) == 2 and d["updates"]["failed_at"]  # still shown, marked out of date
    _send(client, token, updates=None)  # no error: updates turned off, or not an apt host
    assert auth_client.get(f"/api/hosts/{host.id}/updates").json()["updates"] is None
    _send(client, token, updates=_updates())
    db.add(UpgradeRun(host_id=host.id, status="queued", requested_by="admin", requested_at=utcnow() - timedelta(days=2)))
    db.commit()
    poll = client.get("/api/agent/poll", headers={"Authorization": f"Bearer {token}"}).json()
    assert poll["upgrade"] is None  # expired at check-in, not only when someone opens the page


def test_demo_shows_updates_and_a_past_upgrade(client, db, monkeypatch):
    demo.load(db)
    monkeypatch.setattr(settings, "demo_mode", True)  # signs the visitor in as the demo user
    hosts = {h.name: h for h in db.scalars(select(Host))}
    pi, home = hosts["pi-dns"], hosts["homeserver"]
    assert pi.agent.agent_version == "1.6.0" and not client.get(f"/api/hosts/{pi.id}").json()["host"]["agent_outdated"]
    d = client.get(f"/api/hosts/{pi.id}/updates").json()
    assert d["can_upgrade"] and d["fixes"] > 0 and d["runs"][0]["status"] == "succeeded"
    assert home.updates["reboot_required"] and not home.updates["can_upgrade"]
