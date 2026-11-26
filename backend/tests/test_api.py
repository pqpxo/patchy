"""API validation, authorisation, CSRF, agent authentication and secret hygiene."""
import importlib.util
import json
import pathlib

import pytest

from app.config import settings
from app.models import AuditLog, Component, Finding, HostPath
from tests.conftest import PASSWORD

AGENT_PATH = pathlib.Path(__file__).resolve().parents[2] / "agent" / "patchy_agent.py"
spec = importlib.util.spec_from_file_location("patchy_agent", AGENT_PATH)
agent_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_mod)


def test_health_is_public(client):
    assert client.get("/api/health").json() == {"status": "ok"}


@pytest.mark.parametrize("path", ["/api/assets", "/api/hosts", "/api/findings", "/api/dashboard", "/api/settings",
                                  "/api/audit", "/api/scans", "/api/repositories", "/api/feeds", "/api/news", "/api/trend"])
def test_endpoints_require_login(client, path):
    assert client.get(path).status_code == 401


def test_login_failure_and_rate_limit(client, admin):
    for _ in range(10):
        assert client.post("/api/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD}).status_code == 429


def test_session_cookie_flags(client, admin):
    r = client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_csrf_required_for_writes(client, admin):
    client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    r = client.post("/api/hosts", json={"name": "x"})
    assert r.status_code == 403
    r = client.post("/api/hosts", json={"name": "x"}, headers={"X-CSRF-Token": "wrong"})
    assert r.status_code == 403


def test_security_headers(client):
    r = client.get("/api/health")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    # Same-origin framing only: lets the SWSuite portal show Patchy, no other site.
    assert r.headers["x-frame-options"] == "SAMEORIGIN"
    assert "frame-ancestors 'self'" in r.headers["content-security-policy"]


def test_index_base_href_follows_forwarded_prefix(tmp_path, monkeypatch):
    from app import main
    index = tmp_path / "index.html"
    index.write_text('<html><head><base href="/" /></head></html>', encoding="utf-8")
    assert '<base href="/patchy/"' in main.render_index(index, "/patchy")
    assert '<base href="/"' in main.render_index(index, "")
    # Anything but plain path segments is ignored, so the header cannot inject markup.
    assert '<base href="/"' in main.render_index(index, '/x"><script>')
    assert "<script" not in main.render_index(index, '/x"><script>')
    assert "theme.css" not in main.render_index(index, "/patchy")
    monkeypatch.setattr(main.settings, "suite_assets_path", "/suite")
    page = main.render_index(index, "/patchy")
    assert page.index('src="/suite/theme-init.js"') < page.index("<base")


def test_asset_crud_and_validation(auth_client, db):
    bad = auth_client.post("/api/assets", json={"name": "", "component_type": "nope", "port": 70000,
                                                "host_ip": "not-an-ip", "evil": 1})
    assert bad.status_code == 422
    assert "not-an-ip" not in bad.text  # submitted values are not echoed
    r = auth_client.post("/api/assets", json={"name": "Django", "component_type": "library", "ecosystem": "PyPI",
                                              "version": "4.2.1", "host_name": "web01", "host_ip": "10.0.0.5",
                                              "port": 8000, "protocol": "tcp", "install_path": "/srv/app",
                                              "repository_url": "https://github.com/octo/site", "branch": "main",
                                              "notes": "<script>alert(1)</script>"})
    assert r.status_code == 201, r.text
    a = r.json()
    assert a["host_name"] == "web01" and a["repository_label"] == "octo/site@main"
    assert a["check_state"] == "not_checked_yet"  # never shown as clean before a feed check
    detail = auth_client.get(f"/api/assets/{a['id']}").json()
    assert detail["paths"] == [{"path": "/srv/app", "kind": "install"}]
    assert detail["notes"] == "<script>alert(1)</script>"  # stored as text; the UI renders it as text
    upd = dict(name="Django", component_type="library", ecosystem="PyPI", version="5.0.0")
    assert auth_client.put(f"/api/assets/{a['id']}", json=upd).json()["version"] == "5.0.0"
    listing = auth_client.get("/api/assets", params={"q": "djan"}).json()
    assert listing["total"] == 1 and listing["page_size"] == 50
    assert auth_client.delete(f"/api/assets/{a['id']}").status_code == 204
    assert auth_client.get(f"/api/assets/{a['id']}").status_code == 404
    actions = {x.action for x in db.query(AuditLog)}
    assert {"asset.create", "asset.update", "asset.delete", "auth.login"} <= actions


def test_unknown_version_asset_state(auth_client):
    r = auth_client.post("/api/assets", json={"name": "requests", "component_type": "library", "ecosystem": "PyPI"})
    assert r.json()["version_status"] == "unknown" and r.json()["check_state"] == "version_unknown"


def test_settings_never_expose_secrets(auth_client):
    r = auth_client.get("/api/settings")
    assert r.json()["github_token_configured"] is True
    assert settings.github_token not in r.text


def _enroll(client, host_id):
    r = client.post(f"/api/hosts/{host_id}/agent")
    assert r.status_code == 201
    return r.json()["token"]


def _report(**over):
    rep = agent_mod.sample_report()
    rep.update(over)
    return rep


def test_agent_enrolment_report_and_idempotency(auth_client, client, host, db):
    token = _enroll(auth_client, host.id)
    assert token.startswith("pa_") and token not in json.dumps([a.detail for a in db.query(AuditLog)])
    assert auth_client.post(f"/api/hosts/{host.id}/agent").status_code == 409  # already enrolled
    rep = _report()
    rep["paths"][0]["entries"] += [{"path": "/srv/sample-app/.env", "type": "file"},
                                   {"path": "/srv/sample-app/.ssh/id_ed25519", "type": "file"}]
    h = {"Authorization": f"Bearer {token}"}
    r = client.post("/api/agent/report", json=rep, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["duplicate"] is False
    again = client.post("/api/agent/report", json=rep, headers=h).json()
    assert again["duplicate"] is True and again["scan_run_id"] == r.json()["scan_run_id"]
    comps = {c.name: c for c in db.query(Component).filter_by(host_id=host.id)}
    assert comps["openssl"].ecosystem == "Debian:12" and comps["openssl"].details["binaries"] == ["libssl3", "openssl"]
    assert comps["nginx"].port is None or comps["nginx"].port == 80
    assert {p.path for p in db.query(HostPath)} == {"/srv/sample-app/app.py"}  # sensitive entries dropped
    detail = auth_client.get(f"/api/hosts/{host.id}").json()
    assert detail["host"]["os_version"] == "12" and detail["host"]["agent"]["last_seen_at"]
    assert "token_hash" not in json.dumps(detail)


def test_agent_rejects_bad_revoked_and_rotated_tokens(auth_client, client, host):
    token = _enroll(auth_client, host.id)
    rep = _report()
    for bad in ("", "Bearer nope", f"Bearer {token}x", "Bearer pa_999_abc"):
        assert client.post("/api/agent/report", json=rep, headers={"Authorization": bad}).status_code == 401
    new = auth_client.post(f"/api/hosts/{host.id}/agent/rotate").json()["token"]
    assert client.get("/api/agent/ping", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert client.get("/api/agent/ping", headers={"Authorization": f"Bearer {new}"}).status_code == 200
    auth_client.post(f"/api/hosts/{host.id}/agent/revoke")
    assert client.get("/api/agent/ping", headers={"Authorization": f"Bearer {new}"}).status_code == 401


def test_agent_report_validation_and_size(auth_client, client, host, monkeypatch):
    h = {"Authorization": f"Bearer {_enroll(auth_client, host.id)}"}
    assert client.post("/api/agent/report", json={"schema": 1}, headers=h).status_code == 422
    assert client.post("/api/agent/report", json=_report(listening=[{"protocol": "tcp", "ip": "x", "port": 99999}]),
                       headers=h).status_code == 422
    assert client.post("/api/agent/report", content=b"x", headers={**h, "Content-Type": "text/plain"}).status_code == 415
    monkeypatch.setattr(settings, "agent_max_report_bytes", 100)
    assert client.post("/api/agent/report", json=_report(), headers=h).status_code == 413


def test_agent_report_does_not_need_csrf_but_session_cannot_post_reports(auth_client, host):
    # A browser session is not an agent credential.
    assert auth_client.post("/api/agent/report", json=_report()).status_code == 401


def test_finding_status_workflow(auth_client, db):
    from app.cli import DEMO_ADVISORY
    from app import vulns
    r = auth_client.post("/api/assets", json={"name": "patchy-demo-lib", "component_type": "library",
                                              "ecosystem": "PyPI", "version": "1.0.0"})
    vulns.upsert_advisory(db, DEMO_ADVISORY, source="demo")
    vulns.rematch(db)
    db.commit()
    f = db.query(Finding).one()
    assert f.match_status == "confirmed"
    bad = auth_client.post(f"/api/findings/{f.id}/status", json={"status": "fixed"})
    assert bad.status_code == 422
    ok = auth_client.post(f"/api/findings/{f.id}/status", json={"status": "false_positive", "note": "not used"})
    assert ok.json()["status"] == "false_positive" and ok.json()["status_changed_by"] == "admin"
    detail = auth_client.get(f"/api/findings/{f.id}").json()
    assert detail["timeline"][-1]["to"] == "false_positive" and detail["timeline"][-1]["actor"] == "admin"
    listed = auth_client.get("/api/findings", params={"status": ["false_positive"], "severity": ["critical"]}).json()
    assert listed["total"] == 1
    dash = auth_client.get("/api/dashboard").json()
    assert dash["severity"] == {}  # false positives don't count as open
    assert r.status_code == 201


def test_agent_files_allowlist(client):
    assert client.get("/api/agent/files/patchy_agent.py").status_code == 200
    assert client.get("/api/agent/files/..%2F..%2Fbackend%2Fapp%2Fconfig.py").status_code == 404
