"""v1.21: the public demo. A made-up lab, real public vulnerability data, and no way to change anything."""
import pytest
from sqlalchemy import func, select

from app import demo
from app.config import settings
from app.models import AuditLog, Finding, Host


@pytest.fixture
def loaded(db):
    return demo.load(db)


def test_demo_has_a_history_from_patchys_own_matching(db, loaded):
    status = dict(db.execute(select(Finding.status, func.count()).group_by(Finding.status)).all())
    assert loaded["findings"] > 500 and status["open"] > 100
    for s in ("resolved", "minor", "not_booted", "acknowledged", "false_positive", "risk_accepted"):
        assert status.get(s), s  # each workflow state appears, so every filter shows something
    hosts = {h.name: h for h in db.scalars(select(Host))}
    assert hosts["old-wiki"].os_eol_state == "eol" and hosts["old-wiki"].agent.agent_version == "1.3.0"
    assert db.scalar(select(func.count()).select_from(Finding).join(Finding.advisory).where(
        Finding.status == "open", Finding.advisory.has(kev=True)))
    with pytest.raises(SystemExit):  # never over a database that has anything in it
        demo.load(db)


def test_demo_mode_signs_everyone_in_and_refuses_changes(client, db, loaded, monkeypatch):
    monkeypatch.setattr(settings, "demo_mode", True)
    me = client.get("/api/auth/me").json()
    assert me["username"] == "demo" and me["demo"] == loaded["snapshot"]
    assert client.get("/api/findings").json()["total"] > 100
    for method, path in (("put", "/api/settings/alerts"), ("post", "/api/auth/login"), ("post", "/api/auth/logout"),
                         ("delete", "/api/hosts/1"), ("post", "/api/agent/report")):
        r = client.request(method.upper(), path, json={})
        assert r.status_code == 403 and "demo" in r.json()["detail"], path
    client.get("/api/findings/export")  # audited, but a visitor's address is never shown to the next one
    assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.ip.is_not(None))) == 0


def test_outside_demo_mode_nothing_changes(client, loaded):
    assert client.get("/api/auth/me").status_code == 401  # the demo user isn't a way in on a real install


def test_demo_mode_set_by_mistake_on_a_real_install_lets_no_one_in(client, db, monkeypatch):
    from datetime import timedelta

    from app.db import utcnow
    from app.models import User, UserSession
    u = User(username="demo", password_hash="x")  # a real user who happens to be called demo
    db.add(u)
    db.flush()
    db.add(UserSession(token_hash="h" * 64, csrf_token="c", user_id=u.id, expires_at=utcnow() + timedelta(days=1)))
    db.commit()
    monkeypatch.setattr(settings, "demo_mode", True)
    assert client.get("/api/auth/me").status_code == 401
