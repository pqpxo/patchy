"""v1.26: AUTH_DISABLED. No sign-in, one shared user, CSRF still checked."""
from sqlalchemy import func, select

from app.config import settings
from app.models import User


def test_auth_disabled_needs_no_sign_in_but_keeps_csrf(client, db, monkeypatch):
    assert client.get("/api/findings").status_code == 401  # off by default
    monkeypatch.setattr(settings, "auth_disabled", True)
    me = client.get("/api/auth/me").json()
    assert me["username"] == "local" and me["sign_in"] is False
    assert client.get("/api/findings").status_code == 200
    assert client.put("/api/settings/alerts", json={"paused": True}).status_code == 403  # no CSRF token
    r = client.put("/api/settings/alerts", json={"paused": True}, headers={"X-CSRF-Token": me["csrf_token"]})
    assert r.status_code < 300
    assert client.get("/api/auth/me").json()["csrf_token"] == me["csrf_token"]  # same session every time
    assert db.scalar(select(func.count()).select_from(User)) == 1
