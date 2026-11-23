"""v1.15: read-only API tokens and the summary Home Assistant polls."""
from fastapi.testclient import TestClient

from app.db import utcnow
from app.main import app
from app.models import Advisory, Component, Finding


def test_tokens_read_the_summary_and_nothing_else(auth_client, db, host):
    client = TestClient(app)  # no session: the token alone
    c = Component(name="lib", version="1", component_type="library", source="agent", host_id=host.id,
                  exposure="network")
    db.add(c)
    db.add_all([Advisory(id="A", severity="critical", kev=True, affected=[]), Advisory(id="B", severity="high", affected=[]),
                Advisory(id="C", severity="low", affected=[])])
    db.flush()
    for adv, match in (("A", "confirmed"), ("B", "possible"), ("C", "unknown_version")):
        db.add(Finding(component_id=c.id, advisory_id=adv, match_status=match, evidence="e", remediation="r",
                       first_detected_at=utcnow()))
    db.commit()

    r = auth_client.post("/api/settings/tokens", json={"name": "Home Assistant"})
    assert r.status_code == 201
    token, tid = r.json()["token"], r.json()["id"]
    assert token.startswith(f"pt_{tid}_") and r.json()["hint"] == "..." + token[-4:]
    assert "token" not in auth_client.get("/api/settings/tokens").json()[0]

    bearer = {"Authorization": f"Bearer {token}"}
    s = client.get("/api/integrations/summary", headers=bearer).json()
    assert (s["open"], s["critical"], s["high"], s["low"], s["kev"], s["network_exposed"]) == (2, 1, 1, 0, 1, 2)
    assert s["alerts_paused"] is False and s["newer_images"] == 0 and "version" in s
    assert client.get("/api/dashboard", headers=bearer).status_code == 401  # read-only: the summary only
    assert client.get("/api/hosts", headers=bearer).status_code == 401
    assert auth_client.get("/api/settings/tokens").json()[0]["last_used_at"]

    assert client.get("/api/integrations/summary", headers={"Authorization": "Bearer pt_1_wrong"}).status_code == 401
    assert client.get("/api/integrations/summary").status_code == 401
    assert auth_client.delete(f"/api/settings/tokens/{tid}").status_code == 204
    assert client.get("/api/integrations/summary", headers=bearer).status_code == 401
    assert [a["action"] for a in auth_client.get("/api/audit").json()["items"][:2]] == ["token.revoke", "token.create"]
    assert auth_client.post("/api/settings/tokens", json={"name": "bad\nname"}).status_code == 422
