"""v1.2: Docker containers, added software, on-request rescans and hourly retry of failed sources."""
import json
from datetime import timedelta

from app import sources
from app.db import utcnow
from app.models import Component, FeedStatus, Host
from tests.test_api import _enroll, _report, agent_mod


def test_containers_and_apps_are_stored_and_sensitive_mounts_hidden(auth_client, client, host, db):
    token = _enroll(auth_client, host.id)
    rep = _report(apps=[{"manager": "dpkg", "name": "plexmediaserver", "version": "1.41.0"},
                        {"manager": "snap", "name": "certbot", "version": "2.11.0"}])
    rep["containers"][0]["mounts"].append({"type": "bind", "source": "/srv/app/.env", "destination": "/app/.env"})
    r = client.post("/api/agent/report", json=rep, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    d = auth_client.get(f"/api/hosts/{host.id}").json()
    assert [c["name"] for c in d["containers"]] == ["sample-web"]
    assert d["containers"][0]["ports"][0]["public"] == 8080
    assert [m["source"] for m in d["containers"][0]["mounts"]] == ["/srv/sample-app/html", None]
    assert {a["name"] for a in d["apps"]} == {"plexmediaserver", "certbot"}
    comps = {(c.name, c.component_type): c for c in db.query(Component).filter_by(host_id=host.id)}
    assert comps[("certbot", "application")].version == "2.11.0"
    assert comps[("nginx", "web_server")].version == "1.22.1"  # the probe and the container image are separate rows
    assert comps[("nginx", "container_image")].version == "1.27"


def test_rescan_is_polled_once_then_cleared_by_the_report(auth_client, client, host, db):
    assert auth_client.post(f"/api/hosts/{host.id}/rescan").status_code == 409  # no agent yet
    token = _enroll(auth_client, host.id)
    h = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/agent/poll", headers=h).json() == {"report": False}
    r = auth_client.post(f"/api/hosts/{host.id}/rescan")
    assert r.status_code == 200 and r.json()["rescan_requested_at"]
    assert client.get("/api/agent/poll", headers=h).json() == {"report": True}
    assert client.post("/api/agent/report", json=_report(), headers=h).status_code == 200
    assert client.get("/api/agent/poll", headers=h).json() == {"report": False}
    assert client.get("/api/agent/poll", headers={"Authorization": "Bearer pa_1_nope"}).status_code == 401


def test_failed_source_retries_after_an_hour_not_a_full_cycle(db):
    sources.save(db, {"epss": {"hours": 24, "enabled": True}})
    db.add(FeedStatus(source="epss", last_attempt_at=utcnow() - timedelta(minutes=90), last_error="boom"))
    db.commit()
    assert "epss" in sources.due(db)
    f = db.get(FeedStatus, "epss")
    f.last_error = None
    db.commit()
    assert "epss" not in sources.due(db)


def test_agent_docker_containers_reads_api_without_env_or_labels(monkeypatch):
    payload = [{"Names": ["/plex"], "Image": "lscr.io/linuxserver/plex:latest", "State": "running", "Status": "Up 3 days",
                "Labels": {"org.opencontainers.image.version": "1.41.0", "com.docker.compose.project": "media",
                           "traefik.http.middlewares.auth.basicauth.users": "admin:$apr1$hash"},
                "Ports": [{"IP": "0.0.0.0", "PrivatePort": 32400, "PublicPort": 32400, "Type": "tcp"},
                          {"IP": "::", "PrivatePort": 32400, "PublicPort": 32400, "Type": "tcp"}],
                "Mounts": [{"Type": "volume", "Name": "plex_config", "Source": "/var/lib/docker/volumes/plex_config/_data",
                            "Destination": "/config", "RW": True},
                           {"Type": "bind", "Source": "/home/me/.ssh", "Destination": "/keys", "RW": False}]}]

    class Fake:
        def __init__(self, *_):
            pass

        def request(self, *_):
            pass

        def getresponse(self):
            class R:
                status = 200

                def read(self, _n):
                    return json.dumps(payload).encode()
            return R()

        def close(self):
            pass

    monkeypatch.setattr(agent_mod, "_UnixHTTP", Fake)
    monkeypatch.setattr(agent_mod.os.path, "exists", lambda p: True)
    out = agent_mod.docker_containers([], "/fake.sock")
    assert out[0]["name"] == "plex" and out[0]["version"] == "1.41.0" and out[0]["compose_project"] == "media"
    assert len(out[0]["ports"]) == 1  # IPv4 and IPv6 bindings collapse
    assert [m["source"] for m in out[0]["mounts"]] == ["/var/lib/docker/volumes/plex_config/_data", None]
    assert "basicauth" not in json.dumps(out)


def test_agent_added_apps_skip_automatic_base_and_plumbing(monkeypatch):
    monkeypatch.setattr(agent_mod, "apt_auto_installed", lambda: {"libfoo1"})
    monkeypatch.setattr(agent_mod, "installer_packages", lambda: None)
    monkeypatch.setattr(agent_mod, "snap_apps", lambda: [{"manager": "snap", "name": "certbot", "version": "2"}])
    monkeypatch.setattr(agent_mod, "flatpak_apps", lambda: [])
    pkgs = [{"manager": "dpkg", "name": n, "version": "1"} for n in
            ("plexmediaserver", "nginx", "libfoo1", "coreutils", "vim", "linux-image-arm64", "raspi-config")]
    meta = {"coreutils": ("required", True), "vim": ("standard", False), "nginx": ("optional", False),
            "plexmediaserver": ("optional", False)}
    names = [a["name"] for a in agent_mod.added_apps(pkgs, meta)]
    assert names == ["plexmediaserver", "nginx", "certbot"]
    monkeypatch.setattr(agent_mod, "installer_packages", lambda: {"nginx"})  # was there at install time
    assert [a["name"] for a in agent_mod.added_apps(pkgs, meta)] == ["plexmediaserver", "vim", "certbot"]
