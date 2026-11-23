"""v1.13: news feeds chosen in Settings, NuGet manifests, and the optional newer-image check."""
import json

import httpx
import pytest

from app import news, parsers, registry, sources
from app.config import settings

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Mine</title>
<item><title>Post</title><link>https://mine.example/p</link></item></channel></rss>"""


def test_news_feeds_can_be_set_in_settings(monkeypatch, auth_client, db):
    monkeypatch.setattr(settings, "news_feeds", "https://env.example/rss")
    s = auth_client.get("/api/settings").json()["news"]
    assert s == {"feeds": ["https://env.example/rss"], "default": ["https://env.example/rss"], "custom": False}

    r = auth_client.put("/api/settings/news", json={"feeds": ["https://mine.example/rss", "https://mine.example/rss"]})
    assert r.status_code == 200 and r.json()["feeds"] == ["https://mine.example/rss"] and r.json()["custom"]
    db.expire_all()
    assert news.pending(db)  # the worker fetches straight away
    client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, content=RSS)))
    assert news.refresh(db, client) == 1 and not news.pending(db)
    assert auth_client.get("/api/news").json()["items"][0]["source"] == "Mine"

    assert auth_client.put("/api/settings/news", json={"feeds": []}).json()["feeds"] == []
    db.expire_all()
    assert news.refresh(db) == 0 and not news.pending(db)
    assert auth_client.get("/api/news").json() == {"enabled": False, "items": [], "errors": [], "updated_at": None}

    assert auth_client.put("/api/settings/news", json={"feeds": None}).json()["feeds"] == ["https://env.example/rss"]
    for bad in (["http://insecure.example/rss"], ["https://x.example/a b"], [f"https://{i}.example/" for i in range(11)]):
        assert auth_client.put("/api/settings/news", json={"feeds": bad}).status_code == 422
    assert auth_client.get("/api/audit").json()["items"][0]["action"] == "settings.news"


CSPROJ = """<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
  <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
  <PackageReference Include="Serilog"><Version>[3.0,4.0)</Version></PackageReference>
  <PackageReference Include="Central.Managed" />
</ItemGroup></Project>"""
LOCK = {"version": 1, "dependencies": {
    "net8.0": {"Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1"},
               "MyLib": {"type": "Project"}},
    "net6.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"}}}}


def test_nuget_manifests():
    got = [(p.name, p.version or p.version_spec, p.version_status) for p in parsers.parser_for("src/App/App.csproj")(CSPROJ)]
    assert got == [("Newtonsoft.Json", "13.0.1", "exact"), ("Serilog", "[3.0,4.0)", "constraint"),
                   ("Central.Managed", None, "unknown")]
    props = '<Project><ItemGroup><PackageVersion Include="Central.Managed" Version="2.1.0" /></ItemGroup></Project>'
    assert [(p.name, p.version) for p in parsers.parser_for("Directory.Packages.props")(props)] == [("Central.Managed", "2.1.0")]
    cfg = '<packages><package id="jQuery" version="3.4.1" targetFramework="net48" /></packages>'
    assert [(p.name, p.ecosystem, p.version) for p in parsers.parser_for("web/packages.config")(cfg)] == \
        [("jQuery", "NuGet", "3.4.1")]
    assert [(p.name, p.version) for p in parsers.parser_for("packages.lock.json")(json.dumps(LOCK))] == \
        [("Newtonsoft.Json", "13.0.1")]
    with pytest.raises(ValueError):
        parsers.parse_msbuild('<!DOCTYPE x [<!ENTITY a "b">]><Project/>')


def test_image_refs():
    assert registry.parse_ref("nginx") == ("docker.io", "library/nginx", "latest")
    assert registry.parse_ref("linuxserver/sonarr:4") == ("docker.io", "linuxserver/sonarr", "4")
    assert registry.parse_ref("ghcr.io/home-assistant/home-assistant:stable") == \
        ("ghcr.io", "home-assistant/home-assistant", "stable")
    for no in ("nginx@sha256:abc", "192.168.1.5:5000/app:1", "localhost/app", "evil.example/x:1", "Bad Name"):
        assert registry.parse_ref(no) is None


def _registry(index_digest):
    """A registry that wants a token, serving an index for nginx:1.27 with amd64 and arm64 builds."""
    calls = []

    def handler(req):
        calls.append((req.method, req.url.host, req.url.path))
        if req.url.host == "auth.docker.io":
            assert req.url.params["scope"] == "repository:library/nginx:pull"
            return httpx.Response(200, json={"token": "t"})
        if req.headers.get("authorization") != "Bearer t":
            return httpx.Response(401, headers={"www-authenticate": 'Bearer realm="https://auth.docker.io/token",'
                                                'service="registry.docker.io",scope="repository:library/nginx:pull"'})
        if req.url.path.endswith("/1.27"):
            return httpx.Response(200, headers={"docker-content-digest": index_digest}, json={"manifests": [
                {"digest": "sha256:amd", "platform": {"os": "linux", "architecture": "amd64"}},
                {"digest": "sha256:arm", "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}}]})
        return httpx.Response(200, json={"config": {"digest": "sha256:cfg-" + req.url.path.rsplit(":", 1)[1]}})
    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_newer_image_check(auth_client, db, host):
    assert sources.schedule(db)["images"]["enabled"] is False  # off unless switched on
    host.arch = "aarch64"
    host.containers = [
        {"name": "web", "image": "nginx:1.27", "image_id": "sha256:old", "ports": [], "mounts": []},
        {"name": "web2", "image": "nginx:1.27", "image_id": "sha256:cfg-arm", "ports": [], "mounts": []},
        {"name": "app", "image": "proj-app", "image_id": "sha256:x", "compose_project": "proj",
         "compose_service": "app", "ports": [], "mounts": []},  # built locally: never looked up
    ]
    db.commit()
    client, calls = _registry("sha256:idx1")
    assert registry.refresh(db, client) == {"images": 1, "checked": 1, "failed": 0, "newer": 1}
    assert ("GET", "registry-1.docker.io", "/v2/library/nginx/manifests/sha256:arm") in calls
    db.commit()
    body = auth_client.get(f"/api/hosts/{host.id}").json()
    assert list(body["image_updates"]) == ["web"]

    client, calls = _registry("sha256:idx1")  # tag hasn't moved: a HEAD (plus its token) and nothing more
    registry.refresh(db, client)
    assert [c[0] for c in calls if c[1] != "auth.docker.io"] == ["HEAD", "HEAD"]

    # web pulls the current build: no longer flagged, even before the next check
    host.containers = [{**host.containers[0], "image_id": "sha256:cfg-arm"}]
    db.commit()
    assert auth_client.get(f"/api/hosts/{host.id}").json()["image_updates"] == {}

    dead = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(503)))
    with pytest.raises(RuntimeError):
        registry.refresh(db, dead)
