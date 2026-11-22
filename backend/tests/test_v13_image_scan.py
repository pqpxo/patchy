"""v1.3: packages inside container images, listed by Syft on the host and matched like any other package."""
import json
import os
import sys

import pytest

from app import eol
from app.agent_ingest import purl_package
from app.db import utcnow
from app.models import Advisory, Component, Finding
from tests.test_api import _enroll, _report, agent_mod

SYFT_DOC = {"distro": {"id": "alpine", "versionID": "3.20.3"}, "artifacts": [
    {"type": "deb", "name": "zlib1g", "version": "1:1.2.13.dfsg-1",
     "metadata": {"package": "zlib1g", "version": "1:1.2.13.dfsg-1", "source": "zlib", "sourceVersion": ""}},
    {"type": "apk", "name": "libcrypto3", "version": "3.3.2-r0", "metadata": {"originPackage": "openssl"}},
    {"type": "rpm", "name": "bash", "version": "5.1.8-9.el9"},
    {"type": "npm", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
    {"type": "binary", "name": "busybox", "version": "1.36.1"},  # no purl: nothing to match it against
    {"type": "python", "name": "nover", "version": "", "purl": "pkg:pypi/nover@"},
]}


def test_syft_json_becomes_a_compact_package_list():
    pkgs = agent_mod.syft_packages(SYFT_DOC)
    assert pkgs == [
        {"type": "deb", "name": "zlib1g", "version": "1:1.2.13.dfsg-1", "source_name": "zlib", "source_version": None},
        {"type": "apk", "name": "libcrypto3", "version": "3.3.2-r0", "source_name": "openssl"},
        {"type": "rpm", "name": "bash", "version": "5.1.8-9.el9"},
        {"type": "npm", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
    ]


def test_images_are_scanned_once_then_cached(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(agent_mod, "find_syft", lambda: "/opt/syft")
    monkeypatch.setattr(agent_mod, "syft_scan", lambda exe, image_id: calls.append(image_id) or
                        {"distro": {"id": "debian", "version_id": "12"}, "packages": []})
    containers = [{"image": "nginx:1.27", "image_id": "sha256:aa"}, {"image": "nginx:1.27", "image_id": "sha256:aa"},
                  {"image": "redis:7", "image_id": "sha256:bb"}, {"image": "old", "image_id": None}]
    errors = []
    out = agent_mod.image_packages(containers, errors, state_dir=str(tmp_path))
    assert [i["image"] for i in out] == ["nginx:1.27", "redis:7"] and calls == ["sha256:aa", "sha256:bb"]
    assert agent_mod.image_packages(containers, errors, state_dir=str(tmp_path)) == out and len(calls) == 2
    monkeypatch.setattr(agent_mod, "IMAGE_SCAN_SECONDS", 0)  # out of time: cached images still sent, new ones wait
    more = containers + [{"image": "a:1", "image_id": "sha256:cc"}, {"image": "b:1", "image_id": "sha256:dd"}]
    assert agent_mod.image_packages(more, errors, state_dir=str(tmp_path)) == out and len(calls) == 2
    assert errors == ["syft: 2 image(s) left for the next report"]
    monkeypatch.setattr(agent_mod, "find_syft", lambda: None)
    assert agent_mod.image_packages(more, [], state_dir=str(tmp_path)) == []


def test_each_scan_is_cached_at_once_so_a_stopped_run_keeps_its_work(monkeypatch, tmp_path):
    def scan(exe, image_id):
        if image_id == "sha256:bb":
            raise KeyboardInterrupt  # stands in for systemd stopping the run mid-way
        return {"distro": {}, "packages": []}
    monkeypatch.setattr(agent_mod, "find_syft", lambda: "/opt/syft")
    monkeypatch.setattr(agent_mod, "syft_scan", scan)
    containers = [{"image": "a:1", "image_id": "sha256:aa"}, {"image": "b:1", "image_id": "sha256:bb"}]
    try:
        agent_mod.image_packages(containers, [], state_dir=str(tmp_path))
    except KeyboardInterrupt:
        pass
    monkeypatch.setattr(agent_mod, "syft_scan", lambda exe, image_id: {"distro": {}, "packages": []})
    monkeypatch.setattr(agent_mod, "IMAGE_SCAN_SECONDS", 0)
    assert [i["image"] for i in agent_mod.image_packages(containers, [], state_dir=str(tmp_path))] == ["a:1"]


def test_only_one_report_is_collected_at_a_time(monkeypatch, tmp_path):
    class Fcntl:  # stand-in for Linux flock: the second exclusive lock on the file fails
        LOCK_EX, LOCK_NB, held = 2, 4, []

        @classmethod
        def flock(cls, fd, op):
            if cls.held:
                raise BlockingIOError
            cls.held.append(fd)
    monkeypatch.setitem(sys.modules, "fcntl", Fcntl)
    first = agent_mod.run_lock(str(tmp_path))
    assert isinstance(first, int) and agent_mod.run_lock(str(tmp_path)) is False
    os.close(first)
    assert agent_mod.run_lock(str(tmp_path / "missing")) is None  # no state dir: run anyway

    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"server_url": "http://127.0.0.1:9", "allow_insecure_http": True}))
    monkeypatch.setattr(agent_mod, "run_lock", lambda: False)
    monkeypatch.setattr(agent_mod, "collect", lambda cfg: pytest.fail("collected while another run held the lock"))
    assert agent_mod.main(["--config", str(cfg), "--dry-run"]) == 0


def test_purls_map_to_osv_names():
    assert purl_package("pkg:npm/%40babel/core@7.24.0") == ("npm", "@babel/core", "7.24.0")
    assert purl_package("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar") == \
        ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
    assert purl_package("pkg:golang/golang.org/x/net@v0.17.0") == ("Go", "golang.org/x/net", "v0.17.0")
    assert purl_package("pkg:generic/busybox@1.36") is None and purl_package(None) is None


def test_packages_inside_images_say_nothing_about_host_binaries(host, db):
    def comp(name, ctype, **kw):
        c = Component(name=name, component_type=ctype, source="agent", detection="detected", host_id=host.id,
                      dedupe_key=f"host:{host.id}|{name}|{ctype}|{kw.get('details')}", **kw)
        db.add(c)
        return c
    comp("nginx", "os_package", ecosystem="Debian:12", details={"image": "nginx:1.27", "binaries": ["nginx"]})
    comp("openssl", "os_package", ecosystem="Debian:12", details={"binaries": ["openssl", "libssl3"]})
    probe_nginx, probe_openssl = comp("nginx", "web_server"), comp("openssl", "library")
    db.flush()
    pkgs = eol.host_packages(db, [host.id])
    assert eol.distro_managed(probe_openssl, pkgs)  # installed by the host's own apt
    assert not eol.distro_managed(probe_nginx, pkgs)  # only an image has it, so it keeps its own checks


def test_image_packages_get_findings_per_image_and_pull_advice(auth_client, client, host, db):
    token = _enroll(auth_client, host.id)
    r = client.post("/api/agent/report", json=_report(), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    in_image = {c.name: c for c in db.query(Component).filter_by(host_id=host.id)
                if (c.details or {}).get("image") == "nginx:1.27"}
    zlib, lodash = in_image["zlib"], in_image["lodash"]
    assert (zlib.component_type, zlib.ecosystem, zlib.version) == ("os_package", "Debian:12", "1:1.2.13.dfsg-1")
    assert zlib.details["binaries"] == ["zlib1g"] and zlib.details["containers"] == ["sample-web"]
    assert (lodash.component_type, lodash.ecosystem, lodash.version) == ("library", "npm", "4.17.20")

    db.add(Advisory(id="GHSA-img", severity="high", kev=True, affected=[]))
    db.add(Finding(component_id=lodash.id, advisory_id="GHSA-img", match_status="confirmed", evidence="e",
                   remediation="r", fixed_versions=["4.17.21"], currently_matching=True, first_detected_at=utcnow()))
    db.commit()
    d = auth_client.get(f"/api/hosts/{host.id}").json()
    assert d["images"] == {"nginx:1.27": {"packages": 2, "total": 1, "worst": "high", "kev": True}}
    plan = auth_client.get("/api/fix-plan", params={"host_id": host.id}).json()
    g = next(g for g in plan["groups"] if g["kind"] == "image")
    assert g["command"] == "docker pull nginx:1.27" and g["title"].endswith("container image nginx:1.27")
    assert [f["image"] for f in auth_client.get("/api/findings").json()["items"]] == ["nginx:1.27"]
