"""Agent safety boundaries (run against the real agent script) and migration integrity."""
import importlib.util
import json
import os
import pathlib

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext

from app.db import Base, make_engine

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("patchy_agent", ROOT / "agent" / "patchy_agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def test_sample_report_is_labelled_and_valid():
    from app.agent_ingest import Report
    rep = agent.sample_report()
    assert any("SAMPLE" in e for e in rep["errors"])
    Report.model_validate(rep)


@pytest.mark.parametrize("root,ok", [("/opt/myapp", True), ("/home/pi/docker/patchy", True), ("/", False),
                                     ("/home", False), ("/etc", False), ("/proc/1", False), ("/root/x", False),
                                     ("relative", False), ("/opt/../etc", False), ("/srv/app/.ssh", False)])
def test_directory_roots_are_restricted(root, ok):
    assert (agent.check_root(root) is None) is ok


def test_listing_skips_sensitive_names_and_respects_limits(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("SECRET_CONTENT")
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "id_rsa").write_text("k")
    (tmp_path / ".env").write_text("PASSWORD=x")
    (tmp_path / "server.key").write_text("k")
    for i in range(20):
        (tmp_path / f"f{i:02}.txt").write_text("")
    entries, truncated = agent.list_dir(str(tmp_path), 3, 10)
    paths = [e["path"] for e in entries]
    assert truncated and len(entries) == 10
    assert not any(".ssh" in p or p.endswith((".env", ".key")) for p in paths)
    assert "SECRET_CONTENT" not in json.dumps(entries)  # names only, never contents
    deep, _ = agent.list_dir(str(tmp_path), 1, 1000)
    assert not any(e["path"].endswith("main.py") for e in deep)  # depth limit


def test_probe_allowlist_rejects_unknown_commands():
    errors = []
    assert agent.probes(["rm -rf /", "bash"], errors) == []
    assert len(errors) == 2


def test_dpkg_status_parsing(tmp_path):
    status = tmp_path / "status"
    status.write_text(
        "Package: libssl3\nStatus: install ok installed\nVersion: 3.0.11-1~deb12u2\nSource: openssl\nArchitecture: arm64\n\n"
        "Package: removed\nStatus: deinstall ok config-files\nVersion: 1.0\n\n"
        "Package: libc6\nStatus: install ok installed\nVersion: 2.36-9+deb12u4\nSource: glibc (2.36-9+deb12u3)\n")
    pkgs = {p["name"]: p for p in agent.dpkg_packages(str(status))}
    assert set(pkgs) == {"libssl3", "libc6"}
    assert pkgs["libssl3"]["source_name"] == "openssl" and pkgs["libssl3"]["source_version"] == "3.0.11-1~deb12u2"
    assert pkgs["libc6"]["source_version"] == "2.36-9+deb12u3"


def test_proc_net_address_decoding():
    assert agent._hex_ip("0100007F") == "127.0.0.1"
    assert agent._hex_ip("00000000000000000000000001000000") == "::1"


def test_config_refuses_plain_http_unless_opted_in(tmp_path):
    cfg = dict(agent.DEFAULTS, server_url="http://192.0.2.1:8080")
    with pytest.raises(SystemExit):
        agent._url(cfg, "/api/agent/ping")
    cfg["allow_insecure_http"] = True
    assert agent._url(cfg, "/x") == "http://192.0.2.1:8080/x"


def test_no_redirects_so_token_is_never_forwarded():
    assert agent._NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example") is None


def test_migrations_match_models(tmp_path):
    url = f"sqlite:///{(tmp_path / 'mig.db').as_posix()}"
    cfg = Config(str(ROOT / "backend" / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "backend" / "alembic"))
    cfg.attributes["url"] = url
    command.upgrade(cfg, "head")
    eng = make_engine(url)
    with eng.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": False}), Base.metadata)
    assert diff == []
    command.downgrade(cfg, "base")
