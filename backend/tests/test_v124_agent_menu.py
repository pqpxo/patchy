"""v1.24: the agent's menu (sudo patchy-agent), driven with scripted picks and answers."""
import json
import os
import pathlib
import shutil
import socket
import urllib.error

import pytest

from tests.test_api import _enroll, agent_mod

AGENT_DIR = pathlib.Path(__file__).resolve().parents[2] / "agent"


@pytest.fixture
def menu(tmp_path, monkeypatch):
    """A config and token in tmp_path, and the menu's prompts answered from lists."""
    cfg = tmp_path / "config.json"
    raw = json.loads((AGENT_DIR / "config.example.json").read_text(encoding="utf-8"))
    raw["token_file"] = str(tmp_path / "token")
    cfg.write_text(json.dumps(raw), encoding="utf-8")
    (tmp_path / "token").write_text("pa_old\n", encoding="utf-8")
    script = {"picks": [], "answers": [], "ran": []}
    monkeypatch.setattr(agent_mod, "_pick", lambda title, items, note="": script["picks"].pop(0))
    monkeypatch.setattr(agent_mod, "_ask", lambda prompt: script["answers"].pop(0))
    monkeypatch.setattr(agent_mod, "_pause", lambda: None)
    monkeypatch.setattr(agent_mod, "_run", lambda argv, capture=False, **kw: script["ran"].append(argv) or (0, ""))
    script["cfg"] = str(cfg)
    script["raw"] = lambda: json.loads(cfg.read_text(encoding="utf-8"))
    return script


def test_keys_and_screen():
    assert agent_mod._menu_key(258, 0, 3) == ("move", 1)
    assert agent_mod._menu_key(259, 0, 3) == ("move", 2)  # wraps to the bottom
    assert agent_mod._menu_key(ord("2"), 0, 3) == ("pick", 1)
    assert agent_mod._menu_key(ord("9"), 0, 3) == ("move", 0)  # no item 9
    assert agent_mod._menu_key(27, 1, 3) == ("back", None)
    lines = [t for t, _ in agent_mod._screen("patchy-agent", ["Status", "Quit"], 1, "Server: x")]
    assert lines[:4] == agent_mod.LOGO and len({len(r) for r in agent_mod.LOGO}) == 1
    assert "   1. Status" in lines and " > 2. Quit" in lines and "Server: x" in lines


def test_status_reads_the_agents_summary_without_trusting_it(tmp_path):
    rep = agent_mod.sample_report()
    agent_mod.save_summary(agent_mod.report_summary(rep, 200), str(tmp_path))
    text = "\n".join(agent_mod.summary_lines(agent_mod._read_json_nofollow(str(tmp_path / "last-report.json"))))
    assert "just now, accepted" in text and "3 packages" in text and "1 pending updates (1 security)" in text
    (tmp_path / "last-report.json").write_text(json.dumps({"http": 500, "errors": ["x\x1b]0;owned\x07"]}))
    text = "\n".join(agent_mod.summary_lines(agent_mod._read_json_nofollow(str(tmp_path / "last-report.json"))))
    assert "\x1b" not in text and "not accepted (HTTP 500)" in text  # no terminal escapes reach root's screen
    (tmp_path / "list.json").write_text("[1]")
    assert agent_mod._read_json_nofollow(str(tmp_path / "list.json")) is None
    assert agent_mod._read_json_nofollow(str(tmp_path)) is None  # a directory, not a file
    if os.name == "posix":
        os.symlink(tmp_path / "last-report.json", tmp_path / "link.json")
        assert agent_mod._read_json_nofollow(str(tmp_path / "link.json")) is None


def test_collect_switches_and_app_directories(menu, tmp_path, monkeypatch):
    keys = [k for k, _ in agent_mod.COLLECT_ITEMS]
    menu["picks"] = [keys.index("updates"), keys.index("image_scan"), keys.index("version_probes"), None]
    agent_mod._menu_collect(menu["cfg"])
    col = menu["raw"]()["collect"]
    assert col["updates"] is False and col["image_scan"] == "auto" and col["version_probes"] == []
    assert col["packages"] is True  # everything else untouched

    monkeypatch.setattr(agent_mod, "check_root", lambda p: None if p == str(tmp_path) else "is too broad")
    menu["picks"] = [0, 0, 1, 0, None]
    menu["answers"] = ["/etc", str(tmp_path), "", "50"]  # refused, then added with depth 3 and 50 names, then removed
    agent_mod._menu_app_dirs(menu["cfg"])
    assert menu["raw"]()["app_dirs"] == []
    menu["picks"], menu["answers"] = [0, None], [str(tmp_path), "99", "x"]
    agent_mod._menu_app_dirs(menu["cfg"])
    assert menu["raw"]()["app_dirs"] == [{"path": str(tmp_path), "max_depth": agent_mod.HARD_MAX_DEPTH, "max_files": 1000}]


def test_containers_need_a_yes_before_joining_the_docker_group(menu, tmp_path, monkeypatch):
    sock = tmp_path / "docker.sock"
    sock.write_text("")
    monkeypatch.setattr(agent_mod, "DOCKER_SOCKET", str(sock))
    docker = [k for k, _ in agent_mod.COLLECT_ITEMS].index("docker_images")
    menu["picks"], menu["answers"] = [docker, None], ["n"]
    agent_mod._menu_collect(menu["cfg"])
    assert menu["raw"]()["collect"]["docker_images"] is False and menu["ran"] == []
    menu["picks"], menu["answers"] = [docker, docker, None], ["y"]
    agent_mod._menu_collect(menu["cfg"])
    assert menu["ran"] == [["usermod", "-aG", "docker", "patchy-agent"], ["gpasswd", "-d", "patchy-agent", "docker"]]
    assert menu["raw"]()["collect"]["docker_images"] is False  # on, then off again


def test_a_new_token_is_saved_only_when_patchy_accepts_it(menu, tmp_path, monkeypatch):
    tokens = ["not-a-token", "pa_rejected", "pa_good"]
    monkeypatch.setattr(agent_mod.getpass, "getpass", lambda prompt: tokens.pop(0))
    monkeypatch.setattr(agent_mod, "ping", lambda cfg, token=None: (token == "pa_good", "Rejected.", {}))
    menu["picks"] = [1, 1, None]
    agent_mod._menu_server(menu["cfg"])
    assert (tmp_path / "token").read_text().strip() == "pa_old"
    menu["picks"] = [1, None]
    agent_mod._menu_server(menu["cfg"])
    assert (tmp_path / "token").read_text().strip() == "pa_good"


def test_connection_problems_are_explained(monkeypatch):
    cfg = agent_mod.load_config(str(AGENT_DIR / "config.example.json"))

    def unreachable(*a, **k):
        raise urllib.error.URLError(socket.gaierror(-2, "Name or service not known"))
    monkeypatch.setattr(agent_mod, "request", unreachable)
    ok, msg, _ = agent_mod.ping(cfg, token="pa_x")
    assert not ok and "/etc/hosts" in msg
    monkeypatch.setattr(agent_mod, "request", lambda *a, **k: json.loads("<html>"))  # a proxy's page, not Patchy
    assert "isn't Patchy" in agent_mod.ping(cfg, token="pa_x")[1]
    monkeypatch.setattr(agent_mod, "request", lambda *a, **k: (401, {"detail": "no"}))
    assert "rotated or revoked" in agent_mod.ping(cfg, token="pa_x")[1]
    monkeypatch.setattr(agent_mod, "request", lambda *a, **k: (200, {"host": "gbv2", "agent_version": "1.7.0"}))
    assert agent_mod.ping(cfg, token="pa_x")[:2] == (True, "Connected. Patchy knows this host as gbv2.")


def test_update_is_offered_only_for_a_newer_agent(menu, monkeypatch, capsys):
    monkeypatch.setattr(agent_mod, "download_agent", lambda cfg, dest: pytest.fail("nothing should download"))
    for bundled, answers in (("1.6.0", []), (agent_mod.VERSION, []), ("99.0.0", ["n"])):
        monkeypatch.setattr(agent_mod, "ping", lambda cfg, token=None, v=bundled: (True, "ok", {"agent_version": v}))
        menu["answers"] = answers
        agent_mod._menu_update(menu["cfg"])
    out = capsys.readouterr().out
    assert out.count("Up to date") == 2 and menu["answers"] == []  # asked only about 99.0.0, and declined
    assert agent_mod.version_tuple("1.10.0") > agent_mod.version_tuple("1.9.2")


def test_ping_names_the_agent_this_patchy_bundles(auth_client, client, host):
    token = _enroll(auth_client, host.id)
    body = client.get("/api/agent/ping", headers={"Authorization": f"Bearer {token}"}).json()
    assert body == {"ok": True, "host": host.name, "agent_version": agent_mod.VERSION}


def test_installer_keeps_itself_and_adds_the_menu_command():
    install = (AGENT_DIR / "install.sh").read_text(encoding="utf-8")
    assert 'if [ "$HERE" != "$LIB" ]' in install  # re-run from the menu without copying files onto themselves
    assert "cat > /usr/local/bin/patchy-agent" in install and "set -- --menu" in install
    assert "rm -f /usr/local/bin/patchy-agent" in (AGENT_DIR / "uninstall.sh").read_text(encoding="utf-8")
    if shutil.which("sh"):  # Git Bash or Linux
        import subprocess
        assert subprocess.run(["sh", "-n", str(AGENT_DIR / "install.sh")]).returncode == 0
