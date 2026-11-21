#!/usr/bin/env python3
"""Patchy Linux agent: read-only software inventory, sent outbound to your Patchy portal.

What it reads (each part can be switched off in the config):
  - OS details from /etc/os-release, kernel release, hostname and primary IP
  - Installed packages from the package database (/var/lib/dpkg/status, /lib/apk/db/installed, or `rpm -qa`)
  - Listening sockets from /proc/net/{tcp,tcp6,udp,udp6} (process names only where readable)
  - Running systemd service names (`systemctl list-units`)
  - Versions from an allowlist of fixed commands (eg `nginx -v`), only those named in the config
  - Optional: container image names (`docker ps`), needs docker group membership (root-equivalent)
  - Optional: names (never contents) of files under directories you list, with depth/count limits

What it never reads or sends: file contents, environment variables, keys, passwords, tokens,
shell history, or anything under excluded sensitive paths. It never accepts commands from the server.

Usage:
  patchy_agent.py --dry-run            collect and print the report, send nothing
  patchy_agent.py --sample             print a synthetic SAMPLE report (reads nothing from this host)
  patchy_agent.py --sample --send      send the SAMPLE report (to test enrolment end to end)
  patchy_agent.py --check              verify the server URL and credential
  patchy_agent.py                      collect and send (what the systemd timer runs)
Python 3.8+, standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import posixpath
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

VERSION = "0.1.0"
DEFAULT_CONFIG = "/etc/patchy-agent/config.json"
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MAX_OUTPUT = 64 * 1024

# Fixed allowlist: name -> (argv, version regex, component type). Config can only pick names from here.
PROBES = {
    "nginx": (["nginx", "-v"], r"nginx/(\S+)", "web_server"),
    "apache2": (["apache2", "-v"], r"Apache/(\S+)", "web_server"),
    "httpd": (["httpd", "-v"], r"Apache/(\S+)", "web_server"),
    "caddy": (["caddy", "version"], r"v(\d+\.\d+\.\d+)", "web_server"),
    "python3": (["python3", "--version"], r"Python (\S+)", "language"),
    "node": (["node", "--version"], r"v(\d\S*)", "language"),
    "java": (["java", "-version"], r'version "([^"]+)"', "language"),
    "go": (["go", "version"], r"go(\d+\.\d+(?:\.\d+)?)", "language"),
    "php": (["php", "--version"], r"PHP (\d\S*)", "language"),
    "ruby": (["ruby", "--version"], r"ruby (\d\S*)", "language"),
    "mysqld": (["mysqld", "--version"], r"Ver (\d\S*)", "database"),
    "mariadb": (["mariadb", "--version"], r"(\d+\.\d+\.\d+)-MariaDB", "database"),
    "redis-server": (["redis-server", "--version"], r"v=(\S+)", "database"),
    "docker": (["docker", "--version"], r"version ([^,\s]+)", "application"),
    "openssl": (["openssl", "version"], r"OpenSSL (\S+)", "application"),
    "openssh": (["ssh", "-V"], r"OpenSSH_([^\s,]+)", "application"),
    "git": (["git", "--version"], r"git version (\S+)", "application"),
}
DEFAULT_PROBES = ["nginx", "apache2", "httpd", "caddy", "python3", "node", "openssl", "openssh", "docker"]

# Directory listing safety. Roots must be specific application directories, not broad trees.
DENY_ROOTS = {"/", "/home", "/root", "/etc", "/var", "/usr", "/opt", "/srv", "/boot", "/run", "/tmp", "/mnt", "/media"}
DENY_PREFIXES = ("/proc", "/sys", "/dev", "/root", "/run", "/var/lib/docker", "/etc/ssl/private")
SENSITIVE = re.compile(
    r"(^|/)(\.ssh|\.gnupg|\.aws|\.kube|\.docker|\.password-store|secrets?|\.git)(/|$)"
    r"|(^|/)(shadow|gshadow|\.env(\..*)?|\.netrc|\.pgpass|\.bash_history|\.zsh_history|id_[a-z0-9]+"
    r"|.*\.(key|pem|p12|pfx|kdbx|crt))$", re.IGNORECASE)
HARD_MAX_DEPTH, HARD_MAX_FILES = 8, 5000

DEFAULTS = {
    "server_url": "",
    "token_file": "/etc/patchy-agent/token",
    "ca_file": None,
    "allow_insecure_http": False,
    "timeout_seconds": 30,
    "collect": {"packages": True, "listening_ports": True, "services": True, "docker_images": False,
                "version_probes": DEFAULT_PROBES},
    "app_dirs": [],
}


# ---------------------------------------------------------------- helpers

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_fixed(argv, timeout=10):
    """Run an allowlisted command: argument list, no shell, clean env, no stdin, bounded output."""
    exe = shutil.which(argv[0], path=SAFE_PATH)
    if not exe:
        return None, None
    try:
        p = subprocess.run([exe] + argv[1:], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout, check=False,
                           env={"PATH": SAFE_PATH, "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError):
        return exe, None
    return exe, p.stdout[:MAX_OUTPUT].decode("utf-8", "replace")


def read_text(path, limit=50 * 1024 * 1024):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read(limit)


# ---------------------------------------------------------------- collectors

def os_release():
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            data = {}
            for line in read_text(path, 64 * 1024).splitlines():
                k, sep, v = line.partition("=")
                if sep:
                    data[k.strip()] = v.strip().strip('"')
            return {"id": data.get("ID"), "version_id": data.get("VERSION_ID"),
                    "pretty_name": data.get("PRETTY_NAME"), "id_like": data.get("ID_LIKE")}
        except OSError:
            continue
    return {}


def host_info():
    ips = []
    try:  # routing lookup only; no packet is sent
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))
        ips.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    u = os.uname()
    return {"hostname": socket.gethostname(), "ips": ips, "os": os_release(), "kernel": u.release, "arch": u.machine}


def dpkg_packages(path="/var/lib/dpkg/status"):
    out = []
    for block in read_text(path).split("\n\n"):
        f = {}
        for line in block.splitlines():
            if line and not line[0].isspace() and ":" in line:
                k, v = line.split(":", 1)
                f[k] = v.strip()
        if "install ok installed" not in f.get("Status", "") or not f.get("Package"):
            continue
        src, src_ver = f["Package"], f.get("Version")
        if f.get("Source"):
            m = re.match(r"^(\S+)(?:\s+\(([^)]+)\))?", f["Source"])
            src, src_ver = m.group(1), m.group(2) or f.get("Version")
        out.append({"manager": "dpkg", "name": f["Package"], "version": f.get("Version", ""),
                    "source_name": src, "source_version": src_ver, "arch": f.get("Architecture")})
    return out


def apk_packages(path="/lib/apk/db/installed"):
    out = []
    for block in read_text(path).split("\n\n"):
        f = dict(line.split(":", 1) for line in block.splitlines() if len(line) > 2 and line[1] == ":")
        if f.get("P") and f.get("V"):
            out.append({"manager": "apk", "name": f["P"], "version": f["V"], "source_name": f.get("o") or f["P"],
                        "source_version": f["V"], "arch": f.get("A")})
    return out


def rpm_packages():
    _, text = run_fixed(["rpm", "-qa", "--qf", "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n"], 60)
    out = []
    for line in (text or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 4:
            ver = parts[2] if parts[1] in ("", "0") else f"{parts[1]}:{parts[2]}"
            out.append({"manager": "rpm", "name": parts[0], "version": ver, "arch": parts[3]})
    return out


def packages(errors):
    if os.path.exists("/var/lib/dpkg/status"):
        return dpkg_packages()
    if os.path.exists("/lib/apk/db/installed"):
        return apk_packages()
    if shutil.which("rpm", path=SAFE_PATH):
        return rpm_packages()
    errors.append("No supported package database found (dpkg, apk, rpm).")
    return []


def _hex_ip(h):
    b = bytes.fromhex(h)
    if len(b) == 4:
        return socket.inet_ntop(socket.AF_INET, b[::-1])
    return socket.inet_ntop(socket.AF_INET6, b"".join(b[i:i + 4][::-1] for i in range(0, 16, 4)))


def socket_owners():
    """inode -> process name, for processes this user may inspect. Others stay unknown."""
    owners = {}
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            name = read_text(f"/proc/{pid}/comm", 256).strip()
            for fd in os.listdir(f"/proc/{pid}/fd"):
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
                if link.startswith("socket:["):
                    owners[link[8:-1]] = name
        except OSError:
            continue
    return owners


def listening():
    owners, out, seen = socket_owners(), [], set()
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        try:
            lines = read_text(f"/proc/net/{proto}", 4 * 1024 * 1024).splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            cols = line.split()
            if len(cols) < 10:
                continue
            state = cols[3]
            if (proto.startswith("tcp") and state != "0A") or (proto.startswith("udp") and state != "07"):
                continue
            ip_hex, port_hex = cols[1].split(":")
            key = (proto, ip_hex, port_hex)
            if key in seen:
                continue
            seen.add(key)
            out.append({"protocol": proto, "ip": _hex_ip(ip_hex), "port": int(port_hex, 16),
                        "process": owners.get(cols[9])})
    return out


def services():
    _, text = run_fixed(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend",
                         "--plain", "--no-pager"])
    return [{"unit": line.split()[0]} for line in (text or "").splitlines() if line.strip()]


def docker_images(errors):
    exe, text = run_fixed(["docker", "ps", "--format", "{{.Image}}"], 20)
    if exe and text is not None and "permission denied" in text.lower():
        errors.append("docker_images: no permission to read the Docker socket.")
        return []
    return [{"image": line.strip()} for line in sorted(set((text or "").splitlines())) if line.strip()][:1000]


def probes(names, errors):
    out = []
    for name in names:
        if name not in PROBES:
            errors.append(f"version probe '{name}' is not in the allowlist; skipped.")
            continue
        argv, rx, ctype = PROBES[name]
        exe, text = run_fixed(argv)
        if not exe:
            continue
        m = re.search(rx, text or "")
        out.append({"name": name, "version": m.group(1) if m else None, "path": exe, "component_type": ctype})
    return out


def check_root(root):
    """Return an error message if a configured directory is not allowed."""
    if not isinstance(root, str) or not root.startswith("/") or posixpath.normpath(root) != root:
        return "must be an absolute, normalised path"
    if root in DENY_ROOTS or root.startswith(DENY_PREFIXES) or SENSITIVE.search(root):
        return "is too broad or sensitive to list"
    return None


def list_dir(root, max_depth, max_files):
    """Names only. Does not follow symlinks, skips sensitive entries, stops at limits."""
    max_depth, max_files = min(int(max_depth), HARD_MAX_DEPTH), min(int(max_files), HARD_MAX_FILES)
    entries, truncated, stack = [], False, [(root, 0)]
    while stack:
        path, depth = stack.pop()
        try:
            with os.scandir(path) as it:
                items = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for e in items:
            if SENSITIVE.search(e.path.replace(os.sep, "/")):
                continue
            if len(entries) >= max_files:
                return entries, True
            try:
                is_dir = e.is_dir(follow_symlinks=False)
            except OSError:
                continue
            entries.append({"path": e.path, "type": "dir" if is_dir else "file"})
            if is_dir and depth + 1 < max_depth:
                stack.append((e.path, depth + 1))
            elif is_dir:
                truncated = True
    return entries, truncated


def collect(cfg):
    errors, col = [], cfg["collect"]
    report = {"schema": 1, "report_id": str(uuid.uuid4()), "agent_version": VERSION, "generated_at": now_iso(),
              "host": host_info(), "packages": [], "probes": [], "listening": [], "services": [], "containers": [],
              "paths": [], "errors": errors}
    steps = [("packages", col.get("packages"), lambda: packages(errors)),
             ("listening", col.get("listening_ports"), listening),
             ("services", col.get("services"), services),
             ("containers", col.get("docker_images"), lambda: docker_images(errors)),
             ("probes", bool(col.get("version_probes")), lambda: probes(col.get("version_probes") or [], errors))]
    for key, enabled, fn in steps:
        if enabled:
            try:
                report[key] = fn()
            except Exception as e:  # keep going; report what failed without details that might be sensitive
                errors.append(f"{key}: {type(e).__name__}")
    for d in cfg.get("app_dirs") or []:
        root = d.get("path") if isinstance(d, dict) else None
        problem = check_root(root)
        if problem:
            errors.append(f"app_dirs: {root!r} {problem}; skipped.")
            continue
        entries, truncated = list_dir(root, d.get("max_depth", 3), d.get("max_files", 1000))
        report["paths"].append({"root": root, "entries": entries, "truncated": truncated})
    return report


def sample_report():
    return {
        "schema": 1, "report_id": str(uuid.uuid4()), "agent_version": VERSION, "generated_at": now_iso(),
        "host": {"hostname": "sample-host", "ips": ["192.0.2.50"], "kernel": "6.1.0-sample", "arch": "aarch64",
                 "os": {"id": "debian", "version_id": "12", "pretty_name": "SAMPLE Debian GNU/Linux 12 (bookworm)"}},
        "packages": [
            {"manager": "dpkg", "name": "libssl3", "version": "3.0.11-1~deb12u1", "source_name": "openssl",
             "source_version": "3.0.11-1~deb12u1", "arch": "arm64"},
            {"manager": "dpkg", "name": "openssl", "version": "3.0.11-1~deb12u1", "source_name": "openssl",
             "source_version": "3.0.11-1~deb12u1", "arch": "arm64"},
            {"manager": "dpkg", "name": "nginx", "version": "1.22.1-9", "source_name": "nginx",
             "source_version": "1.22.1-9", "arch": "arm64"},
        ],
        "probes": [{"name": "nginx", "version": "1.22.1", "path": "/usr/sbin/nginx", "component_type": "web_server"}],
        "listening": [{"protocol": "tcp", "ip": "0.0.0.0", "port": 80, "process": "nginx"},
                      {"protocol": "tcp", "ip": "0.0.0.0", "port": 22, "process": None}],
        "services": [{"unit": "nginx.service"}, {"unit": "ssh.service"}],
        "containers": [], "paths": [{"root": "/srv/sample-app", "truncated": False,
                                     "entries": [{"path": "/srv/sample-app/app.py", "type": "file"}]}],
        "errors": ["SAMPLE REPORT: synthetic data generated with --sample, not read from a real host."],
    }


# ---------------------------------------------------------------- config + transport

def load_config(path):
    cfg = json.loads(json.dumps(DEFAULTS))
    with open(path, "r", encoding="utf-8") as f:
        user = json.load(f)
    for k, v in user.items():
        if k == "collect" and isinstance(v, dict):
            cfg["collect"].update(v)
        elif k in cfg:
            cfg[k] = v
    return cfg


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never forward the token to another URL
        return None


def _url(cfg, path):
    base = (cfg.get("server_url") or "").rstrip("/")
    if not base.startswith(("https://", "http://")):
        raise SystemExit("config: server_url must start with https://")
    if base.startswith("http://") and not cfg.get("allow_insecure_http"):
        raise SystemExit("config: refusing plain http. Use https, or set allow_insecure_http: true for a trusted LAN.")
    return base + path


def read_token(cfg):
    path = cfg["token_file"]
    st = os.stat(path)
    if st.st_mode & stat.S_IROTH:
        raise SystemExit(f"{path} is world-readable. Run: chmod 640 {path}")
    with open(path, "r", encoding="utf-8") as f:
        token = f.read().strip()
    if not token.startswith("pa_"):
        raise SystemExit(f"{path} does not contain a Patchy agent token.")
    return token


def request(cfg, method, path, body=None):
    ctx = ssl.create_default_context(cafile=cfg.get("ca_file") or None)
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(_url(cfg, path), data=data, method=method, headers={
        "Authorization": f"Bearer {read_token(cfg)}", "Content-Type": "application/json",
        "User-Agent": f"patchy-agent/{VERSION}"})
    try:
        with opener.open(req, timeout=cfg.get("timeout_seconds", 30)) as r:
            return r.status, json.loads(r.read(1024 * 1024) or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {"detail": e.read(2048).decode("utf-8", "replace")}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Patchy read-only inventory agent")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--dry-run", action="store_true", help="print the report instead of sending it")
    ap.add_argument("--sample", action="store_true", help="use a synthetic SAMPLE report (reads nothing)")
    ap.add_argument("--send", action="store_true", help="with --sample: send it to the server")
    ap.add_argument("--check", action="store_true", help="test the server URL and credential")
    ap.add_argument("--version", action="version", version=VERSION)
    a = ap.parse_args(argv)

    if a.sample and not a.send:
        print(json.dumps(sample_report(), indent=2))
        return 0
    cfg = load_config(a.config)
    if a.check:
        code, body = request(cfg, "GET", "/api/agent/ping")
        print(f"HTTP {code}: {body}")
        return 0 if code == 200 else 1
    report = sample_report() if a.sample else collect(cfg)
    if a.dry_run:
        print(json.dumps(report, indent=2))
        return 0
    code, body = request(cfg, "POST", "/api/agent/report", report)
    print(f"HTTP {code}: {body}")
    return 0 if code == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
