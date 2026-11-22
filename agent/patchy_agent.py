#!/usr/bin/env python3
"""Patchy Linux agent: read-only software inventory, sent outbound to your Patchy portal.

What it reads (each part can be switched off in the config):
  - OS details from /etc/os-release, kernel release, hostname and primary IP
  - Installed packages from the package database (/var/lib/dpkg/status, /lib/apk/db/installed, or `rpm -qa`)
  - Listening sockets from /proc/net/{tcp,tcp6,udp,udp6} (process names only where readable)
  - Running systemd service names (`systemctl list-units`)
  - Versions from an allowlist of fixed commands (eg `nginx -v`), only those named in the config
  - Software added to the base OS: manually installed packages that aren't part of the base system
    (apt's auto-installed marks, the installer's package list or package priority), plus Snap and Flatpak apps
  - Optional: Docker containers (name, image, state, published ports, mount locations; never environment
    variables), read from the Docker socket. Needs docker group membership, which is root-equivalent.
  - Optional, with containers: the packages inside each container image, listed by Syft if it is installed
    next to this script (the installer offers a pinned, checksum-verified copy). Cached per image ID.
  - Optional: names (never contents) of files under directories you list, with depth/count limits

What it never reads or sends: file contents, environment variables, keys, passwords, tokens,
shell history, or anything under excluded sensitive paths. It never accepts commands from the server.

Usage:
  patchy_agent.py --dry-run            collect and print the report, send nothing
  patchy_agent.py --sample             print a synthetic SAMPLE report (reads nothing from this host)
  patchy_agent.py --sample --send      send the SAMPLE report (to test enrolment end to end)
  patchy_agent.py --check              verify the server URL and credential
  patchy_agent.py                      collect and send (what the systemd timer runs)
  patchy_agent.py --poll               send a report only if Rescan was pressed in Patchy (polled every 5 min)
Python 3.8+, standard library only.
"""
from __future__ import annotations

import argparse
import gzip
import http.client
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
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

VERSION = "1.4.0"
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
    "collect": {"packages": True, "apps": True, "listening_ports": True, "services": True, "docker_images": False,
                "image_packages": True, "image_scan": "manual", "version_probes": DEFAULT_PROBES},
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


def dpkg_packages(path="/var/lib/dpkg/status", meta=None):
    """meta, if given, is filled with name -> (priority, essential) for added_apps()."""
    out = []
    for block in read_text(path).split("\n\n"):
        f = {}
        for line in block.splitlines():
            if line and not line[0].isspace() and ":" in line:
                k, v = line.split(":", 1)
                f[k] = v.strip()
        if "install ok installed" not in f.get("Status", "") or not f.get("Package"):
            continue
        if meta is not None:
            meta[f["Package"]] = (f.get("Priority"), f.get("Essential") == "yes")
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


def packages(errors, meta=None):
    if os.path.exists("/var/lib/dpkg/status"):
        return dpkg_packages(meta=meta)
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


DOCKER_SOCKET = "/var/run/docker.sock"


class _UnixHTTP(http.client.HTTPConnection):
    """HTTP over a Unix socket, so the Docker API can be read without the docker CLI."""

    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def docker_containers(errors, sock_path=DOCKER_SOCKET):
    """Containers from the Docker API list endpoint (all states). Labels and env are never sent."""
    if not os.path.exists(sock_path):
        return []
    conn = _UnixHTTP(sock_path, 20)
    try:
        conn.request("GET", "/containers/json?all=1")
        r = conn.getresponse()
        status, body = r.status, r.read(8 * 1024 * 1024)
    except PermissionError:
        errors.append("docker: no permission to read the Docker socket. Add patchy-agent to the docker group.")
        return []
    except OSError as e:
        errors.append(f"docker: {type(e).__name__}")
        return []
    finally:
        conn.close()
    if status != 200:
        errors.append(f"docker: API returned HTTP {status}")
        return []
    out = []
    for c in json.loads(body)[:1000]:
        labels = c.get("Labels") or {}
        ports, seen = [], set()
        for p in c.get("Ports") or []:
            key = (p.get("PrivatePort"), p.get("PublicPort"), p.get("Type"))
            if p.get("PrivatePort") and key not in seen:  # Docker lists IPv4 and IPv6 bindings separately
                seen.add(key)
                ports.append({"ip": p.get("IP"), "private": p["PrivatePort"], "public": p.get("PublicPort"),
                              "type": p.get("Type")})
        mounts = []
        for m in c.get("Mounts") or []:
            src = m.get("Source")
            if src and SENSITIVE.search(src):
                src = None
            if m.get("Destination"):
                mounts.append({"type": m.get("Type"), "name": m.get("Name"), "source": src,
                               "destination": m["Destination"], "rw": bool(m.get("RW"))})
        out.append({"name": ((c.get("Names") or ["?"])[0] or "?").lstrip("/"), "image": c.get("Image") or "unknown", "image_id": c.get("ImageID"),
                    "state": c.get("State"), "status": c.get("Status"),
                    "version": labels.get("org.opencontainers.image.version"),
                    "compose_project": labels.get("com.docker.compose.project"),
                    "compose_service": labels.get("com.docker.compose.service"), "ports": ports, "mounts": mounts})
    return out


STATE_DIR = "/var/lib/patchy-agent"  # systemd StateDirectory; without it the cache is simply skipped
IMAGE_CACHE = "image-packages.json"
IMAGE_CACHE_FORMAT = 1  # bump when syft_packages output changes, so cached lists are rebuilt
# New scans start only within this many seconds of the first. With Syft's own 900 s limit the run stays
# inside systemd's 1800 s TimeoutStartSec, so a report always goes out; the rest follow on the next runs.
IMAGE_SCAN_SECONDS = 600


def run_lock(state_dir=STATE_DIR):
    """Held while a report is collected, so the 6-hour run and a Rescan never scan images side by side.

    Returns the lock (keep it until exit), False when another run holds it, or None when there is
    nowhere to keep one (a manual run without the systemd state directory), in which case go ahead."""
    try:
        import fcntl
        fd = os.open(os.path.join(state_dir, "run.lock"), os.O_RDONLY | os.O_CREAT, 0o644)
    except (ImportError, OSError):
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return False
    return fd


def find_syft():
    """Syft installed next to this script by install.sh, else one on the system PATH."""
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "syft")
    if os.path.isfile(here) and os.access(here, os.X_OK):
        return here
    return shutil.which("syft", path=SAFE_PATH)


def syft_packages(doc):
    """Compact package list from Syft JSON: distro packages keep their source package, others go by purl."""
    out = []
    for a in doc.get("artifacts") or []:
        t, md = a.get("type"), a.get("metadata") or {}
        if t == "deb":
            out.append({"type": t, "name": md.get("package") or a.get("name"), "version": md.get("version") or a.get("version"),
                        "source_name": md.get("source") or None, "source_version": md.get("sourceVersion") or None})
        elif t == "apk":
            out.append({"type": t, "name": a.get("name"), "version": a.get("version"),
                        "source_name": md.get("originPackage") or None})
        elif t == "rpm":
            out.append({"type": t, "name": a.get("name"), "version": a.get("version")})
        elif isinstance(a.get("purl"), str) and a["purl"].startswith("pkg:"):
            out.append({"type": t, "name": a.get("name"), "version": a.get("version"), "purl": a["purl"][:500]})
    return [p for p in out if p["name"] and p["version"]][:20000]


def syft_scan(exe, image_id, timeout=900):
    """Packages in one local image. Syft reads the image through the Docker socket; nothing is pulled."""
    env = {"PATH": SAFE_PATH, "LC_ALL": "C", "HOME": "/var/tmp", "TMPDIR": "/var/tmp",
           "SYFT_CHECK_FOR_APP_UPDATE": "false", "SYFT_FILE_METADATA_SELECTION": "none",
           "GOMAXPROCS": "1"}  # one CPU core: slower, but it leaves the rest of the host alone
    p = subprocess.run([exe, "scan", f"docker:{image_id}", "-o", "syft-json", "-q"], stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False, env=env)
    if p.returncode != 0:
        return None
    doc = json.loads(p.stdout)
    d = doc.get("distro") or {}
    return {"distro": {"id": d.get("id"), "version_id": d.get("versionID")}, "packages": syft_packages(doc)}


def image_packages(containers, errors, state_dir=STATE_DIR, requested=(), auto=False, deferred=None):
    """Package lists for images in use: cached ones always, new ones only when requested from the host page
    (or every new image with "image_scan": "auto"). Requested IDs left over by the time limit go in `deferred`."""
    images = {}
    for c in containers:
        if c.get("image_id"):
            images.setdefault(c["image_id"], c["image"])
    if not images:
        return []
    path = os.path.join(state_dir, IMAGE_CACHE)
    try:
        cache = json.loads(read_text(path))
        cache = cache.get("images", {}) if cache.get("format") == IMAGE_CACHE_FORMAT else {}
    except (OSError, ValueError, AttributeError):
        cache = {}
    keep = {i: cache[i] for i in images if i in cache}  # only images still in use, so the cache never outgrows the host

    def save():  # after every scan, so work done survives the run being stopped
        try:
            with open(path + ".tmp", "w", encoding="utf-8") as f:
                json.dump({"format": IMAGE_CACHE_FORMAT, "images": keep}, f)
            os.replace(path + ".tmp", path)
        except OSError:
            pass

    todo = sorted((ref, i) for i, ref in images.items() if i not in keep and (auto or i in requested))
    exe = find_syft() if todo else None
    if todo and not exe:
        errors.append("syft: not installed, so images can't be scanned. Re-run the agent installer to add it.")
        todo = []
    stop = time.monotonic() + IMAGE_SCAN_SECONDS
    for n, (ref, image_id) in enumerate(todo, 1):
        if time.monotonic() >= stop:
            errors.append(f"syft: {len(todo) - n + 1} image(s) left for the next report")
            if deferred is not None:
                deferred.extend(i for _, i in todo[n - 1:])
            break
        print(f"Scanning image {n} of {len(todo)}: {ref}", file=sys.stderr, flush=True)
        try:
            entry = syft_scan(exe, image_id)
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            errors.append(f"syft: {ref}: {type(e).__name__}")
            continue
        if entry is None:
            errors.append(f"syft: could not read image {ref}")
            continue
        keep[image_id] = entry
        save()
    save()
    return [{"image_id": i, "image": images[i], **keep[i]} for i in sorted(keep, key=lambda i: images[i])]


BASE_PRIORITIES = {"required", "important", "standard"}
# Boot, kernel, firmware and distro plumbing that images mark as manually installed.
OS_PLUMBING = re.compile(r"^(lib|linux-|grub|shim|efibootmgr|firmware-|raspberrypi-|raspi-|rpi-|cloud-|ubuntu-|debian-"
                         r"|tasksel|os-prober|initramfs|systemd|netplan|ifupdown|dhcpcd|network-manager|openssh-|ssh$"
                         r"|sudo$|locales|tzdata|keyboard-|console-|language-pack)|-firmware$")


def apt_auto_installed(path="/var/lib/apt/extended_states"):
    try:
        text = read_text(path)
    except OSError:
        return None
    auto = set()
    for block in text.split("\n\n"):
        f = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
        if f.get("Auto-Installed") == "1" and f.get("Package"):
            auto.add(f["Package"])
    return auto


def installer_packages(path="/var/log/installer/initial-status.gz"):
    """Packages present when the OS was installed, if the installer left its list and we may read it."""
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            text = f.read(50 * 1024 * 1024)
    except OSError:
        return None
    return set(re.findall(r"^Package: (\S+)", text, re.M))


def dpkg_added(pkgs, meta):
    """apt packages someone chose to install: manual, not in the installer's list, not base priority or plumbing."""
    auto, initial = apt_auto_installed(), installer_packages()
    if auto is None:  # no apt marks, so manual can't be told from automatic
        return []
    out = []
    for p in pkgs:
        name = p["name"]
        priority, essential = meta.get(name, (None, False))
        if name in auto or essential or OS_PLUMBING.search(name):
            continue
        if initial is not None and name in initial:
            continue
        if initial is None and priority in BASE_PRIORITIES:
            continue
        out.append({"manager": "dpkg", "name": name, "version": p["version"]})
    return out


def snap_apps():
    _, text = run_fixed(["snap", "list"], 20)
    out = []
    for line in (text or "").splitlines()[1:]:
        cols = line.split()
        if len(cols) < 6 or cols[5] in ("base", "core", "snapd") or cols[0].startswith(
                ("core", "bare", "snapd", "gtk-common-themes", "gnome-", "kf5-", "mesa-")):
            continue
        out.append({"manager": "snap", "name": cols[0], "version": cols[1]})
    return out


def flatpak_apps():
    _, text = run_fixed(["flatpak", "list", "--app", "--system", "--columns=application,version"], 20)
    return [{"manager": "flatpak", "name": p[0], "version": p[1] if len(p) > 1 and p[1] else None}
            for p in (line.split("\t") for line in (text or "").splitlines()) if p and "." in p[0]]


def added_apps(pkgs, meta):
    out = dpkg_added(pkgs, meta) if pkgs and pkgs[0].get("manager") == "dpkg" else []
    return (out + snap_apps() + flatpak_apps())[:5000]


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


def collect(cfg, requested=()):
    """requested: image IDs someone asked to scan from the host page (handed over by the poll)."""
    errors, col, meta, deferred = [], cfg["collect"], {}, []
    requested = set(requested)
    report = {"schema": 1, "report_id": str(uuid.uuid4()), "agent_version": VERSION, "generated_at": now_iso(),
              "host": host_info(), "packages": [], "apps": [], "probes": [], "listening": [], "services": [],
              "containers": [], "images": [], "paths": [], "errors": errors, "image_requests_done": []}
    scan_images = bool(col.get("docker_images") and col.get("image_packages", True))
    steps = [("packages", col.get("packages"), lambda: packages(errors, meta)),
             ("apps", col.get("apps"), lambda: added_apps(report["packages"], meta)),
             ("listening", col.get("listening_ports"), listening),
             ("services", col.get("services"), services),
             ("containers", col.get("docker_images"), lambda: docker_containers(errors)),
             ("images", scan_images, lambda: image_packages(report["containers"], errors, requested=requested,
                                                           auto=col.get("image_scan") == "auto", deferred=deferred)),
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
    if requested:  # answered, even when it couldn't be done (the reason is in errors), so it is never asked again
        if not scan_images:
            errors.append("syft: image scanning is turned off in the agent config")
        report["image_requests_done"] = sorted(requested - set(deferred))
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
        "apps": [{"manager": "dpkg", "name": "nginx", "version": "1.22.1-9"}],
        "containers": [{"name": "sample-web", "image": "nginx:1.27", "image_id": "sha256:" + "5a" * 32,
                        "state": "running", "status": "Up 2 hours",
                        "ports": [{"ip": "0.0.0.0", "private": 80, "public": 8080, "type": "tcp"}],
                        "mounts": [{"type": "bind", "source": "/srv/sample-app/html", "destination": "/usr/share/nginx/html",
                                    "rw": False}]}],
        "images": [{"image_id": "sha256:" + "5a" * 32, "image": "nginx:1.27", "distro": {"id": "debian", "version_id": "12"},
                    "packages": [{"type": "deb", "name": "zlib1g", "version": "1:1.2.13.dfsg-1", "source_name": "zlib",
                                  "source_version": None},
                                 {"type": "npm", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}]}],
        "image_requests_done": [],
        "paths": [{"root": "/srv/sample-app", "truncated": False,
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
    if os.name == "posix" and st.st_mode & stat.S_IROTH:
        raise SystemExit(f"{path} is world-readable. Run: chmod 640 {path}")
    with open(path, "r", encoding="utf-8") as f:
        token = f.read().strip()
    if not token.startswith("pa_"):
        raise SystemExit(f"{path} does not contain a Patchy agent token.")
    return token


REPORT_TIMEOUT = 300  # storing a big report (container image packages) can take Patchy a while; check-ins stay short


def request(cfg, method, path, body=None, timeout=None):
    ctx = ssl.create_default_context(cafile=cfg.get("ca_file") or None)
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(_url(cfg, path), data=data, method=method, headers={
        "Authorization": f"Bearer {read_token(cfg)}", "Content-Type": "application/json",
        "User-Agent": f"patchy-agent/{VERSION}"})
    try:
        with opener.open(req, timeout=timeout or cfg.get("timeout_seconds", 30)) as r:
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
    ap.add_argument("--poll", action="store_true", help="send a report only if Rescan was pressed in Patchy")
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
    requested = []
    if a.poll:
        code, body = request(cfg, "GET", "/api/agent/poll")
        if code != 200 or not body.get("report"):  # nothing wanted, or a server too old to ask
            return 0
        requested = [i for i in body.get("scan_images") or [] if isinstance(i, str)][:100]
    lock = None if a.sample else run_lock()  # released when the process exits
    if lock is False:
        print("Another report is already being collected; it will cover this one, so this run stops.", file=sys.stderr)
        return 0
    report = sample_report() if a.sample else collect(cfg, requested)
    if a.dry_run:
        print(json.dumps(report, indent=2))
        return 0
    try:
        code, body = request(cfg, "POST", "/api/agent/report", report,
                             timeout=max(cfg.get("timeout_seconds", 30), REPORT_TIMEOUT))
    except OSError as e:  # URLError, timeouts, refused connections: one clear line instead of a traceback
        print(f"Could not send the report to Patchy: {getattr(e, 'reason', None) or e}", file=sys.stderr)
        return 1
    print(f"HTTP {code}: {body}")
    return 0 if code == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
