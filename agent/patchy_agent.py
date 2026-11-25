#!/usr/bin/env python3
"""Patchy Linux agent: read-only software inventory, sent outbound to your Patchy portal.

What it reads (each part can be switched off in the config):
  - OS details from /etc/os-release, kernel release, hostname and primary IP
  - Installed packages from the package database (/var/lib/dpkg/status, /lib/apk/db/installed, or `rpm -qa`)
  - Listening sockets from /proc/net/{tcp,tcp6,udp,udp6} (process names only where readable)
  - Running systemd service names (`systemctl list-units`)
  - Which installed packages running programs come from, from /proc/<pid>/cmdline and the shared libraries
    those programs need (read from their ELF headers, never by running them)
  - Versions from an allowlist of fixed commands (eg `nginx -v`), only those named in the config
  - Software added to the base OS: manually installed packages that aren't part of the base system
    (apt's auto-installed marks, the installer's package list or package priority), plus Snap and Flatpak apps
  - Optional: Docker containers (name, image, state, published ports, mount locations; never environment
    variables), read from the Docker socket. Needs docker group membership, which is root-equivalent.
  - Optional, with containers: the packages inside each container image, listed by Syft if it is installed
    next to this script (the installer offers a pinned, checksum-verified copy). Cached per image ID.
  - Optional: names (never contents) of files under directories you list, with depth/count limits
  - Pending apt updates, from `apt-get -s upgrade` (a simulation: no root, changes nothing), and whether
    the host is waiting for a reboot

What it never reads or sends: file contents, environment variables, keys, passwords, tokens,
shell history, or anything under excluded sensitive paths. It never runs commands from the server.

Upgrades, only if you allowed them at install time: when you press Run upgrade in Patchy, this script
writes /var/lib/patchy-agent/upgrade-request. A separate root service (patchy-agent-upgrade, written by
install.sh) notices the file and runs one fixed command, `apt-get update && apt-get upgrade`. It reads
only the file's timestamp, never its contents, and keeps its log in its own root-owned directory.

Usage:
  patchy_agent.py --dry-run            collect and print the report, send nothing
  patchy_agent.py --sample             print a synthetic SAMPLE report (reads nothing from this host)
  patchy_agent.py --sample --send      send the SAMPLE report (to test enrolment end to end)
  patchy_agent.py --check              verify the server URL and credential
  patchy_agent.py                      collect and send (what the systemd timer runs)
  patchy_agent.py --poll               send a report only if Rescan was pressed in Patchy, and pass on a Run
                                       upgrade (polled every minute with upgrades allowed, else every 5 min)
  patchy_agent.py --menu               interactive menu, as root (installed as: sudo patchy-agent)
Python 3.8+, standard library only.
"""
from __future__ import annotations

import argparse
import getpass
import glob
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
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

VERSION = "1.7.0"
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
    "collect": {"packages": True, "apps": True, "listening_ports": True, "services": True, "in_use": True,
                "updates": True, "docker_images": False,
                "image_packages": True, "image_scan": "manual", "version_probes": DEFAULT_PROBES},
    "app_dirs": [],
}


# ---------------------------------------------------------------- helpers

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_fixed(argv, timeout=10, limit=MAX_OUTPUT, ok_only=False):
    """Run an allowlisted command: argument list, no shell, clean env, no stdin, bounded output.
    With ok_only, a non-zero exit counts as a failure (output None) rather than as output to parse."""
    exe = shutil.which(argv[0], path=SAFE_PATH)
    if not exe:
        return None, None
    try:
        p = subprocess.run([exe] + argv[1:], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout, check=False,
                           env={"PATH": SAFE_PATH, "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError):
        return exe, None
    if ok_only and p.returncode != 0:
        return exe, None
    return exe, p.stdout[:limit].decode("utf-8", "replace")


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


# ---------------------------------------------------------------- packages in use

CONTAINER_CGROUPS = ("docker", "containerd", "kubepods", "libpod", "podman", "lxc")
LIB_DIRS = ("/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib")
MAX_IN_USE_FILES = 20000


def running_programs():
    """Absolute paths of programs running on the host itself (container processes are skipped).

    Reads only what any user can: /proc/<pid>/cmdline, comm and cgroup. Returns None when other users'
    processes are hidden (mounted with hidepid), since then "not running" would only mean "couldn't see".
    """
    try:
        with open("/proc/1/cmdline", "rb") as f:
            if not f.read(4096):
                return None
    except OSError:
        return None
    files = set()
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            if any(k in read_text(f"/proc/{pid}/cgroup", 8192) for k in CONTAINER_CGROUPS):
                continue
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = [a.decode("utf-8", "replace") for a in f.read(8192).split(b"\0") if a]
            comm = read_text(f"/proc/{pid}/comm", 256).strip()
        except OSError:
            continue
        if not argv:  # kernel thread
            continue
        cands = [w for w in argv[0].split() if w.startswith("/")]  # also catches titles like "sshd: /usr/sbin/sshd -D"
        cands += [a for a in argv[1:2] if a.startswith("/")]  # an interpreter's script
        cands += [shutil.which(n, path=SAFE_PATH) or "" for n in (*argv[0].split()[:1], comm) if n and "/" not in n]
        try:
            cands.append(os.readlink(f"/proc/{pid}/exe"))  # only for this user's own processes
        except OSError:
            pass
        files.update(os.path.realpath(c) for c in cands if c.startswith("/") and os.path.isfile(c))
    return files


def elf_needed(path):
    """Shared libraries an ELF file asks for (DT_NEEDED), read from its headers. Never runs the file, unlike ldd."""
    try:
        with open(path, "rb") as f:
            h = f.read(64)
            if len(h) < 52 or h[:4] != b"\x7fELF":
                return []
            is64, end = h[4] == 2, "<" if h[5] == 1 else ">"
            shoff = struct.unpack_from(end + ("Q" if is64 else "I"), h, 0x28 if is64 else 0x20)[0]
            shentsize, shnum = struct.unpack_from(end + "HH", h, 0x3A if is64 else 0x2E)
            if not shoff or not 0 < shnum <= 4096:
                return []
            f.seek(shoff)
            table = f.read(shentsize * shnum)
            fmt = end + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")  # name type flags addr offset size link ...
            secs = [struct.unpack_from(fmt, table, i * shentsize) for i in range(shnum)]
            for s in secs:
                if s[1] != 6:  # SHT_DYNAMIC
                    continue
                strtab = secs[s[6]]
                f.seek(strtab[4])
                strings = f.read(min(strtab[5], 1 << 20))
                f.seek(s[4])
                dyn = f.read(min(s[5], 1 << 20))
                size, entry = (16, end + "qQ") if is64 else (8, end + "iI")
                out = []
                for i in range(0, len(dyn) - size + 1, size):
                    tag, val = struct.unpack_from(entry, dyn, i)
                    if tag == 0:
                        break
                    if tag == 1:  # DT_NEEDED
                        out.append(strings[val:strings.index(b"\0", val)].decode("utf-8", "replace"))
                return out
    except (OSError, struct.error, ValueError, IndexError):
        pass
    return []


def soname_index():
    """soname -> paths in the usual library directories, without running ldconfig."""
    dirs = list(LIB_DIRS) + glob.glob("/lib/*-linux-*") + glob.glob("/usr/lib/*-linux-*")
    for conf in glob.glob("/etc/ld.so.conf.d/*.conf"):
        try:
            dirs += [line.strip() for line in read_text(conf, 65536).splitlines() if line.strip().startswith("/")]
        except OSError:
            pass
    index = {}
    for d in dict.fromkeys(dirs):
        try:
            for name in os.listdir(d):
                if ".so" in name:
                    index.setdefault(name, []).append(os.path.join(d, name))
        except OSError:
            continue
    return index


def _usr_variants(paths):
    """dpkg and apk may list /lib/x when it really lives at /usr/lib/x (merged /usr), and the other way round."""
    out = set()
    for p in paths:
        out.add(p)
        out.add(p[4:] if p.startswith("/usr/") else "/usr" + p)
    return out


def package_owners(files):
    """Names of the installed packages that own any of these files."""
    want, owners = _usr_variants(files), set()
    if os.path.isdir("/var/lib/dpkg/info"):
        for lst in glob.glob("/var/lib/dpkg/info/*.list"):
            try:
                if any(line in want for line in read_text(lst).splitlines()):
                    owners.add(os.path.basename(lst)[:-5].split(":")[0])
            except OSError:
                continue
    elif os.path.exists("/lib/apk/db/installed"):
        for block in read_text("/lib/apk/db/installed").split("\n\n"):
            name, folder = None, ""
            for line in block.splitlines():
                if line.startswith("P:"):
                    name = line[2:]
                elif line.startswith("F:"):
                    folder = line[2:]
                elif line.startswith("R:") and name and f"/{folder}/{line[2:]}" in want:
                    owners.add(name)
                    break
    elif shutil.which("rpm", path=SAFE_PATH):
        real = sorted(f for f in files if os.path.exists(f))
        for i in range(0, len(real), 200):
            _, text = run_fixed(["rpm", "-qf", "--qf", "%{NAME}\\n", *real[i:i + 200]], 60)
            owners.update(line.strip() for line in (text or "").splitlines() if line.strip() and " " not in line.strip())
    return owners


def in_use_packages():
    """Packages that running programs come from, plus the shared libraries they load at start.

    Misses what's loaded later (plugins, Python or Perl modules) and tools that run now and then, so Patchy
    only ranks the rest lower; it never hides them. None when processes can't be seen.
    """
    progs = running_programs()
    if progs is None:
        return None
    index, todo, done = soname_index(), list(progs), set()
    while todo and len(done) < MAX_IN_USE_FILES:
        path = todo.pop()
        if path in done:
            continue
        done.add(path)
        for so in elf_needed(path):
            for lib in index.get(so, ()):
                todo += [lib, os.path.realpath(lib)]
    return sorted(package_owners(done))


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


# ---------------------------------------------------------------- apt updates and upgrades

UPGRADES_FILE = "/etc/patchy-agent/upgrades"  # "yes" when the installer was told to allow upgrades from Patchy
UPGRADE_DIR = "/var/lib/patchy-agent-upgrade"  # the root upgrade service's own directory; read-only to us
UPGRADE_REQUEST = "upgrade-request"  # in STATE_DIR; the root service only looks at its timestamp
UPGRADE_PENDING = "upgrade-pending.json"  # in STATE_DIR: which of Patchy's requests was handed over, and when
APT_INST = re.compile(r"^Inst (\S+) (?:\[([^\]]*)\] )?\((\S+) ([^\[]*)")
APT_HELD = ("The following packages have been kept back", "The following upgrades have been deferred")


def upgrades_allowed(path=UPGRADES_FILE):
    try:
        return read_text(path, 16).strip() == "yes"
    except OSError:
        return False


def _apt_lists_at():
    """Roughly when the package lists were last refreshed (by apt's daily timer, or an upgrade)."""
    times = [os.path.getmtime(p) for p in ("/var/lib/apt/periodic/update-success-stamp", "/var/cache/apt/pkgcache.bin",
                                           "/var/lib/apt/lists") if os.path.exists(p)]
    return datetime.fromtimestamp(max(times), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if times else None


def parse_apt_simulation(text):
    """(packages, held back) from `apt-get -s upgrade` output, in the C locale."""
    pkgs, held, in_held = [], [], False
    for line in text.splitlines():
        mt = APT_INST.match(line)
        if mt:
            pkgs.append({"name": mt.group(1), "installed": mt.group(2) or None, "available": mt.group(3),
                         "security": "security" in mt.group(4).lower()})
        elif line.startswith(APT_HELD):
            in_held = True
        elif in_held and line.startswith(" "):
            held += line.split()
        else:
            in_held = False
    return pkgs, held


def apt_updates():
    """Pending updates as `apt-get upgrade` would install them, from a simulation: no root, no changes."""
    exe, text = run_fixed(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=120, limit=4 * 1024 * 1024,
                          ok_only=True)
    if not exe:
        return None  # not an apt system
    if text is None:  # e.g. unmet dependencies: never report that as "nothing to install"
        raise RuntimeError("apt-get simulation failed")
    pkgs, held = parse_apt_simulation(text)
    try:
        reboot_pkgs = sorted(set(read_text("/run/reboot-required.pkgs", 64 * 1024).split()))[:200]
    except OSError:
        reboot_pkgs = []
    return {"manager": "apt", "packages": pkgs[:5000], "held_back": held[:1000], "lists_at": _apt_lists_at(),
            "reboot_required": os.path.exists("/run/reboot-required"), "reboot_packages": reboot_pkgs,
            "can_upgrade": upgrades_allowed()}


def start_upgrade(run_id, state_dir=STATE_DIR):
    """Hand Patchy's Run upgrade to the root service, which watches the request file. False if this host
    doesn't allow upgrades (the report that follows tells Patchy so)."""
    if not upgrades_allowed():
        return False
    pending = os.path.join(state_dir, UPGRADE_PENDING)
    with open(pending + ".tmp", "w", encoding="utf-8") as f:
        json.dump({"id": int(run_id), "requested_at": now_iso()}, f)
    os.replace(pending + ".tmp", pending)
    with open(os.path.join(state_dir, UPGRADE_REQUEST), "w", encoding="utf-8") as f:
        f.write(f"{int(run_id)}\n")  # closing it after writing is what wakes the root service
    return True


def upgrade_result(state_dir=STATE_DIR, out_dir=UPGRADE_DIR):
    """The finished upgrade that was handed over and not yet reported, else None (none, or still running)."""
    try:
        pending = json.loads(read_text(os.path.join(state_dir, UPGRADE_PENDING), 4096))
        result = json.loads(read_text(os.path.join(out_dir, "result.json"), 4096))
        run_id = int(pending["id"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if str(result.get("started_at") or "") < str(pending.get("requested_at") or ""):
        return None  # an earlier run's result: this one hasn't finished yet
    try:
        with open(os.path.join(out_dir, "upgrade.log"), "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 60000))
            output = f.read().decode("utf-8", "replace")
    except OSError:
        output = ""
    code = result.get("exit_code")
    return {"id": run_id, "exit_code": code if isinstance(code, int) else None, "started_at": result.get("started_at"),
            "finished_at": result.get("finished_at"), "output": output}


def upgrade_reported(state_dir=STATE_DIR):
    try:
        os.remove(os.path.join(state_dir, UPGRADE_PENDING))
    except OSError:
        pass


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
              "containers": [], "images": [], "paths": [], "errors": errors, "image_requests_done": [],
              "in_use": None, "updates": None, "upgrade_result": upgrade_result()}
    scan_images = bool(col.get("docker_images") and col.get("image_packages", True))
    steps = [("packages", col.get("packages"), lambda: packages(errors, meta)),
             ("apps", col.get("apps"), lambda: added_apps(report["packages"], meta)),
             ("listening", col.get("listening_ports"), listening),
             ("services", col.get("services"), services),
             ("in_use", col.get("in_use", True) and col.get("packages"), in_use_packages),
             ("containers", col.get("docker_images"), lambda: docker_containers(errors)),
             ("images", scan_images, lambda: image_packages(report["containers"], errors, requested=requested,
                                                           auto=col.get("image_scan") == "auto", deferred=deferred)),
             ("probes", bool(col.get("version_probes")), lambda: probes(col.get("version_probes") or [], errors)),
             ("updates", col.get("updates", True), apt_updates)]
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
        "in_use": ["libssl3", "nginx"],
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
        "updates": {"manager": "apt", "packages": [{"name": "libssl3", "installed": "3.0.11-1~deb12u1",
                                                    "available": "3.0.15-1~deb12u1", "security": True}],
                    "held_back": [], "lists_at": now_iso(), "reboot_required": False, "reboot_packages": [],
                    "can_upgrade": False},
        "upgrade_result": None,
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


def request(cfg, method, path, body=None, timeout=None, token=None):
    ctx = ssl.create_default_context(cafile=cfg.get("ca_file") or None)
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(_url(cfg, path), data=data, method=method, headers={
        "Authorization": f"Bearer {token or read_token(cfg)}", "Content-Type": "application/json",
        "User-Agent": f"patchy-agent/{VERSION}"})
    try:
        with opener.open(req, timeout=timeout or cfg.get("timeout_seconds", 30)) as r:
            return r.status, json.loads(r.read(1024 * 1024) or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {"detail": e.read(2048).decode("utf-8", "replace")}


# ---------------------------------------------------------------- menu (sudo patchy-agent)

ETC_DIR = "/etc/patchy-agent"
LIB_DIR = "/usr/local/lib/patchy-agent"
AGENT_USER = "patchy-agent"
SELF = os.path.abspath(__file__)
SUMMARY_FILE = "last-report.json"  # in STATE_DIR: written by the agent after each send, shown by Status
AGENT_FILES = ("patchy_agent.py", "install.sh", "uninstall.sh", "config.example.json")
_LETTERS = [  # PATCHY in figlet's "small" font, one letter per entry
    (" ___ ", "| _ \\", "|  _/", "|_|  "),
    ("   _   ", "  /_\\  ", " / _ \\ ", "/_/ \\_\\"),
    (" _____ ", "|_   _|", "  | |  ", "  |_|  "),
    ("  ___ ", " / __|", "| (__ ", " \\___|"),
    (" _  _ ", "| || |", "| __ |", "|_||_|"),
    ("__   __", "\\ \\ / /", " \\ V / ", "  |_|  "),
]
LOGO = ["".join(row) for row in zip(*_LETTERS)]
KEYS_UP, KEYS_DOWN = (259, ord("k")), (258, ord("j"))  # curses.KEY_UP / KEY_DOWN, or vi keys
KEYS_PICK, KEYS_BACK = (10, 13, 343, 261), (27, ord("q"), 260)  # Enter / KEY_ENTER / KEY_RIGHT; Esc, q, KEY_LEFT
COLLECT_ITEMS = [
    ("packages", "Installed packages"), ("apps", "Software added to the base OS"), ("listening_ports", "Listening ports"),
    ("services", "Running services"), ("in_use", "Which packages running programs use"), ("updates", "Pending apt updates"),
    ("version_probes", "Versions of common servers and runtimes"), ("docker_images", "Docker containers (root-equivalent)"),
    ("image_packages", "Packages inside container images (Syft)"), ("image_scan", "Scan new container images automatically"),
]


def report_summary(report, code, error=None):
    """What Status shows about the last report: counts only, nothing from the report's contents."""
    upd = report.get("updates") or {}
    pkgs = upd.get("packages") or []
    return {"sent_at": now_iso(), "http": code, "error": error, "packages": len(report.get("packages") or []),
            "listening": len(report.get("listening") or []), "containers": len(report.get("containers") or []),
            "updates": len(pkgs) if report.get("updates") else None, "security": sum(1 for p in pkgs if p.get("security")),
            "reboot_required": bool(upd.get("reboot_required")), "errors": (report.get("errors") or [])[:20]}


def save_summary(summary, state_dir=STATE_DIR):
    path = os.path.join(state_dir, SUMMARY_FILE)
    try:
        with open(path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(summary, f)
        os.replace(path + ".tmp", path)
    except OSError:
        pass  # run by hand without the state directory: Status just has less to say


def _clean(s, limit=300):
    """Text from files the agent account can write, safe to print as root: no terminal escape sequences."""
    return "".join(c if c.isprintable() else "?" for c in str(s if s is not None else ""))[:limit]


def _read_json_nofollow(path, limit=64 * 1024):
    """Read a small JSON object that the unprivileged agent account may have written: never through a
    symlink, never a FIFO or device, bounded. None if it isn't a plain file holding a JSON object."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = json.loads(os.read(fd, limit) or b"null")
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None
    finally:
        os.close(fd)


def _write_private(path, text, mode=0o640):
    """Atomic write, owned root:patchy-agent as the installer leaves the config and token."""
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        import grp
        try:
            os.chown(tmp, 0, grp.getgrnam(AGENT_USER).gr_gid)
        except KeyError:
            pass
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def read_raw_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_raw_config(path, raw):
    _write_private(path, json.dumps(raw, indent=2) + "\n")


def collect_on(col, key):
    return col.get(key) == "auto" if key == "image_scan" else bool(col.get(key))


def set_collect(raw, key, on):
    col = raw.setdefault("collect", {})
    if key == "image_scan":
        col[key] = "auto" if on else "manual"
    elif key == "version_probes":
        col[key] = list(DEFAULT_PROBES) if on else []
    else:
        col[key] = on


def version_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:3])


def _ago(iso):
    try:
        t = datetime.strptime(str(iso), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return "at an unknown time"
    s = int((datetime.now(timezone.utc) - t).total_seconds())
    return ("just now" if s < 60 else f"{s // 60} min ago" if s < 3600 else f"{s // 3600} h ago" if s < 172800
            else f"{s // 86400} days ago")


def _menu_key(key, i, n):
    """('move', index) | ('pick', index) | ('back', None) for one key press in a list of n items."""
    if key in KEYS_UP:
        return "move", (i - 1) % n
    if key in KEYS_DOWN:
        return "move", (i + 1) % n
    if key in KEYS_PICK:
        return "pick", i
    if key in KEYS_BACK:
        return "back", None
    if ord("1") <= key <= ord("9") and key - ord("1") < n:
        return "pick", key - ord("1")
    return "move", i


def _screen(title, items, i, note=""):
    """One menu screen as (text, style) lines; style is logo, title, dim, selected or ''."""
    lines = [(row, "logo") for row in LOGO] + [("", ""), (title, "title")]
    lines += [(row, "dim") for row in note.split("\n") if row] + [("", "")]
    lines += [((" > " if n == i else "   ") + f"{n + 1}. {item}", "selected" if n == i else "") for n, item in enumerate(items)]
    return lines + [("", ""), ("Up/Down to move, Enter to choose, q or Esc to go back", "dim")]


def _pick(title, items, note=""):
    """Arrow-key list under the logo: the chosen index, or None for Esc/q or the last item (Back/Quit)."""
    import curses

    def run(scr):
        try:
            curses.curs_set(0)
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            accent = curses.color_pair(1) | curses.A_BOLD
        except curses.error:
            accent = curses.A_BOLD
        style = {"logo": accent, "title": curses.A_BOLD, "dim": curses.A_DIM, "selected": curses.A_REVERSE, "": 0}
        i = 0
        while True:
            scr.erase()
            h, w = scr.getmaxyx()
            for y, (text, s) in enumerate(_screen(title, items, i, note)[:h]):
                try:
                    scr.addnstr(y, 1, text, max(w - 2, 1), style[s])
                except curses.error:  # the bottom-right cell can't be written to
                    pass
            scr.refresh()
            action, i = _menu_key(scr.getch(), i, len(items))
            if action == "back" or action == "pick" and i == len(items) - 1:
                return None
            if action == "pick":
                return i

    os.environ.setdefault("ESCDELAY", "50")  # Esc goes back at once instead of after curses' 1 s wait
    return curses.wrapper(run)


def _ask(prompt):
    return input(prompt)


def _yes(prompt):
    return _ask(prompt + " [y/N] ").strip().lower().startswith("y")


def _pause():
    _ask("\nPress Enter to go back ")


def _run(argv, capture=False, **kw):
    """A system command run by the menu (as root): an argument list, never a shell. With capture, stdout is
    returned and stderr still reaches the screen."""
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE if capture else None, text=True, errors="replace", check=False, **kw)
    except OSError as e:
        return 127, str(e)
    return p.returncode, p.stdout or ""


def _prop(unit, prop):
    code, out = _run(["systemctl", "show", unit, f"--property={prop}", "--value"], capture=True)
    out = out.strip()
    return out if code == 0 and out and out != "n/a" else ""


def _rerun_installer():
    script = os.path.join(LIB_DIR, "install.sh")
    if not os.path.isfile(script):
        print("The installer isn't kept on this host yet. Choose Update the agent first.")
        return 1
    print("Re-running the installer (it keeps the config and token)...\n")
    return _run(["sh", script], cwd=LIB_DIR)[0]


def summary_lines(s):
    """Status lines for the last report summary, or a note that there isn't one."""
    if not s:
        return ["Last report   none recorded yet"]
    num = lambda k: s.get(k) if isinstance(s.get(k), int) else 0  # noqa: E731
    http = s.get("http")
    result = "accepted" if http == 200 else f"not accepted (HTTP {num('http')})" if http else "not sent"
    why = f": {_clean(s.get('error'), 200)}" if s.get("error") else ""
    out = [f"Last report   {_ago(s.get('sent_at'))}, {result}{why}"]
    counts = f"{num('packages')} packages, {num('listening')} listening ports, {num('containers')} containers"
    if isinstance(s.get("updates"), int):
        counts += f", {num('updates')} pending updates ({num('security')} security)"
    out.append(f"              {counts}")
    if s.get("reboot_required"):
        out.append("              A reboot is waiting.")
    errors = [_clean(e, 120) for e in s.get("errors") or [] if isinstance(e, str)][:5]
    if errors:
        out.append("              Problems: " + "; ".join(errors))
    return out


def upgrade_state():
    if not shutil.which("apt-get", path=SAFE_PATH):
        return "not available (no apt here)"
    return "allowed" if upgrades_allowed() else "not allowed"


def upgrade_lines(state_dir=STATE_DIR, out_dir=UPGRADE_DIR):
    out = []
    pending = _read_json_nofollow(os.path.join(state_dir, UPGRADE_PENDING))
    if pending:
        out.append(f"Waiting       an upgrade Patchy asked for {_ago(pending.get('requested_at'))}")
    last = _read_json_nofollow(os.path.join(out_dir, "result.json"))
    if last:
        code = last.get("exit_code")
        out.append(f"Last upgrade  {'succeeded' if code == 0 else f'failed (exit code {_clean(code, 10)})'}, "
                   f"finished {_ago(last.get('finished_at'))}")
    return out


def status_lines(cfg, state_dir=STATE_DIR):
    col = cfg["collect"]
    syft = os.path.join(LIB_DIR, "syft.version")
    syft = f", Syft {_clean(read_text(syft, 32).strip(), 20)}" if os.path.isfile(syft) else ", no Syft"
    return [f"Agent         {VERSION} on {socket.gethostname()}", f"Server        {cfg.get('server_url') or 'not set'}",
            *summary_lines(_read_json_nofollow(os.path.join(state_dir, SUMMARY_FILE))),
            f"Next report   {_prop('patchy-agent.timer', 'NextElapseUSecRealtime') or 'not scheduled'}",
            f"Next check-in {_prop('patchy-agent-poll.timer', 'NextElapseUSecRealtime') or 'not scheduled'}",
            f"Containers    {'on' + syft if col.get('docker_images') else 'off'}",
            f"Run upgrade   {upgrade_state()}", *upgrade_lines(state_dir)]


def ping(cfg, token=None):
    """(ok, message in plain words, body) for a connection test."""
    try:
        code, body = request(cfg, "GET", "/api/agent/ping", token=token, timeout=15)
    except SystemExit as e:  # a config or token file problem, already in words
        return False, str(e), {}
    except ValueError:  # not JSON: a proxy's error page, or not Patchy at all
        return False, "Something answered at that address, but it isn't Patchy. Check the server address.", {}
    except OSError as e:
        reason = getattr(e, "reason", None) or e
        text = str(reason)
        if isinstance(reason, socket.gaierror) or "name resolution" in text or "not known" in text:
            hint = " This host can't look up the server's name: check its DNS, or add the name to /etc/hosts."
        elif isinstance(reason, ssl.SSLError) or "CERTIFICATE" in text.upper():
            hint = " The server's certificate isn't trusted here. For a self-signed certificate, set a CA file."
        elif isinstance(reason, ConnectionRefusedError) or "refused" in text:
            hint = " Nothing is listening at that address and port."
        else:
            hint = ""
        return False, f"Couldn't reach Patchy: {_clean(text, 200)}.{hint}", {}
    if code == 200:
        return True, f"Connected. Patchy knows this host as {_clean(body.get('host'), 100)}.", body
    if code == 401:
        return False, "Patchy rejected the token. It may have been rotated or revoked; replace it here.", body
    return False, f"Patchy answered HTTP {code}.", body


def token_hint(cfg):
    try:
        return "ends …" + read_token(cfg)[-4:]
    except (OSError, SystemExit):
        return "missing or unreadable"


def download_agent(cfg, dest):
    """Fetch this Patchy's bundled agent files into dest (the same files the host page's update command gets)."""
    ctx = ssl.create_default_context(cafile=cfg.get("ca_file") or None)
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    for name in AGENT_FILES:
        with opener.open(_url(cfg, f"/api/agent/files/{name}"), timeout=60) as r:
            data = r.read(5 * 1024 * 1024)
        with open(os.path.join(dest, name), "wb") as f:
            f.write(data)
    found = re.search(rb'^VERSION = "([^"]+)"', open(os.path.join(dest, "patchy_agent.py"), "rb").read(), re.M)
    if not found:
        raise ValueError("the downloaded file isn't the Patchy agent")
    return found.group(1).decode()


def _menu_status(cfg_path):
    print("\n".join(status_lines(load_config(cfg_path))))
    _pause()


def _menu_send(cfg_path):
    while True:
        i = _pick("Send a report now", ["Send a report now", "Preview what would be sent (sends nothing)", "Back"],
                  "The report is collected by the patchy-agent service account, never as root.")
        if i is None:
            return
        if i == 0:
            print("Collecting and sending. With container image scanning this can take a few minutes...")
            code, _ = _run(["systemctl", "start", "patchy-agent.service"])
            print("Done." if code == 0 else "The report didn't go through. Logs has the details.")
            print("\n".join(summary_lines(_read_json_nofollow(os.path.join(STATE_DIR, SUMMARY_FILE)))))
        else:
            print("Collecting as the patchy-agent account...")
            code, out = _run(["runuser", "-u", AGENT_USER, "--", sys.executable, SELF, "--config", cfg_path, "--dry-run"],
                             capture=True)
            try:
                report = json.loads(out)
            except ValueError:
                print(f"Collecting failed:\n{_clean(out[-2000:], 2000)}")
            else:
                print("\n".join(summary_lines(report_summary(report, None))[1:]))
                if _yes("Show the whole report?") and _run(["less"], input=out)[0] == 127:
                    print(out)
        _pause()


def _docker_access(on):
    """Join or leave the docker group for the containers switch. False if nothing changed."""
    if on:
        if not os.path.exists(DOCKER_SOCKET):
            print(f"Docker isn't running on this host (no {DOCKER_SOCKET}).")
            return False
        print(f"Reading the Docker socket needs the docker group, which is root-equivalent: anyone who controls "
              f"the {AGENT_USER} account could then control this host.")
        if not _yes(f"Add {AGENT_USER} to the docker group?"):
            return False
        if _run(["usermod", "-aG", "docker", AGENT_USER])[0]:
            print("That didn't work; see the message above.")
            return False
        print("Containers are on from the next report. To scan the packages inside them, switch on "
              "'Packages inside container images' too.")
    else:
        _run(["gpasswd", "-d", AGENT_USER, "docker"], stderr=subprocess.DEVNULL)  # not in the group is fine too
        print(f"Containers are off and {AGENT_USER} has left the docker group.")
    return True


def _menu_collect(cfg_path):
    while True:
        col = load_config(cfg_path)["collect"]
        items = [f"[{'x' if collect_on(col, k) else ' '}] {label}" for k, label in COLLECT_ITEMS]
        i = _pick("What it collects", items + ["App directories", "Back"],
                  "Enter switches an item on or off. Changes apply from the next report.")
        if i is None:
            return
        if i == len(COLLECT_ITEMS):
            _menu_app_dirs(cfg_path)
            continue
        key, on = COLLECT_ITEMS[i][0], not collect_on(col, COLLECT_ITEMS[i][0])
        if key == "docker_images" and not _docker_access(on):
            _pause()
            continue
        raw = read_raw_config(cfg_path)
        set_collect(raw, key, on)
        save_raw_config(cfg_path, raw)
        if key == "image_packages" and on and not os.path.exists(os.path.join(LIB_DIR, "syft")):
            if not col.get("docker_images"):
                print("This needs Docker containers switched on as well.")
            elif _yes("Scanning images needs Syft. Re-run the installer, which asks before downloading it?"):
                try:
                    os.remove(os.path.join(LIB_DIR, "syft.declined"))
                except OSError:
                    pass
                _rerun_installer()
            _pause()
        elif key == "docker_images":
            _pause()


def _ask_int(label, default, lo, hi):
    answer = _ask(f"{label} [{default}]: ").strip()
    try:
        n = int(answer) if answer else default
    except ValueError:
        n = default
    return max(lo, min(hi, n))


def _menu_app_dirs(cfg_path):
    while True:
        raw = read_raw_config(cfg_path)
        dirs = [d for d in raw.get("app_dirs") or [] if isinstance(d, dict)]
        listed = "\n".join(f"  {_clean(d.get('path'), 200)}" for d in dirs) or "  None yet."
        i = _pick("App directories", ["Add a directory", "Remove a directory", "Back"],
                  f"File and folder names (never contents) under these are reported.\n{listed}")
        if i is None:
            return
        if i == 0:
            path = _ask("Directory, like /opt/myapp: ").strip()
            problem = check_root(path) or (None if os.path.isdir(path) else "doesn't exist")
            if not path:
                continue
            if problem:
                print(f"{path} {problem}; nothing changed.")
            elif any(d.get("path") == path for d in dirs):
                print(f"{path} is already listed.")
            else:
                entry = {"path": path, "max_depth": _ask_int("Folder depth to list", 3, 1, HARD_MAX_DEPTH),
                         "max_files": _ask_int("Most names to list", 1000, 1, HARD_MAX_FILES)}
                raw["app_dirs"] = dirs + [entry]
                save_raw_config(cfg_path, raw)
                print(f"Added {path}. It's listed from the next report.")
                if path.startswith("/home/"):
                    print("The service can't see /home by default. Allow it with: sudo systemctl edit patchy-agent, "
                          "then add [Service] and ProtectHome=read-only.")
        else:
            if not dirs:
                print("There's nothing to remove.")
            else:
                j = _pick("Remove which directory?", [_clean(d.get("path"), 200) for d in dirs] + ["Back"])
                if j is None:
                    continue
                raw["app_dirs"] = dirs[:j] + dirs[j + 1:]
                save_raw_config(cfg_path, raw)
                print(f"Removed {_clean(dirs[j].get('path'), 200)}.")
        _pause()


def _menu_upgrade():
    if not shutil.which("apt-get", path=SAFE_PATH):
        print("Run upgrade needs apt (Debian, Ubuntu or Raspberry Pi OS).")
        _pause()
        return
    while True:
        allowed = upgrades_allowed()
        note = "\n".join([f"Run upgrade is {'allowed' if allowed else 'not allowed'} on this host.", *upgrade_lines()])
        i = _pick("Run upgrade", ["Stop allowing Run upgrade" if allowed else "Allow Run upgrade",
                                  "Show the last upgrade's output", "Back"], note)
        if i is None:
            return
        if i == 0:
            if allowed:
                ok = _yes("Stop Patchy's Run upgrade working here? This removes the root upgrade service.")
            else:
                print("A root service will run one fixed command, apt-get update && apt-get upgrade, when someone "
                      "presses Run upgrade in Patchy. Nothing else can be run through it, and it never reboots.")
                ok = _yes("Allow Run upgrade?")
            if ok:
                _write_private(UPGRADES_FILE, ("no" if allowed else "yes") + "\n", mode=0o644)
                _rerun_installer()
        else:
            try:
                lines = read_text(os.path.join(UPGRADE_DIR, "upgrade.log"), 256 * 1024).splitlines()[-100:]
                print("\n".join(_clean(line, 500) for line in lines) or "The log is empty.")
            except OSError:
                print("No upgrade has run on this host yet.")
        _pause()


def _menu_server(cfg_path):
    while True:
        cfg = load_config(cfg_path)
        note = f"Server: {cfg.get('server_url') or 'not set'}\nToken: {token_hint(cfg)}"
        note += f"\nCA file: {cfg['ca_file']}" if cfg.get("ca_file") else ""
        i = _pick("Server and token", ["Test the connection", "Replace the token", "Change the server address",
                                       "Set a CA file (self-signed certificates)", "Back"], note)
        if i is None:
            return
        if i == 0:
            print(ping(cfg)[1])
        elif i == 1:
            token = getpass.getpass("Paste the new token from the host page in Patchy (input hidden): ").strip()
            ok, msg, _ = ping(cfg, token=token) if token.startswith("pa_") else (False, "That isn't a Patchy agent token (pa_...).", {})
            if ok:
                _write_private(cfg["token_file"], token + "\n")
                print("Patchy accepted the token, and it's saved.")
            else:
                print(f"{msg} Nothing changed.")
        elif i in (2, 3):
            raw = read_raw_config(cfg_path)
            if i == 2:
                url = _ask(f"Patchy address [{cfg.get('server_url')}]: ").strip().rstrip("/")
                change = {"server_url": url} if url else {}
                if url.startswith("http://") and not cfg.get("allow_insecure_http"):
                    if _yes(f"{url} is plain HTTP, so the token is sent unencrypted. Allow it on this trusted LAN?"):
                        change["allow_insecure_http"] = True
                    else:
                        change = {}
            else:
                path = _ask("CA certificate file (PEM), or - to stop using one: ").strip()
                change = {"ca_file": None} if path == "-" else {"ca_file": path} if os.path.isfile(path) else {}
                if path and path != "-" and not change:
                    print(f"{path} isn't a file.")
            if change:
                ok, msg, _ = ping({**cfg, **change})
                if ok:
                    save_raw_config(cfg_path, {**raw, **change})
                    print(f"{msg} Saved.")
                else:
                    print(f"{msg} Nothing changed.")
        _pause()


def _menu_logs():
    units = [("Reports", "patchy-agent"), ("Check-ins", "patchy-agent-poll"), ("Upgrades", "patchy-agent-upgrade")]
    while True:
        i = _pick("Logs", [f"{label}: last 50 lines" for label, _ in units] + ["Follow reports and check-ins live", "Back"])
        if i is None:
            return
        if i < len(units):
            _run(["journalctl", "-u", units[i][1], "-n", "50", "--no-pager"])
        else:
            print("Press Ctrl+C to stop.")
            try:
                _run(["journalctl", "-u", "patchy-agent", "-u", "patchy-agent-poll", "-n", "20", "-f"])
            except KeyboardInterrupt:
                pass
        _pause()


def _menu_update(cfg_path):
    cfg = load_config(cfg_path)
    ok, msg, body = ping(cfg)
    latest = body.get("agent_version")
    if not ok:
        print(msg)
    elif not isinstance(latest, str):
        print("This Patchy doesn't say which agent it has (it's older than 1.24). Use the update command on the host page.")
    elif version_tuple(latest) <= version_tuple(VERSION):
        print(f"Up to date: {VERSION} is the newest agent this Patchy has.")
    elif _yes(f"Update from {VERSION} to {_clean(latest, 20)}? It downloads the agent from {cfg['server_url']} "
              f"and re-runs the installer; the config and token stay."):
        import tempfile
        dest = tempfile.mkdtemp(prefix="patchy-agent-")
        try:
            got = download_agent(cfg, dest)
            code = _run(["sh", os.path.join(dest, "install.sh")], cwd=dest)[0]
        except (OSError, ValueError) as e:
            print(f"The download failed, so nothing changed: {_clean(getattr(e, 'reason', None) or e, 200)}")
            code, got = 1, None
        finally:
            shutil.rmtree(dest, ignore_errors=True)
        if code == 0 and got:
            print(f"Updated to {got}. Reopening the menu.")
            _pause()
            os.execv(sys.executable, [sys.executable, os.path.join(LIB_DIR, "patchy_agent.py"), "--config", cfg_path, "--menu"])
        elif got:
            print("The installer reported a problem; see above.")
    _pause()


def _menu_remove():
    host = socket.gethostname()
    print("This stops the agent and removes it, its config, token and services from this host. "
          "Patchy keeps the host and its history.")
    if _ask(f"Type the host name ({host}) to remove the agent: ").strip() != host:
        print("Not removed.")
        _pause()
        return False
    script = os.path.join(LIB_DIR, "uninstall.sh")
    code = _run(["sh", script])[0] if os.path.isfile(script) else 1
    print("Removed. Now revoke it on the host page in Patchy, so its token can't be used again." if code == 0
          else f"Couldn't finish: run sudo sh {script} or the uninstall.sh you installed from.")
    _pause()
    return code == 0


def header_note(cfg, state_dir=STATE_DIR):
    s = _read_json_nofollow(os.path.join(state_dir, SUMMARY_FILE))
    last = (f"last report {_ago(s.get('sent_at'))} ({'OK' if s.get('http') == 200 else 'failed'})" if s
            else "no report recorded yet")
    return f"Server: {cfg.get('server_url') or 'not set'}  ·  {last}  ·  Run upgrade: {upgrade_state()}"


def cmd_menu(cfg_path):
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("patchy-agent: the menu needs a terminal", file=sys.stderr)
        return 2
    try:
        import curses  # noqa: F401 - Linux terminals only
    except ImportError:
        print("patchy-agent: the menu needs a Linux terminal", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("patchy-agent: the menu changes root-owned settings. Run: sudo patchy-agent", file=sys.stderr)
        return 2
    if not os.path.isfile(cfg_path):
        print(f"patchy-agent: no config at {cfg_path}. Install the agent first (the commands are on the host page "
              "in Patchy).", file=sys.stderr)
        return 2
    sections = [("Status", lambda: _menu_status(cfg_path)), ("Send a report now", lambda: _menu_send(cfg_path)),
                ("What it collects", lambda: _menu_collect(cfg_path)), ("Run upgrade", _menu_upgrade),
                ("Server and token", lambda: _menu_server(cfg_path)), ("Logs", _menu_logs),
                ("Update the agent", lambda: _menu_update(cfg_path))]
    try:
        while True:
            cfg = load_config(cfg_path)
            i = _pick(f"patchy-agent {VERSION} on {socket.gethostname()}",
                      [label for label, _ in sections] + ["Remove the agent", "Quit"], header_note(cfg))
            if i is None:
                return 0
            if i == len(sections):
                if _menu_remove():
                    return 0
            else:
                sections[i][1]()
    except KeyboardInterrupt:
        print()
        return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Patchy read-only inventory agent")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--dry-run", action="store_true", help="print the report instead of sending it")
    ap.add_argument("--sample", action="store_true", help="use a synthetic SAMPLE report (reads nothing)")
    ap.add_argument("--send", action="store_true", help="with --sample: send it to the server")
    ap.add_argument("--check", action="store_true", help="test the server URL and credential")
    ap.add_argument("--poll", action="store_true", help="send a report only if Rescan was pressed in Patchy")
    ap.add_argument("--menu", action="store_true", help="interactive menu (run as root: sudo patchy-agent)")
    ap.add_argument("--version", action="version", version=VERSION)
    a = ap.parse_args(argv)

    if a.menu:
        return cmd_menu(a.config)
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
        if code != 200:
            return 0
        refused = False
        if isinstance(body.get("upgrade"), int):
            refused = not start_upgrade(body["upgrade"])  # report straight away, so Patchy learns it isn't allowed
        # A finished upgrade is reported by the run the upgrade service starts; this catches one that was missed.
        if not (body.get("report") or refused or upgrade_result()):  # nothing wanted, or a server too old to ask
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
        reason = getattr(e, "reason", None) or e
        if not a.sample:
            save_summary(report_summary(report, None, f"couldn't reach Patchy: {reason}"))
        print(f"Could not send the report to Patchy: {reason}", file=sys.stderr)
        return 1
    if not a.sample:
        save_summary(report_summary(report, code, None if code == 200 else str(body.get("detail"))[:200]))
    print(f"HTTP {code}: {body}")
    if code == 200 and report.get("upgrade_result"):
        upgrade_reported()
    return 0 if code == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
