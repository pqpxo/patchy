"""The public demo: a made-up home lab matched against a bundled snapshot of real, public vulnerability data.

  python -m app.cli demo-build   fetch a fresh snapshot (OSV, CISA KEV, FIRST EPSS, endoflife.date) for the
                                 inventory below into demo_snapshot.json.gz. Needs internet; run it now and then.
  python -m app.cli demo-load    fill an EMPTY database with the lab and the snapshot. The demo container runs
                                 this on every start, on a throwaway SQLite file, with DEMO_MODE=true.

The lab is ingested twice, as real agent reports: about two months ago, then today after some upgrades. So
findings have a history (found, fixed, overdue) produced by Patchy's own matching, not written by hand.
"""
from __future__ import annotations

import gzip
import json
import pathlib
import random
import secrets
import tempfile
import uuid
from datetime import datetime, timedelta

from sqlalchemy import DateTime, create_engine, delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from . import eol, parsers, risk, vulns
from . import matching as m
from .agent_ingest import Report, ingest
from .config import settings
from .db import Base, SessionLocal, utcnow
from .inventory import sync_components
from .models import (Advisory, AdvisoryPackage, Agent, AppSetting, Component, Finding, FeedStatus, Host, OsvQuery,
                     Repository, RiskRule, ScanRun, UpgradeRun, User, UserSession, UTCDateTime)
from .security import hash_password, sha256

SNAPSHOT = pathlib.Path(__file__).with_name("demo_snapshot.json.gz")
TABLES = (Advisory, AdvisoryPackage, OsvQuery, FeedStatus)
DEMO_USER = "demo"


def _pkg(name, version, source=None, source_version=None):
    return {"manager": "dpkg", "name": name, "version": version, "source_name": source or name,
            "source_version": source_version or version}


def _kernel(release, version, flavour):
    return [_pkg(f"linux-headers-{release}-{flavour}", version, "linux"), _pkg(f"linux-headers-{release}-common", version, "linux")]


DEB12 = {"id": "debian", "version_id": "12", "pretty_name": "Debian GNU/Linux 12 (bookworm)"}
UBU24 = {"id": "ubuntu", "version_id": "24.04", "pretty_name": "Ubuntu 24.04.1 LTS"}
DEB10 = {"id": "debian", "version_id": "10", "pretty_name": "Debian GNU/Linux 10 (buster)"}


def _hosts(phase: int) -> list[dict]:
    """Agent reports for each host. Phase 1 is about two months ago; phase 2 is today, after some upgrades."""
    new = phase == 2
    pi = [
        _pkg("libssl3", "3.0.15-1~deb12u1" if new else "3.0.11-1~deb12u2", "openssl"),
        _pkg("openssl", "3.0.15-1~deb12u1" if new else "3.0.11-1~deb12u2"),
        _pkg("openssh-server", "1:9.2p1-2+deb12u3" if new else "1:9.2p1-2+deb12u2", "openssh"),
        _pkg("openssh-client", "1:9.2p1-2+deb12u3" if new else "1:9.2p1-2+deb12u2", "openssh"),
        _pkg("libc6", "2.36-9+deb12u7" if new else "2.36-9+deb12u4", "glibc"),
        _pkg("curl", "7.88.1-10+deb12u5"), _pkg("libcurl4", "7.88.1-10+deb12u5", "curl"),
        _pkg("sudo", "1.9.13p3-1+deb12u1"), _pkg("systemd", "252.22-1~deb12u1"),
        _pkg("lighttpd", "1.4.69-1"), _pkg("dnsmasq-base", "2.89-1", "dnsmasq"),
        _pkg("libexpat1", "2.5.0-1", "expat"), _pkg("tar", "1.34+dfsg-1.2"), _pkg("bash", "5.2.15-2+b2", "bash", "5.2.15-2"),
        _pkg("git", "1:2.39.2-1.1"), _pkg("python3.11", "3.11.2-6"),
        *_kernel("6.1.0-17", "6.1.69-1", "arm64"), *(_kernel("6.1.0-18", "6.1.76-1", "arm64") if new else []),
    ]
    home = [
        _pkg("libssl3t64", "3.0.13-0ubuntu3.4" if new else "3.0.13-0ubuntu3.1", "openssl"),
        _pkg("openssh-server", "1:9.6p1-3ubuntu13.5" if new else "1:9.6p1-3ubuntu13", "openssh"),
        _pkg("libc6", "2.39-0ubuntu8.3" if new else "2.39-0ubuntu8.1", "glibc"),
        _pkg("curl", "8.5.0-2ubuntu10.1"), _pkg("sudo", "1.9.15p5-3ubuntu5"),
        _pkg("systemd", "255.4-1ubuntu8.1"), _pkg("vim", "2:9.1.0016-1ubuntu7"), _pkg("less", "590-2ubuntu2"),
        _pkg("libxml2", "2.9.14+dfsg-1.3ubuntu3"), _pkg("git", "1:2.43.0-1ubuntu7"),
        _pkg("python3.12", "3.12.3-1"),
        _pkg("docker-ce", "5:27.3.1-1~ubuntu.24.04~noble"), _pkg("containerd.io", "1.7.22-1"),
        *[_pkg(f"linux-headers-6.8.0-40{s}", "6.8.0-40.40", "linux") for s in ("", "-generic")],
        *([_pkg(f"linux-headers-6.8.0-45{s}", "6.8.0-45.45", "linux") for s in ("", "-generic")] if new else []),
    ]
    dashboard_image = {"image_id": "sha256:" + "d1" * 32, "image": "ghcr.io/example/home-dashboard:1.4",
                       "distro": {"id": "debian", "version_id": "12"}, "packages": [
        {"type": "deb", "name": "libssl3", "version": "3.0.11-1~deb12u2", "source_name": "openssl"},
        {"type": "deb", "name": "zlib1g", "version": "1:1.2.13.dfsg-1", "source_name": "zlib"},
        *[{"type": "npm", "name": n, "version": v, "purl": f"pkg:npm/{n}@{v}"} for n, v in (
            ("lodash", "4.17.20"), ("axios", "0.21.1"), ("express", "4.17.1"), ("minimist", "1.2.5"),
            ("node-fetch", "2.6.0"), ("jsonwebtoken", "8.5.1"))]]}
    proxy_image = {"image_id": "sha256:" + "a7" * 32, "image": "jc21/nginx-proxy-manager:2.11.1",
                   "distro": {"id": "debian", "version_id": "12"}, "packages": [
        {"type": "deb", "name": "libssl3", "version": "3.0.11-1~deb12u2", "source_name": "openssl"},
        {"type": "deb", "name": "libexpat1", "version": "2.5.0-1", "source_name": "expat"},
        *[{"type": "npm", "name": n, "version": v, "purl": f"pkg:npm/{n}@{v}"} for n, v in (
            ("express", "4.18.2"), ("body-parser", "1.20.1"), ("semver", "7.3.8"))]]}
    containers = [
        {"name": "proxy", "image": proxy_image["image"], "image_id": proxy_image["image_id"], "state": "running",
         "status": "Up 9 days", "compose_project": "proxy", "compose_service": "app",
         "ports": [{"ip": "0.0.0.0", "private": 80, "public": 80, "type": "tcp"},
                   {"ip": "0.0.0.0", "private": 443, "public": 443, "type": "tcp"},
                   {"ip": "0.0.0.0", "private": 81, "public": 81, "type": "tcp"}],
         "mounts": [{"type": "bind", "source": "/srv/proxy/data", "destination": "/data"}]},
        {"name": "dashboard", "image": dashboard_image["image"], "image_id": dashboard_image["image_id"],
         "state": "running", "status": "Up 9 days", "compose_project": "dashboard", "compose_service": "web",
         "ports": [{"ip": "127.0.0.1", "private": 3000, "public": 3000, "type": "tcp"}], "mounts": []},
    ]
    reports = [
        ("pi-dns", "192.168.1.53", "6.1.0-18-arm64" if new else "6.1.0-17-arm64", "aarch64", DEB12, pi,
         [("udp", "0.0.0.0", 53, "dnsmasq-base"), ("tcp", "0.0.0.0", 80, "lighttpd"), ("tcp", "0.0.0.0", 22, None)],
         ["libc6", "libssl3", "openssh-server", "systemd", "lighttpd", "dnsmasq-base", "bash", "libexpat1"], [], []),
        ("homeserver", "192.168.1.20", "6.8.0-45-generic" if new else "6.8.0-40-generic", "x86_64", UBU24, home,
         [("tcp", "0.0.0.0", 22, None)],
         ["libc6", "libssl3t64", "openssh-server", "systemd", "docker-ce", "containerd.io", "python3.12"],
         containers, [proxy_image, dashboard_image]),
    ]
    if not new:  # the old VM stopped reporting a few days ago, so it only appears in the first round
        reports.append(("old-wiki", "192.168.1.31", "4.19.0-26-amd64", "x86_64", DEB10, [
            _pkg("libssl1.1", "1.1.1n-0+deb10u6", "openssl"), _pkg("apache2", "2.4.38-3+deb10u10"),
            _pkg("php7.3", "7.3.31-1~deb10u5"), _pkg("openssh-server", "1:7.9p1-10+deb10u4", "openssh"),
            _pkg("libc6", "2.28-10+deb10u3", "glibc"), _pkg("sudo", "1.8.27-1+deb10u6")],
            [("tcp", "0.0.0.0", 80, "apache2"), ("tcp", "0.0.0.0", 22, None)],
            ["libc6", "libssl1.1", "apache2", "php7.3", "openssh-server"], [], []))
    def upd(name, installed, available, security=False):
        return {"name": name, "installed": installed, "available": available, "security": security}
    lists_at = (utcnow() - timedelta(hours=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    updates = {  # pending apt updates today: pi-dns allows Run upgrade, homeserver doesn't and wants a reboot
        "pi-dns": {"manager": "apt", "lists_at": lists_at, "reboot_required": False, "reboot_packages": [], "can_upgrade": True,
                   "held_back": [], "packages": [
            upd("curl", "7.88.1-10+deb12u5", "7.88.1-10+deb12u8", True), upd("libcurl4", "7.88.1-10+deb12u5", "7.88.1-10+deb12u8", True),
            upd("git", "1:2.39.2-1.1", "1:2.39.5-0+deb12u2", True), upd("libexpat1", "2.5.0-1", "2.5.0-1+deb12u1", True),
            upd("python3.11", "3.11.2-6", "3.11.2-6+deb12u4", True), upd("tar", "1.34+dfsg-1.2", "1.34+dfsg-1.2+deb12u1"),
            upd("systemd", "252.22-1~deb12u1", "252.33-1~deb12u1")]},
        "homeserver": {"manager": "apt", "lists_at": lists_at, "reboot_required": True,
                       "reboot_packages": ["linux-image-6.8.0-47-generic"], "can_upgrade": False,
                       "held_back": ["linux-generic", "linux-headers-generic", "linux-image-generic"], "packages": [
            upd("curl", "8.5.0-2ubuntu10.1", "8.5.0-2ubuntu10.6", True), upd("git", "1:2.43.0-1ubuntu7", "1:2.43.0-1ubuntu7.2", True),
            upd("libxml2", "2.9.14+dfsg-1.3ubuntu3", "2.9.14+dfsg-1.3ubuntu3.3", True), upd("vim", "2:9.1.0016-1ubuntu7", "2:9.1.0016-1ubuntu7.8", True),
            upd("less", "590-2ubuntu2", "590-2ubuntu2.1", True),
            upd("docker-ce", "5:27.3.1-1~ubuntu.24.04~noble", "5:27.5.1-1~ubuntu.24.04~noble"),
            upd("containerd.io", "1.7.22-1", "1.7.25-1")]},
    } if new else {}
    out = []
    for name, ip, kernel, arch, os_info, pkgs, listening, running, ctrs, images in reports:
        out.append({"name": name, "version": "1.3.0" if name == "old-wiki" else "1.6.0", "report": {
            "schema": 1, "report_id": str(uuid.UUID(int=random.Random(f"{name}{phase}").getrandbits(128))),
            "agent_version": "1.3.0" if name == "old-wiki" else "1.6.0", "generated_at": utcnow().isoformat(),
            "updates": updates.get(name),
            "host": {"hostname": name, "ips": [ip], "kernel": kernel, "arch": arch, "os": os_info},
            "packages": [{**p, "arch": "arm64" if arch == "aarch64" else "amd64"} for p in pkgs],
            "listening": [{"protocol": pr, "ip": i, "port": po, "process": n} for pr, i, po, n in listening],
            "services": [{"unit": "ssh.service"}, {"unit": "systemd-journald.service"}],
            "in_use": running if name != "old-wiki" else None,
            "containers": ctrs, "images": images, "image_requests_done": [] if name != "old-wiki" else None}})
    return out


REPOS = {
    ("example", "home-dashboard"): {"package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "home-dashboard", "version": "1.4.0"},
        **{f"node_modules/{n}": {"version": v} for n, v in (
            ("lodash", "4.17.20"), ("axios", "0.21.1"), ("express", "4.17.1"), ("minimist", "1.2.5"),
            ("node-fetch", "2.6.0"), ("jsonwebtoken", "8.5.1"), ("ws", "7.4.5"), ("semver", "7.3.8"))}}})},
    ("example", "backup-scripts"): {"requirements.txt": "\n".join((
        "requests==2.25.1", "urllib3==1.26.4", "jinja2==2.11.2", "pyyaml==5.3.1", "cryptography==3.3.2",
        "paramiko==2.7.2", "certifi==2020.12.5"))},
}


def _inventory(db: Session, phase: int) -> None:
    """Send this phase's agent reports and repository scans through Patchy's own ingestion."""
    for h in _hosts(phase):
        host = db.scalar(select(Host).where(Host.name == h["name"]))
        if not host:
            host = Host(name=h["name"])
            db.add(host)
            db.flush()
            db.add(Agent(host_id=host.id, token_hash=sha256(secrets.token_urlsafe(32)), token_hint="pa_demo"))
            db.flush()
            db.refresh(host)
        ingest(db, host.agent, Report.model_validate(h["report"]), "192.0.2.1")
    for (owner, name), files in REPOS.items():
        repo = db.scalar(select(Repository).where(Repository.owner == owner, Repository.name == name))
        if not repo:
            repo = Repository(url=f"https://github.com/{owner}/{name}", owner=owner, name=name, is_private=False)
            db.add(repo)
            db.flush()
        run = ScanRun(kind="repo", status="succeeded", repository_id=repo.id, started_at=utcnow(), finished_at=utcnow())
        db.add(run)
        db.flush()
        rows = []
        for path, text in files.items():
            for p in parsers.parser_for(path)(text):
                rows.append({"identity": f"{path}|{p.ecosystem or '-'}|{p.name}", "name": p.name,
                             "component_type": p.component_type, "ecosystem": p.ecosystem, "version": p.version or None,
                             "version_status": p.version_status, "version_spec": p.version_spec or None,
                             "details": p.details or None, "paths": [(path, p.path_kind)]})
        sync_components(db, run, f"repo:{repo.id}", rows, source="repo", repository_id=repo.id)
        repo.last_scanned_at, repo.last_revision = utcnow(), secrets.token_hex(20)
    db.flush()


# ---------------------------------------------------------------- snapshot

def _encode(obj) -> dict:
    """A row as JSON. Integer ids are left out: the loading database numbers its own rows."""
    out = {}
    for c in obj.__table__.columns:
        v = getattr(obj, c.key)
        if c.key == "id" and not isinstance(v, str):
            continue
        out[c.key] = v.isoformat() if isinstance(v, datetime) else v
    return out


def _decode(model, row: dict) -> dict:
    dates = {c.key for c in model.__table__.columns if isinstance(c.type, (DateTime, UTCDateTime))}
    return {k: datetime.fromisoformat(v) if k in dates and v else v for k, v in row.items()}


def _trim(db: Session) -> None:
    """Keep only what the lab can use. An Ubuntu advisory lists every Ubuntu release, which made the snapshot
    ten times bigger; the KEV and endoflife.date catalogues are mostly other products."""
    labs = {e for (e,) in db.execute(select(Component.ecosystem).distinct()) if e}
    keep = labs | {m.ecosystem_base(e) for e in labs}
    for a in db.scalars(select(Advisory)):
        a.affected = [x for x in a.affected or [] if (x.get("package") or {}).get("ecosystem") in keep]
    db.execute(delete(AdvisoryPackage).where(AdvisoryPackage.ecosystem.not_in(keep)))
    if (kev := db.get(FeedStatus, "kev")) and kev.detail:
        cves = {c for (ids,) in db.execute(select(Advisory.cve_ids)) for c in ids or []}
        kev.detail = {**kev.detail, "entries": {c: e for c, e in kev.detail["entries"].items() if c in cves}}
    if (feed := db.get(FeedStatus, "eol")) and feed.detail:
        d = feed.detail
        used = {d["index"][k] for c in db.scalars(select(Component)) for k in eol.keys_for(c) if k in d["index"]}
        used |= {s for s in eol.OS_PRODUCTS.values() if s in d["products"]}
        feed.detail = {**d, "products": {s: p for s, p in d["products"].items() if s in used},
                       "index": {k: s for k, s in d["index"].items() if s in used},
                       "cpes": {s: v for s, v in d["cpes"].items() if s in used}}
    db.flush()


def build(path: pathlib.Path = SNAPSHOT) -> dict:
    """Run Patchy's feeds for the demo lab in a scratch database and keep what they fetched."""
    settings.osv_max_vulns_per_package = 60  # keeps the kernel and other big packages to a readable size
    with tempfile.TemporaryDirectory() as tmp:
        engine = create_engine(f"sqlite:///{tmp}/build.db")
        Base.metadata.create_all(engine)
        with sessionmaker(engine)() as db, vulns.http_client() as client:
            for phase in (1, 2):
                _inventory(db, phase)
                db.commit()
                vulns.run_feed_refresh(db, client, "full", only=["kev", "osv", "eol", "epss"])
            _trim(db)
            snap = {"taken_at": utcnow().isoformat(),
                    "tables": {m.__tablename__: [_encode(o) for o in db.scalars(select(m))] for m in TABLES}}
        engine.dispose()
    path.write_bytes(gzip.compress(json.dumps(snap, separators=(",", ":")).encode(), mtime=0))
    return {t: len(rows) for t, rows in snap["tables"].items()} | {"bytes": path.stat().st_size}


# ---------------------------------------------------------------- load

def _ago(rng: random.Random, lo: int, hi: int) -> datetime:
    return utcnow() - timedelta(days=rng.randint(lo, hi), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))


UPGRADE_LOG = """# apt-get update && apt-get upgrade (requested from Patchy)
Hit:1 http://deb.debian.org/debian bookworm InRelease
Get:2 http://deb.debian.org/debian bookworm-updates InRelease [55.4 kB]
Get:3 http://security.debian.org/debian-security bookworm-security InRelease [48.0 kB]
Get:4 http://security.debian.org/debian-security bookworm-security/main arm64 Packages [241 kB]
Fetched 344 kB in 2s (171 kB/s)
Reading package lists...
Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following packages will be upgraded:
  libc6 libssl3 openssh-client openssh-server openssl
5 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Need to get 6,412 kB of archives.
After this operation, 12.3 kB of additional disk space will be used.
Get:1 http://deb.debian.org/debian bookworm/main arm64 libc6 arm64 2.36-9+deb12u7 [2,322 kB]
Get:2 http://security.debian.org/debian-security bookworm-security/main arm64 libssl3 arm64 3.0.15-1~deb12u1 [1,808 kB]
Get:3 http://security.debian.org/debian-security bookworm-security/main arm64 openssl arm64 3.0.15-1~deb12u1 [1,383 kB]
Get:4 http://deb.debian.org/debian bookworm/main arm64 openssh-server arm64 1:9.2p1-2+deb12u3 [445 kB]
Get:5 http://deb.debian.org/debian bookworm/main arm64 openssh-client arm64 1:9.2p1-2+deb12u3 [454 kB]
Fetched 6,412 kB in 1s (5,104 kB/s)
Preparing to unpack .../libc6_2.36-9+deb12u7_arm64.deb ...
Unpacking libc6:arm64 (2.36-9+deb12u7) over (2.36-9+deb12u4) ...
Setting up libc6:arm64 (2.36-9+deb12u7) ...
Setting up libssl3:arm64 (3.0.15-1~deb12u1) ...
Setting up openssl (3.0.15-1~deb12u1) ...
Setting up openssh-client (1:9.2p1-2+deb12u3) ...
Setting up openssh-server (1:9.2p1-2+deb12u3) ...
Processing triggers for man-db (2.11.2-2) ...
Processing triggers for libc-bin (2.36-9+deb12u7) ...
"""


def load(db: Session) -> dict:
    """Fill an empty database with the demo lab. Refuses a database that has anything in it."""
    if db.scalar(select(func.count()).select_from(User)) or db.scalar(select(func.count()).select_from(Host)):
        raise SystemExit("Refusing to load the demo: this database already has users or hosts. "
                         "The demo needs its own empty database (see docker-compose.demo.yml).")
    snap = json.loads(gzip.decompress(SNAPSHOT.read_bytes()))
    for m in TABLES:
        db.execute(m.__table__.insert(), [_decode(m, r) for r in snap["tables"][m.__tablename__]])
    user = User(username=DEMO_USER, password_hash=hash_password(secrets.token_urlsafe(32)))
    db.add(user)
    db.flush()
    db.add(UserSession(token_hash=sha256(secrets.token_urlsafe(32)), csrf_token=secrets.token_urlsafe(24),
                       user_id=user.id, expires_at=utcnow() + timedelta(days=3650)))
    rng = random.Random(1)

    _inventory(db, 1)
    vulns.rematch(db)
    db.flush()
    then = utcnow() - timedelta(days=58)
    for f in db.scalars(select(Finding)):
        f.first_detected_at = _ago(rng, 59, 150)
        f.status_changed_at = f.last_checked_at = max(f.first_detected_at, then)
    for r in db.scalars(select(ScanRun)):
        r.started_at = r.finished_at = then
    before = set(db.scalars(select(Finding.id)))

    _inventory(db, 2)
    vulns.rematch(db)
    db.flush()
    for f in db.scalars(select(Finding)):
        if f.id not in before:
            f.first_detected_at = f.status_changed_at = _ago(rng, 0, 40)
        elif f.status_changed_at > then:  # changed by today's match: resolved by an upgrade, or set aside
            f.status_changed_at = max(f.first_detected_at + timedelta(days=2), _ago(rng, 3, 45))
    old = db.scalar(select(Host).where(Host.name == "old-wiki"))
    old.last_report_at = old.agent.last_seen_at = utcnow() - timedelta(days=4, hours=3)

    # A little of what a person does: acknowledge, rule out, accept a risk until the old VM is retired.
    def finding(host, pkg):
        return db.scalar(select(Finding).join(Finding.component).where(
            Finding.status == "open", Finding.component.has(name=pkg), Finding.component.has(host_id=host.id))
            .order_by(Finding.id))
    pi = db.scalar(select(Host).where(Host.name == "pi-dns"))
    for f, status, note in ((finding(pi, "curl"), "acknowledged", "Waiting for the next Debian point release."),
                            (finding(pi, "git"), "false_positive", "git only clones our own repositories here.")):
        if f:
            f.status, f.status_note, f.status_changed_by, f.status_changed_at = status, note, DEMO_USER, _ago(rng, 1, 10)
    done = utcnow() - timedelta(days=12, hours=2)
    db.add(UpgradeRun(host_id=pi.id, status="succeeded", requested_by=DEMO_USER, requested_at=done - timedelta(minutes=3),
                      sent_at=done - timedelta(minutes=2, seconds=40), started_at=done - timedelta(minutes=2, seconds=31),
                      finished_at=done, exit_code=0, output=UPGRADE_LOG))
    db.add(RiskRule(package="apache2", host_id=old.id, reason="old-wiki is being retired and sits on an isolated VLAN.",
                    created_by=DEMO_USER, expires_at=utcnow() + timedelta(days=24)))
    db.flush()
    risk.apply(db)
    db.merge(AppSetting(key="demo", value={"snapshot": snap["taken_at"][:10]}))
    db.commit()
    return {"findings": db.scalar(select(func.count()).select_from(Finding)), "snapshot": snap["taken_at"][:10]}


def load_cli() -> None:
    with SessionLocal() as db:
        print("Demo loaded:", load(db))


def build_cli() -> None:
    print("Snapshot written:", build())
