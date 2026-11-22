"""Validation and ingestion of Linux agent reports."""
from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .db import utcnow
from .inventory import sync_components
from .models import Agent, Host, HostPath, HostService, ScanRun

S = Annotated[str, StringConstraints(max_length=255, strip_whitespace=True)]
P = Annotated[str, StringConstraints(max_length=2048)]

# Defence in depth: the agent excludes these too, but the server never stores them either.
SENSITIVE = re.compile(
    r"(^|/)(\.ssh|\.gnupg|\.aws|\.kube|\.docker|\.password-store|secrets?)(/|$)"
    r"|(^|/)(shadow|gshadow|\.env(\..*)?|\.netrc|\.pgpass|id_[a-z0-9]+|.*\.(key|pem|p12|pfx|kdbx))$",
    re.IGNORECASE)


class _M(BaseModel):
    model_config = ConfigDict(extra="ignore")


class OsInfo(_M):
    id: S | None = None
    version_id: S | None = None
    pretty_name: S | None = None
    id_like: S | None = None


class HostInfo(_M):
    hostname: S
    ips: list[S] = Field(default_factory=list, max_length=64)
    os: OsInfo = OsInfo()
    kernel: S | None = None
    arch: S | None = None


class Package(_M):
    manager: Literal["dpkg", "rpm", "apk"]
    name: S
    version: S
    source_name: S | None = None
    source_version: S | None = None
    arch: S | None = None


class Probe(_M):
    name: S
    version: S | None = None
    path: P | None = None
    component_type: Literal["language", "web_server", "database", "application", "other"] = "application"


class Listener(_M):
    protocol: Literal["tcp", "udp", "tcp6", "udp6"]
    ip: S
    port: int = Field(ge=0, le=65535)
    process: S | None = None


class Service(_M):
    unit: S


class ContainerPort(_M):
    ip: S | None = None
    private: int = Field(ge=0, le=65535)
    public: int | None = Field(None, ge=0, le=65535)
    type: S | None = None


class ContainerMount(_M):
    type: S | None = None
    name: S | None = None
    source: P | None = None
    destination: P
    rw: bool = True


class Container(_M):
    image: S
    name: S | None = None
    state: S | None = None
    status: S | None = None
    version: S | None = None  # org.opencontainers.image.version label
    compose_project: S | None = None
    compose_service: S | None = None
    ports: list[ContainerPort] = Field(default_factory=list, max_length=200)
    mounts: list[ContainerMount] = Field(default_factory=list, max_length=200)


class App(_M):
    manager: Literal["dpkg", "snap", "flatpak"]
    name: S
    version: S | None = None


class PathListing(_M):
    root: P
    entries: list[dict] = Field(default_factory=list, max_length=20000)
    truncated: bool = False


class Report(_M):
    schema_version: Literal[1] = Field(alias="schema")
    report_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F-]{8,64}$")]
    agent_version: S
    generated_at: S
    host: HostInfo
    packages: list[Package] = Field(default_factory=list, max_length=50000)
    probes: list[Probe] = Field(default_factory=list, max_length=200)
    listening: list[Listener] = Field(default_factory=list, max_length=5000)
    services: list[Service] = Field(default_factory=list, max_length=2000)
    containers: list[Container] = Field(default_factory=list, max_length=1000)
    apps: list[App] = Field(default_factory=list, max_length=5000)
    paths: list[PathListing] = Field(default_factory=list, max_length=20)
    errors: list[Annotated[str, StringConstraints(max_length=500)]] = Field(default_factory=list, max_length=100)


def os_ecosystem(os: OsInfo, manager: str) -> str | None:
    """OSV ecosystem for a distro package, or None if Patchy can't map it reliably."""
    oid, ver = (os.id or "").lower(), os.version_id or ""
    if manager == "dpkg":
        if oid == "debian" or (oid == "raspbian" and ver):
            return f"Debian:{ver.split('.')[0]}" if ver else None
        if oid == "ubuntu" and ver:
            year, _, month = ver.partition(".")
            lts = month == "04" and year.isdigit() and int(year) % 2 == 0
            return f"Ubuntu:{ver}:LTS" if lts else f"Ubuntu:{ver}"
    if manager == "apk" and oid == "alpine" and ver:
        return "Alpine:v" + ".".join(ver.split(".")[:2])
    if manager == "rpm" and ver:
        major = ver.split(".")[0]
        return {"rocky": f"Rocky Linux:{major}", "almalinux": f"AlmaLinux:{major}"}.get(oid)
    return None


def ingest(db: Session, agent: Agent, report: Report, ip: str) -> tuple[ScanRun, bool, list[int]]:
    """Returns (run, duplicate, component_ids). Re-sent reports are idempotent via report_id."""
    key = f"agent:{agent.id}:{report.report_id}"
    existing = db.scalar(select(ScanRun).where(ScanRun.idempotency_key == key))
    if existing:
        return existing, True, []
    host: Host = agent.host
    now = utcnow()
    run = ScanRun(kind="agent", status="running", host_id=host.id, idempotency_key=key, started_at=now)
    db.add(run)
    db.flush()

    host.reported_hostname = report.host.hostname
    host.ip = next((i for i in report.host.ips if not i.startswith(("127.", "::1", "fe80"))), host.ip)
    host.os_name, host.os_id, host.os_version = report.host.os.pretty_name, report.host.os.id, report.host.os.version_id
    host.kernel, host.arch, host.last_report_at = report.host.kernel, report.host.arch, now

    # Distro packages grouped by source package: that's the identity distro advisories use.
    groups: dict[tuple, dict] = {}
    for p in report.packages:
        src = p.source_name or p.name
        src_ver = p.source_version or p.version
        g = groups.setdefault((p.manager, src, src_ver), {"binaries": [], "versions": set()})
        g["binaries"].append(p.name)
        g["versions"].add(p.version)
    rows = []
    for (manager, src, src_ver), g in groups.items():
        rows.append({
            "identity": f"pkg|{manager}|{src}", "name": src, "component_type": "os_package",
            "ecosystem": os_ecosystem(report.host.os, manager), "version": src_ver, "version_status": "exact",
            "source_package": src, "source_version": src_ver, "vendor": report.host.os.id,
            "details": {"manager": manager, "binaries": sorted(g["binaries"])[:200],
                        "binary_versions": sorted(g["versions"])[:20]}, "paths": [],
        })
    by_process = {}
    for l in report.listening:
        if l.process:
            by_process.setdefault(l.process, l)
    for pr in report.probes:
        lst = by_process.get(pr.name)
        rows.append({
            "identity": f"probe|{pr.name}", "name": pr.name, "component_type": pr.component_type,
            "ecosystem": None, "version": pr.version, "version_status": "exact" if pr.version else "unknown",
            "install_path": pr.path, "listen_ip": lst.ip if lst else None, "port": lst.port if lst else None,
            "protocol": lst.protocol if lst else None,
            "details": {"note": "detected by allowlisted version command"},
            "paths": [(pr.path, "executable")] if pr.path else [],
        })
    for image_ref in sorted({ct.image for ct in report.containers}):
        ct = next(c for c in report.containers if c.image == image_ref)
        image, _, tag = image_ref.rpartition(":") if ":" in image_ref.rsplit("/", 1)[-1] else (image_ref, "", "")
        if (not tag or tag == "latest") and ct.version:  # the image's own version label beats a moving tag
            tag = ct.version
        rows.append({
            "identity": f"container|{image_ref}", "name": image or image_ref, "component_type": "container_image",
            "ecosystem": None, "version": tag or None,
            "version_status": "exact" if tag and tag != "latest" else "unknown", "details": None, "paths": [],
        })
    for a in report.apps:  # dpkg ones are already os_package components above
        if a.manager != "dpkg":
            rows.append({
                "identity": f"{a.manager}|{a.name}", "name": a.name, "component_type": "application", "ecosystem": None,
                "version": a.version, "version_status": "exact" if a.version else "unknown",
                "details": {"note": f"installed with {a.manager}"}, "paths": [],
            })
    ids = sync_components(db, run, f"host:{host.id}", rows, source="agent", host_id=host.id)

    db.execute(delete(HostService).where(HostService.host_id == host.id))
    db.execute(delete(HostPath).where(HostPath.host_id == host.id))
    for l in report.listening:
        db.add(HostService(host_id=host.id, name=l.process, protocol=l.protocol, listen_ip=l.ip, port=l.port))
    for s in report.services:
        db.add(HostService(host_id=host.id, name=s.unit))
    dropped = 0
    for listing in report.paths:
        for e in listing.entries[:20000]:
            path = str(e.get("path", ""))[:2048]
            if not path.startswith("/") or SENSITIVE.search(path):
                dropped += 1
                continue
            db.add(HostPath(host_id=host.id, root=listing.root, path=path, is_dir=e.get("type") == "dir"))

    containers = []
    for ct in report.containers:
        d = ct.model_dump()
        for mnt in d["mounts"]:
            if mnt["source"] and SENSITIVE.search(mnt["source"]):
                mnt["source"] = None
                dropped += 1
        containers.append(d)
    host.containers = containers
    host.apps = [a.model_dump() for a in report.apps]
    host.rescan_requested_at = None

    agent.last_seen_at, agent.last_ip, agent.agent_version = now, ip, report.agent_version
    run.status = "partial" if report.errors else "succeeded"
    run.finished_at = utcnow()
    run.summary = {"packages": len(report.packages), "components": len(rows), "probes": len(report.probes),
                   "listening": len(report.listening), "services": len(report.services),
                   "containers": len(report.containers), "apps": len(report.apps),
                   "path_entries_dropped_as_sensitive": dropped, "agent_errors": report.errors[:50],
                   "unmapped_os": not any(r["ecosystem"] for r in rows if r["component_type"] == "os_package")
                   and bool(report.packages)}
    return run, False, ids
