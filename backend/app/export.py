"""Exports: findings as CSV, and a CycloneDX 1.5 SBOM (with open vulnerabilities) for a host, repository or image."""
from __future__ import annotations

import csv
import io
import uuid
from urllib.parse import quote

from sqlalchemy import Select, select
from sqlalchemy.orm import Session, selectinload

from . import __version__, fixplan
from . import matching as m
from .db import utcnow
from .eol import PURL_TYPES
from .models import Advisory, Component, Finding, Host, Repository
from .routers.common import OPEN

MAX_ROWS = 50_000
CSV_HEAD = ["Advisory", "CVEs", "Severity", "KEV", "EPSS", "CVSS", "Exposure", "Component", "Version", "Ecosystem",
            "Type", "Image", "Location", "Match", "Status", "Fixed in", "First detected", "Published", "Summary"]


def _safe(v) -> str:
    """Plain text that a spreadsheet won't run as a formula."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def findings_csv(db: Session, query: Select) -> tuple[str, int]:
    cols = query.with_only_columns(
        Advisory.id, Advisory.cve_ids, Advisory.severity, Advisory.kev, Advisory.epss, Advisory.cvss_score,
        Component.exposure, Component.name, Component.version, Component.ecosystem, Component.component_type,
        Component.details, Host.name, Repository.owner, Repository.name, Finding.match_status, Finding.status,
        Finding.fixed_versions, Finding.first_detected_at, Advisory.published, Advisory.summary,
        maintain_column_froms=False).limit(MAX_ROWS)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(CSV_HEAD)
    n = 0
    for (adv, cves, sev, kev, epss, cvss, expo, name, ver, eco, ctype, details, host, owner, repo, match, status,
         fixed, first, published, summary) in db.execute(cols):
        w.writerow([_safe(x) for x in (
            adv, ", ".join(cves or []), sev, "yes" if kev else "", f"{epss:.4f}" if epss is not None else "", cvss,
            expo, name, ver, eco, ctype, (details or {}).get("image"), host or (f"{owner}/{repo}" if repo else ""),
            match, status, ", ".join(fixed or []), first.strftime("%Y-%m-%d") if first else "",
            published.strftime("%Y-%m-%d") if published else "", (summary or "")[:500])])
        n += 1
    return out.getvalue(), n


def purl(c: Component) -> str | None:
    eco, ver = m.ecosystem_base(c.ecosystem or ""), c.source_version or c.version
    if not ver or c.version_status != "exact":
        return None
    v = quote(ver, safe="")
    if eco in PURL_TYPES:
        if eco == "Maven" and ":" in c.name:
            group, _, artifact = c.name.partition(":")
            return f"pkg:maven/{quote(group)}/{quote(artifact)}@{v}"
        name = c.name if eco in ("npm", "Go") else m.normalize_name(c.ecosystem, c.name)
        return f"pkg:{PURL_TYPES[eco]}/{quote(name, safe='/')}@{v}"
    parts = (c.ecosystem or "").split(":")
    distro = {"Debian": ("deb", "debian"), "Ubuntu": ("deb", "ubuntu"), "Alpine": ("apk", "alpine"),
              "Rocky Linux": ("rpm", "rocky"), "AlmaLinux": ("rpm", "almalinux")}.get(parts[0])
    if distro and len(parts) > 1:
        release = parts[1].removeprefix("v")
        return f"pkg:{distro[0]}/{distro[1]}/{quote(c.source_package or c.name)}@{v}?distro={distro[1]}-{release}"
    if c.component_type == "container_image":
        image = c.name.removeprefix("docker.io/")
        return f"pkg:docker/{quote(image if '/' in image else 'library/' + image, safe='/')}@{v}"
    return None


CDX_TYPES = {"os_package": "library", "library": "library", "framework": "framework", "container_image": "container",
             "language": "application", "web_server": "application", "database": "application",
             "application": "application"}
ANALYSIS = {"acknowledged": "in_triage"}


def sbom(db: Session, host: Host | None = None, repo: Repository | None = None, image: str | None = None) -> dict:
    q = select(Component).options(selectinload(Component.paths)).where(Component.missing_since.is_(None))
    q = q.where(Component.host_id == host.id) if host else q.where(Component.repository_id == repo.id)
    comps = [c for c in db.scalars(q.order_by(Component.name, Component.id))
             if image is None or (c.details or {}).get("image") == image]
    components = []
    for c in comps:
        d = {"type": CDX_TYPES.get(c.component_type, "library"), "bom-ref": f"component-{c.id}", "name": c.name}
        if c.version:
            d["version"] = c.version
        if p := purl(c):
            d["purl"] = p
        props = [("patchy:type", c.component_type), ("patchy:ecosystem", c.ecosystem), ("patchy:exposure", c.exposure),
                 ("patchy:image", None if image else (c.details or {}).get("image"))]
        props += [("patchy:path", p.path) for p in c.paths[:5]]
        d["properties"] = [{"name": k, "value": str(v)} for k, v in props if v]
        components.append(d)

    vulns: dict[str, dict] = {}
    by_id = {c.id: c for c in comps}
    fixes: dict[str, dict[str, str]] = {}  # advisory -> {component name: version that fixes it}
    ids = [c.id for c in comps]
    for i in range(0, len(ids), 5000):
        for f in db.scalars(select(Finding).options(selectinload(Finding.advisory))
                            .where(Finding.component_id.in_(ids[i:i + 5000]), Finding.status.in_(OPEN),
                                   Finding.currently_matching.is_(True), Finding.match_status != m.UNKNOWN_VERSION)):
            a = f.advisory
            v = vulns.setdefault(a.id, {"id": a.id, "source": {"name": "OSV" if not a.id.startswith("CVE-") else "NVD"},
                                        "ratings": [{"severity": a.severity if a.severity in
                                                     ("critical", "high", "medium", "low", "none") else "unknown",
                                                     **({"score": a.cvss_score} if a.cvss_score else {})}],
                                        "affects": []})
            if a.summary:
                v["description"] = a.summary[:1000]
            if a.cve_ids and a.cve_ids != [a.id]:
                v["references"] = [{"id": x, "source": {"name": "NVD"}} for x in a.cve_ids[:10]]
            c = by_id[f.component_id]
            if target := fixplan.target_version(c, [f])[0]:  # the fix on this component's release line
                fixes.setdefault(a.id, {})[c.name] = target
                v["recommendation"] = "; ".join(f"Upgrade {n} to {t} or later" for n, t in
                                                sorted(fixes[a.id].items())) + "."
            if f.status in ANALYSIS:
                v["analysis"] = {"state": ANALYSIS[f.status]}
            v["affects"].append({"ref": f"component-{f.component_id}"})

    if host and image:
        subject = {"type": "container", "name": image}
    elif host:
        subject = {"type": "device", "name": host.name,
                   **({"description": " ".join(x for x in (host.os_name, host.arch) if x)} if host.os_name else {})}
    else:
        subject = {"type": "application", "name": f"{repo.owner}/{repo.name}",
                   **({"version": repo.last_revision[:40]} if repo.last_revision else {})}
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "tools": {"components": [{"type": "application", "name": "Patchy", "version": __version__}]},
                     "component": {"bom-ref": "subject", **subject}},
        "components": components,
        "vulnerabilities": sorted(vulns.values(), key=lambda v: v["id"]),
    }
