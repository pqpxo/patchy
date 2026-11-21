"""'How to fix' plans: open findings grouped into the fewest upgrade steps, plus end-of-life upgrades.

Package names come from scanned repositories and agent reports, which are untrusted. Any value that
would end up in a copy-paste command must pass SAFE first; anything else is listed but left out of
the command, with a note.
"""
from __future__ import annotations

import posixpath
import re

from sqlalchemy import false, select
from sqlalchemy.orm import Session

from . import matching as m
from .models import Advisory, Component, Finding, Host

SAFE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@/._+~:-]{0,199}$")
DISTRO_CMDS = {
    "Debian": ("apt", "sudo apt update && sudo apt install --only-upgrade {pkgs}"),
    "Ubuntu": ("apt", "sudo apt update && sudo apt install --only-upgrade {pkgs}"),
    "Alpine": ("apk", "sudo apk update && sudo apk upgrade {pkgs}"),
    "Rocky Linux": ("dnf", "sudo dnf upgrade --refresh {pkgs}"),
    "AlmaLinux": ("dnf", "sudo dnf upgrade --refresh {pkgs}"),
}
SEV = m.SEVERITY_ORDER
OPEN = ("open", "acknowledged")


def safe(*values: str | None) -> bool:
    return all(v is not None and SAFE.match(v) for v in values)


def _newer(eco: str, candidate: str, current: str | None) -> bool:
    if not current:
        return True
    r = m.compare(eco, candidate, current)
    return r is None or r > 0


def target_version(c: Component, findings: list[Finding]) -> tuple[str | None, list[Finding]]:
    """Smallest version that fixes every fixable finding, and the findings with no published fix."""
    eco = c.ecosystem or "PyPI"  # NVD product matches: upstream dotted versions, PEP 440 is the closest fit
    current = c.source_version or c.version
    per, no_fix = [], []
    for f in findings:
        cands = [v for v in f.fixed_versions or [] if _newer(eco, v, current)]
        if cands:
            per.append(m.sort_versions(eco, cands)[0])
        else:
            no_fix.append(f)
    return (m.sort_versions(eco, per)[-1] if per else None), no_fix


def _manifest(c: Component) -> str | None:
    return next((p.path for p in c.paths if p.kind in ("manifest", "lockfile")), None) or \
        next((p.path for p in c.paths), None)


def _group(c: Component) -> tuple[tuple, str, str]:
    """(group key, title, kind) for a component."""
    base = m.ecosystem_base(c.ecosystem or "")
    if base in DISTRO_CMDS:
        host = c.host.name if c.host else "host"
        return ("distro", c.host_id, base), f"{host}: {base} packages", DISTRO_CMDS[base][0]
    if c.repository_id:
        path = _manifest(c) or "(no manifest path)"
        return ("repo", c.repository_id, path, base), f"{path} ({base or 'other'})", base or "other"
    if base:
        where = c.host.name if c.host else "manual assets"
        return ("eco", c.host_id, base), f"{where}: {base} packages", base
    where = c.host.name if c.host else "manual assets"
    return ("product", c.host_id), f"{where}: servers and runtimes", "product"


def _command(kind: str, base: str, path: str | None, items: list[dict]) -> tuple[str | None, list[str]]:
    """Copy-paste command for a group, built only from SAFE names and versions."""
    ok = [i for i in items if i["target"] and safe(i["package"], i["target"])]
    skipped = [i["package"] for i in items if i["target"] and i not in ok]
    notes = [f"Left out of the command because of unusual characters: {', '.join(skipped[:10])}"] if skipped else []
    if not ok:
        return None, notes
    fname = posixpath.basename(path or "")
    if base in DISTRO_CMDS:
        pkgs = sorted({b for i in ok for b in i["binaries"] if safe(b)})
        return DISTRO_CMDS[base][1].format(pkgs=" ".join(pkgs[:60])), notes
    if base == "npm":
        tool = "yarn add" if fname == "yarn.lock" else "pnpm add" if fname.startswith("pnpm-lock") else "npm install"
        return f"{tool} " + " ".join(f"{i['package']}@{i['target']}" for i in ok), notes
    if base == "PyPI":
        notes.append(f"Then update the pinned versions in {path}." if path else "Then update your pinned versions.")
        return "pip install --upgrade " + " ".join(f"'{i['package']}>={i['target']}'" for i in ok), notes
    if base == "Go":
        vers = " ".join(f"{i['package']}@{i['target'] if i['target'].startswith('v') else 'v' + i['target']}" for i in ok)
        return f"go get {vers} && go mod tidy", notes
    if base == "crates.io":
        return " && ".join(f"cargo update -p {i['package']} --precise {i['target']}" for i in ok), notes
    if base == "Packagist":
        return "composer require " + " ".join(f"{i['package']}:^{i['target']}" for i in ok), notes
    if base == "RubyGems":
        return "bundle update " + " ".join(i["package"] for i in ok), notes
    if base == "Maven":
        notes.append("Set these versions in pom.xml or build.gradle, then rebuild.")
        return None, notes
    if kind == "product":
        notes.append("Matched from NVD product data. If these came from your distro's packages, the fix may already "
                     "be backported: check your distro's security tracker first.")
    return None, notes


def build(db: Session, host_id: int | None = None, repository_id: int | None = None) -> dict:
    q = (select(Finding).join(Component).join(Advisory)
         .where(Finding.status.in_(OPEN), Finding.currently_matching.is_(True), Component.missing_since.is_(None),
                Finding.match_status != m.UNKNOWN_VERSION))
    cq = select(Component).where(Component.missing_since.is_(None), Component.eol_state.in_(["eol", "eol_soon"]))
    if host_id is not None:
        q, cq = q.where(Component.host_id == host_id), cq.where(Component.host_id == host_id)
    if repository_id is not None:
        q, cq = q.where(Component.repository_id == repository_id), cq.where(Component.repository_id == repository_id)
    by_comp: dict[int, list[Finding]] = {}
    for f in db.scalars(q).all():
        by_comp.setdefault(f.component_id, []).append(f)

    groups: dict[tuple, dict] = {}
    no_fix = []
    for findings in by_comp.values():
        c = findings[0].component
        target, unfixed = target_version(c, findings)
        worst = max((f.advisory.severity for f in findings), key=lambda s: SEV.get(s, 0))
        key, title, kind = _group(c)
        item = {
            "component_id": c.id, "name": c.name, "package": c.source_package or c.name,
            "current": c.source_version or c.version, "target": target, "findings": len(findings),
            "worst": worst, "kev": any(f.advisory.kev for f in findings),
            "epss": max((f.advisory.epss or 0 for f in findings), default=0) or None,
            "possible_only": all(f.match_status == m.POSSIBLE for f in findings),
            "binaries": (c.details or {}).get("binaries") or [c.source_package or c.name],
            "advisories": sorted({f.advisory.id for f in findings})[:20],
            "unfixed": sorted({f.advisory.id for f in unfixed})[:20],
        }
        if target:
            g = groups.setdefault(key, {"title": title, "kind": kind, "base": m.ecosystem_base(c.ecosystem or ""),
                                        "path": _manifest(c) if c.repository_id else None,
                                        "host_id": c.host_id, "repository_id": c.repository_id, "items": []})
            g["items"].append(item)
        if unfixed:
            no_fix.append({**item, "target": None, "findings": len(unfixed)})

    out_groups = []
    for g in groups.values():
        g["items"].sort(key=lambda i: (not i["kev"], -SEV.get(i["worst"], 0), i["name"].lower()))
        g["command"], g["notes"] = _command(g["kind"], g["base"], g["path"], g["items"])
        g["worst"] = g["items"][0]["worst"]
        g["kev"] = any(i["kev"] for i in g["items"])
        out_groups.append(g)
    out_groups.sort(key=lambda g: (not g["kev"], -SEV.get(g["worst"], 0), g["title"].lower()))
    no_fix.sort(key=lambda i: (not i["kev"], -SEV.get(i["worst"], 0), i["name"].lower()))

    eol_items = [_eol_item(c.name, c.version, c.eol, c.id, None) for c in db.scalars(cq) if c.eol]
    hq = select(Host).where(Host.os_eol_state.in_(["eol", "eol_soon"]))
    if repository_id is not None:
        hq = hq.where(false())
    elif host_id is not None:
        hq = hq.where(Host.id == host_id)
    eol_items += [_eol_item(h.os_name or h.name, h.os_version, h.os_eol, None, h.id) for h in db.scalars(hq) if h.os_eol]
    eol_items.sort(key=lambda e: (e["state"] != "eol", e["eol_from"] or ""))

    return {"summary": {"components": len(by_comp), "findings": sum(map(len, by_comp.values())),
                        "upgrade_steps": len(out_groups), "no_fix": len(no_fix), "end_of_life": len(eol_items)},
            "groups": out_groups, "no_fix": no_fix, "end_of_life": eol_items,
            "notes": ["Test updates before deploying them. Patchy builds these steps from advisory data and cannot "
                      "guarantee an update is safe or complete.",
                      "Upgrading to the target version fixes every listed advisory that has a published fix."]}


def _eol_item(name: str, version: str | None, info: dict, component_id: int | None, host_id: int | None) -> dict:
    newest, latest = info.get("newest_supported"), info.get("newest_supported_latest")
    if info["state"] == "eol":
        advice = f"{info['label']} {info['cycle']} is out of support since {info.get('eol_from') or 'an earlier date'}."
    else:
        advice = f"{info['label']} {info['cycle']} leaves support on {info.get('eol_from')}."
    if newest:
        advice += f" Plan an upgrade to {info['label']} {newest}" + (f" (latest {latest})." if latest else ".")
    return {"name": name, "version": version, "component_id": component_id, "host_id": host_id, "state": info["state"],
            "cycle": info["cycle"], "eol_from": info.get("eol_from"), "advice": advice, "link": info.get("link")}
