"""Vulnerability matching: pure functions, no DB or network. Unit-tested in tests/test_matching.py.

Evaluates OSV `affected` entries (https://ossf.github.io/osv-schema/) against a component version.
Only ecosystems with a reliable local comparator are evaluated locally; everything else falls back to
OSV.dev's own server-side version match (osv_hit) or is reported as 'possible', never as clean.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import cmp_to_key
from typing import Callable

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

CONFIRMED, POSSIBLE, UNKNOWN_VERSION, NOT_AFFECTED = "confirmed", "possible", "unknown_version", "not_affected"

Cmp = Callable[[str, str], int]


# ---------- names ----------

def ecosystem_base(ecosystem: str) -> str:
    """'Debian:12' -> 'Debian', 'Ubuntu:22.04:LTS' -> 'Ubuntu'."""
    return (ecosystem or "").split(":", 1)[0]


def normalize_name(ecosystem: str, name: str) -> str:
    base = ecosystem_base(ecosystem)
    if base == "PyPI":
        return canonicalize_name(name)
    if base in ("Debian", "Ubuntu", "Alpine", "Packagist", "crates.io", "NuGet"):
        return name.lower()
    return name  # npm, Go, Maven, RubyGems are case-sensitive


# ---------- comparators (return None when a version cannot be parsed) ----------

def _cmp(a, b) -> int:
    return (a > b) - (a < b)


def cmp_pypi(a: str, b: str) -> int | None:
    try:
        return _cmp(Version(a), Version(b))
    except InvalidVersion:
        return None


_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _semver_key(v: str):
    m = _SEMVER.match(v.strip())
    if not m:
        return None
    pre = m.group(4)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))), (pre.split(".") if pre else None)


def cmp_semver(a: str, b: str) -> int | None:
    ka, kb = _semver_key(a), _semver_key(b)
    if ka is None or kb is None:
        return None
    if ka[0] != kb[0]:
        return _cmp(ka[0], kb[0])
    pa, pb = ka[1], kb[1]
    if pa is None or pb is None:  # release > prerelease
        return 0 if pa == pb else (1 if pa is None else -1)
    for x, y in zip(pa, pb):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return _cmp(int(x), int(y))
        if x.isdigit() != y.isdigit():
            return -1 if x.isdigit() else 1  # numeric identifiers sort lower
        return _cmp(x, y)
    return _cmp(len(pa), len(pb))


def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_part(a: str, b: str) -> int:
    """Debian policy 5.6.12 comparison of upstream_version / debian_revision."""
    i = j = 0
    while i < len(a) or j < len(b):
        diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return _cmp(ac, bc)
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not diff:
                diff = _cmp(a[i], b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if diff:
            return diff
    return 0


_DPKG = re.compile(r"^(?:(\d+):)?([0-9][A-Za-z0-9.+~:-]*?)(?:-([A-Za-z0-9.+~]+))?$")


def cmp_dpkg(a: str, b: str) -> int | None:
    ma, mb = _DPKG.match(a.strip()), _DPKG.match(b.strip())
    if not ma or not mb:
        return None
    ea, eb = int(ma.group(1) or 0), int(mb.group(1) or 0)
    if ea != eb:
        return _cmp(ea, eb)
    return _dpkg_part(ma.group(2), mb.group(2)) or _dpkg_part(ma.group(3) or "", mb.group(3) or "")


# ECOSYSTEM-type range comparators we trust. Anything absent is "unsupported locally".
ECOSYSTEM_COMPARATORS: dict[str, Cmp] = {
    "PyPI": cmp_pypi,
    "npm": cmp_semver,
    "Go": cmp_semver,
    "crates.io": cmp_semver,
    "Debian": cmp_dpkg,
    "Ubuntu": cmp_dpkg,
}

# Ecosystems for which Patchy queries OSV at all (shown honestly in the UI as coverage).
OSV_ECOSYSTEMS = {"PyPI", "npm", "Go", "crates.io", "Packagist", "Maven", "RubyGems", "NuGet",
                  "Debian", "Ubuntu", "Alpine", "Rocky Linux", "AlmaLinux"}


def supports_osv(ecosystem: str | None) -> bool:
    return bool(ecosystem) and ecosystem_base(ecosystem) in OSV_ECOSYSTEMS


def comparator_for(range_type: str, ecosystem: str) -> Cmp | None:
    if range_type == "SEMVER":
        return cmp_semver
    if range_type == "ECOSYSTEM":
        return ECOSYSTEM_COMPARATORS.get(ecosystem_base(ecosystem))
    return None  # GIT ranges reference commits, not versions


def compare(ecosystem: str, a: str, b: str) -> int | None:
    c = ECOSYSTEM_COMPARATORS.get(ecosystem_base(ecosystem))
    return c(a, b) if c else None


def sort_versions(ecosystem: str, versions) -> list[str]:
    """Ascending in ecosystem order where Patchy can compare; plain string order otherwise."""
    versions = list(versions)
    if all(compare(ecosystem, v, versions[0]) is not None for v in versions):
        return sorted(versions, key=cmp_to_key(lambda a, b: compare(ecosystem, a, b)))
    return sorted(versions)


# ---------- range evaluation ----------

def in_range(version: str, events: list[dict], cmp: Cmp) -> bool | None:
    """OSV event semantics. None if any event version can't be compared."""
    def order(x, y):
        vx, vy = next(iter(x.values())), next(iter(y.values()))
        if vx == "0":
            return -1 if vy != "0" else 0
        if vy == "0":
            return 1
        r = cmp(vx, vy)
        if r is None:
            raise ValueError
        return r

    try:
        events = sorted(events, key=cmp_to_key(order))
        affected = False
        for e in events:
            kind, ev = next(iter(e.items()))
            if kind == "introduced":
                r = 1 if ev == "0" else cmp(version, ev)
                if r is None:
                    return None
                if r >= 0:
                    affected = True
            elif kind in ("fixed", "limit", "last_affected"):
                r = cmp(version, ev)
                if r is None:
                    return None
                if (kind == "last_affected" and r > 0) or (kind != "last_affected" and r >= 0):
                    affected = False
        return affected
    except ValueError:
        return None


def describe_range(events: list[dict]) -> str:
    parts = []
    for e in events:
        kind, v = next(iter(e.items()))
        parts.append({"introduced": f">= {v}", "fixed": f"< {v}", "last_affected": f"<= {v}",
                      "limit": f"< {v} (limit)"}.get(kind, f"{kind} {v}"))
    return ", ".join(parts) if parts else "no range data"


@dataclass
class MatchResult:
    status: str
    evidence: str
    affected_ranges: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)


def entries_for(affected: list[dict], ecosystem: str, name: str) -> list[dict]:
    want_eco, want_name = ecosystem, normalize_name(ecosystem, name)
    out = []
    for a in affected or []:
        pkg = a.get("package") or {}
        eco = pkg.get("ecosystem", "")
        # 'Debian:12' must match exactly; a bare 'Debian' entry applies to all releases.
        eco_ok = eco == want_eco or (":" not in eco and eco == ecosystem_base(want_eco))
        if eco_ok and normalize_name(eco, pkg.get("name", "")) == want_name:
            out.append(a)
    return out


def evaluate(affected: list[dict], ecosystem: str, name: str, version: str | None,
             version_status: str = "exact", osv_hit: bool | None = None) -> MatchResult | None:
    """Return a MatchResult or None if the advisory does not concern this package.

    osv_hit: True/False if OSV.dev's version query did/didn't return this advisory for this exact
    version, None if no such query has been made.
    """
    entries = entries_for(affected, ecosystem, name)
    if not entries:
        return None
    ranges_txt, fixed = [], []
    for a in entries:
        for r in a.get("ranges") or []:
            ranges_txt.append(f"{r.get('type')}: {describe_range(r.get('events') or [])}")
            fixed += [e["fixed"] for e in r.get("events") or [] if "fixed" in e]
    fixed = sort_versions(ecosystem, set(fixed))

    if not version or version_status != "exact":
        why = "No version recorded" if not version else f"Only a version constraint is known ({version})"
        return MatchResult(UNKNOWN_VERSION, f"{why}; the package name and ecosystem match this advisory, "
                           "so it may apply. Record the installed version to confirm.", ranges_txt, fixed)

    def same(a, b):
        c = compare(ecosystem, a, b)
        return a == b if c is None else c == 0

    explicit = any(any(same(version, v) for v in a.get("versions") or []) for a in entries)
    if explicit:
        return MatchResult(CONFIRMED, f"Version {version} is listed as affected in the advisory.", ranges_txt, fixed)

    results = []
    for a in entries:
        for r in a.get("ranges") or []:
            cmp = comparator_for(r.get("type", ""), ecosystem)
            results.append((r, in_range(version, r.get("events") or [], cmp) if cmp else None))
    hit = [r for r, res in results if res is True]
    if hit:
        return MatchResult(CONFIRMED, f"Version {version} falls inside the affected range "
                           f"{describe_range(hit[0].get('events') or [])} ({hit[0].get('type')}).", ranges_txt, fixed)
    evaluated_all = bool(results) and all(res is False for _, res in results)
    if evaluated_all:
        if osv_hit:
            return MatchResult(POSSIBLE, f"OSV.dev reports {version} as affected but Patchy's range check "
                               "disagrees. Review the advisory manually.", ranges_txt, fixed)
        return MatchResult(NOT_AFFECTED, f"Version {version} is outside all affected ranges.", ranges_txt, fixed)
    # Could not evaluate locally (unsupported ecosystem comparator, GIT-only ranges, or unparseable version).
    if osv_hit is True:
        return MatchResult(CONFIRMED, f"OSV.dev's version-aware query reports {version} as affected "
                           f"(Patchy cannot compare {ecosystem_base(ecosystem)} versions locally).", ranges_txt, fixed)
    if osv_hit is False:
        return MatchResult(NOT_AFFECTED, f"OSV.dev's version-aware query does not report {version} as affected.",
                           ranges_txt, fixed)
    return MatchResult(POSSIBLE, f"Package matches, but version {version} could not be compared against the "
                       "affected ranges. Check the advisory.", ranges_txt, fixed)


# ---------- severity ----------

_CVSS3_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0},
    "A": {"H": 0.56, "L": 0.22, "N": 0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (i // 10000 + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """CVSS v3.0/3.1 base score from a vector string, per the FIRST specification."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _CVSS3_W["C"][m["C"]]) * (1 - _CVSS3_W["I"][m["I"]]) * (1 - _CVSS3_W["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _CVSS3_W["AV"][m["AV"]] * _CVSS3_W["AC"][m["AC"]] * pr * _CVSS3_W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        raw = 1.08 * (impact + expl) if scope_changed else impact + expl
        return _roundup(min(raw, 10))
    except (KeyError, ValueError):
        return None


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "none"


SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "moderate": 3, "low": 2, "none": 1, "unknown": 0}


def severity_from_osv(record: dict) -> tuple[str, float | None, str | None, str | None]:
    """(label, score, vector, source) from an OSV record. Never guesses."""
    for s in record.get("severity") or []:
        if s.get("type") == "CVSS_V3":
            score = cvss3_base_score(s.get("score", ""))
            if score is not None:
                return severity_from_score(score), score, s["score"], "CVSS v3 (OSV)"
    label = ((record.get("database_specific") or {}).get("severity") or "").lower()
    if label in SEVERITY_ORDER and label != "unknown":
        return ("medium" if label == "moderate" else label), None, None, "advisory label"
    for s in record.get("severity") or []:
        if s.get("type") == "CVSS_V4":
            return "unknown", None, s.get("score"), "CVSS v4 (not scored locally)"
    return "unknown", None, None, None
