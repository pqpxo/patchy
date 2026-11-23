"""Feed sources and their refresh schedule.

Defaults come from environment variables; the Settings page can switch a source on or off and change
how often it refreshes (stored in app_settings). Secrets never live here.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from .config import settings
from .db import utcnow
from .models import AppSetting, FeedStatus

# Refresh order matters: matching needs OSV/NVD/EOL data, EPSS/NVD severity/Dependabot need findings.
ORDER = ("kev", "osv", "nvd_cpe", "eol", "epss", "nvd", "dependabot", "images")
BEFORE_MATCH = ("kev", "osv", "nvd_cpe", "eol")
HOUR_CHOICES = (0, 1, 3, 6, 12, 24, 48, 72, 168)  # 0 = manual refresh only

INFO = {
    "osv": ("OSV.dev", "Package advisories for PyPI, npm, Go, crates.io, Maven, Debian, Ubuntu, Alpine and more."),
    "kev": ("CISA KEV", "Catalogue of vulnerabilities known to be exploited in the wild."),
    "nvd_cpe": ("NVD product matching", "Checks servers, runtimes and manual assets that OSV can't, using NVD's "
                                        "CPE version ranges. Results are 'possible' because distros backport fixes."),
    "eol": ("endoflife.date", "Support and end-of-life dates for runtimes, operating systems, servers and frameworks."),
    "epss": ("FIRST EPSS", "Daily probability that each CVE is exploited in the next 30 days. Used to rank fixes."),
    "nvd": ("NVD severity", "Fills in CVSS scores for advisories that don't carry one. Slow without NVD_API_KEY."),
    "dependabot": ("GitHub Dependabot", "Cross-checks each scanned repository's Dependabot alerts against "
                                        "Patchy's findings."),
    "images": ("Container image updates", "Asks Docker Hub, GHCR, Quay and other public registries whether each running "
                                          "container's tag now points at a newer build. Off by default; Diun and "
                                          "Watchtower do this too."),
}


def _defaults() -> dict[str, tuple[bool, int]]:
    hours = max(settings.feed_refresh_hours, 0)
    return {
        "osv": (settings.osv_enabled, hours), "kev": (settings.kev_enabled, hours),
        "nvd_cpe": (settings.nvd_cpe_enabled, hours), "eol": (settings.eol_enabled, 168 if hours else 0),
        "epss": (settings.epss_enabled, hours), "nvd": (settings.nvd_enabled, hours),
        "dependabot": (settings.dependabot_enabled, hours),
        "images": (settings.image_updates_enabled, 24 if hours else 0),
    }


def unavailable_reason(key: str) -> str | None:
    if key == "dependabot" and not settings.github_token:
        return "Needs GITHUB_TOKEN with the 'Dependabot alerts: read' permission."
    return None


def schedule(db: Session) -> dict[str, dict]:
    row = db.get(AppSetting, "sources")
    saved = row.value if row else {}
    out = {}
    for key, (enabled, hours) in _defaults().items():
        o = saved.get(key) or {}
        reason = unavailable_reason(key)
        out[key] = {"label": INFO[key][0], "about": INFO[key][1], "unavailable": reason,
                    "enabled": bool(o.get("enabled", enabled)) and not reason,
                    "hours": int(o.get("hours", hours))}
    return out


def save(db: Session, changes: dict[str, dict]) -> dict[str, dict]:
    row = db.get(AppSetting, "sources") or AppSetting(key="sources", value={})
    value = dict(row.value or {})
    for key, c in changes.items():
        value[key] = {**(value.get(key) or {}), **c}
    row.value = value  # reassign so the JSON column is marked dirty
    db.add(row)
    db.flush()
    return schedule(db)


def due(db: Session) -> list[str]:
    now, out = utcnow(), []
    for key, s in schedule(db).items():
        if not s["enabled"] or not s["hours"]:
            continue
        f = db.get(FeedStatus, key)
        hours = min(1, s["hours"]) if f and f.last_error else s["hours"]  # a failed source retries hourly
        if not f or not f.last_attempt_at or f.last_attempt_at < now - timedelta(hours=hours):
            out.append(key)
    return [k for k in ORDER if k in out]
