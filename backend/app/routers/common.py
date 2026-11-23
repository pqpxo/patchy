"""Shared query helpers and ORM -> response conversion."""
import functools
import pathlib
import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import matching as m
from ..models import Component, Finding, Advisory
from ..schemas import AdvisoryOut, ComponentOut, FindingOut

OPEN = ("open", "acknowledged")
AGENT_SCRIPT = pathlib.Path(__file__).resolve().parents[3] / "agent" / "patchy_agent.py"


@functools.lru_cache(maxsize=1)
def bundled_agent_version() -> str | None:
    try:
        found = re.search(r'^VERSION = "([^"]+)"', AGENT_SCRIPT.read_text(encoding="utf-8"), re.M)
    except OSError:
        return None
    return found.group(1) if found else None


def paginate(db: Session, query, page: int, page_size: int):
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
    items = db.scalars(query.limit(page_size).offset((page - 1) * page_size)).unique().all()
    return items, total


def repo_label(repo) -> str | None:
    return f"{repo.owner}/{repo.name}" + (f"@{repo.branch}" if repo.branch else "") if repo else None


def finding_stats(db: Session, component_ids: list[int]) -> dict[int, tuple[int, str | None]]:
    """component_id -> (open finding count, worst severity) for currently-matching open findings."""
    if not component_ids:
        return {}
    rows = db.execute(select(Finding.component_id, Advisory.severity).join(Advisory).where(
        Finding.component_id.in_(component_ids), Finding.status.in_(OPEN),
        Finding.currently_matching.is_(True))).all()
    out: dict[int, tuple[int, str | None]] = {}
    for cid, sev in rows:
        n, worst = out.get(cid, (0, None))
        if worst is None or m.SEVERITY_ORDER.get(sev, 0) > m.SEVERITY_ORDER.get(worst, 0):
            worst = sev
        out[cid] = (n + 1, worst)
    return out


def check_state(c: Component, open_findings: int, stale: bool) -> str:
    """How much we actually know about this component's vulnerability status."""
    if c.missing_since:
        return "not_present"
    if open_findings:
        return "vulnerable"
    if not m.supports_osv(c.ecosystem) and not c.vuln_checked_at:
        return "not_checkable"  # neither OSV nor an NVD product match covers it
    if c.version_status != "exact" or not (c.source_version or c.version):
        return "version_unknown"
    if not c.vuln_checked_at:
        return "not_checked_yet"
    return "stale" if stale else "no_known_vulns"


def component_out(c: Component, stats: dict, stale: bool, cls=ComponentOut, **extra):
    n, worst = stats.get(c.id, (0, None))
    return cls.model_validate({
        **{k: getattr(c, k) for k in ComponentOut.model_fields if hasattr(c, k)},
        "host_name": c.host.name if c.host else None, "host_ip": c.host.ip if c.host else None,
        "repository_label": repo_label(c.repository), "repository_url": c.repository.url if c.repository else None,
        "check_state": check_state(c, n, stale), "open_findings": n, "max_severity": worst,
        "image": (c.details or {}).get("image"), **extra,
    })


def finding_out(f: Finding) -> FindingOut:
    c = f.component
    return FindingOut.model_validate({
        **{k: getattr(f, k) for k in FindingOut.model_fields if hasattr(f, k) and k != "advisory"},
        "component_name": c.name, "component_version": c.version, "component_type": c.component_type,
        "ecosystem": c.ecosystem, "host_id": c.host_id, "host_name": c.host.name if c.host else None,
        "repository_id": c.repository_id, "repository_label": repo_label(c.repository),
        "image": (c.details or {}).get("image"), "exposure": c.exposure, "exposure_note": c.exposure_note,
        "advisory": AdvisoryOut.model_validate(f.advisory),
    })
