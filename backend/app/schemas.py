"""Request/response models. Inputs are strict; outputs never include secrets or file contents."""
from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Annotated, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

T = TypeVar("T")
Str = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]
OptStr = Annotated[str | None, StringConstraints(strip_whitespace=True, max_length=255)]
Notes = Annotated[str | None, StringConstraints(max_length=5000)]

ComponentType = Literal["language", "library", "web_server", "database", "os_package", "container_image",
                        "application", "service", "other"]
Ecosystem = Literal["PyPI", "npm", "Go", "crates.io", "Packagist", "Maven", "RubyGems", "NuGet"]
FindingStatus = Literal["open", "acknowledged", "resolved", "false_positive"]


class In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


# ---------- auth ----------

class LoginIn(In):
    username: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=256)]


class PasswordChangeIn(In):
    current_password: Annotated[str, StringConstraints(max_length=256)]
    new_password: Annotated[str, StringConstraints(min_length=12, max_length=256)]


class MeOut(BaseModel):
    username: str
    csrf_token: str


# ---------- inventory ----------

def _ip(v):
    if v:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("not a valid IPv4 or IPv6 address") from None
    return v or None


class AssetIn(In):
    name: Str
    component_type: ComponentType
    vendor: OptStr = None
    ecosystem: Ecosystem | None = None
    version: Annotated[str | None, StringConstraints(strip_whitespace=True, max_length=200)] = None
    version_status: Literal["exact", "constraint", "unknown"] = "exact"
    host_name: OptStr = None
    host_ip: OptStr = None
    listen_ip: OptStr = None
    port: int | None = Field(None, ge=1, le=65535)
    protocol: Literal["tcp", "udp"] | None = None
    install_path: Annotated[str | None, StringConstraints(max_length=1024)] = None
    repository_url: Annotated[str | None, StringConstraints(strip_whitespace=True, max_length=300)] = None
    branch: Annotated[str | None, StringConstraints(strip_whitespace=True, max_length=200)] = None
    cpe: Annotated[str | None, StringConstraints(strip_whitespace=True, to_lower=True, max_length=200,
                                                 pattern=r"^[A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+$")] = None
    notes: Notes = None

    _v_ip = field_validator("host_ip", "listen_ip")(lambda cls, v: _ip(v))


class HostIn(In):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255,
                                           pattern=r"^[A-Za-z0-9._-]+$")]
    ip: OptStr = None
    notes: Notes = None

    _v_ip = field_validator("ip")(lambda cls, v: _ip(v))


class RepoIn(In):
    url: Annotated[str, StringConstraints(strip_whitespace=True, max_length=300)]
    branch: Annotated[str | None, StringConstraints(strip_whitespace=True, max_length=200)] = None
    notes: Notes = None


class FindingStatusIn(In):
    status: FindingStatus
    note: Annotated[str | None, StringConstraints(max_length=2000)] = None


class PathOut(Out):
    path: str
    kind: str


class ComponentOut(Out):
    id: int
    name: str
    component_type: str
    vendor: str | None
    ecosystem: str | None
    version: str | None
    version_status: str
    version_spec: str | None
    source_package: str | None
    source: str
    detection: str
    host_id: int | None
    host_name: str | None = None
    host_ip: str | None = None
    repository_id: int | None
    repository_label: str | None = None
    repository_url: str | None = None
    listen_ip: str | None
    port: int | None
    protocol: str | None
    install_path: str | None
    notes: str | None
    details: dict | None
    missing_since: datetime | None
    last_scanned_at: datetime | None
    vuln_checked_at: datetime | None
    cpe: str | None = None
    eol_state: str | None = None
    eol: dict | None = None
    created_at: datetime
    updated_at: datetime
    check_state: str = "unknown"
    open_findings: int = 0
    max_severity: str | None = None


class ObservationOut(Out):
    scan_run_id: int
    version: str | None
    seen_at: datetime
    kind: str | None = None
    status: str | None = None


class AdvisoryOut(Out):
    id: str
    source: str
    aliases: list
    cve_ids: list
    summary: str | None
    details: str | None
    published: datetime | None
    modified: datetime | None
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    severity_source: str | None
    references: list
    kev: bool
    kev_date_added: str | None
    kev_due_date: str | None
    kev_required_action: str | None
    epss: float | None = None
    epss_percentile: float | None = None
    fetched_at: datetime


class FindingOut(Out):
    id: int
    component_id: int
    component_name: str
    component_version: str | None
    component_type: str
    ecosystem: str | None
    host_id: int | None
    host_name: str | None
    repository_id: int | None
    repository_label: str | None
    advisory: AdvisoryOut
    match_status: str
    evidence: str
    affected_ranges: list
    fixed_versions: list
    remediation: str
    currently_matching: bool
    status: str
    status_note: str | None
    status_changed_at: datetime
    status_changed_by: str
    first_detected_at: datetime
    last_checked_at: datetime


class ComponentDetail(ComponentOut):
    paths: list[PathOut]
    history: list[ObservationOut]
    findings: list[FindingOut]


class AgentOut(Out):
    id: int
    token_hint: str
    created_at: datetime
    rotated_at: datetime | None
    revoked_at: datetime | None
    last_seen_at: datetime | None
    last_ip: str | None
    agent_version: str | None


class HostOut(Out):
    id: int
    name: str
    ip: str | None
    reported_hostname: str | None
    os_name: str | None
    os_id: str | None = None
    os_version: str | None
    os_eol_state: str | None = None
    os_eol: dict | None = None
    kernel: str | None
    arch: str | None
    notes: str | None
    is_demo: bool
    last_report_at: datetime | None
    created_at: datetime
    agent: AgentOut | None = None
    agent_outdated: bool = False
    component_count: int = 0
    open_findings: int = 0


class ServiceOut(Out):
    name: str | None
    protocol: str | None
    listen_ip: str | None
    port: int | None


class HostPathOut(Out):
    root: str
    path: str
    is_dir: bool


class AgentTokenOut(BaseModel):
    agent: AgentOut
    token: str
    note: str = "Shown once. Patchy stores only a hash of this token."


class RepoOut(Out):
    id: int
    url: str
    owner: str
    name: str
    branch: str | None
    is_private: bool | None
    last_revision: str | None
    last_scanned_at: datetime | None
    languages: dict | None
    notes: str | None
    is_demo: bool
    created_at: datetime
    component_count: int = 0
    open_findings: int = 0
    last_scan_status: str | None = None
    dependabot_total: int | None = None
    dependabot_only: int | None = None
    dependabot_error: str | None = None


class ScanRunOut(Out):
    id: int
    kind: str
    status: str
    repository_id: int | None
    host_id: int | None
    target_label: str | None = None
    revision: str | None
    progress: str | None
    summary: dict | None
    error: str | None
    params: dict | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class FeedOut(BaseModel):
    source: str
    label: str = ""
    about: str = ""
    hours: int = 0
    unavailable: str | None = None
    enabled: bool
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    last_error: str | None
    stale: bool
    detail: dict | None


class AuditOut(Out):
    id: int
    at: datetime
    actor: str
    action: str
    target_type: str | None
    target_id: str | None
    detail: dict | None
    ip: str | None


class SourceIn(In):
    enabled: bool | None = None
    hours: int | None = None

    @field_validator("hours")
    @classmethod
    def _hours(cls, v):
        from .sources import HOUR_CHOICES
        if v is not None and v not in HOUR_CHOICES:
            raise ValueError(f"hours must be one of {', '.join(map(str, HOUR_CHOICES))}")
        return v


class RefreshIn(In):
    sources: list[Literal["osv", "kev", "nvd_cpe", "eol", "epss", "nvd", "dependabot"]] | None = None
