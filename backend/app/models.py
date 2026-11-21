"""ORM models. Portable across PostgreSQL (production) and SQLite (tests)."""
from datetime import datetime, timezone

from sqlalchemy import (
    JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, TypeDecorator,
    UniqueConstraint, Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base, utcnow


class UTCDateTime(TypeDecorator):
    """Stores timezone-aware UTC; SQLite drops tzinfo so re-attach it on load."""
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value


TS = UTCDateTime


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(TS)


class UserSession(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(TS)
    user: Mapped[User] = relationship()


class Host(Base):
    __tablename__ = "hosts"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    ip: Mapped[str | None] = mapped_column(String(64))
    reported_hostname: Mapped[str | None] = mapped_column(String(255))
    os_name: Mapped[str | None] = mapped_column(String(255))
    os_id: Mapped[str | None] = mapped_column(String(64))
    os_version: Mapped[str | None] = mapped_column(String(64))
    kernel: Mapped[str | None] = mapped_column(String(255))
    arch: Mapped[str | None] = mapped_column(String(64))
    notes: Mapped[str | None] = mapped_column(Text)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    last_report_at: Mapped[datetime | None] = mapped_column(TS)
    os_eol_state: Mapped[str | None] = mapped_column(String(16))  # eol|eol_soon|supported, None = unknown
    os_eol: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    agent: Mapped["Agent | None"] = relationship(back_populates="host", cascade="all, delete-orphan")


class Agent(Base):
    """One revocable credential per host. Only a SHA-256 of the token is stored."""
    __tablename__ = "agents"
    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64))
    token_hint: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    rotated_at: Mapped[datetime | None] = mapped_column(TS)
    revoked_at: Mapped[datetime | None] = mapped_column(TS)
    last_seen_at: Mapped[datetime | None] = mapped_column(TS)
    last_ip: Mapped[str | None] = mapped_column(String(64))
    agent_version: Mapped[str | None] = mapped_column(String(32))
    host: Mapped[Host] = relationship(back_populates="agent")


class Repository(Base):
    __tablename__ = "repositories"
    __table_args__ = (UniqueConstraint("owner", "name", "branch"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(String(300))
    owner: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    branch: Mapped[str | None] = mapped_column(String(200))  # None = default branch
    is_private: Mapped[bool | None] = mapped_column(Boolean)
    last_revision: Mapped[str | None] = mapped_column(String(64))
    last_scanned_at: Mapped[datetime | None] = mapped_column(TS)
    languages: Mapped[dict | None] = mapped_column(JSON)
    dependabot: Mapped[dict | None] = mapped_column(JSON)  # latest Dependabot alerts cross-check
    notes: Mapped[str | None] = mapped_column(Text)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)


class ScanRun(Base):
    """Scan history and the job queue: kind repo|agent|feed, status queued|running|succeeded|partial|failed."""
    __tablename__ = "scan_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True, default="queued")
    repository_id: Mapped[int | None] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"))
    host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"))
    idempotency_key: Mapped[str | None] = mapped_column(String(200), unique=True)
    params: Mapped[dict | None] = mapped_column(JSON)
    revision: Mapped[str | None] = mapped_column(String(64))
    progress: Mapped[str | None] = mapped_column(String(300))
    summary: Mapped[dict | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(TS)
    finished_at: Mapped[datetime | None] = mapped_column(TS)
    repository: Mapped[Repository | None] = relationship()
    host: Mapped[Host | None] = relationship()


class Component(Base):
    """An inventoried piece of software (an 'asset' in the UI)."""
    __tablename__ = "components"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(300), index=True)
    component_type: Mapped[str] = mapped_column(String(32))
    vendor: Mapped[str | None] = mapped_column(String(200))
    ecosystem: Mapped[str | None] = mapped_column(String(64))  # OSV ecosystem name when known
    version: Mapped[str | None] = mapped_column(String(200))
    version_status: Mapped[str] = mapped_column(String(16), default="unknown")  # exact|constraint|unknown
    version_spec: Mapped[str | None] = mapped_column(String(300))  # declared constraint, eg ^1.2.0
    source_package: Mapped[str | None] = mapped_column(String(300))  # distro source package used for matching
    source_version: Mapped[str | None] = mapped_column(String(200))
    source: Mapped[str] = mapped_column(String(16))  # manual|repo|agent|demo
    detection: Mapped[str] = mapped_column(String(16), default="manual")  # manual|detected
    host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    repository_id: Mapped[int | None] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    listen_ip: Mapped[str | None] = mapped_column(String(64))
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(8))
    install_path: Mapped[str | None] = mapped_column(String(1024))
    details: Mapped[dict | None] = mapped_column(JSON)
    notes: Mapped[str | None] = mapped_column(Text)
    dedupe_key: Mapped[str | None] = mapped_column(String(800), unique=True)
    missing_since: Mapped[datetime | None] = mapped_column(TS)  # not seen in latest scan
    last_scan_run_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="SET NULL"))
    last_scanned_at: Mapped[datetime | None] = mapped_column(TS)
    vuln_checked_at: Mapped[datetime | None] = mapped_column(TS)
    cpe: Mapped[str | None] = mapped_column(String(200))  # optional "vendor:product" for NVD matching
    eol_state: Mapped[str | None] = mapped_column(String(16), index=True)  # eol|eol_soon|supported
    eol: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TS, default=utcnow, onupdate=utcnow)
    host: Mapped[Host | None] = relationship()
    repository: Mapped[Repository | None] = relationship()
    paths: Mapped[list["ComponentPath"]] = relationship(cascade="all, delete-orphan")


class ComponentPath(Base):
    __tablename__ = "component_paths"
    __table_args__ = (UniqueConstraint("component_id", "path"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    component_id: Mapped[int] = mapped_column(ForeignKey("components.id", ondelete="CASCADE"))
    path: Mapped[str] = mapped_column(String(1024))
    kind: Mapped[str] = mapped_column(String(16))  # manifest|config|executable|directory|install


class ComponentObservation(Base):
    """Per-scan sighting of a component: drives the asset's scan history."""
    __tablename__ = "component_observations"
    id: Mapped[int] = mapped_column(primary_key=True)
    component_id: Mapped[int] = mapped_column(ForeignKey("components.id", ondelete="CASCADE"), index=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    version: Mapped[str | None] = mapped_column(String(200))
    seen_at: Mapped[datetime] = mapped_column(TS, default=utcnow)


class HostService(Base):
    __tablename__ = "host_services"
    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    name: Mapped[str | None] = mapped_column(String(255))  # systemd unit or process name
    protocol: Mapped[str | None] = mapped_column(String(8))
    listen_ip: Mapped[str | None] = mapped_column(String(64))
    port: Mapped[int | None] = mapped_column(Integer)


class HostPath(Base):
    """Bounded listing of user-selected application directories (names only, never contents)."""
    __tablename__ = "host_paths"
    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    root: Mapped[str] = mapped_column(String(1024))
    path: Mapped[str] = mapped_column(String(2048))
    is_dir: Mapped[bool] = mapped_column(Boolean, default=False)


class Advisory(Base):
    __tablename__ = "advisories"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)  # OSV id, eg GHSA-xxxx
    source: Mapped[str] = mapped_column(String(16), default="osv")  # osv|demo
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[str | None] = mapped_column(Text)
    details: Mapped[str | None] = mapped_column(Text)
    published: Mapped[datetime | None] = mapped_column(TS)
    modified: Mapped[datetime | None] = mapped_column(TS)
    withdrawn: Mapped[datetime | None] = mapped_column(TS)
    severity: Mapped[str] = mapped_column(String(16), default="unknown")
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    severity_source: Mapped[str | None] = mapped_column(String(32))
    references: Mapped[list] = mapped_column(JSON, default=list)
    affected: Mapped[list] = mapped_column(JSON, default=list)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_date_added: Mapped[str | None] = mapped_column(String(16))
    kev_due_date: Mapped[str | None] = mapped_column(String(16))
    kev_required_action: Mapped[str | None] = mapped_column(Text)
    nvd_checked_at: Mapped[datetime | None] = mapped_column(TS)
    epss: Mapped[float | None] = mapped_column(Float)  # FIRST EPSS probability, 0-1
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    fetched_at: Mapped[datetime] = mapped_column(TS, default=utcnow)


class AdvisoryPackage(Base):
    __tablename__ = "advisory_packages"
    __table_args__ = (
        UniqueConstraint("advisory_id", "ecosystem", "name"),
        Index("ix_advpkg_lookup", "ecosystem", "name"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"))
    ecosystem: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(300))  # normalised


class OsvQuery(Base):
    """Cache of OSV answers for (ecosystem, package, version). version '' = version-less query."""
    __tablename__ = "osv_queries"
    __table_args__ = (UniqueConstraint("ecosystem", "name", "version"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(300))
    version: Mapped[str] = mapped_column(String(200), default="")
    vuln_ids: Mapped[list] = mapped_column(JSON, default=list)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    queried_at: Mapped[datetime] = mapped_column(TS, default=utcnow)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("component_id", "advisory_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    component_id: Mapped[int] = mapped_column(ForeignKey("components.id", ondelete="CASCADE"), index=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), index=True)
    match_status: Mapped[str] = mapped_column(String(16))  # confirmed|possible|unknown_version
    evidence: Mapped[str] = mapped_column(Text)
    affected_ranges: Mapped[list] = mapped_column(JSON, default=list)
    fixed_versions: Mapped[list] = mapped_column(JSON, default=list)
    remediation: Mapped[str] = mapped_column(Text)
    currently_matching: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|acknowledged|resolved|false_positive
    status_note: Mapped[str | None] = mapped_column(Text)
    status_changed_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    status_changed_by: Mapped[str] = mapped_column(String(64), default="system")
    first_detected_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    last_checked_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    component: Mapped[Component] = relationship()
    advisory: Mapped[Advisory] = relationship()


class FeedStatus(Base):
    __tablename__ = "feed_status"
    source: Mapped[str] = mapped_column(String(16), primary_key=True)  # osv|kev|nvd
    last_attempt_at: Mapped[datetime | None] = mapped_column(TS)
    last_success_at: Mapped[datetime | None] = mapped_column(TS)
    last_error: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict | None] = mapped_column(JSON)


class AppSetting(Base):
    """Settings changed from the UI (feed schedules). Secrets stay in environment variables."""
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(TS, default=utcnow, onupdate=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(TS, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict | None] = mapped_column(JSON)
    ip: Mapped[str | None] = mapped_column(String(64))
