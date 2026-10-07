"""SQLAlchemy models for all Web Sentinel tables."""

from __future__ import annotations

import enum
from datetime import date, datetime, time
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Time,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# SQLite (local runs without Docker) only auto-increments plain INTEGER primary keys.
BigIntPk = BigInteger().with_variant(Integer, "sqlite")


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, datetime: DateTime(timezone=True)}


class Criticality(enum.StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Role(enum.StrEnum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Severity(enum.StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    SECURITY = "security"
    MALWARE = "malware"


class CheckType(enum.StrEnum):
    HTTP = "http"
    DNS = "dns"
    TLS = "tls"
    DOMAIN = "domain"
    ENDPOINT = "endpoint"
    CONTENT = "content"
    FLOW = "flow"


class CheckStatus(enum.StrEnum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


class IncidentStatus(enum.StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class ContactKind(enum.StrEnum):
    TECHNICAL = "technical"
    BUSINESS = "business"


def _created_at() -> Mapped[datetime]:
    return mapped_column(server_default=func.now())


# --- Inventory -------------------------------------------------------------


class Site(Base):
    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    url: Mapped[str] = mapped_column(String(500), unique=True)
    criticality: Mapped[str] = mapped_column(String(10), default=Criticality.MEDIUM)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Authorization to monitor the site (who, when): checks run only when both are set.
    authorized_by: Mapped[str | None] = mapped_column(String(200))
    authorized_at: Mapped[date | None] = mapped_column(Date)
    domain_check_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    contacts: Mapped[list[SiteContact]] = relationship(
        back_populates="site", cascade="all, delete-orphan", order_by="SiteContact.kind"
    )
    checks: Mapped[list[Check]] = relationship(
        back_populates="site", cascade="all, delete-orphan", order_by="Check.id"
    )

    @property
    def is_authorized(self) -> bool:
        return bool(self.authorized_by) and self.authorized_at is not None

    @property
    def status(self) -> str:
        """Overall state from the last result of the enabled checks: ok, warn, fail or pending."""
        results = {check.last_status for check in self.checks if check.enabled}
        for state in (CheckStatus.FAIL, CheckStatus.WARN, CheckStatus.OK):
            if state in results:
                return state.value
        return "pending"

    def contact(self, kind: str) -> SiteContact | None:
        return next((c for c in self.contacts if c.kind == kind), None)


class SiteContact(Base):
    __tablename__ = "site_contacts"
    __table_args__ = (UniqueConstraint("site_id", "kind"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(20))
    name: Mapped[str | None] = mapped_column(String(200))
    email: Mapped[str | None] = mapped_column(String(254))
    phone: Mapped[str | None] = mapped_column(String(50))

    site: Mapped[Site] = relationship(back_populates="contacts")


# --- Active monitoring -----------------------------------------------------


class Check(Base):
    __tablename__ = "checks"

    id: Mapped[int] = mapped_column(primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(20))
    target: Mapped[str] = mapped_column(String(500))
    interval_seconds: Mapped[int] = mapped_column(Integer)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=10)
    thresholds: Mapped[dict[str, Any]] = mapped_column(default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_status: Mapped[str | None] = mapped_column(String(10))
    last_run_at: Mapped[datetime | None] = mapped_column()
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = _created_at()

    site: Mapped[Site] = relationship(back_populates="checks")


class CheckResult(Base):
    __tablename__ = "check_results"
    __table_args__ = (Index("ix_check_results_site_created", "site_id", "created_at"),)

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True)
    check_id: Mapped[int] = mapped_column(ForeignKey("checks.id", ondelete="CASCADE"), index=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(10))
    value: Mapped[float | None] = mapped_column(Float)
    message: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = _created_at()


# --- Incidents -------------------------------------------------------------


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_site_status", "site_id", "status"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    check_id: Mapped[int | None] = mapped_column(ForeignKey("checks.id", ondelete="SET NULL"))
    severity: Mapped[str] = mapped_column(String(10))
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(15), default=IncidentStatus.OPEN)
    recommended_action: Mapped[str | None] = mapped_column(Text)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    opened_at: Mapped[datetime] = mapped_column(server_default=func.now())
    acknowledged_at: Mapped[datetime | None] = mapped_column()
    closed_at: Mapped[datetime | None] = mapped_column()

    events: Mapped[list[IncidentEvent]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="IncidentEvent.id"
    )


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(30))
    message: Mapped[str] = mapped_column(Text)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = _created_at()

    incident: Mapped[Incident] = relationship(back_populates="events")


# --- Alerts ----------------------------------------------------------------


class AlertRule(Base):
    """Delivery policy for one severity."""

    __tablename__ = "alert_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    severity: Mapped[str] = mapped_column(String(10), unique=True)
    immediate: Mapped[bool] = mapped_column(Boolean, default=True)
    # Sending window for immediate alerts; both NULL means 24/7.
    active_from: Mapped[time | None] = mapped_column(Time)
    active_to: Mapped[time | None] = mapped_column(Time)
    digest_time: Mapped[time | None] = mapped_column(Time)
    dedup_minutes: Mapped[int | None] = mapped_column(Integer)
    reminder_minutes: Mapped[int | None] = mapped_column(Integer)
    # none | auto (on recovery) | manual (when the incident is closed by hand)
    recovery_mode: Mapped[str] = mapped_column(String(10), default="none")
    silenceable: Mapped[bool] = mapped_column(Boolean, default=True)


class AlertRecipient(Base):
    """Recipient; NULL site_id/severity means "all sites"/"all severities"."""

    __tablename__ = "alert_recipients"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254))
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    severity: Mapped[str | None] = mapped_column(String(10))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class AlertLog(Base):
    __tablename__ = "alert_log"
    __table_args__ = (Index("ix_alert_log_site_sent", "site_id", "sent_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"))
    severity: Mapped[str] = mapped_column(String(10))
    kind: Mapped[str] = mapped_column(String(20))
    recipient: Mapped[str] = mapped_column(String(254))
    subject: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20))
    error: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Silence(Base):
    __tablename__ = "silences"

    id: Mapped[int] = mapped_column(primary_key=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    severity: Mapped[str | None] = mapped_column(String(10))
    starts_at: Mapped[datetime] = mapped_column()
    ends_at: Mapped[datetime] = mapped_column()
    recurrence: Mapped[str | None] = mapped_column(String(100))
    reason: Mapped[str | None] = mapped_column(Text)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = _created_at()


class MaintenanceWindow(Base):
    __tablename__ = "maintenance_windows"

    id: Mapped[int] = mapped_column(primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    starts_at: Mapped[datetime] = mapped_column()
    ends_at: Mapped[datetime] = mapped_column()
    recurrence: Mapped[str | None] = mapped_column(String(100))
    description: Mapped[str | None] = mapped_column(Text)
    # Release window: file changes detected inside it are considered authorized.
    is_release: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = _created_at()


# --- Agent, logs, security -------------------------------------------------


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    token_hash: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[str | None] = mapped_column(String(50))
    last_heartbeat_at: Mapped[datetime | None] = mapped_column()
    created_at: Mapped[datetime] = _created_at()


class LogBucket(Base):
    """Per-minute aggregate of access log lines sent by an agent."""

    __tablename__ = "log_buckets"
    __table_args__ = (
        UniqueConstraint("site_id", "bucket_start"),
        Index("ix_log_buckets_site_created", "site_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    bucket_start: Mapped[datetime] = mapped_column()
    requests: Mapped[int] = mapped_column(Integer, default=0)
    status_counts: Mapped[dict[str, Any]] = mapped_column(default=dict)
    top_paths: Mapped[dict[str, Any]] = mapped_column(default=dict)
    top_user_agents: Mapped[dict[str, Any]] = mapped_column(default=dict)
    distinct_sources: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = _created_at()


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (Index("ix_security_events_site_created", "site_id", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(10))
    # Pseudonymized source (HMAC-SHA256 of the IP), never the clear IP.
    source_pseudonym: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = _created_at()


class FimBaseline(Base):
    __tablename__ = "fim_baseline"
    __table_args__ = (UniqueConstraint("site_id", "path"),)

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    path: Mapped[str] = mapped_column(String(1000))
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int | None] = mapped_column(BigInteger)
    mode: Mapped[str | None] = mapped_column(String(10))
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class FimChange(Base):
    __tablename__ = "fim_changes"
    __table_args__ = (Index("ix_fim_changes_site_detected", "site_id", "detected_at"),)

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    path: Mapped[str] = mapped_column(String(1000))
    change_type: Mapped[str] = mapped_column(String(10))
    old_sha256: Mapped[str | None] = mapped_column(String(64))
    new_sha256: Mapped[str | None] = mapped_column(String(64))
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    detected_at: Mapped[datetime] = mapped_column(server_default=func.now())


class ReputationResult(Base):
    __tablename__ = "reputation_results"
    __table_args__ = (Index("ix_reputation_results_site_checked", "site_id", "checked_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(50))
    target: Mapped[str] = mapped_column(String(255))
    listed: Mapped[bool] = mapped_column(Boolean, default=False)
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    checked_at: Mapped[datetime] = mapped_column(server_default=func.now())


# --- Users, audit, worker --------------------------------------------------


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    full_name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(300))
    role: Mapped[str] = mapped_column(String(10), default=Role.VIEWER)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column()
    created_at: Mapped[datetime] = _created_at()


class AuditLog(Base):
    """Append-only: a database trigger rejects UPDATE and DELETE."""

    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_log_created", "created_at"),)

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True)
    # No foreign key on purpose: rows must survive (unchanged) the removal of a user.
    user_id: Mapped[int | None] = mapped_column(Integer)
    user_email: Mapped[str | None] = mapped_column(String(254))
    action: Mapped[str] = mapped_column(String(60))
    object_type: Mapped[str | None] = mapped_column(String(40))
    object_id: Mapped[str | None] = mapped_column(String(60))
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = _created_at()


class WorkerHeartbeat(Base):
    """Single row (id=1) updated periodically by the worker process."""

    __tablename__ = "worker_heartbeat"

    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column()
    last_beat_at: Mapped[datetime] = mapped_column()
