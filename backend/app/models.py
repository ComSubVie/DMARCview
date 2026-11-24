"""SQLModel schema.

Two report families are stored:

* ``Report`` / ``SourceRecord`` – DMARC aggregate (RUA) reports, one row per
  reporter report and one row per ``<record>`` inside it.
* ``TlsReport`` / ``TlsPolicy`` / ``TlsFailure`` – TLS-RPT (RFC 8460) reports.

``ProcessedMessage`` provides idempotency at the e-mail level so a message
containing several attachments (or a re-run of the poller) is only ingested
once.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, Column, Index, LargeBinary, Text, UniqueConstraint
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    """Timezone-aware UTC now (SQLModel 0.0.50+ stores aware datetimes)."""
    return datetime.now(timezone.utc)


def to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class Domain(SQLModel, table=True):
    __tablename__ = "domains"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True, max_length=255)
    display_name: Optional[str] = Field(default=None, max_length=255)
    notes: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utcnow)


class Report(SQLModel, table=True):
    """One DMARC aggregate report (one ``<feedback>`` document)."""

    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint("org_name", "report_id", "domain_id", name="uq_report_org_reportid_domain"),
        Index("ix_reports_domain_date", "domain_id", "report_date"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    domain_id: int = Field(foreign_key="domains.id", index=True)
    org_name: str = Field(index=True, max_length=255)
    org_email: Optional[str] = Field(default=None, max_length=320)
    report_id: str = Field(max_length=255)
    policy_domain: Optional[str] = Field(default=None, max_length=255)

    date_begin: datetime = Field(index=True)
    date_end: datetime
    report_date: date = Field(index=True)

    policy_p: Optional[str] = Field(default=None, max_length=32)
    policy_sp: Optional[str] = Field(default=None, max_length=32)
    policy_np: Optional[str] = Field(default=None, max_length=32)
    policy_pct: Optional[int] = Field(default=None)
    policy_testing: Optional[str] = Field(default=None, max_length=8)
    policy_discovery: Optional[str] = Field(default=None, max_length=32)
    policy_adkim: Optional[str] = Field(default=None, max_length=16)
    policy_aspf: Optional[str] = Field(default=None, max_length=16)
    policy_fo: Optional[str] = Field(default=None, max_length=32)

    record_count: int = Field(default=0)
    message_count: int = Field(default=0)
    aligned_count: int = Field(default=0)
    failed_count: int = Field(default=0)
    source_count: int = Field(default=0)

    message_id: Optional[str] = Field(default=None, max_length=512)
    raw_sha256: str = Field(unique=True, index=True, max_length=64)
    raw_xml: bytes = Field(sa_column=Column(LargeBinary))
    source: str = Field(default="jmap", max_length=32)
    received_at: Optional[datetime] = Field(default=None)
    ingested_at: datetime = Field(default_factory=utcnow)

    @property
    def aligned_pct(self) -> float:
        return (self.aligned_count / self.message_count * 100.0) if self.message_count else 0.0


class SourceRecord(SQLModel, table=True):
    """A ``<record>`` from a DMARC aggregate report, exploded for analytics."""

    __tablename__ = "source_records"
    __table_args__ = (
        Index("ix_source_records_domain_date", "domain_id", "report_date"),
        Index("ix_source_records_ip", "source_ip"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    report_id: int = Field(foreign_key="reports.id", index=True)
    domain_id: int = Field(foreign_key="domains.id", index=True)
    report_date: date = Field(index=True)

    source_ip: str = Field(max_length=64, index=True)
    message_count: int = Field(default=0)
    disposition: Optional[str] = Field(default=None, max_length=32)
    dkim_pass: bool = Field(default=False)
    spf_pass: bool = Field(default=False)
    dkim_signed: bool = Field(default=False)
    #: Raw (unaligned) authentication results, used for the per-source cells.
    dkim_auth_pass: bool = Field(default=False)
    spf_auth_pass: bool = Field(default=False)

    header_from: Optional[str] = Field(default=None, max_length=255)
    envelope_from: Optional[str] = Field(default=None, max_length=512)
    envelope_to: Optional[str] = Field(default=None, max_length=512)

    dkim_domains: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    dkim_selectors: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    dkim_results: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    spf_domains: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    spf_results: list[str] = Field(default_factory=list, sa_column=Column(JSON))

    reason_type: Optional[str] = Field(default=None, max_length=64)
    reason_comment: Optional[str] = Field(default=None, sa_column=Column(Text))

    country_code: Optional[str] = Field(default=None, max_length=2, index=True)
    country_name: Optional[str] = Field(default=None, max_length=128)

    @property
    def aligned(self) -> bool:
        return bool(self.dkim_pass or self.spf_pass)


class TlsReport(SQLModel, table=True):
    """One TLS-RPT report (RFC 8460 JSON document)."""

    __tablename__ = "tls_reports"
    __table_args__ = (
        UniqueConstraint("org_name", "report_id", "domain_id", name="uq_tls_org_reportid_domain"),
        Index("ix_tls_reports_domain_date", "domain_id", "report_date"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    domain_id: int = Field(foreign_key="domains.id", index=True)
    org_name: str = Field(index=True, max_length=255)
    report_id: str = Field(max_length=255)
    contact_info: Optional[str] = Field(default=None, max_length=1024)

    date_begin: datetime = Field(index=True)
    date_end: datetime
    report_date: date = Field(index=True)

    policy_type: Optional[str] = Field(default=None, max_length=32)
    policy_mode: Optional[str] = Field(default=None, max_length=32)
    policy_domain: Optional[str] = Field(default=None, max_length=255)
    policy_string: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    mx_hosts: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    max_age: Optional[int] = Field(default=None)

    total_success: int = Field(default=0)
    total_failure: int = Field(default=0)

    message_id: Optional[str] = Field(default=None, max_length=512)
    raw_sha256: str = Field(unique=True, index=True, max_length=64)
    raw_json: bytes = Field(sa_column=Column(LargeBinary))
    source: str = Field(default="jmap", max_length=32)
    received_at: Optional[datetime] = Field(default=None)
    ingested_at: datetime = Field(default_factory=utcnow)


class TlsPolicy(SQLModel, table=True):
    __tablename__ = "tls_policies"

    id: Optional[int] = Field(default=None, primary_key=True)
    tls_report_id: int = Field(foreign_key="tls_reports.id", index=True)
    domain_id: int = Field(foreign_key="domains.id", index=True)
    report_date: date = Field(index=True)

    policy_type: Optional[str] = Field(default=None, max_length=32)
    policy_domain: Optional[str] = Field(default=None, max_length=255)
    mx_hosts: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    total_success: int = Field(default=0)
    total_failure: int = Field(default=0)


class TlsFailure(SQLModel, table=True):
    __tablename__ = "tls_failures"
    __table_args__ = (Index("ix_tls_failures_domain_date", "domain_id", "report_date"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    tls_report_id: int = Field(foreign_key="tls_reports.id", index=True)
    domain_id: int = Field(foreign_key="domains.id", index=True)
    report_date: date = Field(index=True)

    policy_domain: Optional[str] = Field(default=None, max_length=255)
    receiving_mx: Optional[str] = Field(default=None, max_length=255)
    result_type: Optional[str] = Field(default=None, max_length=128)
    sending_mta_ip: Optional[str] = Field(default=None, max_length=64)
    failed_count: int = Field(default=0)
    reason_code: Optional[str] = Field(default=None, max_length=128)
    additional_info: Optional[str] = Field(default=None, sa_column=Column(Text))

    country_code: Optional[str] = Field(default=None, max_length=2)
    country_name: Optional[str] = Field(default=None, max_length=128)


class ProcessedMessage(SQLModel, table=True):
    """E-mail level idempotency record."""

    __tablename__ = "processed_messages"

    id: Optional[int] = Field(default=None, primary_key=True)
    source: str = Field(max_length=32)
    source_key: str = Field(unique=True, index=True, max_length=128)
    message_id: Optional[str] = Field(default=None, max_length=512)
    subject: Optional[str] = Field(default=None, max_length=512)
    sender: Optional[str] = Field(default=None, max_length=512)
    received_at: Optional[datetime] = Field(default=None)
    processed_at: datetime = Field(default_factory=utcnow)
    status: str = Field(default="ok", max_length=32)
    reports_created: int = Field(default=0)
    error: Optional[str] = Field(default=None, sa_column=Column(Text))


class IngestRun(SQLModel, table=True):
    __tablename__ = "ingest_runs"

    id: Optional[int] = Field(default=None, primary_key=True)
    source: str = Field(max_length=32)
    started_at: datetime = Field(default_factory=utcnow, index=True)
    finished_at: Optional[datetime] = Field(default=None)
    status: str = Field(default="running", max_length=32)
    messages_seen: int = Field(default=0)
    messages_ingested: int = Field(default=0)
    reports_created: int = Field(default=0)
    tls_reports_created: int = Field(default=0)
    error: Optional[str] = Field(default=None, sa_column=Column(Text))
    detail: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))


class SyncState(SQLModel, table=True):
    """Small key/value store for incremental sync cursors."""

    __tablename__ = "sync_state"

    key: str = Field(primary_key=True, max_length=64)
    value: str = Field(max_length=512)
    updated_at: datetime = Field(default_factory=utcnow)


DEFAULT_DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "mail",
    "s1",
    "stalwart",
]


class DomainSettings(SQLModel, table=True):
    """Per-domain configuration for health checks and probes."""

    __tablename__ = "domain_settings"

    domain_id: int = Field(foreign_key="domains.id", primary_key=True)
    dkim_selectors: list[str] = Field(
        default_factory=lambda: list(DEFAULT_DKIM_SELECTORS), sa_column=Column(JSON)
    )
    probe_targets: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    expected_report_hours: int = Field(default=48)
    dns_checks_enabled: bool = Field(default=True)
    checks_muted_until: Optional[datetime] = Field(default=None)
    updated_at: datetime = Field(default_factory=utcnow)


class ShareLink(SQLModel, table=True):
    """A signed, revocable read-only link. Only the token hash is stored."""

    __tablename__ = "share_links"

    id: Optional[int] = Field(default=None, primary_key=True)
    token_hash: str = Field(unique=True, index=True, max_length=64)
    domain_id: Optional[int] = Field(default=None, foreign_key="domains.id", index=True)
    days: int = Field(default=7)
    include_sources: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(default_factory=utcnow)
    revoked_at: Optional[datetime] = Field(default=None)
    last_used_at: Optional[datetime] = Field(default=None)
    uses: int = Field(default=0)


class JobRun(SQLModel, table=True):
    """History for scheduled work (health checks, probes, enrichment)."""

    __tablename__ = "job_runs"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=64, index=True)
    started_at: datetime = Field(default_factory=utcnow, index=True)
    finished_at: Optional[datetime] = Field(default=None)
    status: str = Field(default="running", max_length=32)
    summary: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    error: Optional[str] = Field(default=None, sa_column=Column(Text))


class DomainHealthSnapshot(SQLModel, table=True):
    """Result of one full health-check pass for a domain."""

    __tablename__ = "domain_health_snapshots"
    __table_args__ = (Index("ix_health_snapshots_domain_checked", "domain_id", "checked_at"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    domain_id: int = Field(foreign_key="domains.id", index=True)
    checked_at: datetime = Field(default_factory=utcnow, index=True)
    overall: str = Field(default="unknown", max_length=16)
    score: float = Field(default=0.0)
    core_passed: int = Field(default=0)
    core_total: int = Field(default=0)
    results: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    duration_ms: int = Field(default=0)
    error: Optional[str] = Field(default=None, sa_column=Column(Text))


class TransportProbe(SQLModel, table=True):
    """STARTTLS / certificate observation for one host:port."""

    __tablename__ = "transport_probes"
    __table_args__ = (Index("ix_transport_probes_domain_checked", "domain_id", "checked_at"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    domain_id: int = Field(foreign_key="domains.id", index=True)
    host: str = Field(max_length=255)
    port: int = Field(default=25)
    mode: str = Field(default="smtp", max_length=16)
    status: str = Field(default="unknown", max_length=16)
    tls_version: Optional[str] = Field(default=None, max_length=32)
    cipher: Optional[str] = Field(default=None, max_length=128)
    cert_subject: Optional[str] = Field(default=None, max_length=512)
    cert_issuer: Optional[str] = Field(default=None, max_length=512)
    not_after: Optional[datetime] = Field(default=None)
    days_left: Optional[int] = Field(default=None)
    hostname_ok: Optional[bool] = Field(default=None)
    chain_ok: Optional[bool] = Field(default=None)
    dane_status: Optional[str] = Field(default=None, max_length=32)
    details: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    error: Optional[str] = Field(default=None, sa_column=Column(Text))
    checked_at: datetime = Field(default_factory=utcnow, index=True)
    duration_ms: int = Field(default=0)


class IpMeta(SQLModel, table=True):
    """Cached reverse DNS and ASN data for sending IPs."""

    __tablename__ = "ip_meta"

    ip: str = Field(primary_key=True, max_length=64)
    ptr: Optional[str] = Field(default=None, max_length=255)
    asn: Optional[int] = Field(default=None)
    asn_org: Optional[str] = Field(default=None, max_length=255)
    updated_at: datetime = Field(default_factory=utcnow)


class AlertRule(SQLModel, table=True):
    """One configurable alert rule, seeded from the built-in kinds."""

    __tablename__ = "alert_rules"

    id: Optional[int] = Field(default=None, primary_key=True)
    kind: str = Field(unique=True, index=True, max_length=64)
    enabled: bool = Field(default=True)
    condition: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    cooldown_minutes: int = Field(default=60)
    updated_at: datetime = Field(default_factory=utcnow)


class AlertEvent(SQLModel, table=True):
    """A fired (and later resolved) incident."""

    __tablename__ = "alert_events"
    __table_args__ = (Index("ix_alert_events_rule_domain", "rule_id", "domain_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    rule_id: int = Field(foreign_key="alert_rules.id", index=True)
    domain_id: int = Field(foreign_key="domains.id", index=True)
    dedupe_key: str = Field(max_length=160)
    severity: str = Field(default="warning", max_length=16)
    title: str = Field(max_length=255)
    message: str = Field(sa_column=Column(Text))
    payload: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    triggered_at: datetime = Field(default_factory=utcnow, index=True)
    resolved_at: Optional[datetime] = Field(default=None)
    delivered_at: Optional[datetime] = Field(default=None)
    delivery_error: Optional[str] = Field(default=None, sa_column=Column(Text))


def dump_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
