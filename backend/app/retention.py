"""Opt-in retention: archive raw payloads, then prune old report rows."""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Optional, TypeVar

from sqlalchemy import delete
from sqlmodel import Session, select

from .config import get_settings
from .models import AuditEvent, Domain, Report, SourceRecord, TlsFailure, TlsPolicy, TlsReport, utcnow

BATCH = 400
T = TypeVar("T")


def _chunks(values: Iterable[T], size: int = BATCH):
    chunk: list[T] = []
    for value in values:
        chunk.append(value)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def _safe(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "").strip("._")
    return cleaned[:120] or "report"


def _archive_path(
    root: Path,
    day: date,
    prefix: str,
    domain: str,
    report_id: str,
    row_id: int,
    suffix: str,
) -> Path:
    folder = root / f"{day.year:04d}" / f"{day.month:02d}"
    return folder / f"{prefix}-{_safe(domain)}-{_safe(report_id)}-{row_id}.{suffix}"


def prune_audit(
    session: Session,
    days: int,
    *,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    if days <= 0:
        return {"enabled": False, "days": 0, "deleted": 0}
    cutoff = (now or utcnow()) - timedelta(days=days)
    result = session.exec(delete(AuditEvent).where(AuditEvent.at < cutoff))
    session.commit()
    return {"enabled": True, "days": days, "deleted": int(getattr(result, "rowcount", 0) or 0)}


def prune(
    session: Session,
    days: int,
    *,
    dry_run: bool = False,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    settings = get_settings()
    if days <= 0:
        return {"enabled": False, "days": 0, "dry_run": dry_run, "message": "retention is off"}
    cutoff = (now or utcnow()) - timedelta(days=days)
    cutoff_date = cutoff.date()
    archive_root = settings.data_dir / "archive"
    domains = {domain.id: domain.name for domain in session.exec(select(Domain)).all()}

    reports = session.exec(
        select(Report).where(Report.report_date < cutoff_date).order_by(Report.report_date)
    ).all()
    tls_reports = session.exec(
        select(TlsReport).where(TlsReport.report_date < cutoff_date).order_by(TlsReport.report_date)
    ).all()

    dmarc_ids = [row.id for row in reports if row.id is not None]
    tls_ids = [row.id for row in tls_reports if row.id is not None]
    source_count = (
        sum(
            len(session.exec(select(SourceRecord.id).where(SourceRecord.report_id.in_(chunk))).all())
            for chunk in _chunks(dmarc_ids)
        )
        if dmarc_ids
        else 0
    )
    policy_count = (
        sum(
            len(session.exec(select(TlsPolicy.id).where(TlsPolicy.tls_report_id.in_(chunk))).all())
            for chunk in _chunks(tls_ids)
        )
        if tls_ids
        else 0
    )
    failure_count = (
        sum(
            len(session.exec(select(TlsFailure.id).where(TlsFailure.tls_report_id.in_(chunk))).all())
            for chunk in _chunks(tls_ids)
        )
        if tls_ids
        else 0
    )

    archived_bytes = 0
    skipped_existing = 0
    for report in reports:
        raw = report.raw_xml or b""
        archived_bytes += len(raw)
        if dry_run:
            continue
        path = _archive_path(
            archive_root,
            report.report_date,
            "dmarc",
            domains.get(report.domain_id, "domain"),
            report.report_id,
            report.id or 0,
            "xml",
        )
        if path.exists():
            skipped_existing += 1
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    for report in tls_reports:
        raw = report.raw_json or b""
        archived_bytes += len(raw)
        if dry_run:
            continue
        path = _archive_path(
            archive_root,
            report.report_date,
            "tls",
            domains.get(report.domain_id, "domain"),
            report.report_id,
            report.id or 0,
            "json",
        )
        if path.exists():
            skipped_existing += 1
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    if not dry_run:
        for chunk in _chunks(dmarc_ids):
            session.exec(delete(SourceRecord).where(SourceRecord.report_id.in_(chunk)))
            session.exec(delete(Report).where(Report.id.in_(chunk)))
            session.commit()
        for chunk in _chunks(tls_ids):
            session.exec(delete(TlsPolicy).where(TlsPolicy.tls_report_id.in_(chunk)))
            session.exec(delete(TlsFailure).where(TlsFailure.tls_report_id.in_(chunk)))
            session.exec(delete(TlsReport).where(TlsReport.id.in_(chunk)))
            session.commit()

    return {
        "enabled": True,
        "days": days,
        "cutoff": cutoff_date.isoformat(),
        "dry_run": dry_run,
        "dmarc_reports": len(reports),
        "tls_reports": len(tls_reports),
        "source_records": source_count,
        "tls_policies": policy_count,
        "tls_failures": failure_count,
        "archived_bytes": archived_bytes,
        "skipped_existing": skipped_existing,
        "archive_dir": str(archive_root),
    }
