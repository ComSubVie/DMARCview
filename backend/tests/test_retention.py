"""Retention archives raw payloads before deleting old rows."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, select

from app.config import get_settings
from app.models import (
    Domain,
    Report,
    SourceRecord,
    TlsFailure,
    TlsPolicy,
    TlsReport,
)
from app.retention import prune


def _report(session: Session, domain: Domain, when: datetime, suffix: str) -> Report:
    report = Report(
        domain_id=domain.id,
        org_name="google.com",
        report_id=f"report-{suffix}",
        policy_domain=domain.name,
        date_begin=when,
        date_end=when + timedelta(hours=1),
        report_date=when.date(),
        message_count=5,
        aligned_count=4,
        failed_count=1,
        record_count=1,
        source_count=1,
        raw_sha256=hashlib.sha256(suffix.encode()).hexdigest(),
        raw_xml=f"<feedback id='{suffix}'/>".encode(),
    )
    session.add(report)
    session.commit()
    session.refresh(report)
    session.add(
        SourceRecord(
            report_id=report.id,
            domain_id=domain.id,
            report_date=when.date(),
            source_ip="203.0.113.10",
            message_count=5,
        )
    )
    session.commit()
    return report


def _tls(session: Session, domain: Domain, when: datetime, suffix: str) -> TlsReport:
    report = TlsReport(
        domain_id=domain.id,
        org_name="google.com",
        report_id=f"tls-{suffix}",
        date_begin=when,
        date_end=when + timedelta(hours=1),
        report_date=when.date(),
        total_success=5,
        total_failure=1,
        raw_sha256=hashlib.sha256(f"tls-{suffix}".encode()).hexdigest(),
        raw_json=f'{{"id":"{suffix}"}}'.encode(),
    )
    session.add(report)
    session.commit()
    session.refresh(report)
    session.add(
        TlsPolicy(
            tls_report_id=report.id,
            domain_id=domain.id,
            report_date=when.date(),
            total_success=5,
            total_failure=1,
        )
    )
    session.add(
        TlsFailure(
            tls_report_id=report.id,
            domain_id=domain.id,
            report_date=when.date(),
            sending_mta_ip="203.0.113.10",
            failed_count=1,
        )
    )
    session.commit()
    return report


def test_retention_archives_then_prunes(session: Session):
    domain = Domain(name="retention.example")
    session.add(domain)
    session.commit()
    session.refresh(domain)
    now = datetime.now(timezone.utc)
    old = _report(session, domain, now - timedelta(days=60), "old")
    keep = _report(session, domain, now - timedelta(days=2), "keep")
    old_tls = _tls(session, domain, now - timedelta(days=60), "old")
    keep_tls = _tls(session, domain, now - timedelta(days=2), "keep")
    old_id, keep_id = old.id, keep.id
    old_tls_id, keep_tls_id = old_tls.id, keep_tls.id
    result = prune(session, 30, now=now)
    assert result["enabled"] is True
    assert result["dmarc_reports"] == 1
    assert result["tls_reports"] == 1
    assert result["source_records"] == 1

    assert session.get(Report, old_id) is None
    assert session.get(Report, keep_id) is not None
    assert session.get(TlsReport, old_tls_id) is None
    assert session.get(TlsReport, keep_tls_id) is not None
    assert session.exec(select(TlsPolicy).where(TlsPolicy.tls_report_id == old_tls_id)).first() is None
    assert session.exec(select(TlsFailure).where(TlsFailure.tls_report_id == old_tls_id)).first() is None

    archive = get_settings().data_dir / "archive"
    xml_files = list(archive.rglob("dmarc-*.xml"))
    json_files = list(archive.rglob("tls-*.json"))
    assert len(xml_files) == 1 and xml_files[0].read_bytes().startswith(b"<feedback")
    assert len(json_files) == 1 and json_files[0].read_bytes().startswith(b'{"id"')

    dry = _report(session, domain, now - timedelta(days=90), "dry")
    dry_id = dry.id
    preview = prune(session, 30, dry_run=True, now=now)
    assert preview["dry_run"] is True
    assert preview["dmarc_reports"] == 1
    assert session.get(Report, dry_id) is not None
    assert not any("dry" in path.name for path in archive.rglob("dmarc-*.xml"))
