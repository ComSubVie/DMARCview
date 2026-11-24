"""Ingestion pipeline: persistence, idempotency, enrichment."""

from __future__ import annotations

from sqlmodel import Session, func, select

from app.ingest.service import ingest_raw_email
from app.models import Domain, ProcessedMessage, Report, SourceRecord, TlsFailure, TlsReport

from .conftest import sample


def _ingest(session: Session, name: str, key: str):
    return ingest_raw_email(session, sample(name), source="upload", source_key=key)


def test_ingest_fixture_set(session: Session):
    results = [
        _ingest(session, "google-dmarc-tgm-2026-11-18.eml", "k1"),
        _ingest(session, "microsoft-dmarc-tgm-2026-11-19.eml", "k2"),
        _ingest(session, "google-dmarc-aeroclub-2026-11-19.eml", "k3"),
        _ingest(session, "google-tlsrpt-tgm-2026-11-18.eml", "k4"),
        _ingest(session, "microsoft-tlsrpt-tgm-2026-11-19.eml", "k5"),
        _ingest(session, "newsletter-noise.eml", "k6"),
    ]
    assert sum(result.reports for result in results) == 3
    assert sum(result.tls_reports for result in results) == 2
    assert results[-1].status == "ignored"

    assert session.exec(select(func.count(Report.id))).one() == 3
    assert session.exec(select(func.count(TlsReport.id))).one() == 2
    assert session.exec(select(func.count(SourceRecord.id))).one() == 7
    assert session.exec(select(func.count(TlsFailure.id))).one() == 2

    domains = {row.name for row in session.exec(select(Domain)).all()}
    assert domains == {"tgm.rocks", "aeroclub.example"}

    tgm = session.exec(select(Domain).where(Domain.name == "tgm.rocks")).one()
    messages = session.exec(
        select(func.sum(Report.message_count)).where(Report.domain_id == tgm.id)
    ).one()
    aligned = session.exec(
        select(func.sum(Report.aligned_count)).where(Report.domain_id == tgm.id)
    ).one()
    assert (messages, aligned) == (17, 11)

    record = session.exec(
        select(SourceRecord).where(SourceRecord.source_ip == "62.116.130.25").limit(1)
    ).first()
    assert record is not None
    assert record.country_code == "DE"
    assert record.dkim_signed is True
    assert record.dkim_auth_pass is True

    report = session.exec(select(Report).where(Report.policy_domain == "tgm.rocks").limit(1)).first()
    assert report is not None
    assert b"<feedback" in report.raw_xml
    assert len(report.raw_sha256) == 64


def test_same_source_key_is_idempotent(session: Session):
    first = _ingest(session, "google-dmarc-tgm-2026-11-18.eml", "same-key")
    second = _ingest(session, "google-dmarc-tgm-2026-11-18.eml", "same-key")
    assert first.reports == 1
    assert second.status == "duplicate"
    assert second.reports == 0
    assert session.exec(select(func.count(Report.id))).one() == 1


def test_same_attachment_different_message_is_deduplicated(session: Session):
    first = _ingest(session, "google-dmarc-tgm-2026-11-18.eml", "key-a")
    second = _ingest(session, "google-dmarc-tgm-2026-11-18.eml", "key-b")
    assert first.reports == 1
    assert second.reports == 0
    assert second.duplicates == 1
    assert session.exec(select(func.count(Report.id))).one() == 1


def test_processed_message_recorded(session: Session):
    _ingest(session, "microsoft-tlsrpt-tgm-2026-11-19.eml", "msg-1")
    processed = session.exec(select(ProcessedMessage)).one()
    assert processed.status == "ok"
    assert processed.message_id is not None
    assert "Report domain" in (processed.subject or "")


def test_no_payload_is_ignored_but_recorded(session: Session):
    result = _ingest(session, "newsletter-noise.eml", "noise")
    assert result.ignored == 1
    processed = session.exec(select(ProcessedMessage)).one()
    assert processed.status == "ignored"
