"""Scheduled job tests (PTR enrichment)."""

from __future__ import annotations

import asyncio
from datetime import date, datetime, timedelta, timezone

from sqlmodel import Session, select

from app.health.dns import Lookup
from app.jobs import _scheduled_checks_disabled, job_ptr_enrichment
from app.models import Domain, DomainSettings, IpMeta, Report, SourceRecord


class FakePtrDns:
    def __init__(self, mapping):
        self.mapping = mapping

    async def ptr(self, ip):
        value = self.mapping.get(ip)
        return Lookup(values=(value,) if value else (), exists=bool(value))


def test_ptr_enrichment_stores_full_ip(session: Session, monkeypatch):
    domain = Domain(name="tgm.rocks", display_name="tgm.rocks")
    session.add(domain)
    session.commit()
    session.refresh(domain)

    report = Report(
        domain_id=domain.id,
        org_name="google.com",
        report_id="ptr-1",
        policy_domain="tgm.rocks",
        date_begin=datetime.now(timezone.utc) - timedelta(days=1),
        date_end=datetime.now(timezone.utc),
        report_date=date.today(),
        message_count=2,
        aligned_count=2,
        failed_count=0,
        record_count=2,
        source_count=1,
        raw_sha256="b" * 64,
        raw_xml=b"<feedback/>",
    )
    session.add(report)
    session.commit()
    session.refresh(report)
    for _ in range(2):
        session.add(
            SourceRecord(
                report_id=report.id,
                domain_id=domain.id,
                report_date=report.report_date,
                source_ip="62.116.130.25",
                message_count=1,
            )
        )
    session.commit()

    monkeypatch.setattr(
        "app.jobs.get_dns_client",
        lambda: FakePtrDns({"62.116.130.25": "mail.tgm.rocks"}),
    )

    result = asyncio.run(job_ptr_enrichment())
    assert result["looked_up"] == 1

    meta = session.exec(select(IpMeta)).all()
    assert [item.ip for item in meta] == ["62.116.130.25"]
    assert meta[0].ptr == "mail.tgm.rocks"

    again = asyncio.run(job_ptr_enrichment())
    assert again == {"looked_up": 0, "pending": 0}


def test_scheduled_checks_respect_mute_and_toggle(session: Session):
    domain = Domain(name="mute.example")
    session.add(domain)
    session.commit()
    session.refresh(domain)
    settings = DomainSettings(
        domain_id=domain.id,
        checks_muted_until=datetime.now(timezone.utc) + timedelta(hours=2),
    )
    session.add(settings)
    session.commit()

    assert _scheduled_checks_disabled(session, domain.id, datetime.now(timezone.utc)) is True

    settings.checks_muted_until = datetime.now(timezone.utc) - timedelta(hours=1)
    session.add(settings)
    session.commit()
    assert _scheduled_checks_disabled(session, domain.id, datetime.now(timezone.utc)) is False

    settings.dns_checks_enabled = False
    session.add(settings)
    session.commit()
    assert _scheduled_checks_disabled(session, domain.id, datetime.now(timezone.utc)) is True
