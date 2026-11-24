"""CLI helpers that are not covered elsewhere."""

from __future__ import annotations

import hashlib
from argparse import Namespace
from datetime import datetime, timezone

from sqlmodel import Session, select

from app.cli import cmd_geo_enrich
from app.models import Domain, Report, SourceRecord


class FakeGeo:
    available = True

    def lookup(self, ip: str):
        return "DE", "Germany"


def test_geo_enrich_backfills_countries(session: Session, monkeypatch):
    domain = Domain(name="geo.example")
    session.add(domain)
    session.commit()
    session.refresh(domain)
    now = datetime.now(timezone.utc)
    report = Report(
        domain_id=domain.id,
        org_name="google.com",
        report_id="geo-report",
        policy_domain=domain.name,
        date_begin=now,
        date_end=now,
        report_date=now.date(),
        message_count=1,
        aligned_count=1,
        failed_count=0,
        record_count=1,
        source_count=1,
        raw_sha256=hashlib.sha256(b"geo").hexdigest(),
        raw_xml=b"<feedback/>",
    )
    session.add(report)
    session.commit()
    session.refresh(report)
    record = SourceRecord(
        report_id=report.id,
        domain_id=domain.id,
        report_date=now.date(),
        source_ip="62.116.130.25",
        message_count=1,
    )
    session.add(record)
    session.commit()
    session.refresh(record)

    monkeypatch.setattr("app.cli.get_geo_resolver", lambda: FakeGeo())
    assert cmd_geo_enrich(Namespace(all=False)) == 0

    session.expire_all()
    refreshed = session.get(SourceRecord, record.id)
    assert refreshed is not None
    assert refreshed.country_code == "DE"
    assert refreshed.country_name == "Germany"
    assert session.exec(select(SourceRecord).where(SourceRecord.country_code.is_(None))).first() is None
