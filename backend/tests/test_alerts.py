"""Alert rule evaluation, dedupe/resolution, delivery and API."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, select

from app.alerts import channels
from app.alerts.channels import ChannelResult
from app.alerts.service import ensure_rules, evaluate
from app.analytics import volume_anomaly
from app.models import (
    AlertEvent,
    AlertRule,
    AlertRuleOverride,
    Domain,
    SourceExpectation,
    DomainHealthSnapshot,
    Report,
    SourceRecord,
    TransportProbe,
)


def only_rule(session: Session, kind: str) -> None:
    ensure_rules(session)
    for rule in session.exec(select(AlertRule)).all():
        rule.enabled = rule.kind == kind
        session.add(rule)
    session.commit()


def make_domain(session: Session, name: str = "tgm.rocks") -> Domain:
    domain = Domain(name=name, display_name=name)
    session.add(domain)
    session.commit()
    session.refresh(domain)
    return domain


def make_report(
    session: Session,
    domain: Domain,
    *,
    begin: datetime,
    end: datetime,
    policy_p: str = "reject",
    suffix: str = "one",
    report_id: str | None = None,
) -> Report:
    report = Report(
        domain_id=domain.id,
        org_name="google.com",
        report_id=report_id or f"report-{suffix}",
        policy_domain=domain.name,
        date_begin=begin,
        date_end=end,
        report_date=begin.date(),
        policy_p=policy_p,
        policy_sp=policy_p,
        policy_pct=100,
        message_count=0,
        aligned_count=0,
        failed_count=0,
        record_count=0,
        source_count=1,
        raw_sha256=hashlib.sha256(suffix.encode()).hexdigest(),
        raw_xml=b"<feedback/>",
    )
    session.add(report)
    session.commit()
    session.refresh(report)
    return report


def add_record(
    session: Session,
    report: Report,
    domain: Domain,
    *,
    ip: str,
    count: int,
    dkim_pass: bool,
    spf_pass: bool,
) -> None:
    session.add(
        SourceRecord(
            report_id=report.id,
            domain_id=domain.id,
            report_date=report.report_date,
            source_ip=ip,
            message_count=count,
            dkim_pass=dkim_pass,
            spf_pass=spf_pass,
            dkim_signed=True,
            dkim_auth_pass=dkim_pass,
            spf_auth_pass=spf_pass,
            dkim_domains=[domain.name],
            dkim_selectors=["selector"],
            dkim_results=["pass" if dkim_pass else "fail"],
            spf_domains=[domain.name],
            spf_results=["pass" if spf_pass else "fail"],
        )
    )
    session.commit()


def evaluate_now(session: Session, *, send: bool = False):
    return asyncio.run(evaluate(session, now=datetime.now(timezone.utc), send=send))


def test_compliance_event_fires_once_and_resolves(session: Session):
    domain = make_domain(session)
    only_rule(session, "compliance_drop")
    now = datetime.now(timezone.utc)
    report = make_report(session, domain, begin=now - timedelta(hours=20), end=now)
    add_record(session, report, domain, ip="192.0.2.1", count=100, dkim_pass=False, spf_pass=False)

    first = evaluate_now(session)
    assert first["created"] == 1
    events = session.exec(select(AlertEvent)).all()
    assert len(events) == 1
    assert events[0].dedupe_key == "compliance"
    assert events[0].resolved_at is None

    second = evaluate_now(session)
    assert second["created"] == 0
    assert len(session.exec(select(AlertEvent)).all()) == 1

    add_record(session, report, domain, ip="192.0.2.2", count=2000, dkim_pass=True, spf_pass=True)
    third = evaluate_now(session)
    assert third["resolved"] == 1
    session.refresh(events[0])
    assert events[0].resolved_at is not None


def test_report_gap(session: Session):
    domain = make_domain(session)
    only_rule(session, "report_gap")
    now = datetime.now(timezone.utc)
    make_report(session, domain, begin=now - timedelta(days=6), end=now - timedelta(days=5))

    result = evaluate_now(session)
    assert result["created"] == 1
    event = session.exec(select(AlertEvent)).one()
    assert event.dedupe_key == "gap"
    assert "No report" in event.message


def test_new_source_ignores_old_ips(session: Session):
    domain = make_domain(session)
    only_rule(session, "new_source")
    now = datetime.now(timezone.utc)
    old = make_report(
        session, domain, begin=now - timedelta(days=30), end=now - timedelta(days=29), suffix="old"
    )
    add_record(session, old, domain, ip="192.0.2.10", count=10, dkim_pass=True, spf_pass=True)
    current = make_report(
        session, domain, begin=now - timedelta(hours=20), end=now, suffix="current"
    )
    add_record(session, current, domain, ip="192.0.2.10", count=1, dkim_pass=True, spf_pass=True)
    add_record(session, current, domain, ip="192.0.2.99", count=7, dkim_pass=True, spf_pass=True)

    result = evaluate_now(session)
    assert result["created"] == 1
    event = session.exec(select(AlertEvent)).one()
    assert event.dedupe_key == "source:192.0.2.99"


def test_known_sender_suppresses_new_source(session: Session):
    domain = make_domain(session)
    only_rule(session, "new_source")
    now = datetime.now(timezone.utc)
    current = make_report(
        session, domain, begin=now - timedelta(hours=20), end=now, suffix="known-sender"
    )
    add_record(session, current, domain, ip="192.0.2.99", count=7, dkim_pass=True, spf_pass=True)
    session.add(
        SourceExpectation(domain_id=domain.id, match_type="cidr", value="192.0.2.0/24", label="relay")
    )
    session.commit()
    result = evaluate_now(session)
    assert result["created"] == 0


def test_domain_override_can_disable_rule(session: Session):
    domain = make_domain(session)
    only_rule(session, "new_source")
    now = datetime.now(timezone.utc)
    current = make_report(
        session, domain, begin=now - timedelta(hours=20), end=now, suffix="override"
    )
    add_record(session, current, domain, ip="198.51.100.7", count=7, dkim_pass=True, spf_pass=True)
    rule = session.exec(select(AlertRule).where(AlertRule.kind == "new_source")).one()
    session.add(AlertRuleOverride(rule_id=rule.id, domain_id=domain.id, enabled=False))
    session.commit()
    result = evaluate_now(session)
    assert result["created"] == 0


def test_cert_expiry(session: Session):
    domain = make_domain(session)
    only_rule(session, "cert_expiry")
    now = datetime.now(timezone.utc)
    session.add(
        TransportProbe(
            domain_id=domain.id,
            host="mail.tgm.rocks",
            port=25,
            mode="smtp",
            status="pass",
            days_left=10,
            checked_at=now,
        )
    )
    session.commit()

    result = evaluate_now(session)
    assert result["created"] == 1
    event = session.exec(select(AlertEvent)).one()
    assert event.dedupe_key == "cert:mail.tgm.rocks:25"
    assert event.severity == "warning"


def test_policy_drift(session: Session):
    domain = make_domain(session)
    only_rule(session, "policy_drift")
    now = datetime.now(timezone.utc)
    make_report(session, domain, begin=now - timedelta(days=2), end=now - timedelta(days=1), policy_p="reject")
    session.add(
        DomainHealthSnapshot(
            domain_id=domain.id,
            checked_at=now,
            overall="pass",
            score=1.0,
            core_passed=4,
            core_total=4,
            results=[{"key": "dmarc", "status": "pass", "evidence": {"p": "none"}}],
        )
    )
    session.commit()

    result = evaluate_now(session)
    assert result["created"] == 1
    event = session.exec(select(AlertEvent)).one()
    assert event.dedupe_key == "policy"
    assert "p=none" in event.title


def test_delivery_is_recorded(session: Session, monkeypatch):
    domain = make_domain(session)
    only_rule(session, "compliance_drop")
    now = datetime.now(timezone.utc)
    report = make_report(session, domain, begin=now - timedelta(hours=20), end=now)
    add_record(session, report, domain, ip="192.0.2.1", count=100, dkim_pass=False, spf_pass=False)

    async def fake_deliver(*args, **kwargs):
        return [ChannelResult("smtp", True)]

    monkeypatch.setattr(channels, "deliver", fake_deliver)
    result = asyncio.run(evaluate(session, now=now, send=True))
    assert result["delivered"] == 1
    event = session.exec(select(AlertEvent)).one()
    assert event.delivered_at is not None
    assert event.delivery_error is None


def test_volume_anomaly_and_spike_alert(session: Session):
    domain = make_domain(session)
    only_rule(session, "volume_spike")
    now = datetime.now(timezone.utc)
    for i in range(1, 22):
        day = now - timedelta(days=i)
        report = make_report(session, domain, begin=day, end=day + timedelta(hours=1), suffix=f"base{i}")
        add_record(
            session,
            report,
            domain,
            ip="192.0.2.50",
            count=5 if i % 2 else 15,
            dkim_pass=True,
            spf_pass=True,
        )
    spike = make_report(session, domain, begin=now, end=now + timedelta(hours=1), suffix="spike")
    add_record(session, spike, domain, ip="192.0.2.51", count=100, dkim_pass=True, spf_pass=True)

    anomaly = volume_anomaly(session, domain.id, as_of=now.date())
    assert anomaly["available"] is True
    assert anomaly["z"] is not None and anomaly["z"] > 3

    rule = session.exec(select(AlertRule).where(AlertRule.kind == "volume_spike")).one()
    rule.condition = {**rule.condition, "multiplier": 1000, "min_z": 3, "min_messages": 1}
    session.add(rule)
    session.commit()

    result = evaluate_now(session)
    assert result["created"] == 1
    event = session.exec(select(AlertEvent)).one()
    assert event.dedupe_key == "volume"
    assert "σ" in event.message


def test_api_rules_and_manual_run(auth_client, session: Session):
    domain = make_domain(session)
    now = datetime.now(timezone.utc)
    report = make_report(session, domain, begin=now - timedelta(hours=20), end=now)
    add_record(session, report, domain, ip="192.0.2.1", count=100, dkim_pass=False, spf_pass=False)

    listing = auth_client.get("/api/alerts").json()
    assert len(listing["rules"]) == len(listing["kinds"]) == 9
    assert {channel["kind"] for channel in listing["channels"]} == {
        "smtp",
        "telegram",
        "signal",
        "webhook",
    }
    compliance = next(rule for rule in listing["rules"] if rule["kind"] == "compliance_drop")
    updated = auth_client.put(
        f"/api/alerts/rules/{compliance['id']}", json={"condition": {"threshold_pct": 50}}
    )
    assert updated.status_code == 200
    assert updated.json()["rules"][0]["condition"]["threshold_pct"] == 50

    invalid = auth_client.put(
        f"/api/alerts/rules/{compliance['id']}", json={"condition": {"nope": 1}}
    )
    assert invalid.status_code == 400

    run = auth_client.post("/api/alerts/run")
    assert run.status_code == 200, run.text
    assert run.json()["summary"]["created"] >= 1
    assert run.json()["alerts"]["unresolved"] >= 1

    test = auth_client.post("/api/alerts/test", json={}).json()
    assert test["ok"] is False
    assert "No matching channel" in test["error"]
