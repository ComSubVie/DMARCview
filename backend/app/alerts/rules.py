"""Evaluation of the built-in alert rules against the stored reports and probes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any, Callable

from sqlalchemy import case, func, or_
from sqlmodel import Session, select

from ..health.service import latest_probes
from ..models import (
    Domain,
    DomainHealthSnapshot,
    DomainSettings,
    Report,
    SourceRecord,
    TlsPolicy,
)
from .specs import SPECS


@dataclass
class Finding:
    key: str
    severity: str
    title: str
    message: str
    payload: dict[str, Any] = field(default_factory=dict)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _cap(findings: list[Finding], limit: int = 10) -> list[Finding]:
    if len(findings) <= limit:
        return findings
    extra = len(findings) - limit
    return findings[:limit] + [
        Finding(
            key="overflow",
            severity="warning",
            title=f"{extra} more findings",
            message=f"{extra} additional findings were suppressed in this pass.",
        )
    ]


def compliance_drop(session: Session, domain: Domain, cond: dict, now: datetime) -> list[Finding]:
    start = (now - timedelta(hours=int(cond["window_hours"]))).date()
    total, aligned = session.exec(
        select(
            func.coalesce(func.sum(SourceRecord.message_count), 0),
            func.coalesce(
                func.sum(
                    case(
                        (or_(SourceRecord.dkim_pass, SourceRecord.spf_pass), SourceRecord.message_count),
                        else_=0,
                    )
                ),
                0,
            ),
        ).where(SourceRecord.domain_id == domain.id, SourceRecord.report_date >= start)
    ).one()
    total, aligned = int(total), int(aligned)
    if total < int(cond["min_messages"]):
        return []
    pct = aligned / total * 100
    if pct >= float(cond["threshold_pct"]):
        return []
    return [
        Finding(
            key="compliance",
            severity="critical",
            title=f"DMARC alignment dropped to {pct:.1f}%",
            message=(
                f"{aligned} of {total} messages aligned in the last {cond['window_hours']}h "
                f"(threshold {cond['threshold_pct']}%)."
            ),
            payload={"aligned": aligned, "messages": total, "pct": round(pct, 1)},
        )
    ]


def new_source(session: Session, domain: Domain, cond: dict, now: datetime) -> list[Finding]:
    start = (now - timedelta(hours=int(cond["window_hours"]))).date()
    rows = session.exec(
        select(
            SourceRecord.source_ip,
            func.sum(SourceRecord.message_count),
            func.max(SourceRecord.country_name),
        )
        .where(SourceRecord.domain_id == domain.id, SourceRecord.report_date >= start)
        .group_by(SourceRecord.source_ip)
    ).all()
    findings: list[Finding] = []
    for ip, total, country in rows:
        total = int(total or 0)
        if total < int(cond["min_messages"]):
            continue
        overall = session.exec(
            select(func.min(SourceRecord.report_date)).where(
                SourceRecord.domain_id == domain.id, SourceRecord.source_ip == ip
            )
        ).one()
        if overall is None or overall < start:
            continue
        findings.append(
            Finding(
                key=f"source:{ip}",
                severity="info",
                title=f"New sending source {ip}",
                message=(
                    f"{ip}{' (' + country + ')' if country else ''} sent {total} messages as "
                    f"{domain.name} and was first seen on {overall}."
                ),
                payload={"ip": ip, "messages": total, "country": country, "first_seen": str(overall)},
            )
        )
    return sorted(findings, key=lambda item: item.key)


def dkim_break(session: Session, domain: Domain, cond: dict, now: datetime) -> list[Finding]:
    start = (now - timedelta(hours=int(cond["window_hours"]))).date()
    prior_end = start - timedelta(days=1)
    prior_start = start - timedelta(days=int(cond["lookback_days"]))
    prior = {
        row[0]
        for row in session.exec(
            select(SourceRecord.source_ip)
            .where(
                SourceRecord.domain_id == domain.id,
                SourceRecord.report_date >= prior_start,
                SourceRecord.report_date <= prior_end,
                SourceRecord.dkim_pass.is_(True),
                SourceRecord.message_count > 0,
            )
            .distinct()
        ).all()
    }
    if not prior:
        return []
    passing = {
        row[0]
        for row in session.exec(
            select(SourceRecord.source_ip)
            .where(
                SourceRecord.domain_id == domain.id,
                SourceRecord.report_date >= start,
                SourceRecord.dkim_pass.is_(True),
            )
            .distinct()
        ).all()
    }
    failing = session.exec(
        select(SourceRecord.source_ip, func.sum(SourceRecord.message_count))
        .where(
            SourceRecord.domain_id == domain.id,
            SourceRecord.report_date >= start,
            SourceRecord.dkim_pass.is_(False),
        )
        .group_by(SourceRecord.source_ip)
    ).all()
    findings: list[Finding] = []
    for ip, total in failing:
        total = int(total or 0)
        if ip not in prior or ip in passing or total < int(cond["min_messages"]):
            continue
        findings.append(
            Finding(
                key=f"dkim:{ip}",
                severity="critical",
                title=f"DKIM failing for {ip}",
                message=(
                    f"{ip} passed DKIM in the previous {cond['lookback_days']} days but "
                    f"{total} messages now fail. Check the selector/key rotation."
                ),
                payload={"ip": ip, "messages": total},
            )
        )
    return findings


def tls_failure(session: Session, domain: Domain, cond: dict, now: datetime) -> list[Finding]:
    start = (now - timedelta(hours=int(cond["window_hours"]))).date()
    success, failure = session.exec(
        select(
            func.coalesce(func.sum(TlsPolicy.total_success), 0),
            func.coalesce(func.sum(TlsPolicy.total_failure), 0),
        ).where(TlsPolicy.domain_id == domain.id, TlsPolicy.report_date >= start)
    ).one()
    success, failure = int(success), int(failure)
    sessions = success + failure
    if sessions < int(cond["min_sessions"]):
        return []
    pct = success / sessions * 100
    if pct >= float(cond["threshold_pct"]):
        return []
    return [
        Finding(
            key="tls",
            severity="warning",
            title=f"TLS success rate {pct:.1f}%",
            message=(
                f"{failure} of {sessions} reported TLS sessions failed in the last "
                f"{cond['window_hours']}h (threshold {cond['threshold_pct']}%)."
            ),
            payload={"success": success, "failure": failure, "sessions": sessions, "pct": round(pct, 1)},
        )
    ]


def report_gap(session: Session, domain: Domain, cond: dict, now: datetime) -> list[Finding]:
    latest = session.exec(select(func.max(Report.date_end)).where(Report.domain_id == domain.id)).one()
    latest_dt = _aware(latest)
    if latest_dt is None:
        return []
    settings_row = session.get(DomainSettings, domain.id)
    expected = int(settings_row.expected_report_hours) if settings_row else 48
    expected += int(cond.get("grace_hours", 0))
    gap = now - latest_dt
    if gap <= timedelta(hours=expected):
        return []
    hours = int(gap.total_seconds() // 3600)
    return [
        Finding(
            key="gap",
            severity="critical",
            title="DMARC reports stopped",
            message=(
                f"No report for {domain.name} in {hours}h (expected every {expected}h). "
                "Check the rua= address and the mailbox."
            ),
            payload={"hours": hours, "expected_hours": expected, "last_report_end": latest_dt.isoformat()},
        )
    ]


def volume_spike(session: Session, domain: Domain, cond: dict, now: datetime) -> list[Finding]:
    recent_start = now.date() - timedelta(days=1)
    baseline_start = now.date() - timedelta(days=int(cond["baseline_days"]) + 1)
    rows = session.exec(
        select(SourceRecord.report_date, func.sum(SourceRecord.message_count))
        .where(
            SourceRecord.domain_id == domain.id,
            SourceRecord.report_date >= baseline_start,
            SourceRecord.report_date < recent_start,
        )
        .group_by(SourceRecord.report_date)
    ).all()
    values = [int(total or 0) for _, total in rows if total]
    if not values:
        return []
    baseline = median(values)
    recent = session.exec(
        select(func.coalesce(func.sum(SourceRecord.message_count), 0)).where(
            SourceRecord.domain_id == domain.id, SourceRecord.report_date >= recent_start
        )
    ).one()
    recent = int(recent or 0)
    if recent < int(cond["min_messages"]) or baseline <= 0:
        return []
    if recent < float(cond["multiplier"]) * baseline:
        return []
    return [
        Finding(
            key="volume",
            severity="warning",
            title=f"Volume spike: {recent} messages",
            message=(
                f"{recent} messages in the last day versus a {baseline:.0f}/day median over "
                f"{cond['baseline_days']} days ({recent / baseline:.1f}×)."
            ),
            payload={"recent": recent, "baseline": baseline, "multiplier": round(recent / baseline, 2)},
        )
    ]


def policy_drift(session: Session, domain: Domain, cond: dict, now: datetime) -> list[Finding]:
    report = session.exec(
        select(Report)
        .where(Report.domain_id == domain.id)
        .order_by(Report.date_end.desc(), Report.id.desc())
    ).first()
    snapshot = session.exec(
        select(DomainHealthSnapshot)
        .where(DomainHealthSnapshot.domain_id == domain.id)
        .order_by(DomainHealthSnapshot.checked_at.desc())
    ).first()
    if report is None or snapshot is None:
        return []
    dns_p = None
    for result in snapshot.results or []:
        if result.get("key") == "dmarc":
            dns_p = (result.get("evidence") or {}).get("p")
            break
    reported_p = (report.policy_p or "").lower()
    dns_p = (dns_p or "").lower()
    if not dns_p or not reported_p or dns_p == reported_p:
        return []
    return [
        Finding(
            key="policy",
            severity="warning",
            title=f"DMARC policy drift (DNS p={dns_p}, reports p={reported_p})",
            message=(
                f"DNS publishes p={dns_p}, but the latest report from {report.org_name} saw "
                f"p={reported_p}. If the change is intentional, reports should catch up within a day."
            ),
            payload={"dns_p": dns_p, "reported_p": reported_p},
        )
    ]


def cert_expiry(session: Session, domain: Domain, cond: dict, now: datetime) -> list[Finding]:
    warn_days = int(cond["warn_days"])
    findings: list[Finding] = []
    for probe in latest_probes(session, domain.id):
        if probe.days_left is None or probe.days_left > warn_days:
            continue
        findings.append(
            Finding(
                key=f"cert:{probe.host}:{probe.port}",
                severity="critical" if probe.days_left < 7 else "warning",
                title=f"Certificate for {probe.host}:{probe.port} expires in {probe.days_left} days",
                message=(
                    f"The certificate presented on {probe.host}:{probe.port} expires in "
                    f"{probe.days_left} days (warn threshold {warn_days})."
                ),
                payload={"host": probe.host, "port": probe.port, "days_left": probe.days_left},
            )
        )
    return findings


def starttls_broken(session: Session, domain: Domain, cond: dict, now: datetime) -> list[Finding]:
    findings: list[Finding] = []
    for probe in latest_probes(session, domain.id):
        if probe.status != "fail":
            continue
        error = (probe.error or "").lower()
        if any(word in error for word in ("certificate", "expires", "expired")):
            continue  # handled by cert_expiry
        findings.append(
            Finding(
                key=f"probe:{probe.host}:{probe.port}",
                severity="critical",
                title=f"STARTTLS failed on {probe.host}:{probe.port}",
                message=probe.error or f"{probe.host}:{probe.port} did not complete a TLS handshake.",
                payload={"host": probe.host, "port": probe.port, "error": probe.error},
            )
        )
    return findings


EVALUATORS: dict[str, Callable[[Session, Domain, dict, datetime], list[Finding]]] = {
    "compliance_drop": compliance_drop,
    "new_source": new_source,
    "dkim_break": dkim_break,
    "tls_failure": tls_failure,
    "report_gap": report_gap,
    "volume_spike": volume_spike,
    "policy_drift": policy_drift,
    "cert_expiry": cert_expiry,
    "starttls_broken": starttls_broken,
}


def evaluate_rule(session: Session, rule, domain: Domain, now: datetime) -> list[Finding]:
    spec = SPECS.get(rule.kind)
    evaluator = EVALUATORS.get(rule.kind)
    if spec is None or evaluator is None:
        return []
    return _cap(evaluator(session, domain, spec.clean(rule.condition), now))
