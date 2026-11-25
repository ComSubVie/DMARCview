"""Evaluation of the built-in alert rules against the stored reports and probes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any, Callable

from sqlalchemy import case, func, or_
from sqlmodel import Session, select

from ..analytics import volume_anomaly
from ..config import get_settings
from ..expectations import matching_label
from ..health.service import latest_probes
from ..models import (
    Domain,
    DomainHealthSnapshot,
    DomainSettings,
    IngestRun,
    JobRun,
    Report,
    SourceRecord,
    SyncState,
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
        if matching_label(session, domain.id, ip, since=start):
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
    if recent < int(cond["min_messages"]):
        return []
    anomaly = volume_anomaly(
        session,
        domain.id,
        baseline_days=int(cond["baseline_days"]),
        as_of=now.date(),
    )
    z = anomaly.get("z")
    z_hit = bool(anomaly.get("available")) and z is not None and z >= float(cond["min_z"])
    multiplier_hit = baseline > 0 and recent >= float(cond["multiplier"]) * baseline
    if not z_hit and not multiplier_hit:
        return []
    pieces = [f"{recent} messages in the last day"]
    if baseline > 0:
        pieces.append(f"{recent / baseline:.1f}× the {baseline:.0f}/day median")
    if z_hit and z is not None:
        pieces.append(f"{z:.1f}σ above the trailing baseline")
    return [
        Finding(
            key="volume",
            severity="warning",
            title=f"Volume spike: {recent} messages",
            message=" · ".join(pieces) + ".",
            payload={
                "recent": recent,
                "baseline": baseline,
                "multiplier": round(recent / baseline, 2) if baseline else None,
                "z": z,
            },
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


STATUS_RANK = {"info": 0, "n/a": 0, "pass": 1, "unknown": 2, "warn": 3, "fail": 4}


def health_regression(session: Session, domain: Domain, cond: dict, now: datetime) -> list[Finding]:
    snapshots = session.exec(
        select(DomainHealthSnapshot)
        .where(DomainHealthSnapshot.domain_id == domain.id)
        .order_by(DomainHealthSnapshot.checked_at.desc())
        .limit(2)
    ).all()
    if len(snapshots) < 2:
        return []
    latest, previous = snapshots[0], snapshots[1]
    before = {item.get("key"): item for item in (previous.results or []) if item.get("key")}
    findings: list[Finding] = []
    for item in latest.results or []:
        key = item.get("key")
        status = str(item.get("status") or "").lower()
        if not key or status not in {"warn", "fail"}:
            continue
        prior = before.get(key)
        if prior is None:
            continue
        prior_status = str(prior.get("status") or "").lower()
        if STATUS_RANK.get(status, 0) <= STATUS_RANK.get(prior_status, 0):
            continue
        label = item.get("label") or key
        findings.append(
            Finding(
                key=f"health:{key}",
                severity="critical" if status == "fail" else "warning",
                title=f"{label} regressed to {status.upper()}",
                message=(
                    f"{label}: {item.get('summary') or status} (previous check: "
                    f"{prior.get('summary') or prior_status})."
                ),
                payload={
                    "check": key,
                    "previous": prior_status,
                    "current": status,
                    "summary": item.get("summary"),
                },
            )
        )
    return findings


def sync_failure(session: Session, domain: Domain | None, cond: dict, now: datetime) -> list[Finding]:
    settings = get_settings()
    if not settings.jmap_enabled:
        return []
    runs = session.exec(
        select(IngestRun)
        .where(IngestRun.source == "jmap")
        .order_by(IngestRun.started_at.desc())
        .limit(20)
    ).all()
    if not runs:
        return []
    failures = 0
    for run in runs:
        status = (run.status or "").lower()
        if status == "ok":
            break
        if status in {"error", "partial"}:
            failures += 1
        elif status == "running":
            continue
        else:
            break
    if failures < int(cond.get("failures", 2)):
        return []
    latest = next((run for run in runs if (run.status or "").lower() in {"error", "partial"}), runs[0])
    error = (latest.error or "no error detail").strip()
    return [
        Finding(
            key="sync",
            severity="critical" if (latest.status or "").lower() == "error" else "warning",
            title=f"JMAP sync failed {failures} times in a row",
            message=(
                f"The last {failures} scheduled JMAP syncs did not complete successfully. "
                f"Latest error: {error[:300]}"
            ),
            payload={
                "failures": failures,
                "last_error": error[:1000],
                "started_at": latest.started_at.isoformat() if latest.started_at else None,
            },
        )
    ]


def job_failure(session: Session, domain: Domain | None, cond: dict, now: datetime) -> list[Finding]:
    findings: list[Finding] = []
    threshold = int(cond.get("failures", 1))
    for name, label in (
        ("health_checks", "Health checks"),
        ("transport_probes", "Transport probes"),
        ("backup", "Backup"),
    ):
        runs = session.exec(
            select(JobRun)
            .where(JobRun.name == name)
            .order_by(JobRun.started_at.desc())
            .limit(20)
        ).all()
        if not runs:
            continue
        failures = 0
        for run in runs:
            summary = run.summary or {}
            errors = summary.get("errors") or []
            failed = (run.status or "").lower() == "error" or bool(errors)
            if failed:
                failures += 1
            elif (run.status or "").lower() == "running":
                continue
            else:
                break
        if failures < threshold:
            continue
        latest = next(
            (
                run
                for run in runs
                if (run.status or "").lower() == "error" or bool((run.summary or {}).get("errors"))
            ),
            runs[0],
        )
        summary = latest.summary or {}
        error = (latest.error or "; ".join(summary.get("errors") or []) or "no error detail").strip()
        findings.append(
            Finding(
                key=f"job:{name}",
                severity="critical",
                title=f"{label} failed {failures} times in a row",
                message=f"The last {failures} scheduled {label.lower()} runs reported errors. {error[:300]}",
                payload={
                    "job": name,
                    "failures": failures,
                    "last_error": error[:1000],
                    "started_at": latest.started_at.isoformat() if latest.started_at else None,
                },
            )
        )
    return findings


def backup_stale(session: Session, domain: Domain | None, cond: dict, now: datetime) -> list[Finding]:
    settings = get_settings()
    if not settings.backup_enabled or not (
        settings.backup_webdav_url or settings.backup_s3_bucket
    ):
        return []
    state = session.get(SyncState, "backup.last_offsite_at")
    if state is None or not state.value:
        return []
    try:
        last = datetime.fromisoformat(state.value.replace("Z", "+00:00"))
    except ValueError:
        return []
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    age = now - last.astimezone(timezone.utc)
    hours = age.total_seconds() / 3600
    threshold = int(cond.get("hours", 48))
    if hours <= threshold:
        return []
    return [
        Finding(
            key="backup_stale",
            severity="warning",
            title=f"Off-box backup is {hours:.1f}h old",
            message=(
                f"The last successful off-box backup was {hours:.1f} hours ago "
                f"(maximum {threshold}h)."
            ),
            payload={"hours": round(hours, 1), "threshold_hours": threshold, "last_at": state.value},
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
    "health_regression": health_regression,
    "sync_failure": sync_failure,
    "job_failure": job_failure,
    "backup_stale": backup_stale,
}


def evaluate_rule(session: Session, rule, domain: Domain, now: datetime) -> list[Finding]:
    spec = SPECS.get(rule.kind)
    evaluator = EVALUATORS.get(rule.kind)
    if spec is None or evaluator is None:
        return []
    return _cap(evaluator(session, domain, spec.clean(rule.condition), now))
