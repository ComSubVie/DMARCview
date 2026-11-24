"""Persistence and API shaping for domain health and transport probes."""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from sqlmodel import Session, select

from ..config import get_settings
from ..models import (
    DEFAULT_DKIM_SELECTORS,
    Domain,
    DomainHealthSnapshot,
    DomainSettings,
    Report,
    SourceRecord,
    TransportProbe,
    utcnow,
)
from .dns import BaseDnsClient, get_dns_client
from .engine import run_health
from .http import BaseFetcher
from .probe import ProbeOutcome, probe_all, targets_for
from .types import HealthReport

STALE_AFTER = timedelta(hours=12)


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def get_settings_row(session: Session, domain: Domain) -> DomainSettings:
    row = session.get(DomainSettings, domain.id)
    if row is None:
        row = DomainSettings(domain_id=domain.id, dkim_selectors=list(DEFAULT_DKIM_SELECTORS))
        session.add(row)
        session.commit()
        session.refresh(row)
    return row


def update_settings(
    session: Session,
    domain: Domain,
    *,
    dkim_selectors: Optional[list[str]] = None,
    probe_targets: Optional[list[str]] = None,
    expected_report_hours: Optional[int] = None,
    dns_checks_enabled: Optional[bool] = None,
    checks_muted_until: Optional[datetime] = None,
    clear_mute: bool = False,
) -> DomainSettings:
    row = get_settings_row(session, domain)
    if dkim_selectors is not None:
        cleaned = []
        for selector in dkim_selectors:
            value = selector.strip().lower()
            if value and value not in cleaned:
                cleaned.append(value[:64])
        row.dkim_selectors = cleaned or list(DEFAULT_DKIM_SELECTORS)
    if probe_targets is not None:
        row.probe_targets = [target.strip()[:255] for target in probe_targets if target.strip()][:25]
    if expected_report_hours is not None:
        row.expected_report_hours = max(6, min(expected_report_hours, 24 * 14))
    if dns_checks_enabled is not None:
        row.dns_checks_enabled = dns_checks_enabled
    if clear_mute:
        row.checks_muted_until = None
    elif checks_muted_until is not None:
        row.checks_muted_until = (
            checks_muted_until
            if checks_muted_until.tzinfo
            else checks_muted_until.replace(tzinfo=timezone.utc)
        )
    row.updated_at = utcnow()
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def serialise_settings(session: Session, domain: Domain) -> dict[str, Any]:
    row = get_settings_row(session, domain)
    return {
        "domain": domain.name,
        "dkim_selectors": row.dkim_selectors,
        "probe_targets": row.probe_targets,
        "expected_report_hours": row.expected_report_hours,
        "dns_checks_enabled": row.dns_checks_enabled,
        "checks_muted_until": _iso(row.checks_muted_until),
        "updated_at": _iso(row.updated_at),
    }


def reported_policy(session: Session, domain_id: int) -> dict[str, Any]:
    latest = session.exec(
        select(Report)
        .where(Report.domain_id == domain_id)
        .order_by(Report.date_end.desc(), Report.id.desc())
    ).first()
    if latest is None:
        return {}
    return {
        "p": (latest.policy_p or "").lower(),
        "sp": (latest.policy_sp or "").lower(),
        "pct": latest.policy_pct,
        "report_date": latest.report_date.isoformat(),
        "org": latest.org_name,
    }


def store_report(session: Session, domain_id: int, report: HealthReport) -> DomainHealthSnapshot:
    checked_at = report.checked_at
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=timezone.utc)
    snapshot = DomainHealthSnapshot(
        domain_id=domain_id,
        checked_at=checked_at.astimezone(timezone.utc),
        overall=report.overall,
        score=report.score,
        core_passed=report.core_passed,
        core_total=report.core_total,
        results=[result.as_dict() for result in report.results],
        duration_ms=report.duration_ms,
        error=report.error,
    )
    session.add(snapshot)
    session.commit()
    session.refresh(snapshot)
    return snapshot


def discover_dkim_selectors(
    session: Session, domain: Domain, days: int = 60, limit: int = 10
) -> list[tuple[str, str]]:
    """Selectors actually used, taken from report ``auth_results``.

    Only signatures whose signing domain aligns with this domain are kept, so
    selectors from forwarders or spoofed mail are not probed.
    """
    cutoff = date.today() - timedelta(days=days)
    rows = session.exec(
        select(SourceRecord.dkim_domains, SourceRecord.dkim_selectors)
        .where(
            SourceRecord.domain_id == domain.id,
            SourceRecord.report_date >= cutoff,
        )
    ).all()
    counts: Counter[tuple[str, str]] = Counter()
    for dkim_domains, dkim_selectors in rows:
        for signing_domain, selector in zip(dkim_domains or [], dkim_selectors or [], strict=False):
            signing_domain = (signing_domain or "").lower().rstrip(".")
            selector = (selector or "").strip()
            if not selector or len(selector) > 64:
                continue
            if signing_domain == domain.name or signing_domain.endswith("." + domain.name):
                counts[(signing_domain, selector)] += 1
    return [pair for pair, _ in counts.most_common(limit)]


async def run_and_store_health(
    session: Session,
    domain: Domain,
    *,
    dns: Optional[BaseDnsClient] = None,
    http: Optional[BaseFetcher] = None,
) -> dict[str, Any]:
    settings_row = get_settings_row(session, domain)
    discovered = discover_dkim_selectors(session, domain)
    report = await run_health(
        domain.name,
        selectors=settings_row.dkim_selectors,
        discovered_selectors=discovered,
        reported_policy=reported_policy(session, domain.id),
        dns=dns,
        http=http,
        http_timeout=get_settings().http_timeout_seconds,
    )
    snapshot = store_report(session, domain.id, report)
    return serialise_snapshot(snapshot)


def serialise_snapshot(snapshot: DomainHealthSnapshot, domain_name: Optional[str] = None) -> dict[str, Any]:
    checked = snapshot.checked_at
    aware = checked if checked.tzinfo else checked.replace(tzinfo=timezone.utc)
    stale = datetime.now(timezone.utc) - aware > STALE_AFTER
    payload: dict[str, Any] = {
        "checked_at": _iso(snapshot.checked_at),
        "overall": snapshot.overall,
        "score": snapshot.score,
        "core_passed": snapshot.core_passed,
        "core_total": snapshot.core_total,
        "duration_ms": snapshot.duration_ms,
        "stale": stale,
        "results": snapshot.results,
        "error": snapshot.error,
    }
    if domain_name is not None:
        payload["domain"] = domain_name
    return payload


def latest_snapshot(session: Session, domain_id: int) -> Optional[DomainHealthSnapshot]:
    return session.exec(
        select(DomainHealthSnapshot)
        .where(DomainHealthSnapshot.domain_id == domain_id)
        .order_by(DomainHealthSnapshot.checked_at.desc(), DomainHealthSnapshot.id.desc())
    ).first()


def _store_probes(session: Session, domain_id: int, outcomes: Iterable[ProbeOutcome]) -> list[TransportProbe]:
    rows: list[TransportProbe] = []
    for outcome in outcomes:
        not_after = outcome.not_after
        if not_after is not None:
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)
            not_after = not_after.astimezone(timezone.utc)
        row = TransportProbe(
            domain_id=domain_id,
            host=outcome.host[:255],
            port=outcome.port,
            mode=outcome.mode,
            status=outcome.status,
            tls_version=outcome.tls_version,
            cipher=(outcome.cipher or "")[:128] or None,
            cert_subject=outcome.cert_subject,
            cert_issuer=outcome.cert_issuer,
            not_after=not_after,
            days_left=outcome.days_left,
            hostname_ok=outcome.hostname_ok,
            chain_ok=outcome.chain_ok,
            dane_status=outcome.dane_status,
            details=outcome.details,
            error=outcome.error,
            checked_at=utcnow(),
            duration_ms=outcome.duration_ms,
        )
        session.add(row)
        rows.append(row)
    session.commit()
    for row in rows:
        session.refresh(row)
    return rows


def serialise_probe(row: TransportProbe) -> dict[str, Any]:
    return {
        "id": row.id,
        "host": row.host,
        "port": row.port,
        "mode": row.mode,
        "status": row.status,
        "tls_version": row.tls_version,
        "cipher": row.cipher,
        "cert_subject": row.cert_subject,
        "cert_issuer": row.cert_issuer,
        "not_after": _iso(row.not_after),
        "days_left": row.days_left,
        "hostname_ok": row.hostname_ok,
        "chain_ok": row.chain_ok,
        "dane_status": row.dane_status,
        "details": row.details,
        "error": row.error,
        "checked_at": _iso(row.checked_at),
        "duration_ms": row.duration_ms,
    }


def latest_probes(session: Session, domain_id: int) -> list[TransportProbe]:
    rows = session.exec(
        select(TransportProbe)
        .where(TransportProbe.domain_id == domain_id)
        .order_by(TransportProbe.checked_at.desc(), TransportProbe.id.desc())
        .limit(120)
    ).all()
    seen: set[tuple[str, int]] = set()
    latest: list[TransportProbe] = []
    for row in rows:
        key = (row.host.lower(), row.port)
        if key in seen:
            continue
        seen.add(key)
        latest.append(row)
    return latest


async def run_and_store_probes(
    session: Session, domain: Domain, *, dns: Optional[BaseDnsClient] = None
) -> list[dict[str, Any]]:
    client = dns or get_dns_client()
    settings_row = get_settings_row(session, domain)
    mx = await client.mx(domain.name)
    specs = targets_for(list(mx.values), settings_row.probe_targets)
    if not specs:
        return []
    outcomes = await probe_all(
        specs, dns=client, timeout=get_settings().probe_timeout_seconds, concurrency=3
    )
    rows = _store_probes(session, domain.id, outcomes)
    return [serialise_probe(row) for row in rows]


def health_payload(session: Session, domain: Domain) -> dict[str, Any]:
    snapshot = latest_snapshot(session, domain.id)
    probes = [serialise_probe(row) for row in latest_probes(session, domain.id)]
    history_rows = session.exec(
        select(DomainHealthSnapshot)
        .where(DomainHealthSnapshot.domain_id == domain.id)
        .order_by(DomainHealthSnapshot.checked_at.desc())
        .limit(30)
    ).all()
    history = [
        {
            "checked_at": _iso(row.checked_at),
            "overall": row.overall,
            "score": row.score,
            "core_passed": row.core_passed,
            "core_total": row.core_total,
        }
        for row in reversed(history_rows)
    ]
    return {
        "domain": domain.name,
        "checked_at": _iso(snapshot.checked_at) if snapshot else None,
        "overall": snapshot.overall if snapshot else "unknown",
        "score": snapshot.score if snapshot else 0.0,
        "core_passed": snapshot.core_passed if snapshot else 0,
        "core_total": snapshot.core_total if snapshot else 0,
        "stale": serialise_snapshot(snapshot)["stale"] if snapshot else True,
        "results": snapshot.results if snapshot else [],
        "duration_ms": snapshot.duration_ms if snapshot else 0,
        "error": snapshot.error if snapshot else None,
        "probes": probes,
        "settings": serialise_settings(session, domain),
        "dkim_discovered": [
            {"domain": selector_domain, "selector": selector}
            for selector_domain, selector in discover_dkim_selectors(session, domain)
        ],
        "history": history,
        "checked": snapshot is not None,
    }


def fleet_health(session: Session) -> list[dict[str, Any]]:
    domains = session.exec(select(Domain).order_by(Domain.name)).all()
    out: list[dict[str, Any]] = []
    for domain in domains:
        row = session.exec(
            select(DomainHealthSnapshot)
            .where(DomainHealthSnapshot.domain_id == domain.id)
            .order_by(DomainHealthSnapshot.checked_at.desc())
            .limit(1)
        ).first()
        probes = latest_probes(session, domain.id)
        failing_probes = sum(1 for probe in probes if probe.status == "fail")
        out.append(
            {
                "domain": domain.name,
                "overall": row.overall if row else "unknown",
                "score": row.score if row else 0.0,
                "core_passed": row.core_passed if row else 0,
                "core_total": row.core_total if row else 0,
                "checked_at": _iso(row.checked_at) if row else None,
                "checked": row is not None,
                "stale": serialise_snapshot(row)["stale"] if row else True,
                "probes": len(probes),
                "failing_probes": failing_probes,
                "next_expiry_days": min(
                    (probe.days_left for probe in probes if probe.days_left is not None),
                    default=None,
                ),
            }
        )
    return out
