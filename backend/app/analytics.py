"""Read-side analytics for the dashboard and report browser.

All aggregation happens in SQL (SQLite) with a handful of in-Python passes for
the small TLS-RPT tables.  Every function returns plain JSON-able structures so
the FastAPI routers stay thin.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import case, distinct, func, or_
from sqlmodel import Session, select

from .config import get_settings
from .geoip import COUNTRY_NAMES, country_flag
from .models import (
    Domain,
    DomainSettings,
    IpMeta,
    Report,
    SourceRecord,
    TlsFailure,
    TlsPolicy,
    TlsReport,
    utcnow,
)
from .providers import provider_for

MAX_DAYS = 366
ALIGNED = or_(SourceRecord.dkim_pass, SourceRecord.spf_pass)


@dataclass(frozen=True)
class DateRange:
    start: date
    end: date
    days: int
    label: str

    @property
    def all_dates(self) -> list[date]:
        return [self.start + timedelta(days=offset) for offset in range((self.end - self.start).days + 1)]


def _parse_date(value: Optional[str]) -> Optional[date]:
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def resolve_range(days: int = 30, date_from: Optional[str] = None, date_to: Optional[str] = None) -> DateRange:
    today = datetime.now(timezone.utc).date()
    explicit_from, explicit_to = _parse_date(date_from), _parse_date(date_to)
    if explicit_from or explicit_to:
        start = explicit_from or (explicit_to - timedelta(days=days - 1))  # type: ignore[operator]
        end = explicit_to or today
        if start > end:
            start, end = end, start
        span = (end - start).days + 1
        if span > MAX_DAYS:
            start = end - timedelta(days=MAX_DAYS - 1)
            span = MAX_DAYS
        return DateRange(start=start, end=end, days=span, label="Custom range")
    span = max(1, min(int(days or 30), MAX_DAYS))
    end = today
    start = end - timedelta(days=span - 1)
    labels = {7: "Last 7 days", 14: "Last 14 days", 30: "Last 30 days", 90: "Last 90 days"}
    return DateRange(start=start, end=end, days=span, label=labels.get(span, f"Last {span} days"))


def _one_int(session: Session, statement: Any) -> int:
    """``select(func.count(...))`` yields a scalar in SQLModel; be tolerant of both."""
    value = session.exec(statement).one()
    if isinstance(value, (tuple, list)):
        value = value[0]
    return int(value or 0)


def _iso(value: Optional[datetime | date]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return aware.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return value.isoformat()


def get_domain(session: Session, name: Optional[str]) -> Optional[Domain]:
    if not name or name in {"all", "*"}:
        return None
    return session.exec(select(Domain).where(Domain.name == name.strip().lower())).first()


def _source_conditions(domain_id: Optional[int], rng: DateRange) -> list[Any]:
    conditions: list[Any] = [
        SourceRecord.report_date >= rng.start,
        SourceRecord.report_date <= rng.end,
    ]
    if domain_id is not None:
        conditions.append(SourceRecord.domain_id == domain_id)
    return conditions


def _tls_conditions(domain_id: Optional[int], rng: DateRange) -> list[Any]:
    conditions: list[Any] = [
        TlsPolicy.report_date >= rng.start,
        TlsPolicy.report_date <= rng.end,
    ]
    if domain_id is not None:
        conditions.append(TlsPolicy.domain_id == domain_id)
    return conditions


def list_domains(session: Session) -> list[dict[str, Any]]:
    today = datetime.now(timezone.utc).date()
    cutoff = today - timedelta(days=29)
    rows = session.exec(
        select(
            Domain.id,
            Domain.name,
            Domain.display_name,
            func.count(distinct(Report.id)).label("reports"),
            func.coalesce(func.sum(Report.message_count), 0).label("messages"),
        )
        .join(Report, Report.domain_id == Domain.id, isouter=True)
        .where(or_(Report.report_date.is_(None), Report.report_date >= cutoff))
        .group_by(Domain.id)
    ).all()
    msgs = session.exec(
        select(
            SourceRecord.domain_id,
            func.coalesce(func.sum(SourceRecord.message_count), 0),
            func.coalesce(func.sum(case((ALIGNED, SourceRecord.message_count), else_=0)), 0),
            func.max(SourceRecord.report_date),
        )
        .where(SourceRecord.report_date >= cutoff)
        .group_by(SourceRecord.domain_id)
    ).all()
    stats = {row[0]: row for row in msgs}
    tls = session.exec(
        select(TlsReport.domain_id, func.count(TlsReport.id), func.max(TlsReport.report_date))
        .group_by(TlsReport.domain_id)
    ).all()
    tls_stats = {row[0]: row for row in tls}

    out: list[dict[str, Any]] = []
    for row in rows:
        domain_id, name, display = row[0], row[1], row[2]
        stat = stats.get(domain_id)
        total = int(stat[1]) if stat else 0
        aligned = int(stat[2]) if stat else 0
        tls_row = tls_stats.get(domain_id)
        out.append(
            {
                "id": domain_id,
                "name": name,
                "display_name": display or name,
                "reports_30d": int(row[3] or 0),
                "messages_30d": total,
                "aligned_pct_30d": round(aligned / total * 100, 1) if total else None,
                "last_report_date": _iso(stat[3] if stat else None),
                "tls_reports": int(tls_row[1]) if tls_row else 0,
                "last_tls_date": _iso(tls_row[2]) if tls_row else None,
            }
        )
    out.sort(key=lambda item: item["messages_30d"], reverse=True)
    return out


def dashboard(session: Session, domain: Optional[Domain], rng: DateRange) -> dict[str, Any]:
    domain_id = domain.id if domain else None
    conditions = _source_conditions(domain_id, rng)

    totals = session.exec(
        select(
            func.coalesce(func.sum(SourceRecord.message_count), 0),
            func.coalesce(func.sum(case((ALIGNED, SourceRecord.message_count), else_=0)), 0),
            func.coalesce(func.sum(case((SourceRecord.dkim_pass, SourceRecord.message_count), else_=0)), 0),
            func.coalesce(func.sum(case((SourceRecord.spf_pass & ~SourceRecord.dkim_pass, SourceRecord.message_count), else_=0)), 0),
            func.coalesce(func.sum(case((SourceRecord.dkim_signed, SourceRecord.message_count), else_=0)), 0),
            func.count(distinct(SourceRecord.source_ip)),
            func.count(distinct(SourceRecord.report_id)),
        ).where(*conditions)
    ).one()
    messages, aligned = int(totals[0]), int(totals[1])
    dkim_pass_msgs, spf_only_msgs = int(totals[2]), int(totals[3])
    signed_msgs = int(totals[4])
    source_count = int(totals[5])
    failed = messages - aligned

    daily_rows = session.exec(
        select(
            SourceRecord.report_date,
            func.sum(SourceRecord.message_count),
            func.sum(case((ALIGNED, SourceRecord.message_count), else_=0)),
        )
        .where(*conditions)
        .group_by(SourceRecord.report_date)
    ).all()
    by_day = {row[0]: (int(row[1] or 0), int(row[2] or 0)) for row in daily_rows}
    daily = []
    for day in rng.all_dates:
        total, ok = by_day.get(day, (0, 0))
        daily.append({"date": day.isoformat(), "aligned": ok, "failed": total - ok, "total": total})

    sources = _source_breakdown(session, domain_id, rng)
    verified = [item for item in sources if item["dmarc"] == "pass"]
    unverified = [item for item in sources if item["dmarc"] != "pass"]
    countries = _country_breakdown(session, conditions)
    submitters = _submitters(session, domain_id, rng)
    policy = _policy_snapshot(session, domain, rng) if domain else None
    policy_overview = _policy_overview(session, rng) if domain is None else []
    coverage = _coverage(session, domain_id, rng)

    settings = get_settings()
    month_start = datetime.now(timezone.utc).date().replace(day=1)
    month_statement = select(func.coalesce(func.sum(SourceRecord.message_count), 0)).where(
        SourceRecord.report_date >= month_start
    )
    if domain_id is not None:
        month_statement = month_statement.where(SourceRecord.domain_id == domain_id)
    month_messages = _one_int(session, month_statement)

    summary = {
        "messages": messages,
        "sources": source_count,
        "aligned": aligned,
        "aligned_pct": round(aligned / messages * 100, 1) if messages else 0.0,
        "failed": failed,
        "dkim_pass_messages": dkim_pass_msgs,
        "spf_only_messages": spf_only_msgs,
        "signed_messages": signed_msgs,
        "unsigned_messages": messages - signed_msgs,
        "verified_sources": len(verified),
        "unverified_sources": len(unverified),
        "verified_messages": sum(item["messages"] for item in verified),
        "unverified_messages": sum(item["messages"] for item in unverified),
        "providers": len(submitters),
    }
    summary["sentences"] = _summary_sentences(summary, policy)

    tls_conditions: list[Any] = [
        TlsPolicy.report_date >= rng.start,
        TlsPolicy.report_date <= rng.end,
    ]
    if domain_id is not None:
        tls_conditions.append(TlsPolicy.domain_id == domain_id)
    tls_row = session.exec(
        select(
            func.coalesce(func.sum(TlsPolicy.total_success), 0),
            func.coalesce(func.sum(TlsPolicy.total_failure), 0),
            func.count(distinct(TlsPolicy.tls_report_id)),
        ).where(*tls_conditions)
    ).one()
    tls_success, tls_failure, tls_reports = int(tls_row[0]), int(tls_row[1]), int(tls_row[2])
    tls_hosts: set[str] = set()
    for tls_policy in session.exec(select(TlsPolicy).where(*tls_conditions)).all():
        for host in tls_policy.mx_hosts or []:
            tls_hosts.add(host)
    tls_sessions = tls_success + tls_failure

    return {
        "domain": {"id": domain.id, "name": domain.name, "display_name": domain.display_name}
        if domain
        else None,
        "range": {
            "start": rng.start.isoformat(),
            "end": rng.end.isoformat(),
            "days": rng.days,
            "label": rng.label,
        },
        "kpis": summary,
        "daily": daily,
        "sources": sources,
        "groups": {
            "verified": {"messages": summary["verified_messages"], "sources": len(verified)},
            "unverified": {"messages": summary["unverified_messages"], "sources": len(unverified)},
        },
        "countries": countries,
        "submitters": submitters,
        "policy": policy,
        "policy_overview": policy_overview,
        "coverage": coverage,
        "volume": {
            "month_messages": month_messages,
            "alert_threshold": settings.monthly_message_alert,
            "pct": round(month_messages / settings.monthly_message_alert * 100, 2)
            if settings.monthly_message_alert
            else 0,
        },
        "tls": {
            "sessions": tls_sessions,
            "success": tls_success,
            "failure": tls_failure,
            "success_pct": round(tls_success / tls_sessions * 100, 1) if tls_sessions else 0.0,
            "reports": tls_reports,
            "mx_hosts": len(tls_hosts),
        },
        "advice": advise(policy, summary, rng.days),
        "report_gaps": _report_gaps(session, domain_id),
        "identities": _identities(session, domain_id, rng),
        "changes": _changes(session, domain_id, rng),
        "generated_at": _iso(datetime.now(timezone.utc)),
    }


def _report_gaps(session: Session, domain_id: Optional[int] = None) -> list[dict[str, Any]]:
    """Domains whose newest report is older than their expected interval."""
    rows = session.exec(
        select(Domain.id, Domain.name, func.max(Report.date_end))
        .join(Report, Report.domain_id == Domain.id)
        .group_by(Domain.id, Domain.name)
    ).all()
    expected_by_domain = {
        row.domain_id: int(row.expected_report_hours)
        for row in session.exec(select(DomainSettings)).all()
    }
    now = utcnow()
    gaps: list[dict[str, Any]] = []
    for did, name, latest in rows:
        if domain_id is not None and did != domain_id:
            continue
        if latest is None:
            continue
        if latest.tzinfo is None:
            latest = latest.replace(tzinfo=timezone.utc)
        expected = expected_by_domain.get(did, 48)
        hours = int((now - latest).total_seconds() // 3600)
        if hours <= expected:
            continue
        gaps.append(
            {
                "domain": name,
                "hours": hours,
                "expected_hours": expected,
                "last_report": _iso(latest),
            }
        )
    return sorted(gaps, key=lambda item: item["hours"], reverse=True)


def _mail_domain(value: Optional[str]) -> str:
    if not value:
        return ""
    text = value.strip().lower()
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    return text.strip(".")


def _identities(
    session: Session, domain_id: Optional[int], rng: DateRange, limit: int = 100
) -> dict[str, Any]:
    """Collapse rotating source IPs into sender identities.

    The key is the envelope/header domain plus the DKIM domain, so 40 rotating ESP
    addresses become one row while different authenticated identities stay apart.
    ASN/PTR is used as a display hint, not as part of the key.
    """
    conditions = _source_conditions(domain_id, rng)
    rows = session.exec(
        select(
            SourceRecord.source_ip,
            SourceRecord.domain_id,
            SourceRecord.envelope_from,
            SourceRecord.header_from,
            func.coalesce(func.sum(SourceRecord.message_count), 0),
            func.coalesce(func.sum(case((ALIGNED, SourceRecord.message_count), else_=0)), 0),
            func.coalesce(func.sum(case((SourceRecord.dkim_pass, SourceRecord.message_count), else_=0)), 0),
            func.coalesce(func.sum(case((SourceRecord.spf_pass, SourceRecord.message_count), else_=0)), 0),
            func.min(SourceRecord.report_date),
            func.max(SourceRecord.report_date),
            func.max(SourceRecord.country_code),
            func.max(SourceRecord.country_name),
        )
        .where(*conditions)
        .group_by(
            SourceRecord.source_ip,
            SourceRecord.domain_id,
            SourceRecord.envelope_from,
            SourceRecord.header_from,
        )
    ).all()
    if not rows:
        return {"total": 0, "items": []}

    dkim_by_source: dict[tuple[str, int, Optional[str], Optional[str]], set[str]] = {}
    for ip, did, envelope, header, domains in session.exec(
        select(
            SourceRecord.source_ip,
            SourceRecord.domain_id,
            SourceRecord.envelope_from,
            SourceRecord.header_from,
            SourceRecord.dkim_domains,
        ).where(*conditions)
    ).all():
        if not domains or not isinstance(domains, list):
            continue
        bucket = dkim_by_source.setdefault((ip, did, envelope, header), set())
        for domain in domains:
            if domain:
                bucket.add(str(domain).lower())

    addresses = [row[0] for row in rows]
    domain_names = {domain.id: domain.name for domain in session.exec(select(Domain)).all()}
    metas = {
        meta.ip: meta
        for meta in session.exec(select(IpMeta).where(IpMeta.ip.in_(addresses))).all()
    }

    groups: dict[str, dict[str, Any]] = {}
    for ip, did, envelope, header, messages, aligned, dkim, spf, first, last, cc, cn in rows:
        env_domain = _mail_domain(envelope) or _mail_domain(header)
        dkim_set = dkim_by_source.get((ip, did, envelope, header), set())
        external_dkim = sorted(domain for domain in dkim_set if domain and domain != env_domain)
        primary_dkim = external_dkim[0] if external_dkim else ""
        key = f"{env_domain}|{primary_dkim}" if (env_domain or primary_dkim) else f"ip:{did}:{ip}"
        if primary_dkim and env_domain and primary_dkim != env_domain:
            label, detail = primary_dkim, f"envelope {env_domain}"
        elif env_domain:
            label, detail = env_domain, ""
        elif primary_dkim:
            label, detail = primary_dkim, ""
        else:
            label, detail = ip, domain_names.get(did, "") if did else ""

        group = groups.get(key)
        if group is None:
            group = {
                "key": key,
                "label": label,
                "detail": detail,
                "messages": 0,
                "aligned": 0,
                "dkim_pass": 0,
                "spf_pass": 0,
                "sources": 0,
                "first_seen": first,
                "last_seen": last,
                "countries": Counter(),
                "networks": Counter(),
                "ips": Counter(),
            }
            groups[key] = group
        group["messages"] += int(messages or 0)
        group["aligned"] += int(aligned or 0)
        group["dkim_pass"] += int(dkim or 0)
        group["spf_pass"] += int(spf or 0)
        group["sources"] += 1
        if first and (group["first_seen"] is None or first < group["first_seen"]):
            group["first_seen"] = first
        if last and (group["last_seen"] is None or last > group["last_seen"]):
            group["last_seen"] = last
        if cc:
            group["countries"][(cc, cn or COUNTRY_NAMES.get(cc, cc))] += int(messages or 0)
        meta = metas.get(ip)
        network = (meta.asn_org if meta and meta.asn_org else None) or (meta.ptr if meta else None)
        if network:
            group["networks"][network] += int(messages or 0)
        group["ips"][ip] += int(messages or 0)

    items: list[dict[str, Any]] = []
    for group in groups.values():
        messages = group["messages"]
        countries = group.pop("countries")
        networks = group.pop("networks")
        ips = group.pop("ips")
        country = countries.most_common(1)[0][0] if countries else (None, None)
        group["country_code"] = country[0]
        group["country"] = country[1]
        group["network"] = networks.most_common(1)[0][0] if networks else ""
        group["aligned_pct"] = round(group["aligned"] / messages * 100, 1) if messages else 0.0
        group["first_seen"] = group["first_seen"].isoformat() if group["first_seen"] else None
        group["last_seen"] = group["last_seen"].isoformat() if group["last_seen"] else None
        group["ips"] = [ip for ip, _ in ips.most_common(3)]
        items.append(group)

    items.sort(key=lambda item: (-item["messages"], item["label"]))
    return {"total": len(items), "items": items[:limit]}


def _period_summary(session: Session, domain_id: Optional[int], rng: DateRange) -> dict[str, Any]:
    conditions = _source_conditions(domain_id, rng)
    messages, aligned, sources = session.exec(
        select(
            func.coalesce(func.sum(SourceRecord.message_count), 0),
            func.coalesce(func.sum(case((ALIGNED, SourceRecord.message_count), else_=0)), 0),
            func.count(distinct(SourceRecord.source_ip)),
        ).where(*conditions)
    ).one()
    messages, aligned, sources = int(messages or 0), int(aligned or 0), int(sources or 0)
    return {
        "messages": messages,
        "aligned": aligned,
        "aligned_pct": round(aligned / messages * 100, 1) if messages else 0.0,
        "sources": sources,
    }


def _changes(session: Session, domain_id: Optional[int], rng: DateRange) -> dict[str, Any]:
    previous_end = rng.start - timedelta(days=1)
    previous_start = previous_end - timedelta(days=max(0, rng.days - 1))
    previous_range = DateRange(previous_start, previous_end, rng.days, "previous")
    current = _period_summary(session, domain_id, rng)
    previous = _period_summary(session, domain_id, previous_range)
    if previous["messages"] == 0:
        return {"available": False, "chips": [], "new_identities": [], "lost_identities": []}

    current_identities = _identities(session, domain_id, rng)
    previous_identities = _identities(session, domain_id, previous_range)
    current_keys = {item["key"]: item["label"] for item in current_identities["items"]}
    previous_keys = {item["key"]: item["label"] for item in previous_identities["items"]}

    def percent_delta(value: float, old: float) -> str:
        return f"{(value - old) / old * 100:+.0f}%" if old else "—"

    aligned_delta = current["aligned_pct"] - previous["aligned_pct"]
    chips = [
        {
            "key": "messages",
            "label": "Messages",
            "display": percent_delta(current["messages"], previous["messages"]),
            "tone": "neutral",
        },
        {
            "key": "aligned",
            "label": "Aligned",
            "display": f"{aligned_delta:+.1f} pts",
            "tone": "good" if aligned_delta >= 0 else "warn",
        },
        {
            "key": "sources",
            "label": "Sources",
            "display": f"{current['sources'] - previous['sources']:+d}",
            "tone": "neutral",
        },
        {
            "key": "identities",
            "label": "Identities",
            "display": f"{current_identities['total'] - previous_identities['total']:+d}",
            "tone": "neutral",
        },
    ]
    return {
        "available": True,
        "chips": chips,
        "new_identities": [label for key, label in current_keys.items() if key not in previous_keys][:5],
        "lost_identities": [label for key, label in previous_keys.items() if key not in current_keys][:5],
    }


def _source_breakdown(session: Session, domain_id: Optional[int], rng: DateRange) -> list[dict[str, Any]]:
    conditions = _source_conditions(domain_id, rng)
    rows = session.exec(
        select(
            SourceRecord.source_ip,
            func.coalesce(func.sum(SourceRecord.message_count), 0),
            func.coalesce(func.sum(case((ALIGNED, SourceRecord.message_count), else_=0)), 0),
            func.coalesce(func.sum(case((SourceRecord.spf_pass, SourceRecord.message_count), else_=0)), 0),
            func.coalesce(func.sum(case((SourceRecord.dkim_pass, SourceRecord.message_count), else_=0)), 0),
            func.coalesce(func.sum(case((SourceRecord.dkim_signed, SourceRecord.message_count), else_=0)), 0),
            func.coalesce(func.sum(case((SourceRecord.spf_auth_pass, SourceRecord.message_count), else_=0)), 0),
            func.coalesce(func.sum(case((SourceRecord.dkim_auth_pass, SourceRecord.message_count), else_=0)), 0),
            func.min(SourceRecord.report_date),
            func.max(SourceRecord.report_date),
            func.max(SourceRecord.country_code),
            func.max(SourceRecord.country_name),
            func.max(SourceRecord.header_from),
            func.max(SourceRecord.envelope_from),
            func.coalesce(
                func.sum(
                    case(
                        (
                            func.lower(func.coalesce(SourceRecord.header_from, "")) != Report.policy_domain,
                            SourceRecord.message_count,
                        ),
                        else_=0,
                    )
                ),
                0,
            ),
        )
        .join(Report, Report.id == SourceRecord.report_id)
        .where(*conditions)
        .group_by(SourceRecord.source_ip)
        .order_by(func.sum(SourceRecord.message_count).desc())
    ).all()

    dispositions: dict[str, dict[str, int]] = {}
    for ip, disposition, count in session.exec(
        select(SourceRecord.source_ip, SourceRecord.disposition, func.sum(SourceRecord.message_count))
        .where(*conditions)
        .group_by(SourceRecord.source_ip, SourceRecord.disposition)
    ).all():
        dispositions.setdefault(ip, {})[(disposition or "none")] = int(count or 0)

    orgs: dict[str, list[str]] = {}
    for ip, org in session.exec(
        select(SourceRecord.source_ip, Report.org_name)
        .join(Report, Report.id == SourceRecord.report_id)
        .where(*conditions)
        .distinct()
    ).all():
        orgs.setdefault(ip, []).append(org)

    ptr_map: dict[str, str | None] = {}
    if rows:
        addresses = [row[0] for row in rows]
        for meta in session.exec(select(IpMeta).where(IpMeta.ip.in_(addresses))).all():
            ptr_map[meta.ip] = meta.ptr

    out: list[dict[str, Any]] = []
    for (
        ip,
        total,
        aligned,
        spf_aligned,
        dkim_aligned,
        signed,
        spf_auth,
        dkim_auth,
        first_seen,
        last_seen,
        code,
        country_name,
        header_from,
        envelope_from,
        foreign,
    ) in rows:
        total = int(total)
        providers = sorted({provider_for(org).name for org in orgs.get(ip, [])})
        out.append(
            {
                "ip": ip,
                "ptr": ptr_map.get(ip),
                "messages": total,
                "aligned": int(aligned),
                "failed": total - int(aligned),
                "verified": total > 0 and int(aligned) == total,
                "dmarc": _status(int(aligned), total),
                "spf": _status(int(spf_auth), total),
                "spf_aligned": _status(int(spf_aligned), total),
                "dkim": _status(int(dkim_auth), total, present=int(signed) > 0),
                "dkim_aligned": _status(int(dkim_aligned), total),
                "dkim_signed_messages": int(signed),
                "unsigned_messages": total - int(signed),
                "foreign_header_messages": int(foreign),
                "country": {
                    "code": code,
                    "name": country_name or (COUNTRY_NAMES.get(code) if code else None),
                    "flag": country_flag(code),
                },
                "first_seen": _iso(first_seen),
                "last_seen": _iso(last_seen),
                "header_from": header_from,
                "envelope_from": envelope_from,
                "providers": providers,
                "dispositions": dispositions.get(ip, {}),
            }
        )
    return out


def _status(pass_messages: int, total: int, present: bool = True) -> str:
    if not present or total <= 0:
        return "none"
    if pass_messages >= total:
        return "pass"
    if pass_messages <= 0:
        return "fail"
    return "mixed"


def _country_breakdown(session: Session, conditions: list[Any]) -> list[dict[str, Any]]:
    rows = session.exec(
        select(
            SourceRecord.country_code,
            func.max(SourceRecord.country_name),
            func.sum(SourceRecord.message_count),
            func.sum(case((ALIGNED, SourceRecord.message_count), else_=0)),
        )
        .where(*conditions)
        .group_by(SourceRecord.country_code)
        .order_by(func.sum(SourceRecord.message_count).desc())
    ).all()
    out = []
    for code, name, total, aligned in rows:
        out.append(
            {
                "code": code,
                "name": name or COUNTRY_NAMES.get(code or "", "Unknown"),
                "flag": country_flag(code),
                "messages": int(total or 0),
                "aligned": int(aligned or 0),
            }
        )
    return out


def _submitters(session: Session, domain_id: Optional[int], rng: DateRange) -> list[dict[str, Any]]:
    conditions = [Report.report_date >= rng.start, Report.report_date <= rng.end]
    if domain_id is not None:
        conditions.append(Report.domain_id == domain_id)
    rows = session.exec(
        select(
            Report.org_name,
            func.count(distinct(Report.id)),
            func.sum(Report.message_count),
        )
        .where(*conditions)
        .group_by(Report.org_name)
        .order_by(func.sum(Report.message_count).desc())
    ).all()
    out = []
    for org, reports, messages in rows:
        provider = provider_for(org)
        out.append(
            {
                "org": org,
                "name": provider.name,
                "color": provider.color,
                "known": provider.known,
                "reports": int(reports or 0),
                "messages": int(messages or 0),
            }
        )
    return out


def _policy_snapshot(session: Session, domain: Domain, rng: DateRange) -> dict[str, Any]:
    latest = session.exec(
        select(Report)
        .where(Report.domain_id == domain.id)
        .order_by(Report.date_end.desc(), Report.id.desc())
    ).first()
    if latest is None:
        return {
            "available": False,
            "message": "No reports ingested for this domain yet.",
        }

    variants = session.exec(
        select(Report.policy_p, Report.policy_sp, Report.policy_pct, func.count(distinct(Report.id)))
        .where(Report.domain_id == domain.id, Report.report_date >= rng.start)
        .group_by(Report.policy_p, Report.policy_sp, Report.policy_pct)
        .order_by(func.count(distinct(Report.id)).desc())
    ).all()
    p = (latest.policy_p or "none").lower()
    sp = (latest.policy_sp or p).lower()
    pct = latest.policy_pct if latest.policy_pct is not None else 100
    enforced = (p == "reject" and pct == 100) or (p == "quarantine" and pct == 100)
    return {
        "available": True,
        "p": p,
        "sp": sp,
        "pct": pct,
        "adkim": latest.policy_adkim,
        "aspf": latest.policy_aspf,
        "fo": latest.policy_fo,
        "label": f"p={p}" + ("" if pct == 100 else f" (pct={pct})"),
        "enforced": enforced,
        "mode": "enforced" if p == "reject" else ("quarantine" if p == "quarantine" else "monitoring"),
        "observed_since": _iso(latest.date_begin),
        "last_report_date": _iso(latest.report_date),
        "variants": [
            {"p": row[0], "sp": row[1], "pct": row[2], "reports": int(row[3] or 0)}
            for row in variants
        ],
    }


def _policy_overview(session: Session, rng: DateRange) -> list[dict[str, Any]]:
    """Latest published policy per domain, for the fleet-level view."""
    domains = session.exec(select(Domain).order_by(Domain.name)).all()
    stats = {
        row[0]: row
        for row in session.exec(
            select(
                SourceRecord.domain_id,
                func.coalesce(func.sum(SourceRecord.message_count), 0),
                func.coalesce(func.sum(case((ALIGNED, SourceRecord.message_count), else_=0)), 0),
            )
            .where(SourceRecord.report_date >= rng.start, SourceRecord.report_date <= rng.end)
            .group_by(SourceRecord.domain_id)
        ).all()
    }
    out: list[dict[str, Any]] = []
    for item in domains:
        latest = session.exec(
            select(Report)
            .where(Report.domain_id == item.id)
            .order_by(Report.date_end.desc(), Report.id.desc())
        ).first()
        if latest is None:
            continue
        stat = stats.get(item.id)
        messages = int(stat[1]) if stat else 0
        aligned = int(stat[2]) if stat else 0
        out.append(
            {
                "domain": item.name,
                "p": (latest.policy_p or "none").lower(),
                "pct": latest.policy_pct if latest.policy_pct is not None else 100,
                "messages": messages,
                "aligned_pct": round(aligned / messages * 100, 1) if messages else None,
                "last_report_date": _iso(latest.report_date),
            }
        )
    out.sort(key=lambda row: row["messages"], reverse=True)
    return out


def _coverage(session: Session, domain_id: Optional[int], rng: DateRange) -> dict[str, Any]:
    conditions = [Report.report_date >= rng.start, Report.report_date <= rng.end]
    if domain_id is not None:
        conditions.append(Report.domain_id == domain_id)
    row = session.exec(
        select(
            func.count(distinct(Report.report_date)),
            func.count(Report.id),
            func.max(Report.ingested_at),
            func.count(distinct(Report.domain_id)),
        ).where(*conditions)
    ).one()
    days_with_reports = int(row[0] or 0)
    return {
        "days_with_reports": days_with_reports,
        "days": rng.days,
        "pct": round(days_with_reports / rng.days * 100, 1) if rng.days else 0,
        "reports": int(row[1] or 0),
        "last_ingested_at": _iso(row[2]),
        "domains": int(row[3] or 0),
    }


def _summary_sentences(summary: dict[str, Any], policy: Optional[dict[str, Any]]) -> list[str]:
    sentences: list[str] = []
    if summary["messages"] == 0:
        return ["No messages were reported in this period."]
    sentences.append(
        f"{summary['messages']} messages from {summary['sources']} sending "
        f"{'source' if summary['sources'] == 1 else 'sources'} this period. "
        f"{summary['aligned']} proved they came from you."
    )
    if summary["failed"] == 0:
        sentences.append("Every reported message authenticated and aligned with your domain.")
    else:
        sentences.append(
            f"{summary['failed']} messages could not prove they came from you — worth a look."
        )
    if summary["spf_only_messages"]:
        sentences.append(
            f"{summary['spf_only_messages']} messages passed on SPF alone — DKIM did not count for "
            "them. An aligned DKIM signature that verifies would keep them authenticated when "
            "they are forwarded."
        )
    if summary["unsigned_messages"] and summary["aligned"]:
        sentences.append(
            f"{summary['unsigned_messages']} messages arrived without a DKIM signature the "
            "receiver could evaluate."
        )
    if policy and policy.get("available"):
        p = policy["p"]
        if p == "none":
            sentences.append(
                "Your published policy is p=none, so receivers still deliver failing mail."
            )
        elif p == "quarantine":
            sentences.append("Your published policy is p=quarantine: failing mail is filtered.")
        elif p == "reject":
            sentences.append("Your published policy is p=reject: failing mail is rejected.")
    return sentences


def advise(policy: Optional[dict[str, Any]], summary: dict[str, Any], days: int) -> dict[str, Any]:
    """Turn the observed policy + compliance into a short recommendation."""
    if not policy or not policy.get("available"):
        return {
            "status": "unknown",
            "label": "No policy observed",
            "tone": "info",
            "advice": "Ingest a few reports to see the published policy and get a recommendation.",
            "options": [],
        }
    p = policy["p"]
    pct = summary["aligned_pct"]
    failed = summary["failed"]
    options = [
        {"value": "none", "label": "p=none", "state": "active" if p == "none" else "off", "detail": "Monitoring"},
        {
            "value": "quarantine",
            "label": "p=quarantine",
            "state": "active" if p == "quarantine" else "off",
            "detail": "Quarantine — ramp 25→50→100%",
        },
        {
            "value": "reject",
            "label": "p=reject",
            "state": "active" if p == "reject" else "off",
            "detail": "Enforced — no pct tag, so all failing mail",
        },
    ]
    pct_enforced = policy.get("pct", 100) == 100
    if p == "reject":
        tone, label = "good", "Fully enforced"
        advice = (
            "Receivers that honour your policy reject unauthenticated mail. Watch this page for "
            "new sending sources before they turn into delivery problems."
        )
        if failed:
            advice += f" {failed} reported messages still failed alignment; they were rejected."
    elif p == "quarantine":
        if not pct_enforced:
            tone, label = "warn", "Partial quarantine"
            advice = (
                f"Only {policy.get('pct')}% of failing mail is quarantined. Raise pct to 100 once "
                "the sources below look clean."
            )
        elif pct >= 99.0 and failed == 0:
            tone, label = "good", "Quarantine enforced"
            advice = "Compliance is clean. Consider moving to p=reject once this holds for a week."
        else:
            tone, label = "warn", "Quarantine enforced"
            advice = (
                f"{failed} messages still fail. Fix the sources listed below before tightening "
                "to p=reject."
            )
    else:
        if pct >= 98.0:
            tone, label = "warn", "Monitoring only"
            advice = (
                "Almost everything authenticates. Move to p=quarantine, then p=reject, to stop "
                "spoofed mail from being delivered."
            )
        else:
            tone, label = "warn", "Monitoring only"
            advice = (
                f"{failed} messages fail alignment and are still delivered. Fix the sending "
                "sources below before publishing an enforcing policy."
            )
    return {
        "status": policy["mode"],
        "label": label,
        "tone": tone,
        "advice": advice,
        "options": options,
        "days_observed": days,
    }


# ------------------------------------------------------------------- reports
def reports_page(
    session: Session,
    *,
    domain: Optional[Domain],
    rng: Optional[DateRange],
    page: int = 1,
    page_size: int = 25,
    query: str = "",
) -> dict[str, Any]:
    page = max(1, page)
    page_size = max(1, min(page_size, 200))
    conditions: list[Any] = []
    if domain is not None:
        conditions.append(Report.domain_id == domain.id)
    if rng is not None:
        conditions.append(Report.report_date >= rng.start)
        conditions.append(Report.report_date <= rng.end)
    if query:
        like = f"%{query.strip().lower()}%"
        conditions.append(
            or_(
                func.lower(Report.org_name).like(like),
                func.lower(Report.report_id).like(like),
                func.lower(Report.policy_domain).like(like),
            )
        )
    total = _one_int(session, select(func.count(Report.id)).where(*conditions))
    rows = session.exec(
        select(Report, Domain)
        .join(Domain, Domain.id == Report.domain_id)
        .where(*conditions)
        .order_by(Report.date_begin.desc(), Report.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    items = []
    for report, domain_row in rows:
        provider = provider_for(report.org_name)
        items.append(
            {
                "id": report.id,
                "kind": "dmarc",
                "domain": domain_row.name,
                "org": report.org_name,
                "org_name": provider.name,
                "org_color": provider.color,
                "report_id": report.report_id,
                "date_begin": _iso(report.date_begin),
                "date_end": _iso(report.date_end),
                "date": report.report_date.isoformat(),
                "messages": report.message_count,
                "aligned": report.aligned_count,
                "failed": report.failed_count,
                "aligned_pct": round(report.aligned_count / report.message_count * 100, 1)
                if report.message_count
                else 0,
                "records": report.record_count,
                "sources": report.source_count,
                "policy": report.policy_p,
                "source": report.source,
                "ingested_at": _iso(report.ingested_at),
            }
        )
    return {
        "items": items,
        "page": page,
        "page_size": page_size,
        "total": total,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


def report_detail(session: Session, report_id: int) -> Optional[dict[str, Any]]:
    report = session.get(Report, report_id)
    if report is None:
        return None
    domain = session.get(Domain, report.domain_id)
    provider = provider_for(report.org_name)
    records = session.exec(
        select(SourceRecord).where(SourceRecord.report_id == report_id).order_by(SourceRecord.message_count.desc())
    ).all()
    return {
        "id": report.id,
        "kind": "dmarc",
        "domain": domain.name if domain else None,
        "org": report.org_name,
        "org_name": provider.name,
        "org_color": provider.color,
        "report_id": report.report_id,
        "org_email": report.org_email,
        "date_begin": _iso(report.date_begin),
        "date_end": _iso(report.date_end),
        "date": report.report_date.isoformat(),
        "policy": {
            "domain": report.policy_domain,
            "p": report.policy_p,
            "sp": report.policy_sp,
            "pct": report.policy_pct,
            "adkim": report.policy_adkim,
            "aspf": report.policy_aspf,
            "fo": report.policy_fo,
        },
        "message_count": report.message_count,
        "aligned_count": report.aligned_count,
        "failed_count": report.failed_count,
        "source_count": report.source_count,
        "ingested_at": _iso(report.ingested_at),
        "received_at": _iso(report.received_at),
        "source": report.source,
        "raw_sha256": report.raw_sha256,
        "records": [
            {
                "ip": record.source_ip,
                "messages": record.message_count,
                "aligned": record.aligned,
                "dkim": "pass" if record.dkim_pass else "fail",
                "spf": "pass" if record.spf_pass else "fail",
                "disposition": record.disposition,
                "header_from": record.header_from,
                "envelope_from": record.envelope_from,
                "envelope_to": record.envelope_to,
                "country": {
                    "code": record.country_code,
                    "name": record.country_name,
                    "flag": country_flag(record.country_code),
                },
                "dkim_entries": [
                    {"domain": d, "selector": s, "result": r}
                    for d, s, r in zip(record.dkim_domains, record.dkim_selectors, record.dkim_results, strict=False)
                ],
                "spf_entries": [
                    {"domain": d, "result": r}
                    for d, r in zip(record.spf_domains, record.spf_results, strict=False)
                ],
                "reason": {"type": record.reason_type, "comment": record.reason_comment}
                if record.reason_type
                else None,
            }
            for record in records
        ],
    }


# ----------------------------------------------------------------------- TLS
def tls_dashboard(session: Session, domain: Optional[Domain], rng: DateRange) -> dict[str, Any]:
    conditions = _tls_conditions(domain.id if domain else None, rng)
    policies = session.exec(select(TlsPolicy).where(*conditions)).all()
    failures = session.exec(
        select(TlsFailure).where(
            TlsFailure.report_date >= rng.start,
            TlsFailure.report_date <= rng.end,
            *([TlsFailure.domain_id == domain.id] if domain else []),
        )
    ).all()
    report_conditions = [
        TlsReport.report_date >= rng.start,
        TlsReport.report_date <= rng.end,
    ]
    if domain:
        report_conditions.append(TlsReport.domain_id == domain.id)
    reports = session.exec(
        select(TlsReport).where(*report_conditions).order_by(TlsReport.date_begin.desc())
    ).all()

    success = sum(policy.total_success for policy in policies)
    failure = sum(policy.total_failure for policy in policies)
    sessions = success + failure

    by_day: dict[date, list[int]] = {}
    by_mx: dict[str, dict[str, int]] = {}
    for policy in policies:
        bucket = by_day.setdefault(policy.report_date, [0, 0])
        bucket[0] += policy.total_success
        bucket[1] += policy.total_failure
        for host in policy.mx_hosts or ["(unknown)"]:
            entry = by_mx.setdefault(host, {"success": 0, "failure": 0, "policies": 0})
            entry["success"] += policy.total_success
            entry["failure"] += policy.total_failure
            entry["policies"] += 1

    daily = []
    for day in rng.all_dates:
        ok, bad = by_day.get(day, (0, 0))
        daily.append({"date": day.isoformat(), "success": ok, "failure": bad, "total": ok + bad})

    failure_rows: dict[str, dict[str, Any]] = {}
    for item in failures:
        key = item.result_type or "unknown"
        entry = failure_rows.setdefault(
            key,
            {"result_type": key, "count": 0, "ips": set(), "hosts": set(), "last_seen": None, "reasons": set()},
        )
        entry["count"] += item.failed_count
        if item.sending_mta_ip:
            entry["ips"].add(item.sending_mta_ip)
        if item.receiving_mx:
            entry["hosts"].add(item.receiving_mx)
        if item.reason_code:
            entry["reasons"].add(item.reason_code)
        if entry["last_seen"] is None or (item.report_date and item.report_date > entry["last_seen"]):
            entry["last_seen"] = item.report_date

    failure_list = []
    for entry in sorted(failure_rows.values(), key=lambda item: item["count"], reverse=True):
        failure_list.append(
            {
                "result_type": entry["result_type"],
                "count": entry["count"],
                "ips": sorted(entry["ips"]),
                "hosts": sorted(entry["hosts"]),
                "reasons": sorted(entry["reasons"]),
                "last_seen": _iso(entry["last_seen"]),
            }
        )

    latest = reports[0] if reports else None
    return {
        "domain": {"id": domain.id, "name": domain.name, "display_name": domain.display_name}
        if domain
        else None,
        "range": {"start": rng.start.isoformat(), "end": rng.end.isoformat(), "days": rng.days, "label": rng.label},
        "kpis": {
            "sessions": sessions,
            "success": success,
            "failure": failure,
            "success_pct": round(success / sessions * 100, 1) if sessions else 0,
            "mx_hosts": len(by_mx),
            "reports": len(reports),
            "submitters": len({report.org_name for report in reports}),
        },
        "daily": daily,
        "policies": [
            {
                "host": host,
                "success": values["success"],
                "failure": values["failure"],
                "sessions": values["success"] + values["failure"],
                "success_pct": round(values["success"] / (values["success"] + values["failure"]) * 100, 1)
                if values["success"] + values["failure"]
                else 0,
                "policies": values["policies"],
            }
            for host, values in sorted(by_mx.items(), key=lambda item: item[1]["success"] + item[1]["failure"], reverse=True)
        ],
        "failures": failure_list,
        "policy": {
            "type": latest.policy_type if latest else None,
            "mode": latest.policy_mode if latest else None,
            "domain": latest.policy_domain if latest else None,
            "mx_hosts": latest.mx_hosts if latest else [],
            "max_age": latest.max_age if latest else None,
            "string": latest.policy_string if latest else [],
            "observed_since": _iso(latest.date_begin) if latest else None,
        }
        if latest
        else None,
        "reports": [_tls_report_row(report, session) for report in reports[:30]],
        "generated_at": _iso(datetime.now(timezone.utc)),
    }


def _tls_report_row(report: TlsReport, session: Session) -> dict[str, Any]:
    domain = session.get(Domain, report.domain_id)
    provider = provider_for(report.org_name)
    return {
        "id": report.id,
        "kind": "tls",
        "domain": domain.name if domain else None,
        "org": report.org_name,
        "org_name": provider.name,
        "org_color": provider.color,
        "report_id": report.report_id,
        "date_begin": _iso(report.date_begin),
        "date_end": _iso(report.date_end),
        "date": report.report_date.isoformat(),
        "success": report.total_success,
        "failure": report.total_failure,
        "sessions": report.total_success + report.total_failure,
        "success_pct": round(report.total_success / (report.total_success + report.total_failure) * 100, 1)
        if (report.total_success + report.total_failure)
        else 0,
        "source": report.source,
        "ingested_at": _iso(report.ingested_at),
    }


def tls_reports_page(
    session: Session,
    *,
    domain: Optional[Domain],
    page: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    page = max(1, page)
    page_size = max(1, min(page_size, 200))
    conditions: list[Any] = []
    if domain is not None:
        conditions.append(TlsReport.domain_id == domain.id)
    total = _one_int(session, select(func.count(TlsReport.id)).where(*conditions))
    rows = session.exec(
        select(TlsReport)
        .where(*conditions)
        .order_by(TlsReport.date_begin.desc(), TlsReport.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {
        "items": [_tls_report_row(report, session) for report in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
        "pages": max(1, (total + page_size - 1) // page_size),
    }


def tls_report_detail(session: Session, report_id: int) -> Optional[dict[str, Any]]:
    report = session.get(TlsReport, report_id)
    if report is None:
        return None
    base = _tls_report_row(report, session)
    policies = session.exec(select(TlsPolicy).where(TlsPolicy.tls_report_id == report_id)).all()
    failures = session.exec(select(TlsFailure).where(TlsFailure.tls_report_id == report_id)).all()
    base.update(
        {
            "contact_info": report.contact_info,
            "policy": {
                "type": report.policy_type,
                "mode": report.policy_mode,
                "domain": report.policy_domain,
                "mx_hosts": report.mx_hosts,
                "max_age": report.max_age,
                "string": report.policy_string,
            },
            "policies": [
                {
                    "type": policy.policy_type,
                    "domain": policy.policy_domain,
                    "mx_hosts": policy.mx_hosts,
                    "success": policy.total_success,
                    "failure": policy.total_failure,
                }
                for policy in policies
            ],
            "failure_details": [
                {
                    "result_type": item.result_type,
                    "mx": item.receiving_mx,
                    "ip": item.sending_mta_ip,
                    "count": item.failed_count,
                    "reason": item.reason_code,
                    "info": item.additional_info,
                    "country": {
                        "code": item.country_code,
                        "name": item.country_name,
                        "flag": country_flag(item.country_code),
                    },
                }
                for item in failures
            ],
            "raw_sha256": report.raw_sha256,
        }
    )
    return base
