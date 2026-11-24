"""Weekly operational digest built from the same aggregate tables as the UI."""

from __future__ import annotations

import html
from datetime import timedelta
from typing import Any

from sqlalchemy import case, func
from sqlmodel import Session, select

from .alerts.channels import send_email
from .analytics import ALIGNED
from .config import Settings
from .models import AlertEvent, Domain, Report, SourceRecord, TlsPolicy, utcnow


def _parse_recipients(value: str, fallback: str) -> list[str]:
    raw = value or fallback
    return [item.strip() for item in raw.replace(";", ",").split(",") if item.strip()]


def build_digest(session: Session, settings: Settings, *, days: int = 7) -> dict[str, Any]:
    end = utcnow().date()
    start = end - timedelta(days=max(1, days) - 1)
    messages, aligned, sources = session.exec(
        select(
            func.coalesce(func.sum(SourceRecord.message_count), 0),
            func.coalesce(func.sum(case((ALIGNED, SourceRecord.message_count), else_=0)), 0),
            func.count(SourceRecord.source_ip.distinct()),
        ).where(SourceRecord.report_date >= start, SourceRecord.report_date <= end)
    ).one()
    messages, aligned, sources = int(messages or 0), int(aligned or 0), int(sources or 0)
    domains = session.exec(select(Domain).order_by(Domain.name)).all()
    rows: list[dict[str, Any]] = []
    for domain in domains:
        domain_messages, domain_aligned = session.exec(
            select(
                func.coalesce(func.sum(SourceRecord.message_count), 0),
                func.coalesce(func.sum(case((ALIGNED, SourceRecord.message_count), else_=0)), 0),
            ).where(
                SourceRecord.domain_id == domain.id,
                SourceRecord.report_date >= start,
                SourceRecord.report_date <= end,
            )
        ).one()
        domain_messages, domain_aligned = int(domain_messages or 0), int(domain_aligned or 0)
        latest = session.exec(
            select(Report)
            .where(Report.domain_id == domain.id)
            .order_by(Report.date_end.desc(), Report.id.desc())
        ).first()
        failures = session.exec(
            select(
                SourceRecord.source_ip,
                func.coalesce(func.sum(SourceRecord.message_count), 0),
                func.coalesce(func.sum(case((ALIGNED, SourceRecord.message_count), else_=0)), 0),
            )
            .where(
                SourceRecord.domain_id == domain.id,
                SourceRecord.report_date >= start,
                SourceRecord.report_date <= end,
            )
            .group_by(SourceRecord.source_ip)
            .order_by(func.sum(SourceRecord.message_count).desc())
        ).all()
        top_failing = [
            {
                "ip": ip,
                "messages": int(total or 0),
                "aligned_pct": round(int(ok or 0) / int(total) * 100, 1) if total else 0.0,
            }
            for ip, total, ok in failures
            if int(total or 0) > int(ok or 0)
        ][:3]
        tls_success, tls_failure = session.exec(
            select(
                func.coalesce(func.sum(TlsPolicy.total_success), 0),
                func.coalesce(func.sum(TlsPolicy.total_failure), 0),
            ).where(
                TlsPolicy.domain_id == domain.id,
                TlsPolicy.report_date >= start,
                TlsPolicy.report_date <= end,
            )
        ).one()
        open_alerts = session.exec(
            select(func.count(AlertEvent.id)).where(
                AlertEvent.domain_id == domain.id, AlertEvent.resolved_at.is_(None)
            )
        ).one()
        rows.append(
            {
                "domain": domain.name,
                "messages": domain_messages,
                "aligned": domain_aligned,
                "aligned_pct": round(domain_aligned / domain_messages * 100, 1)
                if domain_messages
                else 0.0,
                "failed": max(0, domain_messages - domain_aligned),
                "policy": (latest.policy_p or "none") if latest else "none",
                "top_failing": top_failing,
                "tls_success": int(tls_success or 0),
                "tls_failure": int(tls_failure or 0),
                "open_alerts": int(open_alerts if isinstance(open_alerts, int) else open_alerts[0]),
            }
        )
    period = f"{start.isoformat()} → {end.isoformat()}"
    subject = f"[DMARCView] Weekly digest — {len(rows)} domain{'s' if len(rows) != 1 else ''}"
    text_lines = [
        "DMARCView weekly digest",
        f"Period: {period}",
        f"Fleet: {messages:,} messages · {aligned:,} aligned · {sources:,} sources",
        "",
    ]
    for row in rows:
        text_lines.append(
            f"{row['domain']}: {row['messages']:,} msgs · {row['aligned_pct']}% aligned · "
            f"p={row['policy']} · {row['open_alerts']} open alert(s)"
        )
        if row["top_failing"]:
            top = ", ".join(
                f"{item['ip']} ({item['messages']:,}, {item['aligned_pct']}%)"
                for item in row["top_failing"]
            )
            text_lines.append(f"  failing sources: {top}")
        tls_total = row["tls_success"] + row["tls_failure"]
        if tls_total:
            text_lines.append(
                f"  TLS: {row['tls_success'] / tls_total * 100:.1f}% successful "
                f"({tls_total:,} sessions)"
            )
        text_lines.append("")
    text_lines.append("Open DMARCView to inspect the details.")
    text = "\n".join(text_lines)

    html_rows = "".join(
        "<tr>"
        f"<td><strong>{html.escape(row['domain'])}</strong></td>"
        f"<td>{row['messages']:,}</td>"
        f"<td>{row['aligned_pct']}%</td>"
        f"<td><code>p={html.escape(row['policy'])}</code></td>"
        f"<td>{row['open_alerts']}</td>"
        "</tr>"
        for row in rows
    )
    html_body = (
        "<html><body style=\"font-family:system-ui,sans-serif;color:#1f2937\">"
        f"<h2>DMARCView weekly digest</h2><p>{html.escape(period)}</p>"
        f"<p><strong>{messages:,}</strong> messages · {aligned:,} aligned · {sources:,} sources</p>"
        "<table cellpadding=\"6\" cellspacing=\"0\" style=\"border-collapse:collapse\">"
        "<thead><tr><th align=\"left\">Domain</th><th align=\"right\">Messages</th>"
        "<th align=\"right\">Aligned</th><th align=\"left\">Policy</th>"
        "<th align=\"right\">Open alerts</th></tr></thead>"
        f"<tbody>{html_rows}</tbody></table>"
        "<p style=\"color:#667085\">Open DMARCView to inspect the details.</p>"
        "</body></html>"
    )
    return {"subject": subject, "text": text, "html": html_body, "period": period, "domains": rows}


async def send_digest(session: Session, settings: Settings, *, days: int = 7) -> dict[str, Any]:
    digest = build_digest(session, settings, days=days)
    to = _parse_recipients(settings.digest_to, settings.alert_to)
    if not to:
        return {"ok": False, "error": "no digest or alert recipients configured", **digest}
    result = await send_email(
        settings,
        digest["subject"],
        digest["text"],
        html=digest["html"],
        to=to,
    )
    return {
        "ok": result.ok,
        "error": result.error,
        "transport": result.channel,
        "recipients": to,
        **digest,
    }
