"""Domain timeline: private annotations plus derived operational events."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlmodel import Session, select

from . import analytics
from .models import (
    AlertEvent,
    Domain,
    DomainAnnotation,
    DomainHealthSnapshot,
    utcnow,
)

CHECK_LABELS = {
    "dmarc": "DMARC record",
    "spf": "SPF record",
    "mta_sts": "MTA-STS policy",
    "tls_rpt": "TLS-RPT record",
}


def iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _fingerprint(result: dict[str, Any]) -> str:
    evidence = result.get("evidence") or {}
    return json.dumps(
        {
            "status": result.get("status"),
            "record": evidence.get("record"),
            "p": evidence.get("p"),
            "sp": evidence.get("sp"),
            "np": evidence.get("np"),
            "testing": evidence.get("testing"),
            "psd": evidence.get("psd"),
            "rua": evidence.get("rua"),
        },
        sort_keys=True,
        default=str,
    )


def _snapshot_events(session: Session, domain_id: int, since: datetime) -> list[dict[str, Any]]:
    snapshots = session.exec(
        select(DomainHealthSnapshot)
        .where(DomainHealthSnapshot.domain_id == domain_id)
        .order_by(DomainHealthSnapshot.checked_at.desc())
        .limit(20)
    ).all()
    snapshots = list(reversed(snapshots))
    events: list[dict[str, Any]] = []
    previous: dict[str, dict[str, Any]] = {}
    for snapshot in snapshots:
        current: dict[str, dict[str, Any]] = {}
        for result in snapshot.results or []:
            if not isinstance(result, dict) or result.get("key") not in CHECK_LABELS:
                continue
            key = str(result["key"])
            current[key] = result
            old = previous.get(key)
            if old is None:
                continue
            if _fingerprint(old) == _fingerprint(result):
                continue
            checked_at = snapshot.checked_at
            if checked_at.tzinfo is None:
                checked_at = checked_at.replace(tzinfo=timezone.utc)
            if checked_at < since:
                continue
            events.append(
                {
                    "id": f"dns:{snapshot.id}:{key}",
                    "source": "dns",
                    "kind": "dns",
                    "title": f"{CHECK_LABELS[key]} changed",
                    "body": f"{old.get('summary') or 'previous'} → {result.get('summary') or 'changed'}",
                    "occurred_at": iso(checked_at),
                    "editable": False,
                }
            )
        previous = current
    return events


def _alert_events(session: Session, domain_id: int, since: datetime) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    alerts = session.exec(
        select(AlertEvent)
        .where(AlertEvent.domain_id == domain_id, AlertEvent.triggered_at >= since)
        .order_by(AlertEvent.triggered_at.desc())
        .limit(40)
    ).all()
    for alert in alerts:
        events.append(
            {
                "id": f"alert:{alert.id}",
                "source": "alert",
                "kind": alert.severity,
                "title": alert.title,
                "body": alert.message,
                "occurred_at": iso(alert.triggered_at),
                "editable": False,
            }
        )
        if alert.resolved_at is not None:
            events.append(
                {
                    "id": f"alert-resolved:{alert.id}",
                    "source": "alert",
                    "kind": "resolved",
                    "title": f"Resolved: {alert.title}",
                    "body": "The alert condition cleared.",
                    "occurred_at": iso(alert.resolved_at),
                    "editable": False,
                }
            )
    return events


def _identity_events(session: Session, domain: Domain, since: datetime) -> list[dict[str, Any]]:
    end = utcnow().date()
    start = end - timedelta(days=90)
    rng = analytics.DateRange(start, end, 90, "90 days")
    identities = analytics._identities(session, domain.id, rng).get("items", [])  # noqa: SLF001
    events: list[dict[str, Any]] = []
    for item in identities:
        first_seen = item.get("first_seen")
        if not first_seen:
            continue
        try:
            when = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        except ValueError:
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if when < since:
            continue
        events.append(
            {
                "id": f"identity:{item.get('key')}",
                "source": "identity",
                "kind": "new-identity",
                "title": f"New sending identity: {item.get('label')}",
                "body": item.get("detail") or f"{item.get('messages', 0):,} messages",
                "occurred_at": iso(when),
                "editable": False,
            }
        )
    return events


def build_timeline(session: Session, domain: Domain, *, limit: int = 50) -> dict[str, Any]:
    """Return annotations and derived events, newest first.

    Annotations are private and deliberately never included in share payloads.
    """
    since = utcnow() - timedelta(days=180)
    annotations = session.exec(
        select(DomainAnnotation)
        .where(DomainAnnotation.domain_id == domain.id)
        .order_by(DomainAnnotation.occurred_at.desc())
        .limit(limit)
    ).all()
    items: list[dict[str, Any]] = [
        {
            "id": f"annotation:{row.id}",
            "ref_id": row.id,
            "source": "annotation",
            "kind": row.kind,
            "title": row.title,
            "body": row.body,
            "occurred_at": iso(row.occurred_at),
            "created_at": iso(row.created_at),
            "editable": True,
        }
        for row in annotations
    ]
    items.extend(_snapshot_events(session, domain.id, since))
    items.extend(_alert_events(session, domain.id, since))
    items.extend(_identity_events(session, domain, since))
    for gap in analytics._report_gaps(session, domain.id):  # noqa: SLF001
        items.append(
            {
                "id": "report-gap",
                "source": "report_gap",
                "kind": "gap",
                "title": "Reports overdue",
                "body": (
                    f"No report for {gap['hours']} hours; expected every "
                    f"{gap['expected_hours']} hours."
                ),
                "occurred_at": iso(utcnow()),
                "editable": False,
            }
        )
    items.sort(key=lambda item: item.get("occurred_at") or "", reverse=True)
    return {
        "domain": domain.name,
        "items": items[:limit],
        "annotation_count": len(items) - len([item for item in items if item["source"] != "annotation"]),
    }
