"""Alert seeding, evaluation, delivery and API shaping."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlmodel import Session, select

from ..config import get_settings
from ..models import AlertEvent, AlertRule, AlertRuleOverride, Domain, SyncState, utcnow
from . import channels
from .rules import evaluate_rule
from .specs import SPECS

LAST_RUN_KEY = "alerts.last_run"


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    aware = _aware(value)
    return aware.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z") if aware else None


def ensure_rules(session: Session) -> None:
    settings = get_settings()
    existing = {rule.kind for rule in session.exec(select(AlertRule)).all()}
    added = False
    for spec in SPECS.values():
        if spec.kind in existing:
            continue
        session.add(
            AlertRule(
                kind=spec.kind,
                condition=spec.defaults(),
                cooldown_minutes=settings.alert_cooldown_minutes,
            )
        )
        added = True
    if added:
        session.commit()


def _subject(event: AlertEvent, domain_name: str, resolved: bool) -> str:
    prefix = "Resolved" if resolved else event.severity.upper()
    return f"[DMARCView] {prefix} {domain_name}: {event.title}"


def _body(event: AlertEvent, settings) -> str:
    body = event.message
    if settings.alert_base_url:
        body += f"\n\nOpen DMARCView: {settings.alert_base_url}/alerts"
    return body


async def _notify(
    event: AlertEvent, domain: Optional[Domain], settings, *, resolved: bool
) -> list[channels.ChannelResult]:
    domain_name = domain.name if domain is not None else "All domains"
    payload = {
        "event_id": event.id,
        "domain": domain_name,
        "severity": event.severity,
        "title": event.title,
        "message": event.message,
        "resolved": resolved,
    }
    subject = _subject(event, domain_name, resolved)
    body = _body(event, settings)
    results = await channels.deliver(settings, subject, body, payload)
    if resolved:
        return results
    event.delivery_attempts = int(event.delivery_attempts or 0) + 1
    if not results:
        event.delivery_error = "no notification channels configured"
        event.delivered_at = None
        event.next_retry_at = utcnow() + timedelta(minutes=15 * event.delivery_attempts)
        return results
    delivered = [result for result in results if result.ok]
    event.delivered_at = utcnow() if delivered else None
    failures = [f"{result.channel}: {result.error}" for result in results if not result.ok]
    event.delivery_error = "; ".join(failures)[:4000] or None
    if delivered:
        event.next_retry_at = None
    elif event.delivery_attempts < 3:
        event.next_retry_at = utcnow() + timedelta(minutes=15 * event.delivery_attempts)
    return results


async def evaluate(
    session: Session,
    *,
    now: Optional[datetime] = None,
    send: bool = True,
    domain: Optional[Domain] = None,
    include_global: bool = True,
    create: bool = True,
    record_run: bool = True,
) -> dict[str, Any]:
    settings = get_settings()
    now = _aware(now) or utcnow()
    ensure_rules(session)

    rules = session.exec(select(AlertRule).where(AlertRule.enabled.is_(True))).all()
    domains = [domain] if domain is not None else session.exec(
        select(Domain).order_by(Domain.name)
    ).all()
    summary: dict[str, Any] = {
        "created": 0,
        "resolved": 0,
        "delivered": 0,
        "failed": 0,
        "notified": 0,
        "events": [],
    }

    for rule in rules:
        spec = SPECS.get(rule.kind)
        if spec is None:
            continue
        if spec.scope == "global":
            if not include_global or domain is not None:
                continue
            targets: list[Optional[Domain]] = [None]
        else:
            targets = list(domains)
        for target in targets:
            override = None
            if target is not None:
                override = session.exec(
                    select(AlertRuleOverride).where(
                        AlertRuleOverride.rule_id == rule.id,
                        AlertRuleOverride.domain_id == target.id,
                    )
                ).first()
            condition = dict(rule.condition or {})
            cooldown = rule.cooldown_minutes
            if override is not None:
                condition.update(override.condition or {})
                if override.cooldown_minutes is not None:
                    cooldown = override.cooldown_minutes
            findings = (
                []
                if override is not None and not override.enabled
                else evaluate_rule(
                    session,
                    type("RuleView", (), {"kind": rule.kind, "condition": condition})(),
                    target,
                    now,
                )
            )
            domain_clause = (
                AlertEvent.domain_id.is_(None)
                if target is None
                else AlertEvent.domain_id == target.id
            )
            open_events = session.exec(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule.id,
                    domain_clause,
                    AlertEvent.resolved_at.is_(None),
                )
            ).all()
            by_key = {event.dedupe_key: event for event in open_events}
            current_keys = set()

            for finding in findings:
                current_keys.add(finding.key)
                existing = by_key.get(finding.key)
                if existing is not None:
                    existing.title = finding.title[:255]
                    existing.message = finding.message
                    existing.severity = finding.severity
                    existing.payload = finding.payload
                    session.add(existing)
                    continue

                if not create:
                    continue
                latest = session.exec(
                    select(AlertEvent)
                    .where(
                        AlertEvent.rule_id == rule.id,
                        domain_clause,
                        AlertEvent.dedupe_key == finding.key,
                    )
                    .order_by(AlertEvent.triggered_at.desc())
                    .limit(1)
                ).first()
                if latest is not None:
                    last = _aware(latest.triggered_at)
                    if last and now - last < timedelta(minutes=max(0, cooldown)):
                        continue

                event = AlertEvent(
                    rule_id=rule.id,
                    domain_id=target.id if target is not None else None,
                    dedupe_key=finding.key[:160],
                    severity=finding.severity,
                    title=finding.title[:255],
                    message=finding.message,
                    payload=finding.payload,
                    triggered_at=now,
                )
                session.add(event)
                session.flush()
                summary["created"] += 1
                if send:
                    results = await _notify(event, target, settings, resolved=False)
                    if results:
                        summary["notified"] += 1
                        summary["delivered"] += sum(1 for result in results if result.ok)
                        summary["failed"] += sum(1 for result in results if not result.ok)
                summary["events"].append(
                    serialize_event(event, target.name if target else "All domains", rule.kind)
                )

            for key, event in by_key.items():
                if key in current_keys:
                    continue
                event.resolved_at = now
                session.add(event)
                summary["resolved"] += 1
                if send:
                    await _notify(event, target, settings, resolved=True)

            session.commit()

    if not record_run:
        return summary
    state = session.get(SyncState, LAST_RUN_KEY)
    if state is None:
        state = SyncState(key=LAST_RUN_KEY, value=now.isoformat())
        session.add(state)
    else:
        state.value = now.isoformat()
        state.updated_at = utcnow()
        session.add(state)
    session.commit()
    return summary


async def retry_event(session: Session, event_id: int) -> dict[str, Any]:
    settings = get_settings()
    event = session.get(AlertEvent, event_id)
    if event is None:
        raise ValueError("Alert event not found")
    domain = session.get(Domain, event.domain_id) if event.domain_id is not None else None
    if event.domain_id is not None and domain is None:
        raise ValueError("Domain not found")
    results = await _notify(event, domain, settings, resolved=False)
    session.add(event)
    session.commit()
    return {
        "event": serialize_event(event, domain.name if domain else "All domains", ""),
        "delivered": bool(results) and all(item.ok for item in results),
        "results": [item.as_dict() for item in results],
    }


async def send_test(channel: Optional[str] = None) -> dict[str, Any]:
    settings = get_settings()
    results = await channels.deliver(
        settings,
        "[DMARCView] Test notification",
        "If you can read this, alert delivery is configured correctly.",
        {"event": "test"},
        only=channel,
    )
    if not results:
        return {"ok": False, "results": [], "error": "No matching channel is configured"}
    return {"ok": all(result.ok for result in results), "results": [result.as_dict() for result in results]}


def serialize_event(event: AlertEvent, domain_name: str, kind: str) -> dict[str, Any]:
    return {
        "id": event.id,
        "kind": kind,
        "domain": domain_name,
        "severity": event.severity,
        "title": event.title,
        "message": event.message,
        "payload": event.payload,
        "triggered_at": _iso(event.triggered_at),
        "resolved_at": _iso(event.resolved_at),
        "delivered_at": _iso(event.delivered_at),
        "delivery_error": event.delivery_error,
        "delivery_attempts": int(event.delivery_attempts or 0),
        "next_retry_at": _iso(event.next_retry_at),
        "open": event.resolved_at is None,
    }


def payload(session: Session) -> dict[str, Any]:
    settings = get_settings()
    ensure_rules(session)
    rules = session.exec(select(AlertRule)).all()
    domains = {domain.id: domain.name for domain in session.exec(select(Domain)).all()}
    order = list(SPECS.keys())
    rules.sort(key=lambda rule: order.index(rule.kind) if rule.kind in order else 99)

    rule_payload = []
    for rule in rules:
        spec = SPECS.get(rule.kind)
        open_count = len(
            session.exec(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule.id, AlertEvent.resolved_at.is_(None)
                )
            ).all()
        )
        last = session.exec(
            select(AlertEvent)
            .where(AlertEvent.rule_id == rule.id)
            .order_by(AlertEvent.triggered_at.desc())
            .limit(1)
        ).first()
        rule_payload.append(
            {
                "id": rule.id,
                "kind": rule.kind,
                "label": spec.label if spec else rule.kind,
                "description": spec.description if spec else "",
                "severity": spec.severity if spec else "warning",
                "enabled": rule.enabled,
                "condition": spec.clean(rule.condition) if spec else rule.condition,
                "cooldown_minutes": rule.cooldown_minutes,
                "scope": spec.scope if spec else "domain",
                "open": open_count,
                "last_triggered_at": _iso(last.triggered_at) if last else None,
            }
        )

    events = session.exec(
        select(AlertEvent).order_by(AlertEvent.triggered_at.desc()).limit(100)
    ).all()
    kinds = {rule.id: rule.kind for rule in rules}
    event_payload = [
        serialize_event(event, domains.get(event.domain_id, "All domains"), kinds.get(event.rule_id, "?"))
        for event in events
    ]
    state = session.get(SyncState, LAST_RUN_KEY)
    return {
        "enabled": settings.alerts_enabled,
        "rules": rule_payload,
        "kinds": [spec.as_dict() for spec in SPECS.values()],
        "channels": channels.statuses(settings),
        "events": event_payload,
        "unresolved": sum(1 for item in event_payload if item["open"]),
        "last_run": _iso(datetime.fromisoformat(state.value)) if state else None,
    }
