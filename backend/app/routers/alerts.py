"""Alert rules, history and channel testing."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from .. import analytics, audit
from ..alerts.service import evaluate, payload, retry_event, send_test
from ..alerts.specs import SPECS
from ..db import get_session
from ..deps import current_user
from ..models import AlertRule, AlertRuleOverride, Domain, SyncState, utcnow

router = APIRouter(
    prefix="/api/alerts", tags=["alerts"], dependencies=[Depends(current_user)]
)


class RuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    condition: Optional[dict[str, Any]] = None
    cooldown_minutes: Optional[int] = Field(default=None, ge=0, le=1440)


class TestRequest(BaseModel):
    channel: Optional[str] = None


def _domain(session, name: str) -> Domain:
    domain = analytics.get_domain(session, name)
    if domain is None:
        raise HTTPException(status_code=404, detail=f"Unknown domain {name!r}")
    return domain


@router.get("")
def alerts(session: Session = Depends(get_session)) -> dict:
    return payload(session)


@router.put("/rules/{rule_id}")
def update_rule(
    rule_id: int,
    body: RuleUpdate,
    request: Request,
    session: Session = Depends(get_session),
) -> dict:
    rule = session.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    spec = SPECS.get(rule.kind)
    if body.condition is not None and spec is not None:
        unknown = set(body.condition) - {field.key for field in spec.fields}
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown condition fields for {rule.kind}: {', '.join(sorted(unknown))}",
            )
        rule.condition = spec.clean({**rule.condition, **body.condition})
    if body.enabled is not None:
        rule.enabled = body.enabled
    if body.cooldown_minutes is not None:
        rule.cooldown_minutes = body.cooldown_minutes
    rule.updated_at = utcnow()
    session.add(rule)
    audit.record(session, "alert.rule", actor=audit.actor(request), target=rule.kind)
    session.commit()
    return payload(session)


@router.get("/overrides/{domain_name}")
def list_overrides(domain_name: str, session: Session = Depends(get_session)) -> dict:
    domain = _domain(session, domain_name)
    rules = [
        rule
        for rule in session.exec(select(AlertRule)).all()
        if (SPECS.get(rule.kind) is None or SPECS[rule.kind].scope == "domain")
    ]
    overrides = {
        row.rule_id: row
        for row in session.exec(
            select(AlertRuleOverride).where(AlertRuleOverride.domain_id == domain.id)
        ).all()
    }
    items = []
    for rule in rules:
        spec = SPECS.get(rule.kind)
        override = overrides.get(rule.id)
        items.append(
            {
                "rule_id": rule.id,
                "kind": rule.kind,
                "label": spec.label if spec else rule.kind,
                "description": spec.description if spec else "",
                "enabled": rule.enabled,
                "condition": spec.clean(rule.condition) if spec else rule.condition,
                "cooldown_minutes": rule.cooldown_minutes,
                "fields": [field.as_dict() for field in spec.fields] if spec else [],
                "override": {
                    "enabled": override.enabled,
                    "condition": spec.clean({**rule.condition, **(override.condition or {})})
                    if spec
                    else override.condition,
                    "cooldown_minutes": override.cooldown_minutes
                    if override.cooldown_minutes is not None
                    else rule.cooldown_minutes,
                }
                if override
                else None,
            }
        )
    return {"domain": domain.name, "rules": items}


@router.put("/overrides/{domain_name}/{kind}")
def update_override(
    domain_name: str,
    kind: str,
    body: RuleUpdate,
    request: Request,
    session: Session = Depends(get_session),
) -> dict:
    domain = _domain(session, domain_name)
    rule = session.exec(select(AlertRule).where(AlertRule.kind == kind)).first()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    spec = SPECS.get(kind)
    if spec is not None and spec.scope == "global":
        raise HTTPException(status_code=400, detail="Global rules cannot be overridden per domain")
    override = session.exec(
        select(AlertRuleOverride).where(
            AlertRuleOverride.rule_id == rule.id,
            AlertRuleOverride.domain_id == domain.id,
        )
    ).first()
    if override is None:
        override = AlertRuleOverride(rule_id=rule.id, domain_id=domain.id, enabled=True, condition={})
    if body.condition is not None and spec is not None:
        unknown = set(body.condition) - {field.key for field in spec.fields}
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown condition fields for {kind}: {', '.join(sorted(unknown))}",
            )
        override.condition = spec.clean({**rule.condition, **body.condition})
    if body.enabled is not None:
        override.enabled = body.enabled
    if body.cooldown_minutes is not None:
        override.cooldown_minutes = body.cooldown_minutes
    override.updated_at = utcnow()
    session.add(override)
    audit.record(
        session,
        "alert.override",
        actor=audit.actor(request),
        domain=domain.name,
        target=kind,
        detail={"enabled": override.enabled},
    )
    session.commit()
    return list_overrides(domain_name, session)


@router.delete("/overrides/{domain_name}/{kind}")
def delete_override(
    domain_name: str, kind: str, request: Request, session: Session = Depends(get_session)
) -> dict:
    domain = _domain(session, domain_name)
    rule = session.exec(select(AlertRule).where(AlertRule.kind == kind)).first()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    spec = SPECS.get(kind)
    if spec is not None and spec.scope == "global":
        raise HTTPException(status_code=400, detail="Global rules cannot be overridden per domain")
    override = session.exec(
        select(AlertRuleOverride).where(
            AlertRuleOverride.rule_id == rule.id,
            AlertRuleOverride.domain_id == domain.id,
        )
    ).first()
    if override is not None:
        session.delete(override)
        audit.record(session, "alert.override.reset", actor=audit.actor(request), domain=domain.name, target=kind)
        session.commit()
    return list_overrides(domain_name, session)


@router.post("/run")
async def run_alerts(session: Session = Depends(get_session)) -> dict:
    summary = await evaluate(session)
    return {"summary": summary, "alerts": payload(session)}


@router.post("/events/{event_id}/retry")
async def retry_delivery(
    event_id: int, request: Request, session: Session = Depends(get_session)
) -> dict:
    try:
        result = await retry_event(session, event_id)
        audit.record(session, "alert.retry", actor=audit.actor(request), target=str(event_id))
        session.commit()
        return result
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/digest")
def digest_status(session: Session = Depends(get_session)) -> dict:
    from ..alerts import channels
    from ..config import get_settings
    from ..digest import _parse_recipients

    settings = get_settings()
    state = session.get(SyncState, "digest.last_sent_at")
    recipients = _parse_recipients(settings.digest_to, settings.alert_to)
    transport = channels.email_transport(settings)
    return {
        "enabled": settings.digest_enabled,
        "days": settings.digest_days,
        "recipients": [item for item in recipients],
        "smtp_configured": channels.is_configured("smtp", settings),
        "jmap_configured": channels.is_configured("jmap", settings),
        "email_configured": transport is not None and bool(recipients),
        "transport": transport,
        "last_sent_at": state.value if state else None,
    }


@router.post("/digest/run")
async def run_digest(request: Request, session: Session = Depends(get_session)) -> dict:
    from ..config import get_settings
    from ..digest import send_digest

    result = await send_digest(session, get_settings(), days=get_settings().digest_days)
    audit.record(session, "digest.send", actor=audit.actor(request), detail={"ok": result.get("ok", False)})
    session.commit()
    return {
        "ok": result.get("ok", False),
        "error": result.get("error"),
        "domains": len(result.get("domains", [])),
        "period": result.get("period"),
        "transport": result.get("transport"),
    }


@router.post("/test")
async def test_channel(body: TestRequest) -> dict:
    allowed = {"smtp", "jmap", "telegram", "signal", "webhook", None}
    if body.channel not in allowed:
        raise HTTPException(status_code=400, detail="Unknown channel")
    return await send_test(body.channel)
