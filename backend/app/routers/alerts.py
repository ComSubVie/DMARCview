"""Alert rules, history and channel testing."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session

from ..alerts.service import evaluate, payload, send_test
from ..alerts.specs import SPECS
from ..db import get_session
from ..deps import current_user
from ..models import AlertRule, utcnow

router = APIRouter(
    prefix="/api/alerts", tags=["alerts"], dependencies=[Depends(current_user)]
)


class RuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    condition: Optional[dict[str, Any]] = None
    cooldown_minutes: Optional[int] = Field(default=None, ge=0, le=1440)


class TestRequest(BaseModel):
    channel: Optional[str] = None


@router.get("")
def alerts(session: Session = Depends(get_session)) -> dict:
    return payload(session)


@router.put("/rules/{rule_id}")
def update_rule(
    rule_id: int,
    body: RuleUpdate,
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
    session.commit()
    return payload(session)


@router.post("/run")
async def run_alerts(session: Session = Depends(get_session)) -> dict:
    summary = await evaluate(session)
    return {"summary": summary, "alerts": payload(session)}


@router.post("/test")
async def test_channel(body: TestRequest) -> dict:
    allowed = {"smtp", "telegram", "signal", "webhook", None}
    if body.channel not in allowed:
        raise HTTPException(status_code=400, detail="Unknown channel")
    return await send_test(body.channel)
