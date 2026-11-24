"""Read-only audit trail API."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select

from ..db import get_session
from ..deps import current_user
from ..models import AuditEvent

router = APIRouter(prefix="/api", tags=["audit"], dependencies=[Depends(current_user)])


def _iso(value) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")


@router.get("/audit")
def list_audit(
    limit: int = Query(default=100, ge=1, le=500),
    action: Optional[str] = None,
    domain: Optional[str] = None,
    session: Session = Depends(get_session),
) -> dict:
    statement = select(AuditEvent)
    if action:
        statement = statement.where(AuditEvent.action == action)
    if domain:
        statement = statement.where(AuditEvent.domain == domain)
    rows = session.exec(statement.order_by(AuditEvent.at.desc()).limit(limit)).all()
    return {
        "items": [
            {
                "id": row.id,
                "at": _iso(row.at),
                "actor": row.actor,
                "action": row.action,
                "domain": row.domain,
                "target": row.target,
                "detail": row.detail or {},
            }
            for row in rows
        ],
        "total": len(rows),
    }
