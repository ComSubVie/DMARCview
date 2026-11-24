"""Append-only admin audit trail."""

from __future__ import annotations

from typing import Any, Optional

from sqlmodel import Session

from .models import AuditEvent


def actor(request) -> str:
    value = request.session.get("user") if request is not None else None
    return str(value or "admin")[:64]


def record(
    session: Session,
    action: str,
    *,
    actor: str = "admin",
    domain: Optional[str] = None,
    target: Optional[str] = None,
    detail: Optional[dict[str, Any]] = None,
) -> AuditEvent:
    """Add an audit row to the caller's transaction."""
    row = AuditEvent(
        actor=(actor or "admin")[:64],
        action=action[:64],
        domain=domain[:255] if domain else None,
        target=target[:255] if target else None,
        detail=detail or {},
    )
    session.add(row)
    return row
