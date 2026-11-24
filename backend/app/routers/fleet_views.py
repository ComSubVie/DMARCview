"""Saved fleet table filter/sort presets."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from .. import audit
from ..db import get_session
from ..deps import current_user
from ..models import SavedFleetView, utcnow

router = APIRouter(prefix="/api/fleet/views", tags=["fleet"], dependencies=[Depends(current_user)])


class ViewPayload(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    filters: dict[str, Any] = Field(default_factory=dict)


class ViewUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    filters: dict[str, Any] | None = None


def _serialise(row: SavedFleetView) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "filters": row.filters or {},
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.get("")
def list_views(session: Session = Depends(get_session)) -> dict:
    rows = session.exec(select(SavedFleetView).order_by(SavedFleetView.name)).all()
    return {"items": [_serialise(row) for row in rows]}


@router.post("", status_code=201)
def create_view(payload: ViewPayload, request: Request, session: Session = Depends(get_session)) -> dict:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="name must not be empty")
    row = SavedFleetView(name=name, filters=payload.filters)
    session.add(row)
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail="a saved view with this name exists") from exc
    session.refresh(row)
    audit.record(session, "fleet_view.create", actor=audit.actor(request), target=row.name)
    session.commit()
    return _serialise(row)


@router.put("/{view_id}")
def update_view(
    view_id: int, payload: ViewUpdate, request: Request, session: Session = Depends(get_session)
) -> dict:
    row = session.get(SavedFleetView, view_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown saved view")
    if payload.name is not None:
        row.name = payload.name.strip() or row.name
    if payload.filters is not None:
        row.filters = payload.filters
    row.updated_at = utcnow()
    session.add(row)
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail="a saved view with this name exists") from exc
    session.refresh(row)
    audit.record(session, "fleet_view.update", actor=audit.actor(request), target=row.name)
    session.commit()
    return _serialise(row)


@router.delete("/{view_id}")
def delete_view(
    view_id: int, request: Request, session: Session = Depends(get_session)
) -> dict:
    row = session.get(SavedFleetView, view_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown saved view")
    name = row.name
    session.delete(row)
    audit.record(session, "fleet_view.delete", actor=audit.actor(request), target=name)
    session.commit()
    return {"ok": True}
