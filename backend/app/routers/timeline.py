"""Private domain timeline and operator annotations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlmodel import Session

from .. import analytics, audit
from ..db import get_session
from ..deps import current_user
from ..models import Domain, DomainAnnotation, utcnow
from ..timeline import build_timeline, iso

router = APIRouter(prefix="/api", tags=["timeline"], dependencies=[Depends(current_user)])

KINDS = {"note", "dns", "esp", "outage", "other"}


def _domain_or_404(session: Session, name: str) -> Domain:
    domain = analytics.get_domain(session, name)
    if domain is None:
        raise HTTPException(status_code=404, detail=f"Unknown domain {name!r}")
    return domain


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class AnnotationPayload(BaseModel):
    occurred_at: Optional[datetime] = None
    kind: str = Field(default="note", max_length=32)
    title: str = Field(min_length=1, max_length=255)
    body: Optional[str] = Field(default=None, max_length=4000)


class AnnotationUpdate(BaseModel):
    occurred_at: Optional[datetime] = None
    kind: Optional[str] = Field(default=None, max_length=32)
    title: Optional[str] = Field(default=None, max_length=255)
    body: Optional[str] = Field(default=None, max_length=4000)


@router.get("/domains/{domain_name}/timeline")
def domain_timeline(
    domain_name: str,
    limit: int = Query(default=50, ge=1, le=100),
    session: Session = Depends(get_session),
) -> dict:
    domain = _domain_or_404(session, domain_name)
    return build_timeline(session, domain, limit=limit)


@router.post("/domains/{domain_name}/annotations", status_code=201)
def create_annotation(
    domain_name: str,
    payload: AnnotationPayload,
    request: Request,
    session: Session = Depends(get_session),
) -> dict:
    domain = _domain_or_404(session, domain_name)
    kind = payload.kind.strip().lower()
    if kind not in KINDS:
        raise HTTPException(status_code=422, detail=f"kind must be one of {', '.join(sorted(KINDS))}")
    title = payload.title.strip()
    if not title:
        raise HTTPException(status_code=422, detail="title must not be empty")
    row = DomainAnnotation(
        domain_id=domain.id,  # type: ignore[arg-type]
        occurred_at=_as_utc(payload.occurred_at) if payload.occurred_at else utcnow(),
        kind=kind,
        title=title,
        body=(payload.body or "").strip() or None,
    )
    session.add(row)
    audit.record(session, "annotation.create", actor=audit.actor(request), domain=domain.name, target=str(row.title))
    session.commit()
    session.refresh(row)
    return {"id": row.id, "occurred_at": iso(row.occurred_at), "kind": row.kind, "title": row.title, "body": row.body}


@router.put("/annotations/{annotation_id}")
def update_annotation(
    annotation_id: int,
    payload: AnnotationUpdate,
    request: Request,
    session: Session = Depends(get_session),
) -> dict:
    row = session.get(DomainAnnotation, annotation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown annotation")
    if payload.occurred_at is not None:
        row.occurred_at = _as_utc(payload.occurred_at)
    if payload.kind is not None:
        kind = payload.kind.strip().lower()
        if kind not in KINDS:
            raise HTTPException(
                status_code=422, detail=f"kind must be one of {', '.join(sorted(KINDS))}"
            )
        row.kind = kind
    if payload.title is not None:
        title = payload.title.strip()
        if not title:
            raise HTTPException(status_code=422, detail="title must not be empty")
        row.title = title
    if payload.body is not None:
        row.body = payload.body.strip() or None
    row.updated_at = utcnow()
    session.add(row)
    domain = session.get(Domain, row.domain_id)
    audit.record(
        session,
        "annotation.update",
        actor=audit.actor(request),
        domain=domain.name if domain else None,
        target=str(row.id),
    )
    session.commit()
    session.refresh(row)
    return {"id": row.id, "occurred_at": iso(row.occurred_at), "kind": row.kind, "title": row.title, "body": row.body}


@router.delete("/annotations/{annotation_id}")
def delete_annotation(
    annotation_id: int, request: Request, session: Session = Depends(get_session)
) -> dict:
    row = session.get(DomainAnnotation, annotation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown annotation")
    domain = session.get(Domain, row.domain_id)
    session.delete(row)
    audit.record(
        session,
        "annotation.delete",
        actor=audit.actor(request),
        domain=domain.name if domain else None,
        target=str(annotation_id),
    )
    session.commit()
    return {"ok": True}
