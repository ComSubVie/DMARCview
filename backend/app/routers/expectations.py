"""Known-sender expectations that suppress new-source noise."""

from __future__ import annotations

import ipaddress
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from .. import analytics, audit
from ..db import get_session
from ..deps import current_user
from ..models import Domain, SourceExpectation

router = APIRouter(prefix="/api", tags=["expectations"], dependencies=[Depends(current_user)])


def _domain_or_404(session: Session, name: str) -> Domain:
    domain = analytics.get_domain(session, name)
    if domain is None:
        raise HTTPException(status_code=404, detail=f"Unknown domain {name!r}")
    return domain


class ExpectationPayload(BaseModel):
    match_type: Literal["ip", "cidr", "asn", "domain"]
    value: str = Field(min_length=1, max_length=255)
    label: Optional[str] = Field(default=None, max_length=255)


def _clean_value(match_type: str, value: str) -> str:
    text = value.strip()
    if match_type == "ip":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="value is not a valid IP address") from exc
    if match_type == "cidr":
        try:
            return str(ipaddress.ip_network(text, strict=False))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="value is not a valid CIDR network") from exc
    if match_type == "asn":
        raw = text.upper().removeprefix("AS")
        if not raw.isdigit():
            raise HTTPException(status_code=422, detail="ASN must be a number")
        return str(int(raw))
    return text.strip(".").lower()


def _serialise(row: SourceExpectation) -> dict:
    return {
        "id": row.id,
        "match_type": row.match_type,
        "value": row.value,
        "label": row.label,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/domains/{domain_name}/expectations")
def list_expectations(domain_name: str, session: Session = Depends(get_session)) -> dict:
    domain = _domain_or_404(session, domain_name)
    rows = session.exec(
        select(SourceExpectation)
        .where(SourceExpectation.domain_id == domain.id)
        .order_by(SourceExpectation.match_type, SourceExpectation.value)
    ).all()
    return {"items": [_serialise(row) for row in rows]}


@router.post("/domains/{domain_name}/expectations", status_code=201)
def create_expectation(
    domain_name: str,
    payload: ExpectationPayload,
    request: Request,
    session: Session = Depends(get_session),
) -> dict:
    domain = _domain_or_404(session, domain_name)
    value = _clean_value(payload.match_type, payload.value)
    row = SourceExpectation(
        domain_id=domain.id,  # type: ignore[arg-type]
        match_type=payload.match_type,
        value=value,
        label=(payload.label or "").strip() or None,
    )
    session.add(row)
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail="this expectation already exists") from exc
    session.refresh(row)
    audit.record(session, "expectation.create", actor=audit.actor(request), domain=domain.name, target=value)
    session.commit()
    return _serialise(row)


@router.delete("/expectations/{expectation_id}")
def delete_expectation(
    expectation_id: int, request: Request, session: Session = Depends(get_session)
) -> dict:
    row = session.get(SourceExpectation, expectation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown expectation")
    domain = session.get(Domain, row.domain_id)
    session.delete(row)
    audit.record(
        session,
        "expectation.delete",
        actor=audit.actor(request),
        domain=domain.name if domain else None,
        target=row.value,
    )
    session.commit()
    return {"ok": True}
