"""Share-link management and the unauthenticated read-only public endpoint."""

from __future__ import annotations

import hashlib
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from .. import analytics, audit, share
from ..db import get_session
from ..deps import current_user
from ..models import Domain, ShareLink, utcnow

router = APIRouter(
    prefix="/api/share-links", tags=["share"], dependencies=[Depends(current_user)]
)
public_router = APIRouter(prefix="/api/public", tags=["share"])


class CreateShareLink(BaseModel):
    domain: Optional[str] = None
    days: int = Field(default=7, ge=1, le=90)
    include_sources: bool = False


def _domain_name_map(session: Session) -> dict[int, str]:
    return {domain.id: domain.name for domain in session.exec(select(Domain)).all()}


@router.post("")
def create_link(
    payload: CreateShareLink,
    request: Request,
    session: Session = Depends(get_session),
) -> dict:
    domain_row = None
    if payload.domain and payload.domain not in {"all", "*"}:
        domain_row = analytics.get_domain(session, payload.domain)
        if domain_row is None:
            raise HTTPException(status_code=404, detail=f"Unknown domain {payload.domain!r}")
    row, token = share.create_link(
        session,
        domain=domain_row,
        days=payload.days,
        include_sources=payload.include_sources,
    )
    audit.record(
        session,
        "share.create",
        actor=audit.actor(request),
        domain=domain_row.name if domain_row else None,
        target=str(row.id),
        detail={"days": payload.days, "include_sources": payload.include_sources},
    )
    session.commit()
    return {
        **share.serialise_link(row, domain_row.name if domain_row else None),
        "token": token,
        "url": f"/s/{token}",
    }


@router.get("")
def list_links(session: Session = Depends(get_session)) -> dict:
    names = _domain_name_map(session)
    rows = session.exec(select(ShareLink).order_by(ShareLink.created_at.desc())).all()
    return {"items": [share.serialise_link(row, names.get(row.domain_id)) for row in rows]}


@router.post("/{link_id}/revoke")
def revoke_link(
    link_id: int, request: Request, session: Session = Depends(get_session)
) -> dict:
    row = session.get(ShareLink, link_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Share link not found")
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        session.add(row)
        session.commit()
        session.refresh(row)
    names = _domain_name_map(session)
    audit.record(
        session,
        "share.revoke",
        actor=audit.actor(request),
        domain=names.get(row.domain_id),
        target=str(row.id),
    )
    session.commit()
    return share.serialise_link(row, names.get(row.domain_id))


_rate: dict[str, list[float]] = {}


def _rate_allowed(token: str) -> bool:
    now = time.time()
    key = hashlib.sha256(token.encode()).hexdigest()[:24]
    bucket = [stamp for stamp in _rate.get(key, []) if now - stamp < 3600]
    if len(bucket) >= 120:
        return False
    bucket.append(now)
    _rate[key] = bucket
    if len(_rate) > 5000:
        for old_key in [item for item, stamps in _rate.items() if not stamps or now - stamps[-1] > 3600]:
            _rate.pop(old_key, None)
    return True


@public_router.get("/{token}")
def public_view(
    token: str,
    response: Response,
    session: Session = Depends(get_session),
) -> dict:
    if not _rate_allowed(token):
        raise HTTPException(status_code=429, detail="Too many requests")
    resolved = share.resolve_link(session, token)
    if resolved is None:
        raise HTTPException(status_code=404, detail="This share link is invalid or has expired")
    row, domain = resolved
    share.mark_used(session, row)

    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Frame-Options"] = "DENY"

    data = share.public_payload(session, row, domain)
    expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=utcnow().tzinfo)
    return {
        "scope": {
            "domain": domain.name if domain else None,
            "days": row.days,
            "include_sources": row.include_sources,
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
        },
        "dashboard": data,
    }
