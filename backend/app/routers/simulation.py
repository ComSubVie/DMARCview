"""Read-only DMARC policy simulation endpoint."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session

from .. import analytics
from ..db import get_session
from ..deps import current_user
from ..simulation import VALID_POLICIES, simulate

router = APIRouter(prefix="/api", tags=["simulation"], dependencies=[Depends(current_user)])


@router.get("/domains/{domain_name}/simulation")
def domain_simulation(
    domain_name: str,
    days: int = Query(default=30, ge=7, le=365),
    p: Optional[str] = Query(default=None),
    sp: Optional[str] = Query(default=None),
    np: Optional[str] = Query(default=None),
    t: Optional[str] = Query(default=None),
    session: Session = Depends(get_session),
) -> dict:
    domain = analytics.get_domain(session, domain_name)
    if domain is None:
        raise HTTPException(status_code=404, detail=f"Unknown domain {domain_name!r}")
    for name, value in (("p", p), ("sp", sp), ("np", np)):
        if value and value.lower() not in VALID_POLICIES:
            raise HTTPException(status_code=422, detail=f"{name} must be none, quarantine or reject")
    if t and t.lower() not in {"y", "n"}:
        raise HTTPException(status_code=422, detail="t must be y or n")
    return simulate(
        session,
        domain,
        analytics.resolve_range(days),
        proposed_p=p,
        proposed_sp=sp,
        proposed_np=np,
        proposed_testing=t,
    )
