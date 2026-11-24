"""Read API: dashboard, sources, countries, reports and TLS-RPT."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlmodel import Session

from .. import analytics
from ..config import get_settings
from ..db import get_session
from ..deps import current_user
from ..geoip import get_geo_resolver
from ..models import Report, TlsReport
from ..version import VERSION

router = APIRouter(prefix="/api", tags=["dashboard"], dependencies=[Depends(current_user)])


def _domain_or_404(session: Session, name: Optional[str]):
    if not name or name in {"all", "*"}:
        return None
    domain = analytics.get_domain(session, name)
    if domain is None:
        raise HTTPException(status_code=404, detail=f"Unknown domain {name!r}")
    return domain


@router.get("/meta")
def meta(session: Session = Depends(get_session)) -> dict:
    settings = get_settings()
    domains = analytics.list_domains(session)
    return {
        "version": VERSION,
        "app": "DMARCView",
        "jmap_enabled": settings.jmap_enabled,
        "jmap_mailbox": settings.jmap_mailbox,
        "geoip": get_geo_resolver().available,
        "monthly_message_alert": settings.monthly_message_alert,
        "domains": [{"name": item["name"], "display_name": item["display_name"]} for item in domains],
        "domain_count": len(domains),
        "authenticated": True,
    }


@router.get("/domains")
def domains(session: Session = Depends(get_session)) -> dict:
    return {"items": analytics.list_domains(session)}


@router.get("/dashboard")
def dashboard(
    domain: Optional[str] = Query(default=None),
    days: int = Query(default=30, ge=1, le=analytics.MAX_DAYS),
    date_from: Optional[str] = Query(default=None, alias="from"),
    date_to: Optional[str] = Query(default=None, alias="to"),
    session: Session = Depends(get_session),
) -> dict:
    domain_row = _domain_or_404(session, domain)
    rng = analytics.resolve_range(days, date_from, date_to)
    payload = analytics.dashboard(session, domain_row, rng)
    payload["advice"] = analytics.advise(payload.get("policy"), payload["kpis"], rng.days)
    return payload


@router.get("/reports")
def reports(
    domain: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    q: str = Query(default=""),
    days: Optional[int] = Query(default=None, ge=1, le=analytics.MAX_DAYS),
    session: Session = Depends(get_session),
) -> dict:
    domain_row = _domain_or_404(session, domain)
    rng = analytics.resolve_range(days, None, None) if days else None
    return analytics.reports_page(
        session, domain=domain_row, rng=rng, page=page, page_size=page_size, query=q
    )


@router.get("/reports/{report_id}")
def report_detail(report_id: int, session: Session = Depends(get_session)) -> dict:
    payload = analytics.report_detail(session, report_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return payload


@router.get("/reports/{report_id}/raw")
def report_raw(report_id: int, session: Session = Depends(get_session)) -> Response:
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    filename = f"{report.policy_domain}-{report.report_id}.xml".replace("/", "_")
    return Response(
        content=report.raw_xml,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/tls")
def tls_dashboard(
    domain: Optional[str] = Query(default=None),
    days: int = Query(default=30, ge=1, le=analytics.MAX_DAYS),
    date_from: Optional[str] = Query(default=None, alias="from"),
    date_to: Optional[str] = Query(default=None, alias="to"),
    session: Session = Depends(get_session),
) -> dict:
    domain_row = _domain_or_404(session, domain)
    return analytics.tls_dashboard(session, domain_row, analytics.resolve_range(days, date_from, date_to))


@router.get("/tls/reports")
def tls_reports(
    domain: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    session: Session = Depends(get_session),
) -> dict:
    domain_row = _domain_or_404(session, domain)
    return analytics.tls_reports_page(session, domain=domain_row, page=page, page_size=page_size)


@router.get("/tls/reports/{report_id}")
def tls_report_detail(report_id: int, session: Session = Depends(get_session)) -> dict:
    payload = analytics.tls_report_detail(session, report_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="TLS report not found")
    return payload


@router.get("/tls/reports/{report_id}/raw")
def tls_report_raw(report_id: int, session: Session = Depends(get_session)) -> Response:
    report = session.get(TlsReport, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="TLS report not found")
    filename = f"{report.policy_domain}-{report.report_id}.json".replace("/", "_")
    return Response(
        content=report.raw_json,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
