"""CSV/JSON exports and a capped raw-report ZIP."""

from __future__ import annotations

import csv
import io
import os
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, Response
from sqlalchemy import case, func, or_
from sqlmodel import Session, select
from starlette.background import BackgroundTask

from .. import analytics
from ..db import get_session
from ..deps import current_user
from ..models import Domain, IpMeta, Report, SourceRecord, TlsReport

router = APIRouter(prefix="/api/export", tags=["export"], dependencies=[Depends(current_user)])

MAX_ZIP_REPORTS = 500
MAX_ZIP_BYTES = 200 * 1024 * 1024


def _resolve(session: Session, domain: Optional[str]):
    row = None
    if domain and domain not in {"all", "*"}:
        row = analytics.get_domain(session, domain)
        if row is None:
            raise HTTPException(status_code=404, detail=f"Unknown domain {domain!r}")
    return row


def _range(days: int, date_from: Optional[str], date_to: Optional[str]):
    return analytics.resolve_range(days, date_from, date_to)


def _csv(rows: list[list[Any]], header: list[str]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return buffer.getvalue()


def _download(content: str, media_type: str, filename: str) -> Response:
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _report_conditions(domain, rng, query: str) -> list[Any]:
    conditions: list[Any] = [Report.report_date >= rng.start, Report.report_date <= rng.end]
    if domain is not None:
        conditions.append(Report.domain_id == domain.id)
    if query:
        like = f"%{query.strip().lower()}%"
        conditions.append(
            or_(
                func.lower(Report.org_name).like(like),
                func.lower(Report.report_id).like(like),
                func.lower(Report.policy_domain).like(like),
            )
        )
    return conditions


@router.get("/reports.json")
def reports_json(
    domain: Optional[str] = Query(default=None),
    days: int = Query(default=30, ge=1, le=analytics.MAX_DAYS),
    date_from: Optional[str] = Query(default=None, alias="from"),
    date_to: Optional[str] = Query(default=None, alias="to"),
    q: str = Query(default=""),
    session: Session = Depends(get_session),
) -> dict:
    row = _resolve(session, domain)
    rng = _range(days, date_from, date_to)
    rows = session.exec(
        select(Report, Domain)
        .join(Domain, Domain.id == Report.domain_id)
        .where(*_report_conditions(row, rng, q))
        .order_by(Report.date_begin.desc(), Report.id.desc())
    ).all()
    items = []
    for report, domain_row in rows:
        items.append(
            {
                "domain": domain_row.name,
                "report_id": report.report_id,
                "org_name": report.org_name,
                "date_begin": analytics._iso(report.date_begin),
                "date_end": analytics._iso(report.date_end),
                "report_date": report.report_date.isoformat(),
                "messages": report.message_count,
                "aligned": report.aligned_count,
                "failed": report.failed_count,
                "aligned_pct": round(report.aligned_count / report.message_count * 100, 1)
                if report.message_count
                else 0,
                "policy_p": report.policy_p,
                "policy_sp": report.policy_sp,
                "policy_np": report.policy_np,
                "policy_pct": report.policy_pct,
                "policy_testing": report.policy_testing,
                "policy_discovery": report.policy_discovery,
                "source": report.source,
            }
        )
    return {"items": items, "count": len(items)}


@router.get("/reports.csv")
def reports_csv(
    domain: Optional[str] = Query(default=None),
    days: int = Query(default=30, ge=1, le=analytics.MAX_DAYS),
    date_from: Optional[str] = Query(default=None, alias="from"),
    date_to: Optional[str] = Query(default=None, alias="to"),
    q: str = Query(default=""),
    session: Session = Depends(get_session),
) -> Response:
    row = _resolve(session, domain)
    rng = _range(days, date_from, date_to)
    rows = session.exec(
        select(Report, Domain)
        .join(Domain, Domain.id == Report.domain_id)
        .where(*_report_conditions(row, rng, q))
        .order_by(Report.date_begin.desc(), Report.id.desc())
    ).all()
    body = _csv(
        [
            [
                domain_row.name,
                report.report_id,
                report.org_name,
                report.date_begin.isoformat(),
                report.date_end.isoformat(),
                report.report_date.isoformat(),
                report.message_count,
                report.aligned_count,
                report.failed_count,
                round(report.aligned_count / report.message_count * 100, 1)
                if report.message_count
                else 0,
                report.policy_p,
                report.policy_sp,
                report.policy_np,
                report.policy_pct,
                report.policy_testing,
                report.policy_discovery,
                report.source,
            ]
            for report, domain_row in rows
        ],
        [
            "domain",
            "report_id",
            "org_name",
            "date_begin",
            "date_end",
            "report_date",
            "messages",
            "aligned",
            "failed",
            "aligned_pct",
            "policy_p",
            "policy_sp",
            "policy_np",
            "policy_pct",
            "policy_testing",
            "policy_discovery",
            "source",
        ],
    )
    return _download(body, "text/csv; charset=utf-8", "dmarc-reports.csv")


@router.get("/sources.csv")
def sources_csv(
    domain: Optional[str] = Query(default=None),
    days: int = Query(default=30, ge=1, le=analytics.MAX_DAYS),
    date_from: Optional[str] = Query(default=None, alias="from"),
    date_to: Optional[str] = Query(default=None, alias="to"),
    session: Session = Depends(get_session),
) -> Response:
    row = _resolve(session, domain)
    rng = _range(days, date_from, date_to)
    conditions: list[Any] = [
        SourceRecord.report_date >= rng.start,
        SourceRecord.report_date <= rng.end,
    ]
    if row is not None:
        conditions.append(SourceRecord.domain_id == row.id)
    rows = session.exec(
        select(
            Domain.name,
            SourceRecord.source_ip,
            func.sum(SourceRecord.message_count),
            func.sum(case((analytics.ALIGNED, SourceRecord.message_count), else_=0)),
            func.sum(case((SourceRecord.dkim_pass, SourceRecord.message_count), else_=0)),
            func.sum(case((SourceRecord.spf_pass, SourceRecord.message_count), else_=0)),
            func.min(SourceRecord.report_date),
            func.max(SourceRecord.report_date),
            func.max(SourceRecord.country_code),
            func.max(SourceRecord.country_name),
        )
        .join(Domain, Domain.id == SourceRecord.domain_id)
        .where(*conditions)
        .group_by(Domain.name, SourceRecord.source_ip)
        .order_by(func.sum(SourceRecord.message_count).desc())
    ).all()
    ips = [item[1] for item in rows]
    ptrs = {
        meta.ip: meta.ptr
        for meta in session.exec(select(IpMeta).where(IpMeta.ip.in_(ips))).all()
    }
    body = _csv(
        [
            [
                name,
                ip,
                ptrs.get(ip) or "",
                code or "",
                country or "",
                int(messages or 0),
                int(aligned or 0),
                int(messages or 0) - int(aligned or 0),
                int(dkim or 0),
                int(spf or 0),
                first.isoformat() if first else "",
                last.isoformat() if last else "",
            ]
            for name, ip, messages, aligned, dkim, spf, first, last, code, country in rows
        ],
        [
            "domain",
            "source_ip",
            "ptr",
            "country_code",
            "country",
            "messages",
            "aligned",
            "failed",
            "dkim_pass_messages",
            "spf_pass_messages",
            "first_seen",
            "last_seen",
        ],
    )
    return _download(body, "text/csv; charset=utf-8", "dmarc-sources.csv")


@router.get("/tls.csv")
def tls_csv(
    domain: Optional[str] = Query(default=None),
    days: int = Query(default=30, ge=1, le=analytics.MAX_DAYS),
    date_from: Optional[str] = Query(default=None, alias="from"),
    date_to: Optional[str] = Query(default=None, alias="to"),
    session: Session = Depends(get_session),
) -> Response:
    row = _resolve(session, domain)
    rng = _range(days, date_from, date_to)
    conditions: list[Any] = [TlsReport.report_date >= rng.start, TlsReport.report_date <= rng.end]
    if row is not None:
        conditions.append(TlsReport.domain_id == row.id)
    rows = session.exec(
        select(TlsReport, Domain)
        .join(Domain, Domain.id == TlsReport.domain_id)
        .where(*conditions)
        .order_by(TlsReport.date_begin.desc(), TlsReport.id.desc())
    ).all()
    body = _csv(
        [
            [
                domain_row.name,
                report.report_id,
                report.org_name,
                report.date_begin.isoformat(),
                report.date_end.isoformat(),
                report.policy_type or "",
                report.policy_mode or "",
                report.max_age or "",
                report.total_success,
                report.total_failure,
                round(
                    report.total_success / (report.total_success + report.total_failure) * 100, 1
                )
                if (report.total_success + report.total_failure)
                else 0,
                ", ".join(report.mx_hosts or []),
            ]
            for report, domain_row in rows
        ],
        [
            "domain",
            "report_id",
            "org_name",
            "date_begin",
            "date_end",
            "policy_type",
            "policy_mode",
            "max_age",
            "success",
            "failure",
            "success_pct",
            "mx_hosts",
        ],
    )
    return _download(body, "text/csv; charset=utf-8", "tls-reports.csv")


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return cleaned[:120] or "report"


@router.get("/raw.zip")
def raw_zip(
    domain: Optional[str] = Query(default=None),
    days: int = Query(default=30, ge=1, le=analytics.MAX_DAYS),
    date_from: Optional[str] = Query(default=None, alias="from"),
    date_to: Optional[str] = Query(default=None, alias="to"),
    session: Session = Depends(get_session),
) -> FileResponse:
    row = _resolve(session, domain)
    rng = _range(days, date_from, date_to)
    conditions: list[Any] = [Report.report_date >= rng.start, Report.report_date <= rng.end]
    tls_conditions: list[Any] = [
        TlsReport.report_date >= rng.start,
        TlsReport.report_date <= rng.end,
    ]
    if row is not None:
        conditions.append(Report.domain_id == row.id)
        tls_conditions.append(TlsReport.domain_id == row.id)
    reports = session.exec(
        select(Report, Domain)
        .join(Domain, Domain.id == Report.domain_id)
        .where(*conditions)
        .order_by(Report.date_begin.desc())
        .limit(MAX_ZIP_REPORTS)
    ).all()
    tls_reports = session.exec(
        select(TlsReport, Domain)
        .join(Domain, Domain.id == TlsReport.domain_id)
        .where(*tls_conditions)
        .order_by(TlsReport.date_begin.desc())
        .limit(MAX_ZIP_REPORTS)
    ).all()

    handle, path = tempfile.mkstemp(prefix="dmarcview-export-", suffix=".zip")
    os.close(handle)
    total = 0
    added = 0
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for report, domain_row in reports:
            raw = report.raw_xml or b""
            if added >= MAX_ZIP_REPORTS or total + len(raw) > MAX_ZIP_BYTES:
                break
            archive.writestr(
                f"dmarc/{_safe_name(domain_row.name)}/{_safe_name(report.report_id)}-{report.id}.xml",
                raw,
            )
            total += len(raw)
            added += 1
        for report, domain_row in tls_reports:
            raw = report.raw_json or b""
            if added >= MAX_ZIP_REPORTS or total + len(raw) > MAX_ZIP_BYTES:
                break
            archive.writestr(
                f"tls/{_safe_name(domain_row.name)}/{_safe_name(report.report_id)}-{report.id}.json",
                raw,
            )
            total += len(raw)
            added += 1

    if added == 0:
        os.unlink(path)
        raise HTTPException(status_code=404, detail="No raw reports in this selection")
    filename = f"dmarcview-raw-{datetime.now(timezone.utc).date().isoformat()}.zip"
    return FileResponse(
        path,
        media_type="application/zip",
        filename=filename,
        background=BackgroundTask(os.unlink, path),
    )
