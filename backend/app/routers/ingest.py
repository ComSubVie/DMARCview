"""Ingestion API: status, manual sync, .eml upload, connection probe."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import func
from sqlmodel import Session, select

from .. import poller
from ..config import get_settings
from ..db import get_engine, get_session
from ..deps import current_user
from ..geoip import get_geo_resolver
from ..ingest.jmap import JMAPClient, JMAPError
from ..ingest.service import ingest_raw_email
from ..models import IngestRun, Report, TlsReport, utcnow

log = logging.getLogger(__name__)


def _z(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
router = APIRouter(prefix="/api/ingest", tags=["ingest"], dependencies=[Depends(current_user)])

MAX_UPLOAD_BYTES = 40 * 1024 * 1024
_tasks: set[asyncio.Task] = set()


@router.get("/status")
def ingest_status(session: Session = Depends(get_session)) -> dict[str, Any]:
    settings = get_settings()
    runs = session.exec(select(IngestRun).order_by(IngestRun.started_at.desc()).limit(8)).all()
    report_count = session.exec(select(func.count(Report.id))).one()
    tls_count = session.exec(select(func.count(TlsReport.id))).one()
    last_report = session.exec(
        select(Report.ingested_at).order_by(Report.ingested_at.desc()).limit(1)
    ).first()
    return {
        "configured": bool(settings.jmap_enabled and settings.jmap_url),
        "enabled": settings.jmap_enabled,
        "url": settings.jmap_url,
        "username": settings.jmap_username,
        "mailbox": settings.jmap_mailbox,
        "poll_seconds": settings.jmap_poll_seconds,
        "geoip": get_geo_resolver().available,
        "state": poller.status(),
        "counts": {
            "reports": int(report_count[0] if isinstance(report_count, (tuple, list)) else report_count),
            "tls_reports": int(tls_count[0] if isinstance(tls_count, (tuple, list)) else tls_count),
            "last_ingested_at": _z(last_report if isinstance(last_report, datetime) else None),
        },
        "runs": [
            {
                "id": run.id,
                "source": run.source,
                "started_at": _z(run.started_at),
                "finished_at": _z(run.finished_at),
                "status": run.status,
                "messages_seen": run.messages_seen,
                "messages_ingested": run.messages_ingested,
                "reports_created": run.reports_created,
                "tls_reports_created": run.tls_reports_created,
                "error": run.error,
            }
            for run in runs
        ],
    }


@router.post("/run", status_code=202)
async def run_now() -> dict[str, Any]:
    settings = get_settings()
    if not settings.jmap_enabled:
        raise HTTPException(status_code=400, detail="JMAP ingestion is disabled (JMAP_ENABLED=false)")
    if not settings.jmap_url:
        raise HTTPException(status_code=400, detail="JMAP_URL is not configured")
    if poller.is_running():
        raise HTTPException(status_code=409, detail="A sync is already running")

    task = asyncio.create_task(_background_sync())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return {"started": True}


async def _background_sync() -> None:
    with suppress(Exception):  # recorded in poller state
        await poller.run_sync("manual")


@router.post("/probe")
async def probe() -> dict[str, Any]:
    settings = get_settings()
    if not settings.jmap_url:
        raise HTTPException(status_code=400, detail="JMAP_URL is not configured")
    client = JMAPClient(
        settings.jmap_url,
        settings.jmap_username,
        settings.jmap_password,
        settings.jmap_token,
    )
    try:
        result = await client.probe()
        settings_snapshot = get_settings()
        result["mailbox_setting"] = settings_snapshot.jmap_mailbox
        return result
    except JMAPError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/upload")
async def upload(files: list[UploadFile] = File(...)) -> dict[str, Any]:
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")
    payloads: list[tuple[str, bytes]] = []
    for upload_file in files:
        data = await upload_file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413, detail=f"{upload_file.filename} exceeds the 40 MB limit"
            )
        payloads.append((upload_file.filename or "upload.eml", data))
    if not payloads:
        raise HTTPException(status_code=400, detail="No readable files uploaded")
    result = await run_in_threadpool(_process_uploads, payloads)
    return result


def _process_uploads(payloads: list[tuple[str, bytes]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "files": len(payloads),
        "reports": 0,
        "tls_reports": 0,
        "duplicates": 0,
        "ignored": 0,
        "errors": [],
        "items": [],
    }
    with Session(get_engine()) as session:
        run = IngestRun(source="upload", status="running")
        session.add(run)
        session.commit()
        session.refresh(run)
        for name, data in payloads:
            digest = hashlib.sha256(data).hexdigest()
            try:
                result = ingest_raw_email(
                    session,
                    data,
                    source="upload",
                    source_key=f"upload:{digest}",
                    received_at=utcnow(),
                )
            except Exception as exc:  # noqa: BLE001
                log.exception("upload failed for %s", name)
                summary["errors"].append(f"{name}: {exc}")
                summary["items"].append({"file": name, "status": "error", "error": str(exc)})
                continue
            summary["reports"] += result.reports
            summary["tls_reports"] += result.tls_reports
            summary["duplicates"] += result.duplicates
            summary["ignored"] += result.ignored
            summary["errors"].extend(f"{name}: {error}" for error in result.errors)
            summary["items"].append(
                {
                    "file": name,
                    "status": result.status,
                    "reports": result.reports,
                    "tls_reports": result.tls_reports,
                }
            )
        run.finished_at = utcnow()
        run.status = "ok" if not summary["errors"] else "partial"
        run.messages_seen = len(payloads)
        run.messages_ingested = sum(1 for item in summary["items"] if item.get("reports") or item.get("tls_reports"))
        run.reports_created = summary["reports"]
        run.tls_reports_created = summary["tls_reports"]
        run.error = "; ".join(summary["errors"])[:4000] or None
        run.detail = summary["items"][:100]
        session.add(run)
        session.commit()
    return summary


@router.get("/runs")
def runs(session: Session = Depends(get_session), limit: int = 25) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    items = session.exec(select(IngestRun).order_by(IngestRun.started_at.desc()).limit(limit)).all()
    return {
        "items": [
            {
                "id": item.id,
                "source": item.source,
                "status": item.status,
                "started_at": _z(item.started_at),
                "finished_at": _z(item.finished_at),
                "messages_seen": item.messages_seen,
                "messages_ingested": item.messages_ingested,
                "reports_created": item.reports_created,
                "tls_reports_created": item.tls_reports_created,
                "error": item.error,
                "detail": item.detail,
            }
            for item in items
        ]
    }
