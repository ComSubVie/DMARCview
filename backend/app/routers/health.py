"""Domain health, transport probes, settings and storage endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlmodel import Session, select

from .. import audit
from ..config import get_settings
from ..db import get_engine, get_session
from ..deps import current_user
from ..dnsdiff import build_dns_diff
from ..health.service import (
    fleet_health,
    health_payload,
    run_and_store_health,
    run_and_store_probes,
    serialise_settings,
    update_settings,
)
from ..jobs import job_backup, job_specs, status as jobs_status
from ..models import (
    Domain,
    DomainHealthSnapshot,
    JobRun,
    Report,
    SourceRecord,
    SyncState,
    TlsReport,
)
from ..offsite import targets as offsite_targets, test_targets

router = APIRouter(prefix="/api", tags=["health"], dependencies=[Depends(current_user)])


def _domain(session: Session, name: str) -> Domain:
    domain = session.exec(select(Domain).where(Domain.name == name.strip().lower())).first()
    if domain is None:
        raise HTTPException(status_code=404, detail=f"Unknown domain {name!r}")
    return domain


@router.get("/domain-health")
def domain_health(
    domain: str = Query(...),
    session: Session = Depends(get_session),
) -> dict:
    row = _domain(session, domain)
    return health_payload(session, row)


@router.post("/domain-health/run")
async def run_domain_health(
    domain: str = Query(...),
    session: Session = Depends(get_session),
) -> dict:
    row = _domain(session, domain)
    await run_and_store_health(session, row)
    await run_and_store_probes(session, row)
    return health_payload(session, row)


@router.get("/domain-health/fleet")
def domain_health_fleet(session: Session = Depends(get_session)) -> dict:
    return {"items": fleet_health(session)}


@router.get("/domain-health/diff")
def domain_health_diff(
    domain: str = Query(...),
    limit: int = Query(default=30, ge=2, le=100),
    session: Session = Depends(get_session),
) -> dict:
    row = _domain(session, domain)
    return build_dns_diff(session, row, limit=limit)


@router.get("/domain-health/history")
def domain_health_history(
    domain: str = Query(...),
    days: int = Query(default=30, ge=1, le=365),
    session: Session = Depends(get_session),
) -> dict:
    row = _domain(session, domain)
    snapshots = session.exec(
        select(DomainHealthSnapshot)
        .where(DomainHealthSnapshot.domain_id == row.id)
        .order_by(DomainHealthSnapshot.checked_at.desc())
        .limit(days * 8)
    ).all()
    return {
        "items": [
            {
                "id": snapshot.id,
                "checked_at": snapshot.checked_at.replace(tzinfo=timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "overall": snapshot.overall,
                "score": snapshot.score,
                "core_passed": snapshot.core_passed,
                "core_total": snapshot.core_total,
                "results": snapshot.results,
            }
            for snapshot in snapshots
        ]
    }


class DomainSettingsPayload(BaseModel):
    dkim_selectors: Optional[list[str]] = None
    probe_targets: Optional[list[str]] = None
    helo_hostname: Optional[str] = None
    expected_report_hours: Optional[int] = Field(default=None, ge=6, le=336)
    dns_checks_enabled: Optional[bool] = None
    checks_muted_until: Optional[datetime] = None


@router.get("/domains/{domain_name}/settings")
def read_domain_settings(
    domain_name: str, session: Session = Depends(get_session)
) -> dict:
    row = _domain(session, domain_name)
    return serialise_settings(session, row)


@router.put("/domains/{domain_name}/settings")
def write_domain_settings(
    domain_name: str,
    payload: DomainSettingsPayload,
    request: Request,
    session: Session = Depends(get_session),
) -> dict:
    row = _domain(session, domain_name)
    update_settings(
        session,
        row,
        dkim_selectors=payload.dkim_selectors,
        probe_targets=payload.probe_targets,
        helo_hostname=payload.helo_hostname,
        expected_report_hours=payload.expected_report_hours,
        dns_checks_enabled=payload.dns_checks_enabled,
        checks_muted_until=payload.checks_muted_until,
        clear_mute=(
            "checks_muted_until" in payload.model_fields_set
            and payload.checks_muted_until is None
        ),
    )
    audit.record(session, "domain.settings", actor=audit.actor(request), domain=row.name, target=row.name)
    session.commit()
    return serialise_settings(session, row)


@router.post("/backup/test")
async def test_backup(request: Request) -> dict:
    try:
        results = await test_targets(get_settings())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)[:500]) from exc
    with Session(get_engine()) as session:
        audit.record(
            session,
            "backup.test",
            actor=audit.actor(request),
            detail={"results": results},
        )
        session.commit()
    return {"ok": all(item.get("ok") for item in results), "results": results}


@router.post("/backup/run")
async def run_backup(request: Request) -> dict:
    try:
        result = await job_backup(force=True, actor=audit.actor(request))
    except Exception as exc:  # noqa: BLE001 - surface the operation error
        raise HTTPException(status_code=500, detail=str(exc)[:500]) from exc
    return {"ok": True, **result}


@router.get("/jobs")
def jobs(session: Session = Depends(get_session)) -> dict:
    state = jobs_status()
    items = []
    for spec in job_specs():
        last = session.exec(
            select(JobRun).where(JobRun.name == spec.name).order_by(JobRun.started_at.desc()).limit(1)
        ).first()
        items.append(
            {
                "name": spec.name,
                "label": spec.label,
                "interval_seconds": spec.interval_seconds,
                "state": state.get(spec.name, "idle"),
                "last_run": {
                    "started_at": last.started_at.replace(tzinfo=timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "finished_at": last.finished_at.replace(tzinfo=timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                    if last.finished_at
                    else None,
                    "status": last.status,
                    "summary": last.summary,
                    "error": last.error,
                }
                if last
                else None,
            }
        )
    enabled = get_settings().health_checks_enabled
    return {"items": items, "scheduled": enabled}


def _state_value(session: Session, key: str) -> Optional[str]:
    row = session.get(SyncState, key)
    return row.value if row is not None and row.value else None


def _one_int(session: Session, statement) -> int:
    value = session.exec(statement).one()
    if isinstance(value, (tuple, list)):
        value = value[0]
    return int(value or 0)


@router.get("/storage")
def storage(session: Session = Depends(get_session)) -> dict:
    settings = get_settings()
    db_path = settings.db_path
    db_bytes = 0
    wal_bytes = 0
    if db_path is not None and db_path.exists():
        db_bytes = db_path.stat().st_size
        wal = Path(str(db_path) + "-wal")
        if wal.exists():
            wal_bytes = wal.stat().st_size

    raw_xml = _one_int(
        session, select(func.coalesce(func.sum(func.length(Report.raw_xml)), 0))
    )
    raw_json = _one_int(
        session, select(func.coalesce(func.sum(func.length(TlsReport.raw_json)), 0))
    )
    reports = _one_int(session, select(func.count(Report.id)))
    tls_reports = _one_int(session, select(func.count(TlsReport.id)))
    records = _one_int(session, select(func.count(SourceRecord.id)))
    oldest = session.exec(
        select(func.min(Report.date_begin))
    ).one()

    backups_dir = settings.data_dir / "backups"
    backups = sorted(backups_dir.glob("dmarc-*.db")) if backups_dir.is_dir() else []
    last_backup = None
    if backups:
        last_backup = datetime.fromtimestamp(
            backups[-1].stat().st_mtime, tz=timezone.utc
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    return {
        "database_bytes": db_bytes,
        "wal_bytes": wal_bytes,
        "raw_bytes": raw_xml + raw_json,
        "raw_xml_bytes": raw_xml,
        "raw_json_bytes": raw_json,
        "total_bytes": db_bytes + raw_xml + raw_json,
        "reports": reports,
        "tls_reports": tls_reports,
        "source_records": records,
        "oldest_report": oldest.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        if oldest
        else None,
        "backups": {"count": len(backups), "last_at": last_backup},
        "offsite": {
            "enabled": settings.backup_enabled,
            "providers": offsite_targets(settings),
            "last_at": _state_value(session, "backup.last_offsite_at"),
            "last_error": _state_value(session, "backup.last_offsite_error"),
        },
        "retention_days": settings.retention_days,
    }
