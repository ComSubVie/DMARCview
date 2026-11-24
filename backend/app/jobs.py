"""Small in-process scheduler for periodic work.

No Celery/Redis: one container, one event loop, short SQLite writes. Every run
is recorded in ``job_runs`` so the UI can show what happened and when.
"""

from __future__ import annotations

import asyncio
import logging
import random
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

from sqlmodel import Session, select

from .config import get_settings
from .db import get_engine
from .alerts.service import evaluate as evaluate_alerts
from .geoip import get_asn_resolver
from .health.dns import get_dns_client
from .health.service import run_and_store_health, run_and_store_probes
from .models import Domain, DomainSettings, IpMeta, JobRun, SourceRecord, utcnow

log = logging.getLogger(__name__)


def _scheduled_checks_disabled(session: Session, domain_id: int, now: datetime) -> bool:
    row = session.get(DomainSettings, domain_id)
    if row is None:
        return False
    if not row.dns_checks_enabled:
        return True
    muted = row.checks_muted_until
    if muted is not None:
        if muted.tzinfo is None:
            muted = muted.replace(tzinfo=timezone.utc)
        if muted > now:
            return True
    return False


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat() + "Z"


async def job_health_checks() -> dict:
    with Session(get_engine()) as session:
        domains = session.exec(select(Domain).order_by(Domain.name)).all()
    ok = failed = skipped = 0
    errors: list[str] = []
    now = utcnow()
    for domain in domains:
        with Session(get_engine()) as session:
            current = session.get(Domain, domain.id)
            if current is None:  # deleted between listing and run
                skipped += 1
                continue
            if _scheduled_checks_disabled(session, current.id, now):
                skipped += 1
                continue
            try:
                await run_and_store_health(session, current)
                ok += 1
            except Exception as exc:  # noqa: BLE001 - one domain must not fail the job
                log.warning("health check failed for %s: %s", current.name, exc)
                failed += 1
                errors.append(f"{current.name}: {exc}")
    return {"domains": len(domains), "ok": ok, "failed": failed, "skipped": skipped, "errors": errors[:5]}


async def job_transport_probes() -> dict:
    with Session(get_engine()) as session:
        domains = session.exec(select(Domain).order_by(Domain.name)).all()
    ok = failed = targets = skipped = 0
    errors: list[str] = []
    now = utcnow()
    for domain in domains:
        with Session(get_engine()) as session:
            current = session.get(Domain, domain.id)
            if current is None:
                continue
            if _scheduled_checks_disabled(session, current.id, now):
                skipped += 1
                continue
            try:
                results = await run_and_store_probes(session, current)
                targets += len(results)
                ok += sum(1 for item in results if item["status"] in {"pass", "warn"})
                failed += sum(1 for item in results if item["status"] == "fail")
            except Exception as exc:  # noqa: BLE001
                log.warning("transport probe failed for %s: %s", current.name, exc)
                errors.append(f"{current.name}: {exc}")
    return {
        "domains": len(domains),
        "targets": targets,
        "ok": ok,
        "failed": failed,
        "skipped": skipped,
        "errors": errors[:5],
    }


async def job_alerts() -> dict:
    with Session(get_engine()) as session:
        summary = await evaluate_alerts(session)
    return {
        "created": summary["created"],
        "resolved": summary["resolved"],
        "delivered": summary["delivered"],
        "failed": summary["failed"],
    }


async def job_ptr_enrichment() -> dict:
    settings = get_settings()
    if not settings.ptr_enrichment_enabled:
        return {"skipped": "disabled"}
    with Session(get_engine()) as session:
        rows = session.exec(select(SourceRecord.source_ip).distinct()).all()
        # SQLModel returns scalars for a single-column select; be tolerant of
        # drivers/versions that hand back one-element rows instead.
        ips = [row if isinstance(row, str) else str(row[0]) for row in rows]
        metas = {row.ip: row for row in session.exec(select(IpMeta)).all()}

    asn_resolver = get_asn_resolver()
    needs: dict[str, dict[str, bool]] = {}
    for ip in ips:
        meta = metas.get(ip)
        needs_ptr = meta is None
        needs_asn = asn_resolver.available and (meta is None or meta.asn is None)
        if needs_ptr or needs_asn:
            needs[ip] = {"ptr": needs_ptr, "asn": needs_asn}
    todo = list(needs)[:250]
    if not todo:
        return {"looked_up": 0, "pending": 0}

    dns = get_dns_client()
    semaphore = asyncio.Semaphore(10)

    async def lookup(ip: str) -> tuple[str, Optional[str], Optional[int], Optional[str]]:
        async with semaphore:
            ptr = None
            if needs[ip]["ptr"]:
                try:
                    answer = await dns.ptr(ip)
                except Exception:  # noqa: BLE001
                    answer = None
                if answer and answer.values:
                    ptr = answer.values[0][:255]
            asn, asn_org = asn_resolver.lookup(ip) if needs[ip]["asn"] else (None, None)
            return ip, ptr, asn, asn_org

    results = await asyncio.gather(*(lookup(ip) for ip in todo))
    with Session(get_engine()) as session:
        for ip, ptr, asn, asn_org in results:
            meta = session.get(IpMeta, ip)
            if meta is None:
                meta = IpMeta(ip=ip, ptr=ptr, asn=asn, asn_org=asn_org, updated_at=utcnow())
            else:
                if ptr:
                    meta.ptr = ptr
                if needs[ip]["asn"]:
                    meta.asn = asn
                    meta.asn_org = asn_org
                meta.updated_at = utcnow()
            session.add(meta)
        session.commit()
    return {"looked_up": len(results), "pending": max(0, len(needs) - len(results))}


@dataclass(frozen=True)
class JobSpec:
    name: str
    label: str
    interval_seconds: int
    runner: Callable[[], Awaitable[dict]]
    initial_delay: int = 25


def job_specs() -> list[JobSpec]:
    settings = get_settings()
    return [
        JobSpec(
            name="health_checks",
            label="Domain health checks",
            interval_seconds=settings.health_interval_minutes * 60,
            runner=job_health_checks,
            initial_delay=settings.jobs_initial_delay_seconds,
        ),
        JobSpec(
            name="transport_probes",
            label="Transport & certificate probes",
            interval_seconds=settings.probe_interval_minutes * 60,
            runner=job_transport_probes,
            initial_delay=settings.jobs_initial_delay_seconds + 10,
        ),
        JobSpec(
            name="ptr_enrichment",
            label="Reverse DNS for sending IPs",
            interval_seconds=6 * 3600,
            runner=job_ptr_enrichment,
            initial_delay=90,
        ),
        JobSpec(
            name="alerts",
            label="Alert evaluation",
            interval_seconds=settings.alert_interval_minutes * 60,
            runner=job_alerts,
            initial_delay=settings.jobs_initial_delay_seconds + 45,
        ),
    ]


_state: dict[str, str] = {}
_tasks: dict[str, asyncio.Task] = {}
_locks: dict[str, asyncio.Lock] = {}
_stop: Optional[asyncio.Event] = None


def status() -> dict[str, str]:
    return dict(_state)


async def run_job(name: str) -> JobRun:
    spec = next((item for item in job_specs() if item.name == name), None)
    if spec is None:
        raise KeyError(f"unknown job {name}")
    lock = _locks.setdefault(name, asyncio.Lock())
    if lock.locked():
        raise RuntimeError(f"job {name} is already running")

    async with lock:
        run = JobRun(name=name, status="running")
        with Session(get_engine()) as session:
            session.add(run)
            session.commit()
            session.refresh(run)
            run_id = run.id
        _state[name] = "running"
        try:
            summary = await spec.runner()
            with Session(get_engine()) as session:
                row = session.get(JobRun, run_id)
                if row is not None:
                    row.finished_at = utcnow()
                    row.status = "ok"
                    row.summary = summary
                    session.add(row)
                    session.commit()
            _state[name] = "ok"
            return run
        except Exception as exc:  # noqa: BLE001
            with Session(get_engine()) as session:
                row = session.get(JobRun, run_id)
                if row is not None:
                    row.finished_at = utcnow()
                    row.status = "error"
                    row.error = str(exc)[:4000]
                    session.add(row)
                    session.commit()
            _state[name] = "error"
            raise


async def _loop(spec: JobSpec, stop: asyncio.Event) -> None:
    await asyncio.sleep(spec.initial_delay)
    while not stop.is_set():
        try:
            await run_job(spec.name)
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            log.warning("job %s failed: %s", spec.name, exc)
        wait = spec.interval_seconds * random.uniform(0.92, 1.08)
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=wait)
            return


def start(stop: asyncio.Event) -> None:
    global _stop
    settings = get_settings()
    _stop = stop
    started: list[str] = []
    for spec in job_specs():
        if spec.name == "alerts":
            if not settings.alerts_enabled:
                continue
        elif not settings.health_checks_enabled:
            continue
        if spec.name in _tasks and not _tasks[spec.name].done():
            continue
        _tasks[spec.name] = asyncio.create_task(_loop(spec, stop), name=f"job-{spec.name}")
        started.append(spec.name)
    if started:
        log.info("scheduler started: %s", ", ".join(started))
    else:
        log.info("scheduler idle: no job enabled")


async def stop_scheduler() -> None:
    for task in _tasks.values():
        task.cancel()
    for task in _tasks.values():
        with suppress(asyncio.CancelledError, Exception):
            await task
    _tasks.clear()
