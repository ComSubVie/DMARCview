"""Small in-process scheduler for periodic work.

No Celery/Redis: one container, one event loop, short SQLite writes. Every run
is recorded in ``job_runs`` so the UI can show what happened and when.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable, Optional

from sqlmodel import Session, select

from . import audit
from .backup import backup_database, bundle_sha256, create_bundle
from .config import get_settings
from .db import get_engine
from .alerts.service import evaluate as evaluate_alerts
from .geoip import get_asn_resolver
from .health.dns import get_dns_client
from .health.service import run_and_store_health, run_and_store_probes
from .models import (
    AlertEvent,
    Domain,
    DomainSettings,
    IpMeta,
    JobRun,
    SourceRecord,
    SyncState,
    utcnow,
)
from .digest import send_digest
from .offsite import targets as offsite_targets, upload_bundle
from .retention import prune

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


async def job_retention() -> dict:
    settings = get_settings()
    if settings.retention_days <= 0:
        return {"skipped": "disabled"}
    with Session(get_engine()) as session:
        return prune(session, settings.retention_days)


BACKUP_LAST_KEY = "backup.last_offsite_at"
BACKUP_ERROR_KEY = "backup.last_offsite_error"


def _set_backup_state(value: Optional[str], error: Optional[str]) -> None:
    with Session(get_engine()) as session:
        for key, text in ((BACKUP_LAST_KEY, value), (BACKUP_ERROR_KEY, error)):
            if text is None:
                continue
            row = session.get(SyncState, key)
            if row is None:
                session.add(SyncState(key=key, value=text[:512]))
            else:
                row.value = text[:512]
                row.updated_at = utcnow()
                session.add(row)
        session.commit()


_backup_lock = asyncio.Lock()


def _audit_backup(action: str, actor: str, detail: dict) -> None:
    with Session(get_engine()) as session:
        audit.record(session, action, actor=actor, detail=detail)
        session.commit()


async def job_backup(*, force: bool = False, actor: str = "scheduler") -> dict:
    async with _backup_lock:
        settings = get_settings()
        if not settings.backup_enabled and not force:
            return {"skipped": "disabled"}
        snapshot = backup_database()
        stamp = utcnow().replace(microsecond=0).isoformat()
        if not offsite_targets(settings):
            _set_backup_state(stamp, None)
            result = {"snapshot": snapshot.name, "providers": [], "bytes": snapshot.stat().st_size}
            _audit_backup("backup.local", actor, result)
            return result
        bundle = create_bundle(snapshot, settings.data_dir / "archive", settings.data_dir / "backups")
        digest = bundle_sha256(bundle)
        try:
            results = await upload_bundle(settings, bundle)
            result = {
                "snapshot": snapshot.name,
                "providers": [item["provider"] for item in results],
                "bytes": sum(int(item.get("bytes", 0)) for item in results),
                "sha256": digest,
                "bundle": bundle.name,
            }
            _set_backup_state(stamp, "")
            _audit_backup("backup.run", actor, result)
            return result
        except Exception as exc:
            _set_backup_state(None, str(exc))
            _audit_backup(
                "backup.failed",
                actor,
                {"snapshot": snapshot.name, "bundle": bundle.name, "error": str(exc)[:1000]},
            )
            raise
        finally:
            if bundle.exists():
                bundle.unlink()


DIGEST_STATE_KEY = "digest.last_sent_at"


async def job_retry_alerts() -> dict:
    settings = get_settings()
    if not settings.alerts_enabled:
        return {"skipped": "disabled"}
    from .alerts.service import _notify  # local import avoids a cycle at module load

    sent = failed = 0
    with Session(get_engine()) as session:
        events = session.exec(
            select(AlertEvent)
            .where(
                AlertEvent.delivered_at.is_(None),
                AlertEvent.resolved_at.is_(None),
                AlertEvent.next_retry_at.is_not(None),
                AlertEvent.next_retry_at <= utcnow(),
                AlertEvent.delivery_attempts < 3,
            )
            .limit(50)
        ).all()
        for event in events:
            domain = session.get(Domain, event.domain_id) if event.domain_id is not None else None
            if event.domain_id is not None and domain is None:
                continue
            results = await _notify(event, domain, settings, resolved=False)
            if results and all(item.ok for item in results):
                sent += 1
            else:
                failed += 1
            session.add(event)
            session.commit()
    return {"retried": len(events), "sent": sent, "failed": failed}


async def job_digest() -> dict:
    settings = get_settings()
    if not settings.digest_enabled:
        return {"skipped": "disabled"}
    with Session(get_engine()) as session:
        state = session.get(SyncState, DIGEST_STATE_KEY)
        if state is not None:
            try:
                last = datetime.fromisoformat(state.value.replace("Z", "+00:00"))
            except ValueError:
                last = None
            if last is not None:
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                if utcnow() - last < timedelta(days=settings.digest_days):
                    return {"skipped": "not due"}
        result = await send_digest(session, settings, days=settings.digest_days)
        if result.get("ok"):
            value = utcnow().replace(microsecond=0).isoformat()
            if state is None:
                session.add(SyncState(key=DIGEST_STATE_KEY, value=value))
            else:
                state.value = value
                state.updated_at = utcnow()
                session.add(state)
            session.commit()
        return {
            "ok": result.get("ok", False),
            "error": result.get("error"),
            "domains": len(result.get("domains", [])),
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


async def _fcrdns_status(dns, ip: str, ptr: str) -> tuple[str, Optional[str]]:
    """Forward-confirm a PTR name against the source IP."""
    try:
        answer = await dns.addresses(ptr.rstrip("."))
    except Exception as exc:  # noqa: BLE001 - network errors are data
        return "unknown", str(exc)[:255]
    if answer.error:
        return "unknown", str(answer.error)[:255]
    values = [str(value).strip() for value in (answer.values or []) if str(value).strip()]
    forward = ", ".join(values[:3]) or None
    try:
        wanted = ipaddress.ip_address(ip)
        matched = any(ipaddress.ip_address(value) == wanted for value in values)
    except ValueError:
        matched = ip in values
    return ("match" if matched else "mismatch"), forward


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
        # A PTR without a usable FCrDNS result is inconsistent; recompute it.
        needs_fcrdns = (
            meta is None
            or meta.fcrdns_status is None
            or (meta.fcrdns_status == "none" and bool(meta.ptr))
        )
        if needs_ptr or needs_asn or needs_fcrdns:
            needs[ip] = {"ptr": needs_ptr, "asn": needs_asn, "fcrdns": needs_fcrdns}
    todo = list(needs)[:250]
    if not todo:
        return {"looked_up": 0, "pending": 0}

    dns = get_dns_client()
    semaphore = asyncio.Semaphore(10)

    async def lookup(
        ip: str,
    ) -> tuple[str, Optional[str], Optional[int], Optional[str], Optional[str], Optional[str]]:
        async with semaphore:
            # Reuse a cached PTR when only FCrDNS needs (re)checking.
            ptr = metas[ip].ptr if ip in metas else None
            if needs[ip]["ptr"]:
                ptr = None
                try:
                    answer = await dns.ptr(ip)
                except Exception:  # noqa: BLE001
                    answer = None
                if answer and answer.values:
                    ptr = answer.values[0][:255]
            fcrdns, forward = None, None
            if needs[ip]["fcrdns"]:
                if ptr:
                    fcrdns, forward = await _fcrdns_status(dns, ip, ptr)
                else:
                    fcrdns = "none"
            asn, asn_org = asn_resolver.lookup(ip) if needs[ip]["asn"] else (None, None)
            return ip, ptr, asn, asn_org, fcrdns, forward

    results = await asyncio.gather(*(lookup(ip) for ip in todo))
    with Session(get_engine()) as session:
        for ip, ptr, asn, asn_org, fcrdns, forward in results:
            meta = session.get(IpMeta, ip)
            if meta is None:
                meta = IpMeta(
                    ip=ip,
                    ptr=ptr,
                    asn=asn,
                    asn_org=asn_org,
                    fcrdns_status=fcrdns,
                    fcrdns_forward=forward,
                    updated_at=utcnow(),
                )
            else:
                if ptr:
                    meta.ptr = ptr
                if needs[ip]["asn"]:
                    meta.asn = asn
                    meta.asn_org = asn_org
                if needs[ip]["fcrdns"]:
                    meta.fcrdns_status = fcrdns
                    meta.fcrdns_forward = forward
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
            name="alert_retry",
            label="Alert delivery retry",
            interval_seconds=15 * 60,
            runner=job_retry_alerts,
            initial_delay=240,
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
        *(
            [
                JobSpec(
                    name="digest",
                    label="Weekly email digest",
                    interval_seconds=6 * 3600,
                    runner=job_digest,
                    initial_delay=120,
                )
            ]
            if settings.digest_enabled
            else []
        ),
        *(
            [
                JobSpec(
                    name="retention",
                    label="Retention archive and prune",
                    interval_seconds=24 * 3600,
                    runner=job_retention,
                    initial_delay=180,
                )
            ]
            if settings.retention_days > 0
            else []
        ),
        *(
            [
                JobSpec(
                    name="backup",
                    label="Backup and off-box upload",
                    interval_seconds=settings.backup_interval_hours * 3600,
                    runner=job_backup,
                    initial_delay=300,
                )
            ]
            if settings.backup_enabled
            else []
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
        elif spec.name == "retention":
            if settings.retention_days <= 0:
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
