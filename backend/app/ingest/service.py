"""Ingestion orchestration: e-mail -> parsed reports -> database.

The entry point is :func:`ingest_raw_email`, which is deliberately synchronous
so it can be reused by the CLI importer, the upload endpoint and the JMAP
poller.  All writes are idempotent at three levels: processed message,
attachment digest, and reporter/report-id uniqueness.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from ..config import get_settings
from ..db import get_engine
from ..geoip import get_geo_resolver
from ..models import (
    Domain,
    IngestRun,
    ProcessedMessage,
    Report,
    SourceRecord,
    SyncState,
    TlsFailure,
    TlsPolicy,
    TlsReport,
    utcnow,
)
from .dmarc import DmarcParseError, parse_dmarc
from .jmap import JMAPClient, JMAPError
from .mime import MimeParseError, extract_payloads
from .tlsrpt import TlsParseError, parse_tlsrpt

log = logging.getLogger(__name__)


@dataclass
class IngestResult:
    status: str = "ok"
    reports: int = 0
    tls_reports: int = 0
    duplicates: int = 0
    ignored: int = 0
    messages: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reports": self.reports,
            "tls_reports": self.tls_reports,
            "duplicates": self.duplicates,
            "ignored": self.ignored,
            "messages": self.messages,
            "errors": self.errors,
        }


def normalize_domain(value: str) -> str:
    return (value or "").strip().lower().rstrip(".")


def _get_or_create_domain(session: Session, name: str) -> Domain:
    normalized = normalize_domain(name)
    domain = session.exec(select(Domain).where(Domain.name == normalized)).first()
    if domain is not None:
        return domain
    domain = Domain(name=normalized, display_name=normalized)
    session.add(domain)
    session.flush()
    return domain


def _message_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def ingest_raw_email(
    session: Session,
    raw: bytes,
    *,
    source: str,
    source_key: str,
    received_at: Optional[datetime] = None,
    force: bool = False,
) -> IngestResult:
    """Parse one raw RFC822 message and persist every report it carries."""
    result = IngestResult(messages=1)

    if not force:
        existing = session.exec(
            select(ProcessedMessage).where(ProcessedMessage.source_key == source_key)
        ).first()
        if existing is not None and existing.status in {"ok", "ignored", "partial"}:
            result.status = "duplicate"
            result.duplicates += 1
            return result

    try:
        parsed, payloads = extract_payloads(raw)
    except MimeParseError as exc:
        result.status = "error"
        result.errors.append(f"MIME: {exc}")
        _record_message(session, source, source_key, None, None, None, received_at, "error", 0, str(exc))
        return result

    if not payloads:
        result.status = "ignored"
        result.ignored += 1
        _record_message(
            session,
            source,
            source_key,
            parsed.message_id,
            parsed.subject,
            parsed.sender,
            parsed.received_at or received_at,
            "ignored",
            0,
            "; ".join(parsed.notes) or "no DMARC/TLS-RPT payload found",
        )
        return result

    created = 0
    for payload in payloads:
        try:
            if payload.kind == "dmarc":
                if _report_exists(session, Report, payload.sha256):
                    result.duplicates += 1
                    continue
                _store_dmarc(session, payload.data, payload.sha256, parsed, source, received_at)
                result.reports += 1
                created += 1
            else:
                if _report_exists(session, TlsReport, payload.sha256):
                    result.duplicates += 1
                    continue
                _store_tls(session, payload.data, payload.sha256, parsed, source, received_at)
                result.tls_reports += 1
                created += 1
        except (DmarcParseError, TlsParseError) as exc:
            result.errors.append(f"{payload.filename or payload.kind}: {exc}")
        except IntegrityError:
            session.rollback()
            result.duplicates += 1
        except Exception as exc:  # noqa: BLE001 - keep the batch alive
            log.exception("unexpected ingest failure for %s", payload.filename)
            result.errors.append(f"{payload.filename or payload.kind}: {exc}")

    status = "ok" if not result.errors else ("partial" if created else "error")
    result.status = status
    _record_message(
        session,
        source,
        source_key,
        parsed.message_id,
        parsed.subject,
        parsed.sender,
        parsed.received_at or received_at,
        status,
        created,
        "; ".join(result.errors + parsed.notes) or None,
    )
    return result


def _record_message(
    session: Session,
    source: str,
    source_key: str,
    message_id: Optional[str],
    subject: Optional[str],
    sender: Optional[str],
    received_at: Optional[datetime],
    status: str,
    created: int,
    error: Optional[str],
) -> None:
    existing = session.exec(
        select(ProcessedMessage).where(ProcessedMessage.source_key == source_key)
    ).first()
    if existing is None:
        existing = ProcessedMessage(source=source, source_key=source_key)
        session.add(existing)
    existing.message_id = (message_id or "")[:512] or None
    existing.subject = (subject or "")[:512] or None
    existing.sender = (sender or "")[:512] or None
    existing.received_at = received_at
    existing.status = status
    existing.reports_created = created
    existing.error = (error or "")[:4000] or None
    existing.processed_at = utcnow()
    session.commit()


def _report_exists(session: Session, model: Any, digest: str) -> bool:
    return session.exec(select(model.id).where(model.raw_sha256 == digest)).first() is not None


def _store_dmarc(
    session: Session,
    data: bytes,
    digest: str,
    parsed: Any,
    source: str,
    received_at: Optional[datetime],
) -> None:
    report = parse_dmarc(data)
    domain = _get_or_create_domain(session, report.policy_domain)
    geo = get_geo_resolver()

    record = Report(
        domain_id=domain.id,  # type: ignore[arg-type]
        org_name=report.org_name,
        org_email=report.org_email,
        report_id=report.report_id,
        policy_domain=normalize_domain(report.policy_domain),
        date_begin=report.date_begin,
        date_end=report.date_end,
        report_date=report.date_begin.date(),
        policy_p=report.policy_p,
        policy_sp=report.policy_sp,
        policy_np=report.policy_np,
        policy_pct=report.policy_pct,
        policy_testing=report.policy_testing,
        policy_discovery=report.policy_discovery,
        policy_adkim=report.policy_adkim,
        policy_aspf=report.policy_aspf,
        policy_fo=report.policy_fo,
        report_errors=report.report_errors,
        record_count=len(report.records),
        message_count=report.message_count,
        aligned_count=report.aligned_count,
        failed_count=report.failed_count,
        source_count=report.source_count,
        message_id=(parsed.message_id or "")[:512] or None,
        raw_sha256=digest,
        raw_xml=data,
        source=source,
        received_at=parsed.received_at or received_at,
    )
    session.add(record)
    session.flush()

    for item in report.records:
        code, name = geo.lookup(item.source_ip)
        session.add(
            SourceRecord(
                report_id=record.id,  # type: ignore[arg-type]
                domain_id=domain.id,  # type: ignore[arg-type]
                report_date=report.date_begin.date(),
                source_ip=item.source_ip,
                message_count=item.count,
                disposition=item.disposition,
                dkim_pass=item.dkim_pass,
                spf_pass=item.spf_pass,
                dkim_signed=bool(item.dkim_domains),
                dkim_auth_pass=any(result == "pass" for result in item.dkim_results),
                spf_auth_pass=any(result == "pass" for result in item.spf_results),
                header_from=item.header_from,
                envelope_from=item.envelope_from,
                envelope_to=item.envelope_to,
                dkim_domains=item.dkim_domains,
                dkim_selectors=item.dkim_selectors,
                dkim_results=item.dkim_results,
                spf_domains=item.spf_domains,
                spf_results=item.spf_results,
                reason_type=item.reason_type,
                reason_comment=item.reason_comment,
                country_code=code,
                country_name=name,
            )
        )
    session.commit()


def _store_tls(
    session: Session,
    data: bytes,
    digest: str,
    parsed: Any,
    source: str,
    received_at: Optional[datetime],
) -> None:
    report = parse_tlsrpt(data)
    domain = _get_or_create_domain(session, report.policy_domain or "")
    geo = get_geo_resolver()

    record = TlsReport(
        domain_id=domain.id,  # type: ignore[arg-type]
        org_name=report.org_name,
        report_id=report.report_id,
        contact_info=(report.contact_info or None),
        date_begin=report.date_begin,
        date_end=report.date_end,
        report_date=report.date_begin.date(),
        policy_type=report.policy_type,
        policy_mode=report.policy_mode,
        policy_domain=normalize_domain(report.policy_domain or ""),
        policy_string=report.policy_string,
        mx_hosts=report.mx_hosts,
        max_age=report.max_age,
        total_success=report.total_success,
        total_failure=report.total_failure,
        message_id=(parsed.message_id or "")[:512] or None,
        raw_sha256=digest,
        raw_json=data,
        source=source,
        received_at=parsed.received_at or received_at,
    )
    session.add(record)
    session.flush()

    for policy in report.policies:
        policy_name = normalize_domain(policy.policy_domain or report.policy_domain or "")
        policy_domain = (
            _get_or_create_domain(session, policy_name) if policy_name else domain
        )
        session.add(
            TlsPolicy(
                tls_report_id=record.id,  # type: ignore[arg-type]
                domain_id=policy_domain.id,  # type: ignore[arg-type]
                report_date=report.date_begin.date(),
                policy_type=policy.policy_type,
                policy_domain=normalize_domain(policy.policy_domain or ""),
                mx_hosts=policy.mx_hosts,
                total_success=policy.total_success,
                total_failure=policy.total_failure,
            )
        )
        for failure in policy.failures:
            code, name = geo.lookup(failure.sending_mta_ip)
            session.add(
                TlsFailure(
                    tls_report_id=record.id,  # type: ignore[arg-type]
                    domain_id=policy_domain.id,  # type: ignore[arg-type]
                    report_date=report.date_begin.date(),
                    policy_domain=policy_name or None,
                    receiving_mx=failure.receiving_mx,
                    result_type=failure.result_type,
                    sending_mta_ip=failure.sending_mta_ip,
                    failed_count=failure.failed_count,
                    reason_code=failure.reason_code,
                    additional_info=failure.additional_info,
                    country_code=code,
                    country_name=name,
                )
            )
    session.commit()


def reparse_tls_mx_hosts(session: Session, *, dry_run: bool = False) -> dict[str, Any]:
    """Backfill ``mx_hosts`` for TLS-RPT policies that omitted the explicit field.

    The raw JSON is retained, so reports parsed before policy-string extraction was
    added can be repaired without downloading them again.
    """
    updated_reports = updated_policies = failed = 0
    errors: list[str] = []
    reports = session.exec(select(TlsReport)).all()
    for report in reports:
        try:
            parsed = parse_tlsrpt(report.raw_json)
        except TlsParseError as exc:
            failed += 1
            errors.append(f"{report.report_id}: {exc}")
            continue
        changed = False
        if parsed.mx_hosts and parsed.mx_hosts != (report.mx_hosts or []):
            if not dry_run:
                report.mx_hosts = parsed.mx_hosts
                session.add(report)
            changed = True
        policies = session.exec(
            select(TlsPolicy)
            .where(TlsPolicy.tls_report_id == report.id)
            .order_by(TlsPolicy.id)
        ).all()
        for stored, fresh in zip(policies, parsed.policies, strict=False):
            if fresh.mx_hosts and fresh.mx_hosts != (stored.mx_hosts or []):
                if not dry_run:
                    stored.mx_hosts = fresh.mx_hosts
                    session.add(stored)
                updated_policies += 1
                changed = True
        if changed:
            updated_reports += 1
    if not dry_run:
        session.commit()
    return {
        "dry_run": dry_run,
        "reports": len(reports),
        "updated_reports": updated_reports,
        "updated_policies": updated_policies,
        "failed": failed,
        "errors": errors[:5],
    }


def ingest_files(session: Session, paths: Iterable[Path], source: str = "import") -> IngestResult:
    total = IngestResult(messages=0)
    for path in paths:
        raw = path.read_bytes()
        result = ingest_raw_email(
            session,
            raw,
            source=source,
            source_key=f"{source}:{path.name}:{_message_digest(raw)[:16]}",
        )
        total.messages += 1
        total.reports += result.reports
        total.tls_reports += result.tls_reports
        total.duplicates += result.duplicates
        total.ignored += result.ignored
        total.errors.extend(result.errors)
    total.status = "ok" if not total.errors else "partial"
    return total


# --------------------------------------------------------------------- JMAP
def _get_cursor(session: Session, key: str) -> Optional[datetime]:
    state = session.get(SyncState, key)
    if state is None:
        return None
    try:
        return datetime.fromisoformat(state.value)
    except ValueError:
        return None


def _set_cursor(session: Session, key: str, value: datetime) -> None:
    state = session.get(SyncState, key)
    if state is None:
        state = SyncState(key=key, value=value.isoformat())
        session.add(state)
    else:
        state.value = value.isoformat()
        state.updated_at = utcnow()
    session.commit()


async def sync_jmap(
    *,
    trigger: str = "schedule",
    max_messages: int = 1500,
    since_override: Optional[datetime] = None,
    scan_all: bool = False,
) -> dict[str, Any]:
    """Fetch new report mail over JMAP and ingest it. Returns a run summary."""
    settings = get_settings()
    if not settings.jmap_enabled:
        raise JMAPError("JMAP ingestion is disabled (set JMAP_ENABLED=true)")
    if not settings.jmap_url:
        raise JMAPError("JMAP_URL is not configured")

    run = IngestRun(source="jmap", status="running")
    with Session(get_engine()) as session:
        session.add(run)
        session.commit()
        session.refresh(run)
        run_id = run.id

        cursor_key = "jmap.last_received_at"
        if scan_all:
            since = None
        elif since_override is not None:
            since = since_override
        else:
            since = _get_cursor(session, cursor_key)
            if since is None:
                since = utcnow() - _days(settings.ingest_initial_days)
                log.info("first JMAP sync: looking back %s days", settings.ingest_initial_days)

    client = JMAPClient(
        settings.jmap_url,
        settings.jmap_username,
        settings.jmap_password,
        settings.jmap_token,
    )
    try:
        mailbox = await client.find_mailbox(settings.jmap_mailbox)
        since_query = None if scan_all else (since - _days(1) if since else since)  # one day overlap
        ids = await client.query_email_ids(
            mailbox["id"], since_query, max_messages=max_messages
        )
        emails = await client.get_emails(ids)
        emails = [email for email in emails if email.get("blobId")]

        downloaded: list[tuple[dict[str, Any], bytes]] = []
        semaphore = asyncio.Semaphore(4)

        async def fetch(email: dict[str, Any]) -> Optional[tuple[dict[str, Any], bytes]]:
            async with semaphore:
                try:
                    raw = await client.download(email["blobId"], f"{email['id']}.eml")
                    return email, raw
                except JMAPError as exc:
                    log.warning("could not download %s: %s", email.get("id"), exc)
                    return None

        for item in await asyncio.gather(*(fetch(email) for email in emails)):
            if item is not None:
                downloaded.append(item)

        summary = await asyncio.to_thread(_process_downloads, downloaded)
        with Session(get_engine()) as session:
            run = session.get(IngestRun, run_id)
            if run is not None:
                run.finished_at = utcnow()
                run.status = summary["status"]
                run.messages_seen = len(emails)
                run.messages_ingested = summary["ingested"]
                run.reports_created = summary["reports"]
                run.tls_reports_created = summary["tls_reports"]
                run.error = "; ".join(summary["errors"])[:4000] or None
                run.detail = summary["detail"][:200]
                session.add(run)
                session.commit()
            newest = _newest_timestamp(downloaded, emails)
            if newest is not None:
                _set_cursor(session, "jmap.last_received_at", newest)
        return {"run_id": run_id, **summary}
    except Exception as exc:
        with Session(get_engine()) as session:
            run = session.get(IngestRun, run_id)
            if run is not None:
                run.finished_at = utcnow()
                run.status = "error"
                run.error = str(exc)[:4000]
                session.add(run)
                session.commit()
        raise


def _process_downloads(downloaded: list[tuple[dict[str, Any], bytes]]) -> dict[str, Any]:
    from ..db import get_engine

    summary: dict[str, Any] = {
        "status": "ok",
        "ingested": 0,
        "reports": 0,
        "tls_reports": 0,
        "duplicates": 0,
        "errors": [],
        "detail": [],
    }
    with Session(get_engine()) as session:
        for email, raw in downloaded:
            try:
                result = ingest_raw_email(
                    session,
                    raw,
                    source="jmap",
                    source_key=f"jmap:{email.get('id')}",
                    received_at=_parse_received(email.get("receivedAt")),
                )
            except Exception as exc:  # noqa: BLE001
                log.exception("ingest failed for JMAP message %s", email.get("id"))
                summary["errors"].append(f"{email.get('id')}: {exc}")
                continue
            summary["reports"] += result.reports
            summary["tls_reports"] += result.tls_reports
            summary["duplicates"] += result.duplicates
            summary["errors"].extend(result.errors)
            if result.reports or result.tls_reports:
                summary["ingested"] += 1
            summary["detail"].append(
                {
                    "id": email.get("id"),
                    "subject": email.get("subject"),
                    "status": result.status,
                    "reports": result.reports,
                    "tls": result.tls_reports,
                }
            )
    if summary["errors"]:
        summary["status"] = "partial" if summary["reports"] or summary["tls_reports"] else "error"
    return summary


def _newest_timestamp(
    downloaded: list[tuple[dict[str, Any], bytes]], emails: list[dict[str, Any]]
) -> Optional[datetime]:
    candidates: list[datetime] = []
    for email, _raw in downloaded:
        parsed = _parse_received(email.get("receivedAt"))
        if parsed:
            candidates.append(parsed)
    for email in emails:
        parsed = _parse_received(email.get("receivedAt"))
        if parsed:
            candidates.append(parsed)
    return max(candidates) if candidates else None


def _parse_received(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _days(count: int):
    from datetime import timedelta

    return timedelta(days=count)
