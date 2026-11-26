"""Command line helper: credentials, database, offline import, one-shot sync.

Usage:
    python -m app.cli hash-password
    python -m app.cli init-db
    python -m app.cli import samples/*.eml
    python -m app.cli sync
    python -m app.cli probe
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys
from datetime import timedelta
from pathlib import Path

from sqlmodel import Session, func, select

from .backup import BackupError, backup_database, create_bundle, prune_bundles, restore_database, verify_backup
from .config import get_settings
from .db import get_engine, init_db
from .geoip import get_geo_resolver
from .offsite import OffsiteError, fetch_latest, upload_bundle
from .ingest.dmarc import DmarcParseError, parse_dmarc
from .ingest.jmap import JMAPClient
from .ingest.mime import MimeParseError, extract_payloads
from .ingest.service import ingest_files, reparse_tls_mx_hosts, sync_jmap
from .ingest.tlsrpt import TlsParseError, parse_tlsrpt
from .models import (
    Domain,
    ProcessedMessage,
    Report,
    SourceRecord,
    TlsFailure,
    TlsReport,
    utcnow,
)
from .retention import prune
from .security import hash_password


def _collect(paths: list[str]) -> list[Path]:
    found: list[Path] = []
    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_dir():
            found.extend(sorted(path.glob("*.eml")))
            found.extend(sorted(path.glob("*.zip")))
        elif path.is_file():
            found.append(path)
        else:
            print(f"skipping missing path: {raw}", file=sys.stderr)
    return found


def cmd_hash_password(args: argparse.Namespace) -> int:
    password = args.password or getpass.getpass("Admin password: ")
    if not password:
        print("aborted: empty password", file=sys.stderr)
        return 2
    if not args.password:
        confirm = getpass.getpass("Repeat password: ")
        if confirm != password:
            print("aborted: passwords differ", file=sys.stderr)
            return 2
    print(hash_password(password))
    return 0


def cmd_init_db(_args: argparse.Namespace) -> int:
    init_db()
    print(f"database ready at {get_settings().sqlalchemy_url}")
    return 0


def cmd_mailbox_debug(args: argparse.Namespace) -> int:
    """Inspect messages and payloads without writing to the database."""
    init_db()
    settings = get_settings()
    if not settings.jmap_enabled or not settings.jmap_url:
        print("JMAP is not configured (JMAP_ENABLED/JMAP_URL)", file=sys.stderr)
        return 1

    async def run() -> dict:
        client = JMAPClient(
            settings.jmap_url,
            settings.jmap_username,
            settings.jmap_password,
            settings.jmap_token,
        )
        mailbox = await client.find_mailbox(settings.jmap_mailbox)
        since = None if args.all else utcnow() - timedelta(days=args.days)
        ids = await client.query_email_ids(mailbox["id"], since, max_messages=args.max)
        emails = await client.get_emails(ids)
        items: list[dict] = []
        with Session(get_engine()) as session:
            for email in emails:
                entry: dict = {
                    "id": email.get("id"),
                    "received_at": email.get("receivedAt"),
                    "subject": email.get("subject"),
                    "payloads": [],
                    "error": None,
                }
                try:
                    raw = await client.download(email["blobId"], f"{email['id']}.eml")
                    parsed, payloads = extract_payloads(raw)
                    entry["message_id"] = parsed.message_id
                    for payload in payloads:
                        info = {
                            "kind": payload.kind,
                            "filename": payload.filename,
                            "sha256": payload.sha256,
                        }
                        processed = session.exec(
                            select(ProcessedMessage).where(
                                ProcessedMessage.source_key == f"jmap:{email.get('id')}"
                            )
                        ).first()
                        info["processed"] = processed.status if processed else None
                        info["processed_error"] = processed.error if processed else None
                        try:
                            if payload.kind == "tlsrpt":
                                report = parse_tlsrpt(payload.data)
                                domain = session.exec(
                                    select(Domain).where(Domain.name == report.policy_domain)
                                ).first()
                                info.update(
                                    {
                                        "report_id": report.report_id,
                                        "org_name": report.org_name,
                                        "domain": report.policy_domain,
                                        "date_begin": report.date_begin.isoformat(),
                                        "date_end": report.date_end.isoformat(),
                                    }
                                )
                                info["raw_in_db"] = (
                                    session.exec(
                                        select(TlsReport.id).where(
                                            TlsReport.raw_sha256 == payload.sha256
                                        )
                                    ).first()
                                    is not None
                                )
                                info["unique_in_db"] = bool(
                                    domain
                                    and session.exec(
                                        select(TlsReport.id).where(
                                            TlsReport.org_name == report.org_name,
                                            TlsReport.report_id == report.report_id,
                                            TlsReport.domain_id == domain.id,
                                        )
                                    ).first()
                                )
                            else:
                                report = parse_dmarc(payload.data)
                                domain = session.exec(
                                    select(Domain).where(Domain.name == report.policy_domain)
                                ).first()
                                info.update(
                                    {
                                        "report_id": report.report_id,
                                        "org_name": report.org_name,
                                        "domain": report.policy_domain,
                                        "date_begin": report.date_begin.isoformat(),
                                        "date_end": report.date_end.isoformat(),
                                    }
                                )
                                info["raw_in_db"] = (
                                    session.exec(
                                        select(Report.id).where(
                                            Report.raw_sha256 == payload.sha256
                                        )
                                    ).first()
                                    is not None
                                )
                                info["unique_in_db"] = bool(
                                    domain
                                    and session.exec(
                                        select(Report.id).where(
                                            Report.org_name == report.org_name,
                                            Report.report_id == report.report_id,
                                            Report.domain_id == domain.id,
                                        )
                                    ).first()
                                )
                        except (DmarcParseError, TlsParseError) as exc:
                            info["parse_error"] = str(exc)
                        entry["payloads"].append(info)
                except MimeParseError as exc:
                    entry["error"] = f"MIME: {exc}"
                except Exception as exc:  # noqa: BLE001
                    entry["error"] = str(exc)
                items.append(entry)
        return {
            "mailbox": mailbox.get("name"),
            "since": None if since is None else since.isoformat(),
            "messages": len(emails),
            "items": items,
        }

    try:
        result = asyncio.run(run())
    except Exception as exc:  # noqa: BLE001
        print(f"mailbox debug failed: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    print(f"{result['messages']} messages in {result['mailbox']} (since {result['since'] or 'beginning'})")
    for item in result["items"]:
        print(f"- {item['id']} {item['received_at']} {item['subject']}")
        if item["error"]:
            print(f"    error: {item['error']}")
        for payload in item["payloads"]:
            if "parse_error" in payload:
                print(f"    {payload['kind']} {payload['filename']}: {payload['parse_error']}")
                continue
            print(
                f"    {payload['kind']} {payload['filename']} "
                f"domain={payload['domain']} report={payload['report_id']}"
            )
            print(
                f"      processed={payload['processed']} raw_in_db={payload['raw_in_db']} "
                f"unique_in_db={payload['unique_in_db']}"
            )
            if payload["processed_error"]:
                print(f"      processed_error: {payload['processed_error']}")
    return 0


def _remote_bundle(args: argparse.Namespace) -> Path:
    settings = get_settings()
    result = asyncio.run(
        fetch_latest(
            settings,
            target=args.target,
            name=args.name,
            dest_dir=Path(args.destination) if getattr(args, "destination", None) else None,
        )
    )
    print(f"downloaded {result['provider']} bundle {result['path']}")
    return Path(result["path"])


def cmd_restore(args: argparse.Namespace) -> int:
    if not args.yes:
        print("refusing to restore without --yes (stop the app first)", file=sys.stderr)
        return 1
    try:
        snapshot = _remote_bundle(args) if args.remote else Path(args.snapshot or "")
        if args.remote and not snapshot:
            raise BackupError("no remote bundle selected")
        safety = restore_database(snapshot, with_archive=args.with_archive)
    except (BackupError, OffsiteError) as exc:
        print(f"restore failed: {exc}", file=sys.stderr)
        return 1
    if safety and safety != Path():
        print(f"safety backup: {safety}")
    print(f"restored {snapshot}")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    settings = get_settings()
    try:
        result = asyncio.run(
            fetch_latest(
                settings,
                target=args.target,
                name=args.name,
                dest_dir=Path(args.destination) if args.destination else None,
            )
        )
    except OffsiteError as exc:
        print(f"fetch failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    init_db()
    paths = _collect(args.paths)
    if not paths:
        print("nothing to import", file=sys.stderr)
        return 2
    with Session(get_engine()) as session:
        result = ingest_files(session, paths, source="import")
    print(json.dumps(result.as_dict(), indent=2))
    return 0 if not result.errors else 1


def cmd_sync(args: argparse.Namespace) -> int:
    from .poller import run_sync

    init_db()
    try:
        if args.all or args.days is not None:
            since = None if args.all else utcnow() - timedelta(days=args.days)
            result = asyncio.run(
                sync_jmap(
                    trigger="cli",
                    since_override=since,
                    scan_all=bool(args.all),
                    max_messages=args.max,
                )
            )
        else:
            result = asyncio.run(run_sync("cli"))
    except Exception as exc:  # noqa: BLE001
        print(f"sync failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


def cmd_probe(_args: argparse.Namespace) -> int:
    settings = get_settings()
    if not settings.jmap_url:
        print("JMAP_URL is not set", file=sys.stderr)
        return 2
    client = JMAPClient(
        settings.jmap_url, settings.jmap_username, settings.jmap_password, settings.jmap_token
    )
    try:
        result = asyncio.run(client.probe())
    except Exception as exc:  # noqa: BLE001
        print(f"probe failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


def cmd_migrate(_args: argparse.Namespace) -> int:
    from .db import run_migrations

    run_migrations()
    print("database is at the latest migration")
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    if args.verify:
        try:
            result = verify_backup(Path(args.verify))
        except BackupError as exc:
            print(f"verify failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2))
        return 0
    try:
        target = backup_database(
            dest_dir=Path(args.destination) if args.destination else None,
            keep=args.keep,
        )
    except BackupError as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        return 1
    print(f"backup written to {target}")
    if not (args.bundle or args.offsite):
        return 0
    settings = get_settings()
    bundle = create_bundle(target, settings.data_dir / "archive", target.parent)
    prune_bundles(bundle.parent, settings.backup_keep)
    print(f"bundle written to {bundle}")
    if args.offsite:
        try:
            results = asyncio.run(upload_bundle(settings, bundle))
        except OffsiteError as exc:
            print(f"off-box upload failed: {exc}", file=sys.stderr)
            return 1
        for result in results:
            print(f"uploaded to {result['provider']}: {result['key']} ({result['bytes']} bytes)")
        if not args.bundle:
            bundle.unlink(missing_ok=True)
    return 0


def cmd_tls_reparse(args: argparse.Namespace) -> int:
    init_db()
    with Session(get_engine()) as session:
        result = reparse_tls_mx_hosts(session, dry_run=args.dry_run)
    print(json.dumps(result, indent=2))
    return 0 if result["failed"] == 0 else 1


def cmd_geo_enrich(args: argparse.Namespace) -> int:
    """Backfill country data for rows ingested before the GeoIP database existed."""
    init_db()
    geo = get_geo_resolver()
    if not geo.available:
        print(
            "No GeoIP database is loaded. Put dbip-country-lite.mmdb in data/geoip/ "
            "(or set GEOIP_DB), restart, then rerun.",
            file=sys.stderr,
        )
        return 1
    with Session(get_engine()) as session:
        source_stmt = select(SourceRecord.source_ip).where(SourceRecord.source_ip.is_not(None))
        tls_stmt = select(TlsFailure.sending_mta_ip).where(TlsFailure.sending_mta_ip.is_not(None))
        if not args.all:
            source_stmt = source_stmt.where(SourceRecord.country_code.is_(None))
            tls_stmt = tls_stmt.where(TlsFailure.country_code.is_(None))
        ips = set(session.exec(source_stmt.distinct()).all())
        ips.update(session.exec(tls_stmt.distinct()).all())
        ips = {ip for ip in ips if ip}

        from sqlalchemy import update

        resolved = rows = 0
        for ip in sorted(ips):
            code, name = geo.lookup(ip)
            if not code:
                continue
            resolved += 1
            source_where = [SourceRecord.source_ip == ip]
            tls_where = [TlsFailure.sending_mta_ip == ip]
            if not args.all:
                source_where.append(SourceRecord.country_code.is_(None))
                tls_where.append(TlsFailure.country_code.is_(None))
            result = session.exec(
                update(SourceRecord)
                .where(*source_where)
                .values(country_code=code, country_name=name)
            )
            rows += result.rowcount or 0
            result = session.exec(
                update(TlsFailure)
                .where(*tls_where)
                .values(country_code=code, country_name=name)
            )
            rows += result.rowcount or 0
        session.commit()
    print(f"ips={len(ips)} resolved={resolved} rows={rows} unresolved={len(ips) - resolved}")
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    init_db()
    settings = get_settings()
    days = args.days if args.days is not None else settings.retention_days
    if days <= 0:
        print("retention is off: set RETENTION_DAYS or pass --days", file=sys.stderr)
        return 1
    if not args.dry_run and not args.yes:
        print("refusing to delete without --yes (use --dry-run to preview)", file=sys.stderr)
        return 1
    with Session(get_engine()) as session:
        result = prune(session, days, dry_run=args.dry_run)
    print(json.dumps(result, indent=2))
    return 0


def cmd_stats(_args: argparse.Namespace) -> int:
    init_db()
    with Session(get_engine()) as session:
        reports = session.exec(select(func.count(Report.id))).one()
        tls = session.exec(select(func.count(TlsReport.id))).one()
        messages = session.exec(select(func.count(ProcessedMessage.id))).one()
        print(f"reports={reports} tls_reports={tls} processed_messages={messages}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("hash-password", help="print a PBKDF2 hash for ADMIN_PASSWORD_HASH")
    p.add_argument("--password", help="password on the command line (avoid; prefer the prompt)")
    p.set_defaults(func=cmd_hash_password)

    p = sub.add_parser("init-db", help="create the SQLite schema")
    p.set_defaults(func=cmd_init_db)

    p = sub.add_parser("import", help="ingest .eml/.zip files from disk")
    p.add_argument("paths", nargs="+", help="files or directories")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("sync", help="run one JMAP sync now")
    p.add_argument("--days", type=int, default=None, help="scan from this many days ago")
    p.add_argument("--all", action="store_true", help="scan the whole mailbox (up to --max)")
    p.add_argument("--max", type=int, default=1500, help="maximum messages to fetch")
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("mailbox-debug", help="inspect mailbox messages and payloads without writing")
    p.add_argument("--days", type=int, default=90, help="look back this many days (default 90)")
    p.add_argument("--all", action="store_true", help="scan the whole mailbox")
    p.add_argument("--max", type=int, default=1500, help="maximum messages to inspect")
    p.add_argument("--json", action="store_true", help="print machine-readable output")
    p.set_defaults(func=cmd_mailbox_debug)

    p = sub.add_parser("probe", help="check JMAP connectivity and mailbox lookup")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("migrate", help="apply database migrations")
    p.set_defaults(func=cmd_migrate)

    p = sub.add_parser("restore", help="restore a snapshot or bundle (requires --yes)")
    p.add_argument("snapshot", nargs="?", help="path to a dmarc-*.db or dmarc-*.tar.gz")
    p.add_argument("--remote", action="store_true", help="download the selected remote bundle first")
    p.add_argument("--target", choices=["webdav", "s3"], help="remote backup target")
    p.add_argument("--name", help="remote bundle filename (default: latest)")
    p.add_argument("--destination", help="where to save a downloaded bundle")
    p.add_argument("--yes", action="store_true", help="confirm the restore")
    p.add_argument("--with-archive", action="store_true", help="also extract archive/ from a bundle")
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("fetch", help="download the latest off-box bundle")
    p.add_argument("--target", choices=["webdav", "s3"], help="remote backup target")
    p.add_argument("--name", help="bundle filename (default: latest)")
    p.add_argument("--destination", help="destination directory")
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("backup", help="write a consistent SQLite backup")
    p.add_argument("--destination", help="directory for the snapshot")
    p.add_argument("--keep", type=int, default=None, help="number of snapshots to keep")
    p.add_argument("--bundle", action="store_true", help="keep a .tar.gz with the database and archive")
    p.add_argument("--offsite", action="store_true", help="upload the bundle to configured off-box targets")
    p.add_argument("--verify", metavar="PATH", help="verify a snapshot or bundle instead of creating one")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("prune", help="archive and delete reports older than RETENTION_DAYS")
    p.add_argument("--days", type=int, default=None, help="override RETENTION_DAYS")
    p.add_argument("--dry-run", action="store_true", help="report what would be archived and deleted")
    p.add_argument("--yes", action="store_true", help="confirm actual deletion")
    p.set_defaults(func=cmd_prune)

    p = sub.add_parser("tls-reparse", help="backfill TLS-RPT receiving MX hosts from raw reports")
    p.add_argument("--dry-run", action="store_true", help="report changes without saving")
    p.set_defaults(func=cmd_tls_reparse)

    p = sub.add_parser("geo-enrich", help="backfill countries for existing report rows")
    p.add_argument("--all", action="store_true", help="re-resolve every IP, not only unknown rows")
    p.set_defaults(func=cmd_geo_enrich)

    p = sub.add_parser("stats", help="print row counts")
    p.set_defaults(func=cmd_stats)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
