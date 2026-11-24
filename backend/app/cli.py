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
from pathlib import Path

from sqlmodel import Session, func, select

from .backup import BackupError, backup_database
from .config import get_settings
from .db import get_engine, init_db
from .ingest.jmap import JMAPClient
from .ingest.service import ingest_files
from .geoip import get_geo_resolver
from .models import ProcessedMessage, Report, SourceRecord, TlsFailure, TlsReport
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


def cmd_sync(_args: argparse.Namespace) -> int:
    from .poller import run_sync

    init_db()
    try:
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
    try:
        target = backup_database(
            dest_dir=Path(args.destination) if args.destination else None,
            keep=args.keep,
        )
    except BackupError as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        return 1
    print(f"backup written to {target}")
    return 0


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
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("probe", help="check JMAP connectivity and mailbox lookup")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("migrate", help="apply database migrations")
    p.set_defaults(func=cmd_migrate)

    p = sub.add_parser("backup", help="write a consistent SQLite backup")
    p.add_argument("--destination", help="directory for the snapshot")
    p.add_argument("--keep", type=int, default=None, help="number of snapshots to keep")
    p.set_defaults(func=cmd_backup)

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
