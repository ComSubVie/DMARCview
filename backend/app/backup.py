"""Consistent SQLite backups with local rotation.

A plain copy of a live SQLite database (or just the WAL) can be inconsistent;
``Connection.backup`` takes a safe snapshot while the app keeps running.
"""

from __future__ import annotations

import sqlite3
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import get_settings


class BackupError(RuntimeError):
    pass


def backup_database(
    db_path: Optional[Path] = None,
    dest_dir: Optional[Path] = None,
    keep: Optional[int] = None,
) -> Path:
    settings = get_settings()
    source_path = Path(db_path) if db_path else settings.db_path
    if source_path is None or not source_path.exists():
        raise BackupError(f"database not found at {source_path}")
    target_dir = Path(dest_dir) if dest_dir else settings.data_dir / "backups"
    target_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    target = target_dir / f"dmarc-{stamp}.db"

    source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
    try:
        destination = sqlite3.connect(target)
        try:
            source.backup(destination)
            check = destination.execute("PRAGMA integrity_check").fetchone()
            if not check or check[0] != "ok":
                raise BackupError(f"integrity check failed: {check}")
        finally:
            destination.close()
    finally:
        source.close()

    limit = keep if keep is not None else settings.backup_keep
    if limit > 0:
        backups = sorted(target_dir.glob("dmarc-*.db"))
        for old in backups[:-limit]:
            with suppress(OSError):
                old.unlink()
    return target


def verify_snapshot(path: Path) -> None:
    """Raise BackupError unless *path* is a readable, consistent SQLite database."""
    path = Path(path)
    if not path.exists() or not path.is_file():
        raise BackupError(f"snapshot not found at {path}")
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.DatabaseError as exc:
        raise BackupError(f"cannot open snapshot: {exc}") from exc
    try:
        check = connection.execute("PRAGMA integrity_check").fetchone()
        if not check or check[0] != "ok":
            raise BackupError(f"integrity check failed: {check}")
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "alembic_version" not in tables or "domains" not in tables:
            raise BackupError("snapshot is not a DMARCView database")
    except sqlite3.DatabaseError as exc:
        raise BackupError(f"invalid SQLite snapshot: {exc}") from exc
    finally:
        connection.close()


def restore_database(
    snapshot: Path,
    *,
    db_path: Optional[Path] = None,
    safety: bool = True,
) -> Path:
    """Restore a snapshot, taking a safety backup of the current database first.

    The caller must stop the web process: SQLite cannot safely replace a file
    while another process holds it open. The CLI enforces an explicit --yes.
    """
    settings = get_settings()
    source_path = Path(snapshot).expanduser()
    target_path = Path(db_path) if db_path else settings.db_path
    if target_path is None:
        raise BackupError("no database path configured")
    if source_path.resolve() == target_path.resolve():
        raise BackupError("snapshot and live database are the same file")
    verify_snapshot(source_path)

    safety_path: Optional[Path] = None
    if safety and target_path.exists():
        safety_path = backup_database(db_path=target_path)

    target_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = target_path.with_suffix(target_path.suffix + ".restore-tmp")
    try:
        temporary.write_bytes(source_path.read_bytes())
        verify_snapshot(temporary)
        for suffix in ("-wal", "-shm"):
            stale = Path(str(target_path) + suffix)
            if stale.exists():
                stale.unlink()
        temporary.replace(target_path)
        verify_snapshot(target_path)
    except Exception:
        temporary.unlink(missing_ok=True)
        if safety_path is not None and safety_path.exists() and not target_path.exists():
            target_path.write_bytes(safety_path.read_bytes())
        raise
    return safety_path or Path()
