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
