"""Restore safety and integrity checks."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.backup import BackupError, backup_database, restore_database, verify_snapshot


def _make_db(path: Path, names: list[str]) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32))")
        connection.execute("INSERT OR REPLACE INTO alembic_version VALUES ('test')")
        connection.execute("CREATE TABLE IF NOT EXISTS domains (name TEXT)")
        for name in names:
            connection.execute("INSERT INTO domains VALUES (?)", (name,))
        connection.commit()
    finally:
        connection.close()


def test_restore_verifies_and_keeps_safety_backup(tmp_path: Path):
    live = tmp_path / "live.db"
    _make_db(live, ["old.example"])
    snapshot = backup_database(db_path=live, dest_dir=tmp_path / "snapshots", keep=0)
    verify_snapshot(snapshot)

    with sqlite3.connect(live) as connection:
        connection.execute("INSERT INTO domains VALUES ('new.example')")
    assert _count(live) == 2

    safety = restore_database(snapshot, db_path=live, safety=True)
    assert safety.exists()
    assert _count(live) == 1


def test_restore_rejects_invalid_snapshot(tmp_path: Path):
    bad = tmp_path / "bad.db"
    bad.write_text("not a database")
    with pytest.raises(BackupError):
        verify_snapshot(bad)


def _count(path: Path) -> int:
    with sqlite3.connect(path) as connection:
        return int(connection.execute("SELECT COUNT(*) FROM domains").fetchone()[0])
