"""Database engine and session helpers (SQLite-first, WAL enabled)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Optional

from sqlalchemy import event, inspect
from sqlalchemy.engine import Engine
from sqlmodel import Session, create_engine

from .config import get_settings

_engine: Optional[Engine] = None


def _connect_args(url: str) -> dict:
    if url.startswith("sqlite"):
        return {"check_same_thread": False, "timeout": 30}
    return {}


def _ensure_sqlite_directory(url: str) -> None:
    """Create the parent directory for file-backed SQLite URLs."""
    if not url.startswith("sqlite:///") or ":memory:" in url:
        return
    raw = url[len("sqlite:///") :]
    if not raw or raw.startswith("file:"):
        return
    with suppress(OSError):
        Path(raw).expanduser().parent.mkdir(parents=True, exist_ok=True)


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        settings = get_settings()
        url = settings.sqlalchemy_url
        _ensure_sqlite_directory(url)
        _engine = create_engine(
            url,
            echo=False,
            connect_args=_connect_args(url),
            pool_pre_ping=True,
        )
        if url.startswith("sqlite"):
            _configure_sqlite(_engine)
    return _engine


def _configure_sqlite(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _record):  # pragma: no cover - driver hook
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()


def reset_engine() -> None:
    """Dispose the engine so a new URL is picked up (used by tests)."""
    global _engine
    if _engine is not None:
        _engine.dispose()
    _engine = None


BACKEND_DIR = Path(__file__).resolve().parent.parent
BASELINE_REVISION = "0001"


def alembic_config():
    """Alembic config that works regardless of the current working directory."""
    from alembic.config import Config

    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


def run_migrations() -> None:
    """Bring the database to the latest revision, stamping v1 databases first.

    v1 shipped before Alembic existed, so an existing database has all baseline
    tables but no ``alembic_version`` row. Stamping the baseline revision lets
    the following revisions add the new tables without touching existing data.
    """
    from alembic import command

    engine = get_engine()
    tables = set(inspect(engine).get_table_names())
    config = alembic_config()
    if "alembic_version" not in tables and "domains" in tables:
        command.stamp(config, BASELINE_REVISION)
    command.upgrade(config, "head")


def init_db() -> None:
    from . import models  # noqa: F401  (register tables)

    run_migrations()


@contextmanager
def session_scope() -> Iterator[Session]:
    with Session(get_engine()) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


def get_session() -> Iterator[Session]:
    """FastAPI dependency."""
    with Session(get_engine()) as session:
        yield session
