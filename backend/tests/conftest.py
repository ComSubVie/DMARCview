"""Test configuration: isolated database and credentials before app import."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TMP = Path(tempfile.mkdtemp(prefix="dmarcview-tests-"))

os.environ["APP_ENV"] = "test"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "test-password"
os.environ["ADMIN_PASSWORD_HASH"] = ""
os.environ["DATABASE_URL"] = f"sqlite:///{TMP / 'test.db'}"
os.environ["DATA_DIR"] = str(TMP)
os.environ["JMAP_ENABLED"] = "false"
os.environ["JMAP_URL"] = ""
os.environ["JMAP_USERNAME"] = ""
os.environ["JMAP_PASSWORD"] = ""
os.environ["JMAP_TOKEN"] = ""
os.environ["JMAP_MAILBOX"] = "DMARC"
os.environ["GEOIP_DB"] = str(REPO / "data" / "geoip" / "dbip-country-lite.mmdb")
os.environ["COOKIE_SECURE"] = "false"
os.environ["HEALTH_CHECKS_ENABLED"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel  # noqa: E402

from app.db import get_engine, init_db, reset_engine  # noqa: E402
from app.main import app  # noqa: E402
from app.security import login_throttle  # noqa: E402

SAMPLES = REPO / "samples"


class StubGeoResolver:
    """Deterministic country data so tests never depend on the local .mmdb."""

    available = True
    MAPPING = {
        "62.116.130.25": ("DE", "Germany"),
        "209.85.220.41": ("US", "United States"),
        "159.135.224.17": ("US", "United States"),
        "40.92.19.44": ("US", "United States"),
        "185.199.108.153": ("US", "United States"),
        "91.198.174.192": ("NL", "Netherlands"),
    }

    def lookup(self, ip):
        return self.MAPPING.get(ip or "", (None, None))


@pytest.fixture(autouse=True)
def deterministic_geo(monkeypatch):
    stub = StubGeoResolver()
    monkeypatch.setattr("app.ingest.service.get_geo_resolver", lambda: stub)
    yield stub


@pytest.fixture(autouse=True)
def clean_database():
    reset_engine()
    engine = get_engine()
    with engine.begin() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        for table in reversed(SQLModel.metadata.sorted_tables):
            connection.exec_driver_sql(f'DROP TABLE IF EXISTS "{table.name}"')
        connection.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
    init_db()
    login_throttle._attempts.clear()
    yield


@pytest.fixture()
def session() -> Session:
    with Session(get_engine()) as db_session:
        yield db_session


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def auth_client(client: TestClient) -> TestClient:
    response = client.post(
        "/api/auth/login", json={"username": "admin", "password": "test-password"}
    )
    assert response.status_code == 200, response.text
    return client


def sample(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()
