"""Weekly digest construction and disable behaviour."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlmodel import Session

from app.config import get_settings
from app.db import get_engine
from app.digest import build_digest
from app.jobs import job_digest


def test_digest_contains_domain_summary(auth_client: TestClient):
    from tests.test_api import upload_all

    upload_all(auth_client)
    with Session(get_engine()) as session:
        digest = build_digest(session, get_settings(), days=7)
    assert digest["subject"].startswith("[DMARCView] Weekly digest")
    assert "tgm.rocks" in digest["text"]
    assert "tgm.rocks" in digest["html"]
    assert digest["domains"]
    assert all("aligned_pct" in row for row in digest["domains"])


def test_digest_is_skipped_when_disabled():
    import asyncio

    assert asyncio.run(job_digest()) == {"skipped": "disabled"}
