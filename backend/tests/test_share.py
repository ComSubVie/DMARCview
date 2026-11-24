"""Read-only share links: creation, public payload and revoke/expiry."""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session

from app.models import ShareLink, utcnow

from .test_api import upload_all


def _create(client: TestClient, **payload) -> dict:
    response = client.post("/api/share-links", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def test_share_link_public_view_and_stripping(auth_client: TestClient):
    upload_all(auth_client)
    created = _create(auth_client, domain="tgm.rocks", days=7, include_sources=False)
    token = created["token"]
    assert created["url"] == f"/s/{token}"

    listing = auth_client.get("/api/share-links").json()["items"]
    assert any(item["id"] == created["id"] for item in listing)

    auth_client.cookies.clear()
    public = auth_client.get(f"/api/public/{token}")
    assert public.status_code == 200, public.text
    assert public.headers["Referrer-Policy"] == "no-referrer"
    assert public.headers["X-Robots-Tag"].startswith("noindex")
    assert public.headers["Cache-Control"] == "no-store"
    body = public.json()
    assert body["scope"]["domain"] == "tgm.rocks"
    assert body["dashboard"]["sources"] == []
    assert body["dashboard"]["identities"]["items"] == []

    refreshed = auth_client.get(f"/api/public/{token}").json()
    assert refreshed["scope"]["domain"] == "tgm.rocks"


def test_share_link_with_sources_strips_envelope(auth_client: TestClient):
    upload_all(auth_client)
    created = _create(auth_client, domain="tgm.rocks", days=30, include_sources=True)
    body = auth_client.get(f"/api/public/{created['token']}").json()
    sources = body["dashboard"]["sources"]
    assert sources
    assert all("envelope_from" not in source and "envelope_to" not in source for source in sources)


def test_share_link_revoke_and_expiry(auth_client: TestClient, session: Session):
    upload_all(auth_client)
    created = _create(auth_client, domain="tgm.rocks", days=7)
    token = created["token"]
    assert auth_client.get(f"/api/public/{token}").status_code == 200

    revoked = auth_client.post(f"/api/share-links/{created['id']}/revoke")
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] is True
    assert auth_client.get(f"/api/public/{token}").status_code == 404

    second = _create(auth_client, domain=None, days=7)
    row = session.get(ShareLink, second["id"])
    assert row is not None
    row.expires_at = utcnow() - timedelta(minutes=1)
    session.add(row)
    session.commit()
    assert auth_client.get(f"/api/public/{second['token']}").status_code == 404


def test_share_link_tamper(auth_client: TestClient):
    upload_all(auth_client)
    created = _create(auth_client, domain="tgm.rocks", days=7)
    token = created["token"]
    tampered = token[:-2] + ("aa" if token[-2:] != "aa" else "bb")
    assert auth_client.get(f"/api/public/{tampered}").status_code == 404
