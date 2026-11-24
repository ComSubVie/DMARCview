"""Signed, revocable read-only share links.

Only the SHA-256 hash of the read-only token is stored. The token itself is a
URL-safe payload plus an HMAC, so a forged token cannot be used to probe the
database, and a leaked database cannot be turned into working links.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import timedelta, timezone
from typing import Any, Optional

from sqlmodel import Session, select

from . import analytics
from .config import get_settings
from .models import Domain, ShareLink, utcnow

DEFAULT_DAYS = 7
MAX_DAYS = 90


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _signature(secret: str, body: str) -> str:
    return _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())


def encode_token(payload: dict[str, Any], secret: str) -> str:
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    return f"{body}.{_signature(secret, body)}"


def decode_token(token: str, secret: str) -> Optional[dict[str, Any]]:
    try:
        body, signature = token.split(".", 1)
    except ValueError:
        return None
    if not hmac.compare_digest(signature, _signature(secret, body)):
        return None
    try:
        payload = json.loads(_unb64(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("v") != 1:
        return None
    try:
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
    except (TypeError, ValueError):
        return None
    return payload


def create_link(
    session: Session,
    *,
    domain: Optional[Domain],
    days: int = DEFAULT_DAYS,
    include_sources: bool = False,
) -> tuple[ShareLink, str]:
    settings = get_settings()
    days = max(1, min(int(days), MAX_DAYS))
    now = utcnow()
    expires = now + timedelta(days=days)
    row = ShareLink(
        token_hash="pending",
        domain_id=domain.id if domain else None,
        days=days,
        include_sources=include_sources,
        created_at=now,
        expires_at=expires,
    )
    session.add(row)
    session.flush()
    payload = {
        "v": 1,
        "id": row.id,
        "domain": domain.name if domain else None,
        "days": days,
        "include_sources": include_sources,
        "exp": int(expires.timestamp()),
    }
    token = encode_token(payload, settings.secret_key)
    row.token_hash = hashlib.sha256(token.encode()).hexdigest()
    session.add(row)
    session.commit()
    session.refresh(row)
    return row, token


def resolve_link(session: Session, token: str) -> Optional[tuple[ShareLink, Optional[Domain]]]:
    settings = get_settings()
    payload = decode_token(token, settings.secret_key)
    if payload is None:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = session.exec(select(ShareLink).where(ShareLink.token_hash == token_hash)).first()
    if row is None or row.id != payload.get("id"):
        return None
    if row.revoked_at is not None:
        return None
    expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    if expires < utcnow():
        return None
    domain = session.get(Domain, row.domain_id) if row.domain_id is not None else None
    if row.domain_id is not None and domain is None:
        return None
    return row, domain


def mark_used(session: Session, row: ShareLink) -> None:
    row.uses = (row.uses or 0) + 1
    row.last_used_at = utcnow()
    session.add(row)
    session.commit()


def _strip_envelope(source: dict[str, Any]) -> None:
    source.pop("envelope_from", None)
    source.pop("envelope_to", None)


def public_payload(session: Session, row: ShareLink, domain: Optional[Domain]) -> dict[str, Any]:
    rng = analytics.resolve_range(row.days)
    data = analytics.dashboard(session, domain, rng)
    data["advice"] = analytics.advise(data.get("policy"), data["kpis"], rng.days)

    if row.include_sources:
        for source in data.get("sources") or []:
            _strip_envelope(source)
    else:
        data["sources"] = []
        data["groups"] = {
            "verified": {"messages": 0, "sources": 0},
            "unverified": {"messages": 0, "sources": 0},
        }
    data["identities"] = {"total": 0, "items": []}
    for item in data.get("fleet") or []:
        item["tags"] = []
    if data.get("coverage_detail"):
        data["coverage_detail"]["subdomains"] = []
    if data.get("changes"):
        data["changes"]["new_identities"] = []
        data["changes"]["lost_identities"] = []
    return data


def serialise_link(row: ShareLink, domain_name: Optional[str]) -> dict[str, Any]:
    expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    return {
        "id": row.id,
        "domain": domain_name,
        "days": row.days,
        "include_sources": row.include_sources,
        "created_at": row.created_at.isoformat().replace("+00:00", "Z") if row.created_at else None,
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "revoked_at": row.revoked_at.isoformat().replace("+00:00", "Z") if row.revoked_at else None,
        "last_used_at": row.last_used_at.isoformat().replace("+00:00", "Z") if row.last_used_at else None,
        "uses": row.uses,
        "revoked": row.revoked_at is not None,
    }
