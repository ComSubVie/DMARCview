"""Structured DNS/health record diffs for a domain."""

from __future__ import annotations

import json
from datetime import timezone
from typing import Any

from sqlmodel import Session, select

from .models import Domain, DomainHealthSnapshot
from .timeline import CHECK_LABELS, iso


def _fingerprint(result: dict[str, Any]) -> str:
    evidence = result.get("evidence") or {}
    return json.dumps(
        {
            "status": result.get("status"),
            "record": evidence.get("record"),
            "p": evidence.get("p"),
            "sp": evidence.get("sp"),
            "np": evidence.get("np"),
            "testing": evidence.get("testing"),
            "psd": evidence.get("psd"),
            "rua": evidence.get("rua"),
        },
        sort_keys=True,
        default=str,
    )


def _entry(result: dict[str, Any]) -> dict[str, Any]:
    evidence = result.get("evidence") or {}
    return {
        "status": result.get("status"),
        "summary": result.get("summary"),
        "record": evidence.get("record"),
        "evidence": evidence,
    }


def build_dns_diff(session: Session, domain: Domain, *, limit: int = 30) -> dict[str, Any]:
    snapshots = session.exec(
        select(DomainHealthSnapshot)
        .where(DomainHealthSnapshot.domain_id == domain.id)
        .order_by(DomainHealthSnapshot.checked_at.desc())
        .limit(limit)
    ).all()
    snapshots = list(reversed(snapshots))
    current: dict[str, dict[str, Any]] = {}
    previous: dict[str, dict[str, Any]] = {}
    changes: list[dict[str, Any]] = []
    for snapshot in snapshots:
        current = {}
        checked_at = snapshot.checked_at
        if checked_at.tzinfo is None:
            checked_at = checked_at.replace(tzinfo=timezone.utc)
        for result in snapshot.results or []:
            if not isinstance(result, dict) or result.get("key") not in CHECK_LABELS:
                continue
            key = str(result["key"])
            current[key] = result
            old = previous.get(key)
            if old is None or _fingerprint(old) == _fingerprint(result):
                continue
            changes.append(
                {
                    "id": f"{snapshot.id}:{key}",
                    "key": key,
                    "label": CHECK_LABELS[key],
                    "checked_at": iso(checked_at),
                    "before": _entry(old),
                    "after": _entry(result),
                }
            )
        previous = current
    return {
        "domain": domain.name,
        "current": [
            {"key": key, "label": CHECK_LABELS[key], **_entry(current[key])}
            for key in CHECK_LABELS
            if key in current
        ],
        "changes": list(reversed(changes)),
    }
