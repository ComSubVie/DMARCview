"""Off-box backup uploads (WebDAV and S3-compatible)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

import httpx

from .config import Settings


class OffsiteError(RuntimeError):
    pass


def targets(settings: Settings) -> list[str]:
    providers: list[str] = []
    if settings.backup_webdav_url:
        providers.append("webdav")
    if settings.backup_s3_bucket:
        providers.append("s3")
    return providers


def configured(settings: Settings) -> bool:
    return bool(targets(settings))


async def upload_webdav(
    settings: Settings,
    bundle: Path,
    *,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> dict[str, Any]:
    base = settings.backup_webdav_url
    if not base:
        raise OffsiteError("WEBDAV backup target is not configured")
    url = f"{base.rstrip('/')}/{quote(bundle.name, safe='')}"
    auth = (
        httpx.BasicAuth(settings.backup_webdav_username, settings.backup_webdav_password)
        if settings.backup_webdav_username
        else None
    )
    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True, transport=transport) as client:
            response = await client.put(
                url,
                content=bundle.read_bytes(),
                auth=auth,
                headers={"Content-Type": "application/gzip"},
            )
    except httpx.HTTPError as exc:
        raise OffsiteError(f"WebDAV upload failed: {type(exc).__name__}: {exc}") from exc
    if not 200 <= response.status_code < 300:
        detail = response.text[:300].replace("\n", " ")
        raise OffsiteError(f"WebDAV upload returned {response.status_code}: {detail}")
    return {"provider": "webdav", "key": bundle.name, "bytes": bundle.stat().st_size}


def upload_s3(settings: Settings, bundle: Path) -> dict[str, Any]:
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:  # pragma: no cover - dependency is in requirements
        raise OffsiteError("boto3 is not installed; rebuild the image with backend/requirements.txt") from exc

    if not settings.backup_s3_bucket:
        raise OffsiteError("S3 backup target is not configured")
    prefix = settings.backup_s3_prefix.strip("/")
    key = f"{prefix}/{bundle.name}" if prefix else bundle.name
    kwargs: dict[str, Any] = {
        "region_name": settings.backup_s3_region or "us-east-1",
        "config": Config(s3={"addressing_style": "path" if settings.backup_s3_path_style else "auto"}),
    }
    if settings.backup_s3_endpoint:
        kwargs["endpoint_url"] = settings.backup_s3_endpoint
    if settings.backup_s3_access_key:
        kwargs["aws_access_key_id"] = settings.backup_s3_access_key
    if settings.backup_s3_secret_key:
        kwargs["aws_secret_access_key"] = settings.backup_s3_secret_key
    if settings.backup_s3_session_token:
        kwargs["aws_session_token"] = settings.backup_s3_session_token
    try:
        client = boto3.client("s3", **kwargs)
        client.upload_file(
            str(bundle),
            settings.backup_s3_bucket,
            key,
            ExtraArgs={"ContentType": "application/gzip"},
        )
    except Exception as exc:  # noqa: BLE001 - boto3 raises several unrelated types
        raise OffsiteError(f"S3 upload failed: {type(exc).__name__}: {exc}") from exc
    return {"provider": "s3", "key": key, "bytes": bundle.stat().st_size}


async def upload_bundle(settings: Settings, bundle: Path) -> list[dict[str, Any]]:
    names = targets(settings)
    if not names:
        raise OffsiteError("no off-box backup target configured")
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    if "webdav" in names:
        try:
            results.append(await upload_webdav(settings, bundle))
        except OffsiteError as exc:
            errors.append(str(exc))
    if "s3" in names:
        try:
            results.append(await asyncio.to_thread(upload_s3, settings, bundle))
        except OffsiteError as exc:
            errors.append(str(exc))
    if errors:
        raise OffsiteError("; ".join(errors))
    return results
