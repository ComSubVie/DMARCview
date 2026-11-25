"""Off-box backup uploads (WebDAV and S3-compatible)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

import httpx

from .backup import bundle_sha256
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
    digest: Optional[str] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> dict[str, Any]:
    base = settings.backup_webdav_url
    if not base:
        raise OffsiteError("WEBDAV backup target is not configured")
    digest = digest or bundle_sha256(bundle)
    url = f"{base.rstrip('/')}/{quote(bundle.name, safe='')}"
    checksum_url = f"{url}.sha256"
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
            if 200 <= response.status_code < 300:
                response = await client.put(
                    checksum_url,
                    content=f"{digest}  {bundle.name}\n".encode(),
                    auth=auth,
                    headers={"Content-Type": "text/plain"},
                )
            if 200 <= response.status_code < 300:
                response = await client.head(url, auth=auth)
            if 200 <= response.status_code < 300:
                size = response.headers.get("content-length")
                if size is not None and int(size) != bundle.stat().st_size:
                    raise OffsiteError(
                        f"WebDAV verification failed: remote size {size} != {bundle.stat().st_size}"
                    )
                response = await client.get(checksum_url, auth=auth)
            if 200 <= response.status_code < 300:
                remote_digest = response.text.split()[0] if response.text.split() else ""
                if remote_digest != digest:
                    raise OffsiteError("WebDAV verification failed: checksum mismatch")
    except httpx.HTTPError as exc:
        raise OffsiteError(f"WebDAV upload failed: {type(exc).__name__}: {exc}") from exc
    if not 200 <= response.status_code < 300:
        detail = response.text[:300].replace("\n", " ")
        raise OffsiteError(f"WebDAV upload returned {response.status_code}: {detail}")
    return {
        "provider": "webdav",
        "key": bundle.name,
        "bytes": bundle.stat().st_size,
        "sha256": digest,
        "verified": True,
    }


def upload_s3(settings: Settings, bundle: Path, *, digest: Optional[str] = None) -> dict[str, Any]:
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:  # pragma: no cover - dependency is in requirements
        raise OffsiteError("boto3 is not installed; rebuild the image with backend/requirements.txt") from exc

    if not settings.backup_s3_bucket:
        raise OffsiteError("S3 backup target is not configured")
    digest = digest or bundle_sha256(bundle)
    prefix = settings.backup_s3_prefix.strip("/")
    key = f"{prefix}/{bundle.name}" if prefix else bundle.name
    checksum_key = f"{key}.sha256"
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
            ExtraArgs={"ContentType": "application/gzip", "Metadata": {"sha256": digest}},
        )
        client.put_object(
            Bucket=settings.backup_s3_bucket,
            Key=checksum_key,
            Body=f"{digest}  {bundle.name}\n".encode(),
            ContentType="text/plain",
        )
        head = client.head_object(Bucket=settings.backup_s3_bucket, Key=key)
        if int(head.get("ContentLength", -1)) != bundle.stat().st_size:
            raise OffsiteError("S3 verification failed: remote size mismatch")
        if str((head.get("Metadata") or {}).get("sha256", "")) != digest:
            raise OffsiteError("S3 verification failed: checksum metadata mismatch")
    except OffsiteError:
        raise
    except Exception as exc:  # noqa: BLE001 - boto3 raises several unrelated types
        raise OffsiteError(f"S3 upload failed: {type(exc).__name__}: {exc}") from exc
    return {
        "provider": "s3",
        "key": key,
        "bytes": bundle.stat().st_size,
        "sha256": digest,
        "verified": True,
    }


async def upload_bundle(settings: Settings, bundle: Path) -> list[dict[str, Any]]:
    names = targets(settings)
    if not names:
        raise OffsiteError("no off-box backup target configured")
    digest = bundle_sha256(bundle)
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    if "webdav" in names:
        try:
            results.append(await upload_webdav(settings, bundle, digest=digest))
        except OffsiteError as exc:
            errors.append(str(exc))
    if "s3" in names:
        try:
            results.append(await asyncio.to_thread(upload_s3, settings, bundle, digest=digest))
        except OffsiteError as exc:
            errors.append(str(exc))
    if errors:
        raise OffsiteError("; ".join(errors))
    return results
