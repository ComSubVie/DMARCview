"""Off-box backup uploads (WebDAV and S3-compatible)."""

from __future__ import annotations

import asyncio
import hashlib
import re
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote, unquote
from xml.etree import ElementTree

import httpx

from .backup import bundle_sha256, prune_bundles
from .config import Settings


class OffsiteError(RuntimeError):
    pass


def redact_error(value: str) -> str:
    """Remove URL credentials and obvious secrets from stored error text."""
    text = re.sub(r"(https?://)[^\s/@]+@", r"\1***@", str(value))
    text = re.sub(
        r"(?i)(token|secret|password|access[_-]?key)\s*[=:]\s*[^\s&,;]+",
        r"\1=***",
        text,
    )
    return text[:4000]


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
            bundle_response = await client.put(
                url,
                content=bundle.read_bytes(),
                auth=auth,
                headers={"Content-Type": "application/gzip"},
            )
            if not 200 <= bundle_response.status_code < 300:
                detail = bundle_response.text[:300].replace("\n", " ")
                raise OffsiteError(f"WebDAV upload returned {bundle_response.status_code}: {detail}")
            checksum_response = await client.put(
                checksum_url,
                content=f"{digest}  {bundle.name}\n".encode(),
                auth=auth,
                headers={"Content-Type": "text/plain"},
            )
            if not 200 <= checksum_response.status_code < 300:
                detail = checksum_response.text[:300].replace("\n", " ")
                raise OffsiteError(
                    f"WebDAV checksum upload returned {checksum_response.status_code}: {detail}"
                )
            head = await client.head(url, auth=auth)
            if head.status_code not in {405, 501}:
                if not 200 <= head.status_code < 300:
                    raise OffsiteError(f"WebDAV HEAD returned {head.status_code}")
                size = head.headers.get("content-length")
                if size is not None and int(size) != bundle.stat().st_size:
                    raise OffsiteError(
                        f"WebDAV verification failed: remote size {size} != {bundle.stat().st_size}"
                    )
            remote = await client.get(checksum_url, auth=auth)
            if not 200 <= remote.status_code < 300:
                raise OffsiteError(f"WebDAV checksum read returned {remote.status_code}")
            remote_digest = remote.text.split()[0] if remote.text.split() else ""
            if remote_digest != digest:
                raise OffsiteError("WebDAV verification failed: checksum mismatch")
    except httpx.HTTPError as exc:
        raise OffsiteError(f"WebDAV upload failed: {type(exc).__name__}: {exc}") from exc
    return {
        "provider": "webdav",
        "key": bundle.name,
        "bytes": bundle.stat().st_size,
        "sha256": digest,
        "verified": True,
    }


def _s3_client(settings: Settings):
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:  # pragma: no cover - dependency is in requirements
        raise OffsiteError("boto3 is not installed; rebuild the image with backend/requirements.txt") from exc
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
    return boto3.client("s3", **kwargs)


def upload_s3(settings: Settings, bundle: Path, *, digest: Optional[str] = None) -> dict[str, Any]:
    if not settings.backup_s3_bucket:
        raise OffsiteError("S3 backup target is not configured")
    digest = digest or bundle_sha256(bundle)
    prefix = settings.backup_s3_prefix.strip("/")
    key = f"{prefix}/{bundle.name}" if prefix else bundle.name
    checksum_key = f"{key}.sha256"
    try:
        client = _s3_client(settings)
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


def _target(settings: Settings, target: Optional[str] = None) -> str:
    available = targets(settings)
    if target:
        if target not in available:
            raise OffsiteError(f"{target} is not configured")
        return target
    if "webdav" in available:
        return "webdav"
    if "s3" in available:
        return "s3"
    raise OffsiteError("no off-box backup target configured")


def _bundle_name(value: str) -> Optional[str]:
    name = Path(unquote(value)).name
    if name.startswith("dmarc-") and name.endswith(".tar.gz"):
        return name
    return None


async def list_webdav(
    settings: Settings, *, transport: Optional[httpx.AsyncBaseTransport] = None
) -> list[str]:
    auth = (
        httpx.BasicAuth(settings.backup_webdav_username, settings.backup_webdav_password)
        if settings.backup_webdav_username
        else None
    )
    body = (
        '<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop>'
        "<d:displayname/></d:prop></d:propfind>"
    ).encode()
    try:
        async with httpx.AsyncClient(timeout=60, follow_redirects=True, transport=transport) as client:
            response = await client.request(
                "PROPFIND",
                settings.backup_webdav_url,
                content=body,
                auth=auth,
                headers={"Depth": "1", "Content-Type": "application/xml"},
            )
    except httpx.HTTPError as exc:
        raise OffsiteError(f"WebDAV list failed: {type(exc).__name__}: {exc}") from exc
    if response.status_code not in {200, 207}:
        raise OffsiteError(f"WebDAV list returned {response.status_code}")
    try:
        root = ElementTree.fromstring(response.content)
    except ElementTree.ParseError as exc:
        raise OffsiteError("WebDAV list returned invalid XML") from exc
    names = set()
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "href" or not element.text:
            continue
        name = _bundle_name(element.text)
        if name:
            names.add(name)
    return sorted(names)


async def download_webdav(
    settings: Settings,
    name: str,
    dest: Path,
    *,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> Path:
    auth = (
        httpx.BasicAuth(settings.backup_webdav_username, settings.backup_webdav_password)
        if settings.backup_webdav_username
        else None
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    base = settings.backup_webdav_url.rstrip("/")
    url = f"{base}/{quote(name, safe='')}"
    try:
        async with httpx.AsyncClient(timeout=300, follow_redirects=True, transport=transport) as client:
            bundle = await client.get(url, auth=auth)
            if not 200 <= bundle.status_code < 300:
                raise OffsiteError(f"WebDAV download returned {bundle.status_code}")
            checksum = await client.get(f"{url}.sha256", auth=auth)
    except httpx.HTTPError as exc:
        raise OffsiteError(f"WebDAV download failed: {type(exc).__name__}: {exc}") from exc
    if not 200 <= checksum.status_code < 300:
        raise OffsiteError(f"WebDAV checksum download returned {checksum.status_code}")
    expected = checksum.text.split()[0] if checksum.text.split() else ""
    actual = hashlib.sha256(bundle.content).hexdigest()
    if not expected or expected != actual:
        raise OffsiteError("WebDAV download verification failed: checksum mismatch")
    dest.write_bytes(bundle.content)
    return dest


def list_s3(settings: Settings) -> list[str]:
    client = _s3_client(settings)
    prefix = settings.backup_s3_prefix.strip("/")
    prefix = f"{prefix}/" if prefix else ""
    try:
        response = client.list_objects_v2(Bucket=settings.backup_s3_bucket, Prefix=prefix)
    except Exception as exc:  # noqa: BLE001
        raise OffsiteError(f"S3 list failed: {type(exc).__name__}: {exc}") from exc
    names = set()
    for item in response.get("Contents") or []:
        name = _bundle_name(str(item.get("Key", "")))
        if name:
            names.add(name)
    return sorted(names)


def download_s3(settings: Settings, name: str, dest: Path) -> Path:
    client = _s3_client(settings)
    prefix = settings.backup_s3_prefix.strip("/")
    key = f"{prefix}/{name}" if prefix else name
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        client.download_file(settings.backup_s3_bucket, key, str(dest))
        sidecar = client.get_object(Bucket=settings.backup_s3_bucket, Key=f"{key}.sha256")
        expected = sidecar["Body"].read().decode().split()[0]
    except Exception as exc:  # noqa: BLE001
        raise OffsiteError(f"S3 download failed: {type(exc).__name__}: {exc}") from exc
    actual = hashlib.sha256(dest.read_bytes()).hexdigest()
    if not expected or expected != actual:
        dest.unlink(missing_ok=True)
        raise OffsiteError("S3 download verification failed: checksum mismatch")
    return dest


async def fetch_latest(
    settings: Settings,
    *,
    target: Optional[str] = None,
    name: Optional[str] = None,
    dest_dir: Optional[Path] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> dict[str, Any]:
    provider = _target(settings, target)
    chosen = name
    if provider == "webdav":
        if not chosen:
            names = await list_webdav(settings, transport=transport)
            if not names:
                raise OffsiteError("no remote bundles found")
            chosen = names[-1]
        if not _bundle_name(chosen) or Path(chosen).name != chosen or ".." in chosen:
            raise OffsiteError("invalid remote bundle name")
        destination = (dest_dir or settings.data_dir / "backups") / chosen
        prune_bundles(destination.parent, settings.backup_keep)
        path = await download_webdav(settings, chosen, destination, transport=transport)
    else:
        if not chosen:
            names = await asyncio.to_thread(list_s3, settings)
            if not names:
                raise OffsiteError("no remote bundles found")
            chosen = names[-1]
        if not _bundle_name(chosen) or Path(chosen).name != chosen or ".." in chosen:
            raise OffsiteError("invalid remote bundle name")
        destination = (dest_dir or settings.data_dir / "backups") / chosen
        prune_bundles(destination.parent, settings.backup_keep)
        path = await asyncio.to_thread(download_s3, settings, chosen, destination)
    return {"provider": provider, "name": chosen, "path": str(path)}


async def test_webdav(
    settings: Settings, *, transport: Optional[httpx.AsyncBaseTransport] = None
) -> dict[str, Any]:
    auth = (
        httpx.BasicAuth(settings.backup_webdav_username, settings.backup_webdav_password)
        if settings.backup_webdav_username
        else None
    )
    base = settings.backup_webdav_url.rstrip("/")
    probe = f"{base}/.dmarcview-test"
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, transport=transport) as client:
            listing = await client.request(
                "PROPFIND", base, auth=auth, headers={"Depth": "0"}
            )
            if listing.status_code not in {200, 207}:
                raise OffsiteError(f"WebDAV returned {listing.status_code} for the target folder")
            written = await client.put(probe, content=b"test", auth=auth)
            if not 200 <= written.status_code < 300:
                raise OffsiteError(f"WebDAV write returned {written.status_code}")
            removed = await client.delete(probe, auth=auth)
            if not 200 <= removed.status_code < 300:
                raise OffsiteError(f"WebDAV cleanup returned {removed.status_code}")
    except httpx.HTTPError as exc:
        raise OffsiteError(f"WebDAV test failed: {type(exc).__name__}: {exc}") from exc
    return {"provider": "webdav", "ok": True}


def test_s3(settings: Settings) -> dict[str, Any]:
    try:
        client = _s3_client(settings)
        client.head_bucket(Bucket=settings.backup_s3_bucket)
        prefix = settings.backup_s3_prefix.strip("/")
        key = f"{prefix}/.dmarcview-test" if prefix else ".dmarcview-test"
        client.put_object(Bucket=settings.backup_s3_bucket, Key=key, Body=b"test")
        client.delete_object(Bucket=settings.backup_s3_bucket, Key=key)
    except Exception as exc:  # noqa: BLE001
        raise OffsiteError(redact_error(f"S3 test failed: {type(exc).__name__}: {exc}")) from exc
    return {"provider": "s3", "ok": True}


async def test_targets(settings: Settings) -> list[dict[str, Any]]:
    names = targets(settings)
    if not names:
        raise OffsiteError("no off-box backup target configured")
    results: list[dict[str, Any]] = []
    if "webdav" in names:
        try:
            results.append(await test_webdav(settings))
        except OffsiteError as exc:
            results.append({"provider": "webdav", "ok": False, "error": redact_error(str(exc))})
    if "s3" in names:
        try:
            results.append(await asyncio.to_thread(test_s3, settings))
        except OffsiteError as exc:
            results.append({"provider": "s3", "ok": False, "error": redact_error(str(exc))})
    return results


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
