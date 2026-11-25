"""Off-box backup bundle and WebDAV upload tests."""

from __future__ import annotations

import asyncio
import io
import sqlite3
import tarfile
from pathlib import Path

import httpx

from app.backup import bundle_sha256, create_bundle, extract_archive, extract_snapshot, is_bundle, prune_bundles, restore_database
from app.config import get_settings
from app.offsite import download_s3, fetch_latest, list_s3, test_s3 as probe_s3, upload_s3, upload_webdav


def _snapshot(path: Path) -> Path:
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE alembic_version (version_num TEXT)")
    connection.execute("INSERT INTO alembic_version VALUES ('0015')")
    connection.execute("CREATE TABLE domains (id INTEGER)")
    connection.commit()
    connection.close()
    return path


def test_bundle_contains_database_and_archive(tmp_path: Path):
    db = _snapshot(tmp_path / "dmarc-20260101-000000.db")
    archive = tmp_path / "archive" / "2026" / "01"
    archive.mkdir(parents=True)
    (archive / "report.xml").write_text("<feedback/>")

    bundle = create_bundle(db, tmp_path / "archive", tmp_path)

    assert is_bundle(bundle)
    with tarfile.open(bundle, "r:gz") as tar:
        names = set(tar.getnames())
    assert db.name in names
    assert "archive/2026/01/report.xml" in names

    extracted = extract_snapshot(bundle, tmp_path / "extract")
    assert extracted.name == db.name
    assert extracted.read_bytes() == db.read_bytes()

    archive_out = tmp_path / "archive-out"
    assert extract_archive(bundle, archive_out) == 1
    assert (archive_out / "2026" / "01" / "report.xml").read_text() == "<feedback/>"


def test_webdav_upload_uses_basic_auth(tmp_path: Path):
    bundle = _snapshot(tmp_path / "dmarc-20260101-000000.db")
    seen: dict[str, object] = {}

    digest = bundle_sha256(bundle)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.setdefault("methods", []).append(request.method)
        seen.setdefault("urls", []).append(str(request.url))
        seen["method"] = request.method
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen.setdefault("content_types", []).append(request.headers.get("content-type"))
        seen.setdefault("bodies", []).append(request.content)
        if request.method == "HEAD":
            return httpx.Response(200, headers={"content-length": str(bundle.stat().st_size)})
        if request.method == "GET":
            return httpx.Response(200, text=f"{digest}  {bundle.name}\n")
        return httpx.Response(201)

    settings = get_settings()
    settings = settings.__class__(
        **{**settings.__dict__, "backup_webdav_url": "https://dav.example/backups",
           "backup_webdav_username": "backup", "backup_webdav_password": "secret"}
    )
    result = asyncio.run(
        upload_webdav(settings, bundle, transport=httpx.MockTransport(handler))
    )
    assert result["provider"] == "webdav"
    assert result["verified"] is True
    assert seen["methods"][:2] == ["PUT", "PUT"]
    assert seen["methods"][-2:] == ["HEAD", "GET"]
    assert seen["urls"][0] == f"https://dav.example/backups/{bundle.name}"
    assert str(seen["auth"]).startswith("Basic ")
    assert seen["content_types"][0] == "application/gzip"
    assert seen["bodies"][0] == bundle.read_bytes()


def test_s3_upload_uses_prefix_and_endpoint(tmp_path: Path, monkeypatch):
    import boto3

    bundle = _snapshot(tmp_path / "dmarc-20260101-000000.db")
    seen: dict[str, object] = {}

    class FakeClient:
        def upload_file(self, path, bucket, key, ExtraArgs=None):
            seen.update(path=path, bucket=bucket, key=key, extra=ExtraArgs)

        def put_object(self, **kwargs):
            seen["sidecar"] = kwargs

        def head_object(self, **kwargs):
            return {
                "ContentLength": bundle.stat().st_size,
                "Metadata": {"sha256": bundle_sha256(bundle)},
            }

    monkeypatch.setattr(boto3, "client", lambda *args, **kwargs: (seen.update(client_kwargs=kwargs), FakeClient())[1])
    settings = get_settings()
    settings = settings.__class__(
        **{
            **settings.__dict__,
            "backup_s3_bucket": "backups",
            "backup_s3_prefix": "dmarcview/",
            "backup_s3_endpoint": "https://s3.example",
            "backup_s3_access_key": "key",
            "backup_s3_secret_key": "secret",
        }
    )
    result = upload_s3(settings, bundle)
    assert result["provider"] == "s3"
    assert seen["bucket"] == "backups"
    assert seen["key"] == f"dmarcview/{bundle.name}"
    assert seen["extra"]["ContentType"] == "application/gzip"
    assert seen["extra"]["Metadata"]["sha256"] == bundle_sha256(bundle)
    assert seen["sidecar"]["Key"] == f"dmarcview/{bundle.name}.sha256"
    assert seen["client_kwargs"]["endpoint_url"] == "https://s3.example"


def test_restore_accepts_bundle(tmp_path: Path):
    db = _snapshot(tmp_path / "dmarc-20260101-000000.db")
    bundle = create_bundle(db, None, tmp_path)
    target = tmp_path / "live.db"
    restore_database(bundle, db_path=target, safety=False)
    assert target.exists()
    connection = sqlite3.connect(target)
    try:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0015"
    finally:
        connection.close()


def test_fetch_latest_webdav_verifies_checksum(tmp_path: Path):
    bundle = create_bundle(_snapshot(tmp_path / "dmarc-20260101-000000.db"), None, tmp_path)
    digest = bundle_sha256(bundle)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PROPFIND":
            return httpx.Response(
                207,
                text=(
                    '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">'
                    f"<d:response><d:href>/backups/{bundle.name}</d:href></d:response>"
                    "</d:multistatus>"
                ),
            )
        if request.url.path.endswith(".sha256"):
            return httpx.Response(200, text=f"{digest}  {bundle.name}\n")
        return httpx.Response(200, content=bundle.read_bytes())

    settings = get_settings()
    settings = settings.__class__(
        **{
            **settings.__dict__,
            "backup_webdav_url": "https://dav.example/backups",
            "data_dir": tmp_path,
        }
    )
    result = asyncio.run(
        fetch_latest(
            settings,
            dest_dir=tmp_path / "downloaded",
            transport=httpx.MockTransport(handler),
        )
    )
    assert result["provider"] == "webdav"
    assert Path(result["path"]).name == bundle.name
    assert Path(result["path"]).read_bytes() == bundle.read_bytes()


def test_prune_bundles_keeps_newest(tmp_path: Path):
    names = ["dmarc-20260101-000000", "dmarc-20260102-000000", "dmarc-20260103-000000"]
    for name in names:
        (tmp_path / f"{name}.tar.gz").write_bytes(b"x")
    assert prune_bundles(tmp_path, 2) == 1
    assert sorted(path.name for path in tmp_path.glob("dmarc-*.tar.gz")) == [
        f"{names[1]}.tar.gz",
        f"{names[2]}.tar.gz",
    ]


def test_s3_list_download_and_target_test(tmp_path: Path, monkeypatch):
    import boto3

    bundle = create_bundle(_snapshot(tmp_path / "dmarc-20260101-000000.db"), None, tmp_path)
    digest = bundle_sha256(bundle)
    calls: list[tuple[str, dict]] = []

    class FakeClient:
        def list_objects_v2(self, **kwargs):
            calls.append(("list", kwargs))
            return {
                "Contents": [
                    {"Key": "dmarcview/dmarc-20260101-000000.tar.gz"},
                    {"Key": "dmarcview/dmarc-20260101-000000.tar.gz.sha256"},
                ]
            }

        def download_file(self, bucket, key, filename):
            Path(filename).write_bytes(bundle.read_bytes())

        def get_object(self, **kwargs):
            return {"Body": io.BytesIO(f"{digest}  {bundle.name}\n".encode())}

        def head_bucket(self, **kwargs):
            calls.append(("head_bucket", kwargs))

        def put_object(self, **kwargs):
            calls.append(("put", kwargs))

        def delete_object(self, **kwargs):
            calls.append(("delete", kwargs))

    monkeypatch.setattr(boto3, "client", lambda *args, **kwargs: FakeClient())
    settings = get_settings()
    settings = settings.__class__(
        **{
            **settings.__dict__,
            "backup_s3_bucket": "backups",
            "backup_s3_prefix": "dmarcview/",
            "data_dir": tmp_path,
        }
    )

    assert list_s3(settings) == [bundle.name]
    dest = tmp_path / "downloaded" / bundle.name
    download_s3(settings, bundle.name, dest)
    assert dest.read_bytes() == bundle.read_bytes()
    result = probe_s3(settings)
    assert result == {"provider": "s3", "ok": True}
    assert any(name == "head_bucket" for name, _ in calls)
    assert any(name == "put" for name, _ in calls)
    assert any(name == "delete" for name, _ in calls)
