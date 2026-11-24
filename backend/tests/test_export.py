"""Export endpoints: CSV, JSON and the capped raw ZIP."""

from __future__ import annotations

import csv
import io
import zipfile

from fastapi.testclient import TestClient

from .test_api import upload_all


def test_reports_csv_and_json(auth_client: TestClient):
    upload_all(auth_client)
    response = auth_client.get("/api/export/reports.csv?domain=tgm.rocks&days=30")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert rows
    assert {row["domain"] for row in rows} == {"tgm.rocks"}
    assert any(row["report_id"] == "tgm-2026-11-19-outlook" for row in rows)

    payload = auth_client.get("/api/export/reports.json?domain=tgm.rocks&days=30").json()
    assert payload["count"] == len(rows)
    assert payload["items"][0]["domain"] == "tgm.rocks"
    assert payload["items"][0]["messages"] > 0


def test_sources_and_tls_csv(auth_client: TestClient):
    upload_all(auth_client)
    sources = auth_client.get("/api/export/sources.csv?domain=tgm.rocks&days=30")
    assert sources.status_code == 200
    source_rows = list(csv.DictReader(io.StringIO(sources.text)))
    assert source_rows
    assert all(row["domain"] == "tgm.rocks" for row in source_rows)
    assert any(row["source_ip"] == "62.116.130.25" for row in source_rows)

    tls = auth_client.get("/api/export/tls.csv?domain=tgm.rocks&days=30")
    assert tls.status_code == 200
    tls_rows = list(csv.DictReader(io.StringIO(tls.text)))
    assert tls_rows
    assert all(row["domain"] == "tgm.rocks" for row in tls_rows)
    assert int(tls_rows[0]["success"]) + int(tls_rows[0]["failure"]) > 0


def test_raw_zip(auth_client: TestClient):
    upload_all(auth_client)
    response = auth_client.get("/api/export/raw.zip?domain=tgm.rocks&days=30")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        names = archive.namelist()
        dmarc = [name for name in names if name.startswith("dmarc/")]
        tls = [name for name in names if name.startswith("tls/")]
        assert dmarc and tls
        assert archive.read(dmarc[0]).startswith(b"<")


def test_export_requires_auth(client: TestClient):
    assert client.get("/api/export/reports.csv").status_code == 401
    assert client.get("/api/export/raw.zip").status_code == 401
