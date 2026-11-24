"""HTTP API tests: auth, dashboard maths, reports, TLS, upload."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app.models import Domain, Report, SourceRecord

from .conftest import sample


def upload_all(client: TestClient) -> dict:
    names = [
        "google-dmarc-tgm-2026-11-18.eml",
        "microsoft-dmarc-tgm-2026-11-19.eml",
        "google-dmarc-aeroclub-2026-11-19.eml",
        "google-tlsrpt-tgm-2026-11-18.eml",
        "microsoft-tlsrpt-tgm-2026-11-19.eml",
        "newsletter-noise.eml",
    ]
    files = [
        ("files", (name, sample(name), "message/rfc822"))
        for name in names
    ]
    response = client.post("/api/ingest/upload", files=files)
    assert response.status_code == 200, response.text
    return response.json()


def test_requires_authentication(client: TestClient):
    assert client.get("/api/dashboard").status_code == 401
    assert client.get("/api/reports").status_code == 401
    assert client.get("/api/domains").status_code == 401


def test_login_and_session(client: TestClient):
    assert client.get("/api/auth/me").json()["authenticated"] is False
    bad = client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert bad.status_code == 401
    good = client.post(
        "/api/auth/login", json={"username": "admin", "password": "test-password"}
    )
    assert good.status_code == 200
    assert client.get("/api/auth/me").json() == {"authenticated": True, "username": "admin"}
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").json()["authenticated"] is False


def test_security_headers_and_health(client: TestClient):
    health = client.get("/api/health")
    assert health.json()["ok"] is True
    page = client.get("/")
    assert page.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in page.headers["Content-Security-Policy"]


def test_cross_origin_post_is_blocked(client: TestClient):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "test-password"},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403


def test_upload_and_dashboard(auth_client: TestClient):
    result = upload_all(auth_client)
    assert result["reports"] == 3
    assert result["tls_reports"] == 2
    assert result["ignored"] == 1
    assert result["errors"] == []

    meta = auth_client.get("/api/meta").json()
    assert {item["name"] for item in meta["domains"]} == {"tgm.rocks", "aeroclub.example"}

    dashboard = auth_client.get(
        "/api/dashboard", params={"domain": "tgm.rocks", "days": 30}
    ).json()
    assert dashboard["kpis"]["messages"] == 17
    assert dashboard["kpis"]["aligned"] == 11
    assert dashboard["kpis"]["aligned_pct"] == 64.7
    assert dashboard["kpis"]["failed"] == 6
    assert dashboard["kpis"]["sources"] == 4
    assert dashboard["kpis"]["providers"] == 2
    assert dashboard["policy"]["p"] == "reject"
    assert dashboard["advice"]["label"] == "Fully enforced"
    assert dashboard["tls"]["sessions"] == 22

    countries = {item["code"]: item["messages"] for item in dashboard["countries"]}
    assert countries == {"DE": 11, "US": 6}

    sources = {item["ip"]: item for item in dashboard["sources"]}
    assert sources["62.116.130.25"]["dmarc"] == "pass"
    assert sources["62.116.130.25"]["messages"] == 11
    assert sources["209.85.220.41"]["spf"] == "pass"
    assert sources["209.85.220.41"]["dmarc"] == "fail"
    assert sources["40.92.19.44"]["dkim"] == "fail"

    unknown = auth_client.get("/api/dashboard", params={"domain": "missing.example"})
    assert unknown.status_code == 404


def test_reports_endpoints(auth_client: TestClient):
    upload_all(auth_client)
    listing = auth_client.get("/api/reports", params={"domain": "tgm.rocks"}).json()
    assert listing["total"] == 2
    report_id = listing["items"][0]["id"]

    detail = auth_client.get(f"/api/reports/{report_id}").json()
    assert detail["records"]
    assert detail["policy"]["p"] == "reject"
    assert detail["records"][0]["country"]["code"] in {"DE", "US"}

    raw = auth_client.get(f"/api/reports/{report_id}/raw")
    assert raw.status_code == 200
    assert raw.headers["content-type"].startswith("application/xml")
    assert b"<feedback" in raw.content
    assert "attachment" in raw.headers["content-disposition"]

    search = auth_client.get("/api/reports", params={"q": "outlook"}).json()
    assert search["total"] == 1

    assert auth_client.get("/api/reports/9999").status_code == 404


def test_tls_endpoints(auth_client: TestClient):
    upload_all(auth_client)
    tls = auth_client.get("/api/tls", params={"domain": "tgm.rocks"}).json()
    assert tls["kpis"]["sessions"] == 22
    assert tls["kpis"]["failure"] == 3
    assert tls["kpis"]["success_pct"] == 86.4
    assert tls["policies"][0]["host"] == "mail.tgm.rocks"
    assert {item["result_type"] for item in tls["failures"]} == {
        "certificate-expired",
        "starttls-not-supported",
    }
    assert tls["policy"]["mode"] == "enforce"

    listing = auth_client.get("/api/tls/reports").json()
    assert listing["total"] == 2
    detail = auth_client.get(f"/api/tls/reports/{listing['items'][0]['id']}").json()
    assert detail["failure_details"] or detail["failure"] == 0


def test_dashboard_report_gap(auth_client: TestClient):
    upload_all(auth_client)
    data = auth_client.get("/api/dashboard").json()
    gaps = {gap["domain"]: gap for gap in data["report_gaps"]}
    assert "tgm.rocks" in gaps
    assert gaps["tgm.rocks"]["hours"] > gaps["tgm.rocks"]["expected_hours"]


def test_dashboard_identities(auth_client: TestClient):
    upload_all(auth_client)
    data = auth_client.get("/api/dashboard").json()
    identities = data["identities"]
    assert identities["total"] >= 3
    assert sum(item["messages"] for item in identities["items"]) == data["kpis"]["messages"]
    tgm_items = [item for item in identities["items"] if item["label"] == "tgm.rocks"]
    assert sum(item["messages"] for item in tgm_items) >= 11
    assert sum(item["sources"] for item in tgm_items) >= 2
    assert all(0 <= item["aligned_pct"] <= 100 for item in identities["items"])
    assert "changes" in data and "chips" in data["changes"]


def test_dashboard_changes(auth_client: TestClient, session: Session):
    upload_all(auth_client)
    domain = session.exec(select(Domain).where(Domain.name == "tgm.rocks")).one()
    now = datetime.now(timezone.utc)
    begin = now - timedelta(days=45)
    report = Report(
        domain_id=domain.id,
        org_name="google.com",
        report_id="old-tgm-report",
        policy_domain="tgm.rocks",
        date_begin=begin,
        date_end=begin + timedelta(days=1),
        report_date=begin.date(),
        policy_p="reject",
        message_count=50,
        aligned_count=40,
        failed_count=10,
        record_count=1,
        source_count=1,
        raw_sha256=hashlib.sha256(b"old-tgm").hexdigest(),
        raw_xml=b"<feedback/>",
    )
    session.add(report)
    session.commit()
    session.refresh(report)
    session.add(
        SourceRecord(
            report_id=report.id,
            domain_id=domain.id,
            report_date=begin.date(),
            source_ip="203.0.113.9",
            message_count=50,
            dkim_pass=True,
            spf_pass=True,
            dkim_signed=True,
            dkim_auth_pass=True,
            spf_auth_pass=True,
            dkim_domains=["tgm.rocks"],
            dkim_selectors=["selector"],
            dkim_results=["pass"],
            spf_domains=["tgm.rocks"],
            spf_results=["pass"],
        )
    )
    session.commit()

    changes = auth_client.get("/api/dashboard?days=30").json()["changes"]
    assert changes["available"] is True
    assert {chip["key"] for chip in changes["chips"]} == {"messages", "aligned", "sources", "identities"}
    assert changes["chips"][0]["display"].endswith("%")


def test_domain_profile(auth_client: TestClient):
    upload_all(auth_client)
    updated = auth_client.put(
        "/api/domains/tgm.rocks/profile",
        json={"display_name": "TGM Rocks", "notes": "owner: ops"},
    )
    assert updated.status_code == 200
    assert updated.json()["display_name"] == "TGM Rocks"
    profile = auth_client.get("/api/domains/tgm.rocks/profile").json()
    assert profile["notes"] == "owner: ops"
    meta = auth_client.get("/api/meta").json()
    entry = next(item for item in meta["domains"] if item["name"] == "tgm.rocks")
    assert entry["display_name"] == "TGM Rocks"


def test_dashboard_fleet(auth_client: TestClient):
    upload_all(auth_client)
    data = auth_client.get("/api/dashboard").json()
    fleet = data["fleet"]
    assert len(fleet) >= 2
    tgm = next(item for item in fleet if item["domain"] == "tgm.rocks")
    assert tgm["messages"] >= 11
    assert 0 <= tgm["aligned_pct"] <= 100
    assert len(tgm["sparkline"]) == 14
    assert "tls_pct" in tgm and "health" in tgm

    single = auth_client.get("/api/dashboard?domain=tgm.rocks").json()
    assert single["fleet"] == []


def test_dashboard_coverage(auth_client: TestClient):
    upload_all(auth_client)
    data = auth_client.get("/api/dashboard?domain=tgm.rocks").json()
    coverage = data["coverage_detail"]
    orgs = {item["org"] for item in coverage["reporters"]}
    assert any("google" in org for org in orgs)
    assert any("microsoft" in org for org in orgs)
    assert coverage["pct_timeline"]
    assert coverage["pct_latest"] == 100
    assert coverage["subdomains"] == []

    all_domains = auth_client.get("/api/dashboard").json()["coverage_detail"]
    assert all_domains["reporters"]
    assert all_domains["subdomains"] == []
    assert all_domains["pct_timeline"] == []


def test_dashboard_all_domains(auth_client: TestClient):
    upload_all(auth_client)
    dashboard = auth_client.get("/api/dashboard").json()
    assert dashboard["kpis"]["messages"] == 22
    assert dashboard["domain"] is None
    assert len(dashboard["policy_overview"]) == 2
    assert dashboard["policy"] is None


def test_duplicate_upload(auth_client: TestClient):
    upload_all(auth_client)
    again = upload_all(auth_client)
    assert again["reports"] == 0
    assert again["tls_reports"] == 0
    assert again["duplicates"] == 6  # 5 reports + the ignored newsletter
