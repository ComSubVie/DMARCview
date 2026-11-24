"""HTTP API tests: auth, dashboard maths, reports, TLS, upload."""

from __future__ import annotations

from fastapi.testclient import TestClient

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
