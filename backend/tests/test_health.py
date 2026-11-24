"""Health checks, transport probes and their API surface."""

from __future__ import annotations

import base64
import hashlib
import socket
import ssl
import threading
from datetime import date, datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlmodel import Session

from app.health.checks import dkim_key_info, evaluate_spf, parse_tags
from app.health.dns import BaseDnsClient, Lookup
from app.health.engine import run_health
from app.health.http import BaseFetcher, FetchResult
from app.health.probe import (
    ProbeSpec,
    _hostname_matches,
    _inspect,
    probe_sync,
    parse_target,
    targets_for,
    verification_context,
)
from app.health.selectors import build_candidates
from app.health.service import discover_dkim_selectors, store_report
from app.health.types import HealthReport, Status
from app.models import Domain, Report, SourceRecord

from .conftest import sample


class FakeDns(BaseDnsClient):
    def __init__(self, records: dict[tuple[str, str], list[str]], ad: bool = False, errors=None):
        self.records = {(name.lower().rstrip("."), rtype): values for (name, rtype), values in records.items()}
        self.ad = ad
        self.errors = errors or {}

    async def lookup(self, name, rtype):
        key = (name.lower().rstrip("."), rtype)
        if key in self.errors:
            return Lookup(error=self.errors[key])
        values = self.records.get(key)
        if values is None:
            return Lookup(exists=False, ad=self.ad)
        return Lookup(values=tuple(values), exists=True, ad=self.ad)


class FakeFetcher(BaseFetcher):
    def __init__(self, responses: dict[str, FetchResult]):
        self.responses = responses

    async def get(self, url, *, max_bytes=131072, timeout=6.0):
        return self.responses.get(url, FetchResult(status=404, error="not found"))


def rsa_dkim_key(bits: int = 2048) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode()


def full_records(selector: str = "selector1", bits: int = 2048):
    policy = b"version: STSv1\nmode: enforce\nmx: mail.tgm.rocks\nmax_age: 604800\n"
    policy_id = hashlib.sha256(policy).hexdigest()
    records = {
        ("_dmarc.tgm.rocks", "TXT"): ["v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@tgm.rocks"],
        ("tgm.rocks", "TXT"): ["v=spf1 include:_spf.example.net -all"],
        ("_spf.example.net", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        (f"{selector}._domainkey.tgm.rocks", "TXT"): [f"v=DKIM1; k=rsa; p={rsa_dkim_key(bits)}"],
        ("tgm.rocks", "MX"): ["10 mail.tgm.rocks"],
        ("mail.tgm.rocks", "A"): ["192.0.2.10"],
        ("_mta-sts.tgm.rocks", "TXT"): [f"v=STSv1; id={policy_id}"],
        ("_smtp._tls.tgm.rocks", "TXT"): ["v=TLSRPTv1; rua=mailto:tlsrpt@tgm.rocks"],
        ("tgm.rocks", "DS"): ["12345 13 2 ABCDEF"],
        ("default._bimi.tgm.rocks", "TXT"): [
            "v=BIMI1; l=https://tgm.rocks/logo.svg; a=https://tgm.rocks/vmc.pem"
        ],
    }
    fetcher = FakeFetcher(
        {
            "https://mta-sts.tgm.rocks/.well-known/mta-sts.txt": FetchResult(
                status=200, body=policy, content_type="text/plain"
            ),
            "https://tgm.rocks/logo.svg": FetchResult(
                status=200, body=b"<svg xmlns='http://www.w3.org/2000/svg'/>", content_type="image/svg+xml"
            ),
        }
    )
    return records, fetcher


@pytest.mark.asyncio
async def test_fully_configured_domain_passes():
    records, fetcher = full_records()
    report = await run_health(
        "tgm.rocks",
        selectors=["selector1"],
        reported_policy={"p": "reject"},
        dns=FakeDns(records, ad=True),
        http=fetcher,
    )
    by_key = {result.key: result for result in report.results}
    assert report.overall == "pass"
    assert report.score == 1.0
    assert report.core_total == 4
    assert by_key["dmarc"].status is Status.PASS
    assert by_key["spf"].status is Status.PASS
    assert by_key["dkim"].status is Status.PASS
    assert by_key["mx"].status is Status.PASS
    assert by_key["mta_sts"].status is Status.PASS
    assert by_key["tls_rpt"].status is Status.PASS
    assert by_key["dnssec"].status is Status.PASS
    assert by_key["bimi"].status is Status.PASS


@pytest.mark.asyncio
async def test_missing_dmarc_fails():
    records, fetcher = full_records()
    records.pop(("_dmarc.tgm.rocks", "TXT"))
    report = await run_health("tgm.rocks", selectors=["selector1"], dns=FakeDns(records), http=fetcher)
    dmarc = next(result for result in report.results if result.key == "dmarc")
    assert dmarc.status is Status.FAIL
    assert report.overall == "fail"
    assert dmarc.remediation


@pytest.mark.asyncio
async def test_p_none_warns_but_is_not_a_failure():
    records, fetcher = full_records()
    records[("_dmarc.tgm.rocks", "TXT")] = ["v=DMARC1; p=none; rua=mailto:dmarc@tgm.rocks"]
    report = await run_health("tgm.rocks", selectors=["selector1"], dns=FakeDns(records), http=fetcher)
    by_key = {result.key: result for result in report.results}
    assert by_key["dmarc"].status is Status.WARN
    assert report.overall == "warn"


@pytest.mark.asyncio
async def test_dmarc_drift_against_reports_is_flagged():
    records, fetcher = full_records()
    records[("_dmarc.tgm.rocks", "TXT")] = ["v=DMARC1; p=none; rua=mailto:dmarc@tgm.rocks"]
    report = await run_health(
        "tgm.rocks", selectors=["selector1"], reported_policy={"p": "reject"},
        dns=FakeDns(records), http=fetcher,
    )
    dmarc = next(result for result in report.results if result.key == "dmarc")
    assert any("Receivers report p=reject" in detail for detail in dmarc.details)


@pytest.mark.asyncio
async def test_spf_lookup_limit_fails():
    records, fetcher = full_records()
    records[("tgm.rocks", "TXT")] = ["v=spf1 include:a0.example -all"]
    for index in range(12):
        nxt = f"include:a{index + 1}.example" if index < 11 else "-all"
        records[(f"a{index}.example", "TXT")] = [f"v=spf1 {nxt}"]
    report = await run_health("tgm.rocks", selectors=["selector1"], dns=FakeDns(records), http=fetcher)
    spf = next(result for result in report.results if result.key == "spf")
    assert spf.status is Status.FAIL
    assert "DNS lookups" in spf.summary


@pytest.mark.asyncio
async def test_spf_plus_all_warns():
    records, fetcher = full_records()
    records[("tgm.rocks", "TXT")] = ["v=spf1 ip4:192.0.2.1 +all"]
    report = await run_health("tgm.rocks", selectors=["selector1"], dns=FakeDns(records), http=fetcher)
    spf = next(result for result in report.results if result.key == "spf")
    assert spf.status is Status.WARN


@pytest.mark.asyncio
async def test_spf_include_loop_is_reported():
    records, fetcher = full_records()
    records[("tgm.rocks", "TXT")] = ["v=spf1 include:loop.example -all"]
    records[("loop.example", "TXT")] = ["v=spf1 include:tgm.rocks -all"]
    ctx_dns = FakeDns(records)
    from app.health.checks import CheckContext

    evaluation = await evaluate_spf(
        CheckContext(domain="tgm.rocks", dns=ctx_dns, http=fetcher), "tgm.rocks"
    )
    assert any("loop" in error.lower() for error in evaluation.errors)


@pytest.mark.asyncio
async def test_dkim_missing_key_fails_and_weak_key_warns():
    records, fetcher = full_records()
    records.pop(("selector1._domainkey.tgm.rocks", "TXT"))
    report = await run_health("tgm.rocks", selectors=["selector1"], dns=FakeDns(records), http=fetcher)
    dkim = next(result for result in report.results if result.key == "dkim")
    assert dkim.status is Status.FAIL

    weak_records, weak_fetcher = full_records(bits=1024)
    report = await run_health(
        "tgm.rocks", selectors=["selector1"], dns=FakeDns(weak_records), http=weak_fetcher
    )
    dkim = next(result for result in report.results if result.key == "dkim")
    assert dkim.status is Status.WARN
    assert "1024" in dkim.summary


@pytest.mark.asyncio
async def test_mta_sts_testing_mode_warns():
    records, fetcher = full_records()
    policy = b"version: STSv1\nmode: testing\nmx: mail.tgm.rocks\nmax_age: 604800\n"
    fetcher.responses["https://mta-sts.tgm.rocks/.well-known/mta-sts.txt"] = FetchResult(
        status=200, body=policy, content_type="text/plain"
    )
    report = await run_health("tgm.rocks", selectors=["selector1"], dns=FakeDns(records), http=fetcher)
    mta = next(result for result in report.results if result.key == "mta_sts")
    assert mta.status is Status.WARN
    assert "not enforced" in mta.summary


@pytest.mark.asyncio
async def test_mta_sts_missing_id_fails():
    records, fetcher = full_records()
    records[("_mta-sts.tgm.rocks", "TXT")] = ["v=STSv1"]
    report = await run_health("tgm.rocks", selectors=["selector1"], dns=FakeDns(records), http=fetcher)
    mta = next(result for result in report.results if result.key == "mta_sts")
    assert mta.status is Status.FAIL
    assert "no id=" in mta.summary


@pytest.mark.asyncio
async def test_dns_failure_is_unknown_not_fail():
    errors = {}
    for key in [
        ("_dmarc.tgm.rocks", "TXT"),
        ("tgm.rocks", "TXT"),
        ("selector1._domainkey.tgm.rocks", "TXT"),
        ("tgm.rocks", "MX"),
        ("_mta-sts.tgm.rocks", "TXT"),
        ("_smtp._tls.tgm.rocks", "TXT"),
        ("tgm.rocks", "DS"),
        ("default._bimi.tgm.rocks", "TXT"),
    ]:
        errors[key] = "DNS timeout"
    report = await run_health(
        "tgm.rocks", selectors=["selector1"], dns=FakeDns({}, errors=errors), http=FakeFetcher({})
    )
    assert report.overall == "unknown"
    assert all(result.status is Status.UNKNOWN for result in report.results if result.core)


def test_selector_candidates_merge_and_rotate():
    candidates = build_candidates(
        ["default"],
        "tgm.rocks",
        [("tgm.rocks", "v1-ed25519-20260101"), ("tgm.rocks", "default")],
        date(2026, 11, 24),
    )
    values = {(item.selector, item.source) for item in candidates}
    assert ("default", "configured") in values
    assert ("v1-ed25519-20260101", "report") in values
    assert ("v1-ed25519-20261124", "rotation") in values
    assert ("v1-ed25519-20261123", "rotation") in values
    # "default" is both configured and seen in a report: only one candidate.
    assert sum(1 for item in candidates if item.selector == "default") == 1


@pytest.mark.asyncio
async def test_dkim_uses_selector_discovered_from_reports():
    records, fetcher = full_records(selector="v1-ed25519-20260101", bits=2048)
    report = await run_health(
        "tgm.rocks",
        selectors=[],
        discovered_selectors=[("tgm.rocks", "v1-ed25519-20260101")],
        dns=FakeDns(records),
        http=fetcher,
    )
    dkim = next(result for result in report.results if result.key == "dkim")
    assert dkim.status is Status.PASS
    assert "from reports" in dkim.details[0]
    assert "v1-ed25519-20260101" in dkim.summary


def test_discover_selectors_from_reports(session):
    domain = Domain(name="tgm.rocks", display_name="tgm.rocks")
    session.add(domain)
    session.commit()
    session.refresh(domain)
    report = Report(
        domain_id=domain.id,
        org_name="google.com",
        report_id="discovery-1",
        policy_domain="tgm.rocks",
        date_begin=datetime.now(timezone.utc) - timedelta(days=1),
        date_end=datetime.now(timezone.utc),
        report_date=date.today() - timedelta(days=1),
        message_count=2,
        aligned_count=2,
        failed_count=0,
        record_count=2,
        source_count=1,
        raw_sha256="a" * 64,
        raw_xml=b"<feedback/>",
    )
    session.add(report)
    session.commit()
    session.refresh(report)

    def record(domain_name, selector, ip):
        return SourceRecord(
            report_id=report.id,
            domain_id=domain.id,
            report_date=report.report_date,
            source_ip=ip,
            message_count=1,
            dkim_domains=[domain_name],
            dkim_selectors=[selector],
        )

    session.add(record("tgm.rocks", "v1-ed25519-20260101", "192.0.2.1"))
    session.add(record("tgm.rocks", "v1-ed25519-20260101", "192.0.2.2"))
    session.add(record("mail.tgm.rocks", "v1-rsa-20260101", "192.0.2.3"))
    session.add(record("evil.example", "spoofed", "192.0.2.4"))
    session.commit()

    discovered = discover_dkim_selectors(session, domain)
    assert discovered[0] == ("tgm.rocks", "v1-ed25519-20260101")
    pairs = set(discovered)
    assert ("mail.tgm.rocks", "v1-rsa-20260101") in pairs
    assert ("evil.example", "spoofed") not in pairs


def test_parse_tags_and_dkim_key_info():
    tags = parse_tags("v=DKIM1; k=rsa; p=abc; t=y")
    assert tags == {"v": "DKIM1", "k": "rsa", "p": "abc", "t": "y"}
    key_type, bits = dkim_key_info({"k": "rsa", "p": rsa_dkim_key(2048)})
    assert key_type == "rsa" and bits == 2048


def test_parse_target_and_targets_for():
    assert parse_target("mail.tgm.rocks") == ProbeSpec("mail.tgm.rocks", 25, "smtp")
    assert parse_target("mail.tgm.rocks:465") == ProbeSpec("mail.tgm.rocks", 465, "tls")
    assert parse_target("mail.tgm.rocks:25:tls") == ProbeSpec("mail.tgm.rocks", 25, "tls")
    assert parse_target(":25") is None
    targets = targets_for(
        ["10 mail.tgm.rocks", "20 mail2.tgm.rocks"],
        ["mail.tgm.rocks:465", "imap.tgm.rocks:993", "mail.tgm.rocks:25"],
    )
    assert [(spec.host, spec.port) for spec in targets] == [
        ("mail.tgm.rocks", 25),
        ("mail2.tgm.rocks", 25),
        ("mail.tgm.rocks", 465),
        ("imap.tgm.rocks", 993),
    ]


def test_hostname_matching():
    assert _hostname_matches("mail.tgm.rocks", ["mail.tgm.rocks"]) is True
    assert _hostname_matches("mail.tgm.rocks", ["*.tgm.rocks"]) is True
    assert _hostname_matches("a.b.tgm.rocks", ["*.tgm.rocks"]) is False
    assert _hostname_matches("mail.example.com", ["mail.tgm.rocks"]) is False


def make_certificate(tmp_path, hostname="localhost", days=30, bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert, cert_path, key_path


def test_verification_context_is_strict():
    context = verification_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_certificate_inspection(tmp_path):
    cert, _, _ = make_certificate(tmp_path, "mail.tgm.rocks", days=40)
    info = _inspect(cert, "mail.tgm.rocks")
    assert info["hostname_match"] is True
    assert info["days_left"] in {39, 40}
    assert info["key_bits"] == 2048


def test_probe_against_local_tls_server(tmp_path):
    _cert, cert_path, key_path = make_certificate(tmp_path, "localhost", days=30)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    server.settimeout(5)

    def serve():
        # Two connections: the first verified handshake fails (self-signed),
        # the client then reconnects without verification to inspect the cert.
        for _ in range(2):
            try:
                connection, _ = server.accept()
                with context.wrap_socket(connection, server_side=True) as tls:
                    tls.recv(64)
            except Exception:  # noqa: BLE001 - the client is expected to hang up
                continue
        server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    outcome = probe_sync(ProbeSpec("127.0.0.1", port, "tls"), timeout=5)
    thread.join(timeout=5)

    # Self-signed: the chain must be reported as invalid, but the certificate
    # itself must still be inspected (days left, subject).
    assert outcome.status == "fail"
    assert "verification failed" in (outcome.error or "")
    assert outcome.days_left is not None and outcome.days_left <= 30
    assert outcome.cert_subject


@pytest.mark.asyncio
async def test_health_persists_and_serialises(session: Session, monkeypatch):
    domain = Domain(name="tgm.rocks", display_name="tgm.rocks")
    session.add(domain)
    session.commit()
    session.refresh(domain)

    report = HealthReport(
        domain="tgm.rocks",
        checked_at=datetime.now(timezone.utc),
        overall="pass",
        score=1.0,
        core_passed=4,
        core_total=4,
        results=[],
    )
    from app.health.service import health_payload, latest_snapshot, serialise_snapshot

    snapshot = store_report(session, domain.id, report)
    assert serialise_snapshot(snapshot)["overall"] == "pass"
    assert latest_snapshot(session, domain.id) is not None
    assert health_payload(session, domain)["checked"] is True


@pytest.mark.asyncio
async def test_api_run_health(auth_client, session: Session, monkeypatch):
    from app.health.types import CheckResult

    domain = Domain(name="tgm.rocks", display_name="tgm.rocks")
    session.add(domain)
    session.commit()

    async def fake_run(
        domain_name,
        *,
        selectors,
        reported_policy=None,
        dns=None,
        http=None,
        http_timeout=6.0,
        discovered_selectors=None,
    ):
        return HealthReport(
            domain=domain_name,
            checked_at=datetime.now(timezone.utc),
            overall="warn",
            score=0.75,
            core_passed=3,
            core_total=4,
            results=[
                CheckResult(
                    key="dmarc",
                    label="DMARC",
                    status=Status.PASS,
                    summary="p=reject",
                    core=True,
                )
            ],
            duration_ms=12,
        )

    async def fake_probes(*args, **kwargs):
        return []

    monkeypatch.setattr("app.health.service.run_health", fake_run)
    monkeypatch.setattr("app.routers.health.run_and_store_probes", fake_probes)

    empty = auth_client.get("/api/domain-health", params={"domain": "tgm.rocks"}).json()
    assert empty["checked"] is False
    assert empty["overall"] == "unknown"

    run = auth_client.post("/api/domain-health/run", params={"domain": "tgm.rocks"})
    assert run.status_code == 200, run.text
    payload = run.json()
    assert payload["overall"] == "warn"
    assert payload["results"][0]["key"] == "dmarc"
    assert payload["settings"]["dkim_selectors"]

    fleet = auth_client.get("/api/domain-health/fleet").json()
    assert fleet["items"][0]["domain"] == "tgm.rocks"
    assert fleet["items"][0]["overall"] == "warn"

    history = auth_client.get("/api/domain-health/history", params={"domain": "tgm.rocks"}).json()
    assert history["items"]


def test_discovered_selectors_in_health_payload(auth_client):
    for name in ["google-dmarc-tgm-2026-11-18.eml", "microsoft-dmarc-tgm-2026-11-19.eml"]:
        auth_client.post(
            "/api/ingest/upload",
            files=[("files", (name, sample(name), "message/rfc822"))],
        )
    payload = auth_client.get("/api/domain-health", params={"domain": "tgm.rocks"}).json()
    assert {"domain": "tgm.rocks", "selector": "stalwart"} in payload["dkim_discovered"]


def test_settings_roundtrip(auth_client, session: Session):
    domain = Domain(name="aeroclub.example", display_name="aeroclub.example")
    session.add(domain)
    session.commit()

    initial = auth_client.get("/api/domains/aeroclub.example/settings").json()
    assert "default" in initial["dkim_selectors"]

    updated = auth_client.put(
        "/api/domains/aeroclub.example/settings",
        json={
            "dkim_selectors": ["mail", "selector1", "mail"],
            "probe_targets": ["mail.aeroclub.example:993"],
            "expected_report_hours": 72,
        },
    )
    assert updated.status_code == 200, updated.text
    body = updated.json()
    assert body["dkim_selectors"] == ["mail", "selector1"]
    assert body["probe_targets"] == ["mail.aeroclub.example:993"]
    assert body["expected_report_hours"] == 72


def test_storage_and_jobs_endpoints(auth_client, session: Session):
    domain = Domain(name="tgm.rocks", display_name="tgm.rocks")
    session.add(domain)
    session.commit()
    from app.ingest.service import ingest_raw_email

    ingest_raw_email(
        session,
        sample("google-dmarc-tgm-2026-11-18.eml"),
        source="test",
        source_key="health-storage",
    )

    storage = auth_client.get("/api/storage").json()
    assert storage["reports"] == 1
    assert storage["raw_bytes"] > 0

    jobs = auth_client.get("/api/jobs").json()
    assert {item["name"] for item in jobs["items"]} == {
        "health_checks",
        "transport_probes",
        "ptr_enrichment",
    }


def test_health_requires_auth(client):
    assert client.get("/api/domain-health", params={"domain": "tgm.rocks"}).status_code == 401
    assert client.get("/api/domain-health/fleet").status_code == 401
    assert client.get("/api/storage").status_code == 401
