"""Parser and MIME-shape tests against the hand-written fixtures."""

from __future__ import annotations

import base64
import gzip
import io
import json
import zipfile

import pytest

from app.ingest.dmarc import DmarcParseError, parse_dmarc
from app.ingest.mime import MimeParseError, extract_payloads
from app.ingest.tlsrpt import TlsParseError, parse_tlsrpt

from .conftest import sample


def payload_for(name: str):
    parsed, payloads = extract_payloads(sample(name))
    assert payloads, f"no payload extracted from {name}"
    return payloads[0]


def test_google_zip_dmarc_gzip_shape():
    payload = payload_for("google-dmarc-tgm-2026-11-18.eml")
    assert payload.kind == "dmarc"
    report = parse_dmarc(payload.data)
    assert report.org_name == "google.com"
    assert report.policy_domain == "tgm.rocks"
    assert report.report_id == "tgm-2026-11-18-google"
    assert report.message_count == 8
    assert report.aligned_count == 6
    assert report.failed_count == 2
    assert report.source_count == 2
    assert report.policy_p == "reject"
    assert report.policy_adkim == "r"
    assert report.date_begin.isoformat().startswith("2026-11-18T00:00:00")
    # Record B was forwarded: raw SPF passed for example.net but was not aligned.
    forwarded = next(record for record in report.records if record.source_ip == "209.85.220.41")
    assert forwarded.dkim_pass is False
    assert forwarded.spf_pass is False
    assert forwarded.reason_type == "forwarded"
    assert set(forwarded.dkim_domains) == {"example.net", "tgm.rocks"}
    assert forwarded.spf_results == ["pass"]


def test_microsoft_gzip_dmarc_namespace_v1():
    payload = payload_for("microsoft-dmarc-tgm-2026-11-19.eml")
    report = parse_dmarc(payload.data)
    assert report.message_count == 9
    assert report.aligned_count == 5
    assert len(report.records) == 3
    rejected = [record for record in report.records if record.disposition == "reject"]
    assert len(rejected) == 2
    assert sum(record.count for record in rejected) == 4


def test_inline_body_dmarc_without_namespace():
    parsed, payloads = extract_payloads(sample("google-dmarc-aeroclub-2026-11-19.eml"))
    assert len(payloads) == 1
    assert payloads[0].kind == "dmarc"
    report = parse_dmarc(payloads[0].data)
    assert report.policy_domain == "aeroclub.example"
    assert report.message_count == 5
    assert report.policy_p == "none"


def test_tlsrpt_gzip_attachment():
    payload = payload_for("google-tlsrpt-tgm-2026-11-18.eml")
    assert payload.kind == "tlsrpt"
    report = parse_tlsrpt(payload.data)
    assert report.total_success == 12
    assert report.total_failure == 0
    assert report.policy_mode == "enforce"
    assert report.max_age == 604800
    assert report.mx_hosts == ["mail.tgm.rocks"]


def test_tlsrpt_json_attachment_with_failures():
    payload = payload_for("microsoft-tlsrpt-tgm-2026-11-19.eml")
    report = parse_tlsrpt(payload.data)
    assert report.policy_type == "sts"
    assert report.total_success == 7
    assert report.total_failure == 3
    failures = [failure for policy in report.policies for failure in policy.failures]
    assert {failure.result_type for failure in failures} == {
        "certificate-expired",
        "starttls-not-supported",
    }
    assert sum(failure.failed_count for failure in failures) == 3


def test_newsletter_is_ignored():
    parsed, payloads = extract_payloads(sample("newsletter-noise.eml"))
    assert payloads == []


def test_zip_with_multiple_documents():
    xml = b"""<?xml version="1.0"?><feedback><report_metadata><org_name>a.example</org_name>
    <report_id>r1</report_id><date_range><begin>1794960000</begin><end>1795046400</end></date_range>
    </report_metadata><policy_published><domain>tgm.rocks</domain><p>none</p></policy_published>
    <record><row><source_ip>192.0.2.1</source_ip><count>1</count><policy_evaluated>
    <disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    </record></feedback>"""
    xml2 = xml.replace(b"r1", b"r2").replace(b"192.0.2.1", b"192.0.2.2")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("one.xml", xml)
        archive.writestr("two.xml", xml2)
        archive.writestr("__MACOSX/._one.xml", b"junk")

    raw = (
        b"From: reports@example.com\r\n"
        b"To: dmarc@tgm.rocks\r\n"
        b"Subject: reports\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        b"--b\r\n"
        b"Content-Type: application/zip\r\n"
        b'Content-Disposition: attachment; filename="reports.zip"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        + base64.encodebytes(buffer.getvalue())
        + b"\r\n--b--\r\n"
    )
    parsed, payloads = extract_payloads(raw)
    assert len(payloads) == 2
    assert {parse_dmarc(item.data).report_id for item in payloads} == {"r1", "r2"}


def test_gzip_bomb_limit(monkeypatch):
    from app.ingest import mime

    monkeypatch.setattr(mime, "MAX_PAYLOAD_BYTES", 512)
    raw = gzip.compress(b"<feedback>" + b"a" * 4096)
    with pytest.raises(MimeParseError):
        mime._unwrap(raw, "big.gz", "application/gzip")


def test_malformed_xml_raises():
    with pytest.raises(DmarcParseError):
        parse_dmarc(b"<feedback><oops>")


def test_tlsrpt_draft_keys_and_nested_summary():
    document = {
        "organization-name": "Example",
        "report-id": "abc",
        "date-range": {"start-datetime": "2026-11-18T00:00:00Z", "end-datetime": "2026-11-19T00:00:00Z"},
        "policies": [
            {
                "policy": {"policy-type": "tlsa", "policy-domain": "tgm.rocks", "mx-host": "mail.tgm.rocks"},
                "summary": {
                    "total-success-session-count": 3,
                    "total-failure-session-count": 2,
                    "failure-details": [
                        {
                            "result-type": "starttls-not-supported",
                            "sending-mta-ip": "192.0.2.5",
                            "receiving-mx-hostname": "mail.tgm.rocks",
                            "failed-session-count": 2,
                        }
                    ],
                },
            }
        ],
    }
    report = parse_tlsrpt(json.dumps(document).encode())
    assert report.total_success == 3
    assert report.total_failure == 2
    assert report.mx_hosts == ["mail.tgm.rocks"]
    assert report.policies[0].failures[0].receiving_mx == "mail.tgm.rocks"


def test_tlsrpt_invalid_json():
    with pytest.raises(TlsParseError):
        parse_tlsrpt(b"{not json")


def test_epoch_milliseconds_supported():
    xml = b"""<feedback><report_metadata><org_name>x</org_name><report_id>1</report_id>
    <date_range><begin>1794960000000</begin><end>1795046400000</end></date_range></report_metadata>
    <policy_published><domain>tgm.rocks</domain><p>none</p></policy_published>
    <record><row><source_ip>192.0.2.9</source_ip><count>1</count></row></record></feedback>"""
    report = parse_dmarc(xml)
    assert report.date_begin.year == 2026


def test_dmarcbis_policy_fields():
    xml = b"""<feedback>
      <report_metadata>
        <org_name>example.org</org_name><email>dmarc@example.org</email>
        <error>Invalid rua destination</error>
        <report_id>dmarcbis-1</report_id>
        <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
      </report_metadata>
      <policy_published>
        <domain>example.com</domain><p>reject</p><sp>quarantine</sp>
        <np>none</np><testing>y</testing>
        <discovery_method>treewalk</discovery_method>
      </policy_published>
      <record>
        <row><source_ip>192.0.2.1</source_ip><count>2</count>
          <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
        </row>
        <identifiers><header_from>example.com</header_from></identifiers>
        <auth_results>
          <dkim><domain>example.com</domain><result>pass</result></dkim>
          <spf><domain>example.com</domain><result>pass</result></spf>
        </auth_results>
      </record>
    </feedback>"""
    report = parse_dmarc(xml)
    assert report.policy_np == "none"
    assert report.policy_testing == "y"
    assert report.policy_discovery == "treewalk"
    assert report.report_errors == ["Invalid rua destination"]


def test_tlsrpt_extracts_mx_from_policy_string():
    document = {
        "organization-name": "Example",
        "report-id": "policy-string-mx",
        "date-range": {
            "start-datetime": "2026-11-18T00:00:00Z",
            "end-datetime": "2026-11-19T00:00:00Z",
        },
        "policies": [
            {
                "policy": {
                    "policy-type": "sts",
                    "policy-domain": "tgm.rocks",
                    "policy-string": [
                        "version: STSv1",
                        "mode: enforce",
                        "mx: mail.tgm.rocks",
                        "max_age: 604800",
                    ],
                },
                "summary": {"total-successful-session-count": 8},
            }
        ],
    }
    report = parse_tlsrpt(json.dumps(document).encode())
    assert report.mx_hosts == ["mail.tgm.rocks"]
    assert report.policies[0].mx_hosts == ["mail.tgm.rocks"]
