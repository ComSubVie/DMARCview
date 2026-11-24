"""Generate a realistic 30-day demo dataset.

This is *only* for local previews and screenshots — the production app never
runs it. Point it at a throwaway database:

    DATABASE_URL=sqlite:///data/demo.db python scripts/demo_seed.py

Existing report days are left untouched, so the real fixtures in ``samples/``
can be imported first.
"""

from __future__ import annotations

import math
import random
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from sqlmodel import Session, select  # noqa: E402

from app.db import get_engine, init_db  # noqa: E402
from app.geoip import get_geo_resolver  # noqa: E402
from app.models import (  # noqa: E402
    Domain,
    DomainHealthSnapshot,
    Report,
    SourceRecord,
    TlsFailure,
    TlsPolicy,
    TlsReport,
    TransportProbe,
)

random.seed(20261124)
TODAY = date(2026, 11, 24)
DAYS = 30

DOMAINS = {
    "tgm.rocks": {
        "policy": ("reject", "reject"),
        "reporters": ["google.com", "microsoft.com"],
        "verified_ip": "62.116.130.25",
        "noisy": [
            ("209.85.220.41", 2),
            ("159.135.224.17", 3),
        ],
    },
    "aeroclub.example": {
        "policy": ("none", "none"),
        "reporters": ["google.com"],
        "verified_ip": "62.116.130.25",
        "noisy": [("185.199.108.153", 1)],
    },
    "nightowl.example": {
        "policy": ("quarantine", "quarantine"),
        "reporters": ["yahoo.com"],
        "verified_ip": "62.116.130.25",
        "noisy": [],
    },
}

COUNTRY_FALLBACK = {
    "62.116.130.25": ("DE", "Germany"),
    "209.85.220.41": ("US", "United States"),
    "159.135.224.17": ("US", "United States"),
    "185.199.108.153": ("US", "United States"),
    "40.92.19.44": ("US", "United States"),
    "91.198.174.192": ("NL", "Netherlands"),
}


def dmarc_xml(policy_domain: str, org: str, report_id: str, start: datetime, end: datetime,
              policy: tuple[str, str], records: list[dict]) -> bytes:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">',
        "  <version>1.0</version>",
        "  <report_metadata>",
        f"    <org_name>{org}</org_name>",
        f"    <email>noreply-dmarc@{org}</email>",
        f"    <report_id>{report_id}</report_id>",
        "    <date_range>",
        f"      <begin>{int(start.timestamp())}</begin>",
        f"      <end>{int(end.timestamp())}</end>",
        "    </date_range>",
        "  </report_metadata>",
        "  <policy_published>",
        f"    <domain>{policy_domain}</domain>",
        "    <adkim>r</adkim>",
        "    <aspf>r</aspf>",
        f"    <p>{policy[0]}</p>",
        f"    <sp>{policy[1]}</sp>",
        "    <pct>100</pct>",
        "    <fo>0</fo>",
        "  </policy_published>",
    ]
    for record in records:
        lines.extend(
            [
                "  <record>",
                "    <row>",
                f"      <source_ip>{record['ip']}</source_ip>",
                f"      <count>{record['count']}</count>",
                "      <policy_evaluated>",
                f"        <disposition>{record['disposition']}</disposition>",
                f"        <dkim>{'pass' if record['dkim_pass'] else 'fail'}</dkim>",
                f"        <spf>{'pass' if record['spf_pass'] else 'fail'}</spf>",
                "      </policy_evaluated>",
                "    </row>",
                "    <identifiers>",
                f"      <header_from>{record['header_from']}</header_from>",
                f"      <envelope_from>{record['envelope_from']}</envelope_from>",
                "    </identifiers>",
                "    <auth_results>",
                f"      <dkim><domain>{record['dkim_domain']}</domain><selector>stalwart</selector>"
                f"<result>{'pass' if record['dkim_pass'] else 'fail'}</result></dkim>",
                f"      <spf><domain>{record['spf_domain']}</domain>"
                f"<result>{'pass' if record['spf_pass'] else 'fail'}</result></spf>",
                "    </auth_results>",
                "  </record>",
            ]
        )
    lines.append("</feedback>")
    return "\n".join(lines).encode("utf-8")


def ensure_domain(session: Session, name: str) -> Domain:
    domain = session.exec(select(Domain).where(Domain.name == name)).first()
    if domain is None:
        domain = Domain(name=name, display_name=name)
        session.add(domain)
        session.flush()
    return domain


def _check(key, label, status, summary, core, details=None, remediation=None):
    return {
        "key": key,
        "label": label,
        "status": status,
        "summary": summary,
        "details": details or [],
        "remediation": remediation,
        "core": core,
        "evidence": {},
        "duration_ms": 40,
    }


HEALTH: dict[str, list[dict]] = {
    "tgm.rocks": [
        _check("dmarc", "DMARC", "pass", "p=reject · reports to postmaster@tgm.rocks", True,
               ["p=reject", "sp=reject", "pct=100", "adkim=r · aspf=r", "rua=mailto:postmaster@tgm.rocks"]),
        _check("spf", "SPF", "pass", "2/10 lookups · -all", True,
               ["2 DNS lookups (limit 10)", "0 void lookups (limit 2)", "all: -"]),
        _check("dkim", "DKIM", "pass", "2 keys found (v1-ed25519-20261101, v1-rsa-20261101)", True,
               ["checked 6 selectors (8 configured, 2 from reports, 4 rotation candidates)",
                "v1-ed25519-20261101@tgm.rocks: ed25519",
                "v1-rsa-20261101@tgm.rocks: rsa 2048 bit"]),
        _check("mx", "MX", "pass", "1 MX host", True,
               ["10 mail.tgm.rocks → 188.245.193.117"]),
        _check("mta_sts", "MTA-STS", "warn", "mode=testing — TLS is not enforced", False,
               ["mode=testing", "max_age=604800", "mx: mail.tgm.rocks", "id=17929410896137013158"],
               "Switch the policy to mode: enforce once every MX host presents a valid certificate."),
        _check("tls_rpt", "TLS-RPT", "pass", "reports to postmaster@tgm.rocks", False,
               ["rua=mailto:postmaster@tgm.rocks"]),
        _check("dnssec", "DNSSEC", "info", "Zone is not signed", False,
               ["Optional for mail, but it enables DANE."]),
        _check("bimi", "BIMI", "info", "Not published", False),
    ],
    "aeroclub.example": [
        _check("dmarc", "DMARC", "warn", "p=none — failing mail is still delivered", True,
               ["p=none", "sp=none", "pct=100", "rua=mailto:dmarc@aeroclub.example"]),
        _check("spf", "SPF", "pass", "1/10 lookups · -all", True,
               ["1 DNS lookup (limit 10)", "0 void lookups"]),
        _check("dkim", "DKIM", "pass", "1 key found (mail)", True,
               ["selectors checked: mail", "mail: rsa 2048 bit"]),
        _check("mx", "MX", "pass", "1 MX host", True, ["10 mail.tgm.rocks → 188.245.193.117"]),
        _check("mta_sts", "MTA-STS", "info", "Not published", False),
        _check("tls_rpt", "TLS-RPT", "info", "Not published", False),
        _check("dnssec", "DNSSEC", "info", "Zone is not signed", False),
        _check("bimi", "BIMI", "info", "Not published", False),
    ],
    "nightowl.example": [
        _check("dmarc", "DMARC", "pass", "p=quarantine · reports to dmarc@nightowl.example", True,
               ["p=quarantine", "pct=100", "rua=mailto:dmarc@nightowl.example"]),
        _check("spf", "SPF", "pass", "1/10 lookups · -all", True, ["1 DNS lookup", "0 void lookups"]),
        _check("dkim", "DKIM", "pass", "1 key found (selector1)", True, ["selector1: rsa 2048 bit"]),
        _check("mx", "MX", "pass", "1 MX host", True, ["10 mail.tgm.rocks → 188.245.193.117"]),
        _check("mta_sts", "MTA-STS", "info", "Not published", False),
        _check("tls_rpt", "TLS-RPT", "info", "Not published", False),
        _check("dnssec", "DNSSEC", "info", "Zone is not signed", False),
        _check("bimi", "BIMI", "info", "Not published", False),
    ],
}


def seed_health(session) -> None:
    now = datetime.now(timezone.utc)
    for name, results in HEALTH.items():
        domain = session.exec(select(Domain).where(Domain.name == name)).first()
        if domain is None:
            continue
        core = [item for item in results if item["core"]]
        passed = sum(1 for item in core if item["status"] == "pass")
        overall = "fail" if any(item["status"] == "fail" for item in core) else (
            "warn" if any(item["status"] == "warn" for item in core) else "pass"
        )
        for days_ago in (3, 2, 1, 0):
            session.add(
                DomainHealthSnapshot(
                    domain_id=domain.id,
                    checked_at=now - timedelta(days=days_ago, minutes=18),
                    overall=overall,
                    score=passed / len(core),
                    core_passed=passed,
                    core_total=len(core),
                    results=results,
                    duration_ms=380 + days_ago * 20,
                )
            )
        if name == "tgm.rocks":
            for host, port, mode, days, version in [
                ("mail.tgm.rocks", 25, "smtp", 68, "TLSv1.3"),
                ("mail.tgm.rocks", 465, "tls", 68, "TLSv1.3"),
                ("mail.tgm.rocks", 993, "tls", 68, "TLSv1.3"),
            ]:
                session.add(
                    TransportProbe(
                        domain_id=domain.id,
                        host=host,
                        port=port,
                        mode=mode,
                        status="pass",
                        tls_version=version,
                        cipher="TLS_AES_256_GCM_SHA384",
                        cert_subject="CN=mail.tgm.rocks",
                        cert_issuer="CN=R11, O=Let's Encrypt, C=US",
                        not_after=now + timedelta(days=days),
                        days_left=days,
                        hostname_ok=True,
                        chain_ok=True,
                        dane_status="none",
                        details={"key_bits": 2048, "key_type": "_RSAPublicKey"},
                        checked_at=now - timedelta(minutes=17),
                        duration_ms=180,
                    )
                )
    session.commit()


def seed() -> None:
    init_db()
    geo = get_geo_resolver()
    with Session(get_engine()) as session:
        for domain_name, config in DOMAINS.items():
            domain = ensure_domain(session, domain_name)
            for offset in range(DAYS):
                day = TODAY - timedelta(days=DAYS - 1 - offset)
                start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
                end = start + timedelta(days=1)
                policy = config["policy"]

                rotation = day.replace(day=1).strftime("%Y%m%d")
                for index, org in enumerate(config["reporters"]):
                    algorithm = "ed25519" if org.startswith("google") else "rsa"
                    selector = f"v1-{algorithm}-{rotation}"
                    wave = 1.0 + 0.35 * math.sin(offset / 3.2)
                    verified = max(3, int(random.uniform(6, 14) * wave))
                    records = [
                        {
                            "ip": config["verified_ip"],
                            "count": verified,
                            "dkim_pass": True,
                            "spf_pass": True,
                            "disposition": "none",
                            "header_from": domain_name,
                            "envelope_from": f"bounce@{domain_name}",
                            "dkim_domain": domain_name,
                            "spf_domain": domain_name,
                            "selector": selector,
                        }
                    ]
                    for ip, weight in config["noisy"]:
                        if random.random() < 0.45:
                            continue
                        count = max(1, int(random.uniform(1, 4) * weight / 2))
                        records.append(
                            {
                                "ip": ip,
                                "count": count,
                                "dkim_pass": False,
                                "spf_pass": False,
                                "disposition": "reject" if policy[0] == "reject" else "none",
                                "header_from": domain_name,
                                "envelope_from": "spoof@evil.example",
                                "dkim_domain": "evil.example",
                                "spf_domain": "evil.example",
                                "selector": "v1-ed25519-19700101",
                            }
                        )
                    report_id = f"{domain_name}-{day.isoformat()}-{org.split('.')[0]}-{index}"
                    message_count = sum(record["count"] for record in records)
                    aligned = sum(record["count"] for record in records if record["dkim_pass"] or record["spf_pass"])
                    report = Report(
                        domain_id=domain.id,
                        org_name=org,
                        org_email=f"noreply-dmarc@{org}",
                        report_id=report_id,
                        policy_domain=domain_name,
                        date_begin=start,
                        date_end=end,
                        report_date=day,
                        policy_p=policy[0],
                        policy_sp=policy[1],
                        policy_pct=100,
                        policy_adkim="r",
                        policy_aspf="r",
                        policy_fo="0",
                        record_count=len(records),
                        message_count=message_count,
                        aligned_count=aligned,
                        failed_count=message_count - aligned,
                        source_count=len({record["ip"] for record in records}),
                        raw_sha256=f"{report_id}-seed".replace("-", "")[:64].ljust(64, "0"),
                        raw_xml=dmarc_xml(domain_name, org, report_id, start, end, policy, records),
                        source="import",
                        received_at=end + timedelta(hours=3),
                        ingested_at=end + timedelta(hours=4),
                    )
                    session.add(report)
                    session.flush()
                    for record in records:
                        code, name = geo.lookup(record["ip"])
                        session.add(
                            SourceRecord(
                                report_id=report.id,
                                domain_id=domain.id,
                                report_date=day,
                                source_ip=record["ip"],
                                message_count=record["count"],
                                disposition=record["disposition"],
                                dkim_pass=record["dkim_pass"],
                                spf_pass=record["spf_pass"],
                                dkim_signed=True,
                                dkim_auth_pass=record["dkim_pass"],
                                spf_auth_pass=record["spf_pass"],
                                header_from=record["header_from"],
                                envelope_from=record["envelope_from"],
                                dkim_domains=[record["dkim_domain"]],
                                dkim_selectors=[record["selector"]],
                                dkim_results=["pass" if record["dkim_pass"] else "fail"],
                                spf_domains=[record["spf_domain"]],
                                spf_results=["pass" if record["spf_pass"] else "fail"],
                                country_code=code or COUNTRY_FALLBACK.get(record["ip"], (None, None))[0],
                                country_name=name or COUNTRY_FALLBACK.get(record["ip"], (None, None))[1],
                            )
                        )

                # TLS-RPT: one report per day for tgm.rocks.
                if domain_name == "tgm.rocks":
                    success = random.randint(22, 48)
                    failure = random.choice([0, 0, 0, 1, 2, 3])
                    report = TlsReport(
                        domain_id=domain.id,
                        org_name="google.com",
                        report_id=f"{domain_name}-{day.isoformat()}-tls",
                        contact_info="mailto:dmarc@tgm.rocks",
                        date_begin=start,
                        date_end=end,
                        report_date=day,
                        policy_type="sts",
                        policy_mode="enforce",
                        policy_domain=domain_name,
                        policy_string=[
                            "version: STSv1",
                            "mode: enforce",
                            "mx: mail.tgm.rocks",
                            "max_age: 604800",
                        ],
                        mx_hosts=["mail.tgm.rocks"],
                        max_age=604800,
                        total_success=success,
                        total_failure=failure,
                        raw_sha256=f"{domain_name}{day.isoformat()}tls".replace("-", "").ljust(64, "1"),
                        raw_json=b'{"policies":[]}',
                        source="import",
                        received_at=end + timedelta(hours=4),
                        ingested_at=end + timedelta(hours=5),
                    )
                    session.add(report)
                    session.flush()
                    session.add(
                        TlsPolicy(
                            tls_report_id=report.id,
                            domain_id=domain.id,
                            report_date=day,
                            policy_type="sts",
                            policy_domain=domain_name,
                            mx_hosts=["mail.tgm.rocks"],
                            total_success=success,
                            total_failure=failure,
                        )
                    )
                    if failure:
                        session.add(
                            TlsFailure(
                                tls_report_id=report.id,
                                domain_id=domain.id,
                                report_date=day,
                                policy_domain=domain_name,
                                receiving_mx="mail.tgm.rocks",
                                result_type="certificate-expired",
                                sending_mta_ip="40.92.19.44",
                                failed_count=failure,
                                reason_code="certificate-expired",
                                additional_info="certificate expired before renewal",
                                country_code="US",
                                country_name="United States",
                            )
                        )
                session.commit()
    with Session(get_engine()) as session:
        seed_health(session)
    print(f"seeded {DAYS} days for {len(DOMAINS)} domains into {get_engine().url}")


if __name__ == "__main__":
    seed()
