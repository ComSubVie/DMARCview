"""TLS-RPT reports with multiple policy domains are attributed per domain."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlmodel import Session, select

from app import analytics
from app.ingest.service import _store_tls
from app.models import Domain, TlsPolicy


def test_tls_multi_policy_attribution(session: Session):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    document = {
        "organization-name": "Example",
        "report-id": "multi-policy-test",
        "date-range": {
            "start-datetime": (now - timedelta(hours=1)).isoformat(),
            "end-datetime": now.isoformat(),
        },
        "policies": [
            {
                "policy": {
                    "policy-type": "sts",
                    "policy-domain": "a.example",
                    "mx-host": ["mx.a.example"],
                },
                "summary": {"total-successful-session-count": 3},
            },
            {
                "policy": {
                    "policy-type": "sts",
                    "policy-domain": "b.example",
                    "mx-host": ["mx.b.example"],
                },
                "summary": {
                    "total-successful-session-count": 5,
                    "total-failure-session-count": 2,
                },
            },
        ],
    }
    raw = json.dumps(document).encode()
    _store_tls(
        session,
        raw,
        hashlib.sha256(raw).hexdigest(),
        SimpleNamespace(message_id="multi-policy", received_at=None),
        "test",
        None,
    )

    policies = session.exec(select(TlsPolicy)).all()
    assert len(policies) == 2
    assert {policy.policy_domain for policy in policies} == {"a.example", "b.example"}
    assert {policy.domain_id for policy in policies} == {
        session.exec(select(Domain).where(Domain.name == "a.example")).one().id,
        session.exec(select(Domain).where(Domain.name == "b.example")).one().id,
    }

    a = analytics.get_domain(session, "a.example")
    b = analytics.get_domain(session, "b.example")
    assert a is not None and b is not None
    rng = analytics.resolve_range(30)
    dashboard_a = analytics.tls_dashboard(session, a, rng)
    dashboard_b = analytics.tls_dashboard(session, b, rng)
    assert dashboard_a["kpis"]["sessions"] == 3
    assert dashboard_b["kpis"]["sessions"] == 7
    assert dashboard_a["policy_domains"][0]["domain"] == "a.example"
    assert dashboard_b["policy_domains"][0]["domain"] == "b.example"
    assert analytics.tls_reports_page(session, domain=a)["total"] == 1
    assert analytics.tls_reports_page(session, domain=b)["total"] == 1
