"""Read-only DMARC policy simulation over stored aggregate reports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import case, func
from sqlmodel import Session, select

from .analytics import ALIGNED, DateRange
from .models import Domain, Report, SourceRecord

VALID_POLICIES = {"none", "quarantine", "reject"}
ACTIONS = {"none": 0, "quarantine": 1, "reject": 2}
ACTION_LABELS = {0: "delivered", 1: "quarantined", 2: "rejected"}
TESTING = {"y", "n", ""}


def _policy(value: Optional[str], fallback: str) -> str:
    if value is None or value == "":
        return fallback
    value = value.lower()
    return value if value in VALID_POLICIES else fallback


def _action(policy: str, testing: str) -> int:
    action = ACTIONS.get(policy, 0)
    if testing == "y":
        action = max(0, action - 1)
    return action


def _effective_policy(header_from: Optional[str], domain: str, p: str, sp: str) -> str:
    header = (header_from or "").strip().lower()
    root = domain.strip().lower()
    if header and header != root and header.endswith("." + root):
        return sp or p
    return p


def _policy_labels(p: str, sp: str, np: str, testing: str) -> dict[str, str]:
    return {
        "p": p,
        "sp": sp,
        "np": np,
        "testing": testing or "n",
        "label": f"p={p}" + ("" if sp == p else f"; sp={sp}") + ("; t=y" if testing == "y" else ""),
    }


def simulate(
    session: Session,
    domain: Domain,
    rng: DateRange,
    *,
    proposed_p: Optional[str] = None,
    proposed_sp: Optional[str] = None,
    proposed_np: Optional[str] = None,
    proposed_testing: Optional[str] = None,
) -> dict[str, Any]:
    """Project a proposed policy onto observed source/header-from traffic.

    This is deliberately an aggregate projection: no message is re-evaluated and
    nothing is written. A source is affected when it has failing messages and the
    proposed action is stronger than the policy last observed in a report.
    """
    latest = session.exec(
        select(Report)
        .where(Report.domain_id == domain.id)
        .order_by(Report.date_end.desc(), Report.id.desc())
    ).first()
    if latest is None:
        return {
            "available": False,
            "domain": domain.name,
            "range": {"start": rng.start.isoformat(), "end": rng.end.isoformat(), "days": rng.days},
            "message": "No reports ingested for this domain yet.",
            "current": None,
            "proposed": None,
            "warnings": ["Import a few DMARC aggregate reports before simulating a policy."],
        }

    current_p = (latest.policy_p or "none").lower()
    current_sp = (latest.policy_sp or current_p).lower()
    current_np = (latest.policy_np or "").lower()
    current_testing = (latest.policy_testing or "n").lower()
    p = _policy(proposed_p, current_p)
    sp = _policy(proposed_sp, current_sp)
    np = (proposed_np or current_np or "").lower()
    if np and np not in VALID_POLICIES:
        np = ""
    testing = (proposed_testing or current_testing or "n").lower()
    if testing not in TESTING:
        testing = "n"

    rows = session.exec(
        select(
            SourceRecord.source_ip,
            SourceRecord.header_from,
            func.coalesce(func.sum(SourceRecord.message_count), 0),
            func.coalesce(func.sum(case((ALIGNED, SourceRecord.message_count), else_=0)), 0),
        )
        .where(
            SourceRecord.domain_id == domain.id,
            SourceRecord.report_date >= rng.start,
            SourceRecord.report_date <= rng.end,
        )
        .group_by(SourceRecord.source_ip, SourceRecord.header_from)
        .order_by(func.sum(SourceRecord.message_count).desc())
    ).all()

    totals = {
        "messages": 0,
        "aligned": 0,
        "failed": 0,
        "newly_affected": 0,
        "newly_blocked": 0,
        "newly_quarantined": 0,
        "already_affected": 0,
        "relaxed": 0,
        "unaffected": 0,
        "sources": 0,
        "affected_sources": 0,
    }
    sources: list[dict[str, Any]] = []
    current_max = 0
    proposed_max = 0
    foreign_messages = 0
    for ip, header_from, messages, aligned in rows:
        messages, aligned = int(messages or 0), int(aligned or 0)
        failed = max(0, messages - aligned)
        header = (header_from or "").lower() or None
        foreign = bool(
            header
            and header != domain.name.lower()
            and not header.endswith("." + domain.name.lower())
        )
        if foreign:
            foreign_messages += messages
        current_action = 0 if foreign else _action(
            _effective_policy(header, domain.name, current_p, current_sp), current_testing
        )
        proposed_action = 0 if foreign else _action(
            _effective_policy(header, domain.name, p, sp), testing
        )
        current_max = max(current_max, current_action)
        proposed_max = max(proposed_max, proposed_action)
        newly = failed if proposed_action > current_action else 0
        blocked = failed if proposed_action == 2 and current_action < 2 else 0
        quarantined = failed if proposed_action == 1 and current_action == 0 else 0
        already = failed if proposed_action > 0 and proposed_action == current_action else 0
        relaxed = failed if proposed_action < current_action else 0
        totals["messages"] += messages
        totals["aligned"] += aligned
        totals["failed"] += failed
        totals["newly_affected"] += newly
        totals["newly_blocked"] += blocked
        totals["newly_quarantined"] += quarantined
        totals["already_affected"] += already
        totals["relaxed"] += relaxed
        totals["unaffected"] += messages - failed
        totals["sources"] += 1
        if newly or already or blocked:
            totals["affected_sources"] += 1
        if newly or already or relaxed or messages:
            sources.append(
                {
                    "ip": ip,
                    "header_from": header_from,
                    "messages": messages,
                    "aligned": aligned,
                    "aligned_pct": round(aligned / messages * 100, 1) if messages else 0.0,
                    "failed": failed,
                    "current_action": ACTION_LABELS[current_action],
                    "proposed_action": ACTION_LABELS[proposed_action],
                    "current_severity": current_action,
                    "proposed_severity": proposed_action,
                    "newly_affected": newly,
                    "newly_blocked": blocked,
                    "already_affected": already,
                    "relaxed": relaxed,
                    "foreign": foreign,
                }
            )

    sources.sort(key=lambda item: (-item["newly_affected"], -item["messages"], item["ip"]))
    sources = sources[:25]
    total_messages = totals["messages"]
    failed = totals["failed"]
    newly = totals["newly_affected"]
    warnings: list[str] = []
    if foreign_messages:
        warnings.append(
            f"{foreign_messages:,} messages had a header-from outside this domain and are excluded "
            "from the projection."
        )
    if np:
        warnings.append("np= is not applied here: observed header-from domains exist in the reports.")
    if testing == "y":
        warnings.append("t=y reduces the applied policy by one level, including reject → quarantine.")
    if p == "none":
        warnings.append("p=none only monitors; no failing message is quarantined or rejected.")
    if current_p != p or current_sp != sp or current_testing != testing:
        warnings.append("The comparison baseline is the policy in the latest report, not the live DNS record.")

    if proposed_max < current_max:
        verdict = {
            "level": "info",
            "label": "Relaxation",
            "detail": "The proposed policy is weaker than the latest observed policy; some failing mail would be delivered.",
        }
    elif proposed_max == current_max and newly == 0:
        verdict = {
            "level": "info",
            "label": "No action change",
            "detail": "The proposed policy applies the same action as the latest observed policy.",
        }
    elif failed == 0:
        verdict = {
            "level": "good",
            "label": "Safe in this window",
            "detail": "No failing messages were observed, so the proposed policy affects no traffic in this window.",
        }
    elif newly == 0:
        verdict = {
            "level": "good",
            "label": "Already covered",
            "detail": "All failing messages are already subject to the same or a stronger action.",
        }
    elif newly / max(total_messages, 1) <= 0.02:
        verdict = {
            "level": "good",
            "label": "Low projected impact",
            "detail": f"{newly:,} failing messages ({newly / total_messages * 100:.2f}% of observed mail) would see a new action.",
        }
    elif newly / max(total_messages, 1) <= 0.10:
        verdict = {
            "level": "warn",
            "label": "Review before tightening",
            "detail": f"{newly:,} failing messages ({newly / total_messages * 100:.2f}%) would see a new action. Check the sources below.",
        }
    else:
        verdict = {
            "level": "bad",
            "label": "High projected impact",
            "detail": f"{newly:,} failing messages ({newly / total_messages * 100:.2f}%) would see a new action. Identify the senders first.",
        }

    if total_messages < 100 or rng.days < 14:
        confidence = "low"
    elif total_messages < 1000 or rng.days < 30:
        confidence = "medium"
    else:
        confidence = "high"

    return {
        "available": True,
        "domain": domain.name,
        "range": {"start": rng.start.isoformat(), "end": rng.end.isoformat(), "days": rng.days},
        "current": _policy_labels(current_p, current_sp, current_np, current_testing),
        "proposed": _policy_labels(p, sp, np, testing),
        "totals": totals,
        "newly_affected_pct": round(newly / total_messages * 100, 2) if total_messages else 0.0,
        "affected_pct": round(totals["already_affected"] / failed * 100, 1) if failed else 0.0,
        "sources": sources,
        "verdict": verdict,
        "confidence": confidence,
        "warnings": warnings,
        "caveats": [
            "Projection only: receivers still make their own policy decisions.",
            "Based on aggregate alignment, not individual message evaluation.",
            "Observed header-from domains are treated as existing, so np= is not simulated.",
        ],
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
