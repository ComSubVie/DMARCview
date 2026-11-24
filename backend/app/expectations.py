"""Known-sender matching for new-source alert suppression."""

from __future__ import annotations

import ipaddress
from typing import Optional

from sqlmodel import Session, select

from .models import IpMeta, SourceExpectation, SourceRecord


def _normalize(value: str) -> str:
    return value.strip().strip(".").lower()


def _mail_domain(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    text = value.strip()
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    text = text.strip(".").lower()
    return text or None


def _source_domains(session: Session, domain_id: int, ip: str, since) -> set[str]:
    domains: set[str] = set()
    rows = session.exec(
        select(SourceRecord.envelope_from, SourceRecord.header_from, SourceRecord.dkim_domains)
        .where(
            SourceRecord.domain_id == domain_id,
            SourceRecord.source_ip == ip,
            SourceRecord.report_date >= since,
        )
        .distinct()
    ).all()
    for envelope, header, dkim_domains in rows:
        for item in (envelope, header):
            value = _mail_domain(item)
            if value:
                domains.add(value)
        if isinstance(dkim_domains, list):
            domains.update(_normalize(item) for item in dkim_domains if item)
    return domains


def matching_label(
    session: Session,
    domain_id: int,
    ip: str,
    *,
    since,
    expectations: Optional[list[SourceExpectation]] = None,
) -> Optional[str]:
    """Return a label when *ip* matches a known sender rule for this domain."""
    if expectations is None:
        expectations = session.exec(
            select(SourceExpectation).where(SourceExpectation.domain_id == domain_id)
        ).all()
    if not expectations:
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        address = None
    meta = session.get(IpMeta, ip)
    domains: Optional[set[str]] = None
    for rule in expectations:
        kind = (rule.match_type or "").lower()
        value = (rule.value or "").strip()
        matched = False
        if kind == "ip":
            matched = value == ip
        elif kind == "cidr" and address is not None:
            try:
                matched = address in ipaddress.ip_network(value, strict=False)
            except ValueError:
                matched = False
        elif kind == "asn":
            try:
                matched = meta is not None and meta.asn == int(value.lstrip("ASas"))
            except (TypeError, ValueError):
                matched = False
        elif kind == "domain":
            if domains is None:
                domains = _source_domains(session, domain_id, ip, since)
            wanted = _normalize(value)
            matched = any(
                domain == wanted or domain.endswith("." + wanted) for domain in domains
            )
        if matched:
            return rule.label or f"known {kind} {value}"
    return None
