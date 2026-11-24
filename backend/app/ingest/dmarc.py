"""DMARC aggregate report (RUA) XML parser.

Namespace-agnostic on purpose: reporters use dmarc-1.0, dmarc-2.0, or no
namespace at all, and a few emit surprising capitalisation.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


class DmarcParseError(ValueError):
    pass


@dataclass
class DmarcRecord:
    source_ip: str
    count: int = 0
    disposition: str = "none"
    dkim_pass: bool = False
    spf_pass: bool = False
    header_from: Optional[str] = None
    envelope_from: Optional[str] = None
    envelope_to: Optional[str] = None
    dkim_domains: list[str] = field(default_factory=list)
    dkim_selectors: list[str] = field(default_factory=list)
    dkim_results: list[str] = field(default_factory=list)
    spf_domains: list[str] = field(default_factory=list)
    spf_results: list[str] = field(default_factory=list)
    reason_type: Optional[str] = None
    reason_comment: Optional[str] = None

    @property
    def aligned(self) -> bool:
        return self.dkim_pass or self.spf_pass


@dataclass
class DmarcReport:
    org_name: str
    org_email: Optional[str]
    report_id: str
    date_begin: datetime
    date_end: datetime
    policy_domain: str
    policy_p: Optional[str] = None
    policy_sp: Optional[str] = None
    policy_np: Optional[str] = None
    policy_pct: Optional[int] = None
    policy_testing: Optional[str] = None
    policy_discovery: Optional[str] = None
    policy_adkim: Optional[str] = None
    policy_aspf: Optional[str] = None
    policy_fo: Optional[str] = None
    report_errors: list[str] = field(default_factory=list)
    records: list[DmarcRecord] = field(default_factory=list)

    @property
    def message_count(self) -> int:
        return sum(record.count for record in self.records)

    @property
    def aligned_count(self) -> int:
        return sum(record.count for record in self.records if record.aligned)

    @property
    def failed_count(self) -> int:
        return self.message_count - self.aligned_count

    @property
    def source_count(self) -> int:
        return len({record.source_ip for record in self.records})


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _children(node: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(node) if _local(child.tag) == name]


def _child(node: ET.Element | None, name: str) -> Optional[ET.Element]:
    if node is None:
        return None
    for candidate in list(node):
        if _local(candidate.tag) == name:
            return candidate
    return None


def _text(node: ET.Element | None, name: str, default: Optional[str] = None) -> Optional[str]:
    found = _child(node, name)
    if found is None or found.text is None:
        return default
    value = found.text.strip()
    return value or default


def _attr(node: ET.Element | None, name: str) -> Optional[str]:
    if node is None:
        return None
    value = node.get(name)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _attr_or_text(node: ET.Element | None, name: str) -> Optional[str]:
    """``<reason type="forwarded">`` puts the value in an attribute."""
    return _attr(node, name) or _text(node, name)


def _descendant(node: ET.Element, name: str) -> Optional[ET.Element]:
    for candidate in node.iter():
        if _local(candidate.tag) == name:
            return candidate
    return None


def _epoch(value: str | None) -> datetime:
    if not value:
        raise DmarcParseError("missing date_range value")
    try:
        stamp = float(value.strip())
    except ValueError as exc:
        raise DmarcParseError(f"invalid epoch timestamp {value!r}") from exc
    if stamp > 10_000_000_000:  # milliseconds
        stamp /= 1000.0
    try:
        return datetime.fromtimestamp(stamp, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise DmarcParseError(f"epoch timestamp out of range: {value!r}") from exc


def _bool_result(value: str | None) -> bool:
    return (value or "").strip().lower() == "pass"


def parse_dmarc(data: bytes) -> DmarcReport:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise DmarcParseError(f"malformed XML: {exc}") from exc

    if _local(root.tag) != "feedback":
        feedback = _descendant(root, "feedback")
        if feedback is None:
            raise DmarcParseError("not a DMARC aggregate report (no <feedback> element)")
        root = feedback

    metadata = _child(root, "report_metadata")
    if metadata is None:
        raise DmarcParseError("report has no <report_metadata>")

    org_name = (_text(metadata, "org_name") or "unknown").strip()
    date_range = _child(metadata, "date_range")
    date_begin = _epoch(_text(date_range, "begin"))
    date_end = _epoch(_text(date_range, "end"))

    report_id = _text(metadata, "report_id")
    if not report_id:
        # Some reporters omit it; fabricate a stable identifier.
        report_id = f"{org_name}-{int(date_begin.timestamp())}"
    if date_end < date_begin:
        date_end = date_begin

    published = _child(root, "policy_published")
    if published is None:
        raise DmarcParseError("report has no <policy_published>")
    policy_domain = (_text(published, "domain") or "").strip().lower()
    if not policy_domain:
        raise DmarcParseError("policy_published has no <domain>")

    pct_raw = _text(published, "pct")
    try:
        pct = int(float(pct_raw)) if pct_raw is not None else None
    except ValueError:
        pct = None

    report = DmarcReport(
        org_name=org_name.lower(),
        org_email=_text(metadata, "email"),
        report_id=report_id,
        date_begin=date_begin,
        date_end=date_end,
        policy_domain=policy_domain,
        policy_p=_text(published, "p"),
        policy_sp=_text(published, "sp") or _text(published, "p"),
        policy_np=_text(published, "np"),
        policy_pct=pct,
        policy_testing=_text(published, "testing") or _text(published, "t"),
        policy_discovery=_text(published, "discovery_method") or _text(published, "discovery-method"),
        policy_adkim=_text(published, "adkim"),
        policy_aspf=_text(published, "aspf"),
        policy_fo=_text(published, "fo"),
        report_errors=[
            (node.text or "").strip()
            for node in _children(metadata, "error")
            if (node.text or "").strip()
        ],
    )

    for node in _children(root, "record"):
        row = _child(node, "row")
        if row is None:
            continue
        source_ip = (_text(row, "source_ip") or "").strip()
        if not source_ip:
            continue
        try:
            count = int(float(_text(row, "count") or "0"))
        except ValueError:
            count = 0
        evaluated = _child(row, "policy_evaluated")
        identifiers = _child(node, "identifiers")
        auth = _child(node, "auth_results")

        reason_type = reason_comment = None
        if evaluated is not None:
            reason = _child(evaluated, "reason")
            if reason is not None:
                reason_type = _attr_or_text(reason, "type")
                reason_comment = _text(reason, "comment")

        record = DmarcRecord(
            source_ip=source_ip,
            count=count,
            disposition=(_text(evaluated, "disposition") or "none").strip().lower(),
            dkim_pass=_bool_result(_text(evaluated, "dkim")),
            spf_pass=_bool_result(_text(evaluated, "spf")),
            header_from=(_text(identifiers, "header_from") or "").strip().lower() or None,
            envelope_from=_text(identifiers, "envelope_from"),
            envelope_to=_text(identifiers, "envelope_to"),
            reason_type=reason_type,
            reason_comment=reason_comment,
        )

        if auth is not None:
            for dkim in _children(auth, "dkim"):
                domain = (_text(dkim, "domain") or "").strip().lower()
                result = (_text(dkim, "result") or "").strip().lower()
                selector = (_text(dkim, "selector") or "").strip()
                if domain:
                    record.dkim_domains.append(domain)
                if selector:
                    record.dkim_selectors.append(selector)
                if result:
                    record.dkim_results.append(result)
            for spf in _children(auth, "spf"):
                domain = (_text(spf, "domain") or "").strip().lower()
                result = (_text(spf, "result") or "").strip().lower()
                if domain:
                    record.spf_domains.append(domain)
                if result:
                    record.spf_results.append(result)

        report.records.append(record)

    if not report.records:
        raise DmarcParseError("report contains no usable <record> elements")
    return report
