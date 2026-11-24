"""TLS-RPT (RFC 8460) JSON parser.

Tolerates both the final RFC key names (``total-successful-session-count``)
and the older draft spellings still emitted by some reporters
(``total-success-session-count``), plus the ``receiving-mx`` /
``receiving-mx-hostname`` divergence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


class TlsParseError(ValueError):
    pass


@dataclass
class TlsFailureData:
    result_type: str
    sending_mta_ip: Optional[str]
    receiving_mx: Optional[str]
    failed_count: int
    reason_code: Optional[str]
    additional_info: Optional[str]


@dataclass
class TlsPolicyData:
    policy_type: Optional[str]
    policy_domain: Optional[str]
    mx_hosts: list[str] = field(default_factory=list)
    total_success: int = 0
    total_failure: int = 0
    failures: list[TlsFailureData] = field(default_factory=list)


@dataclass
class TlsReportData:
    org_name: str
    report_id: str
    contact_info: Optional[str]
    date_begin: datetime
    date_end: datetime
    policy_type: Optional[str] = None
    policy_mode: Optional[str] = None
    policy_domain: Optional[str] = None
    policy_string: list[str] = field(default_factory=list)
    mx_hosts: list[str] = field(default_factory=list)
    max_age: Optional[int] = None
    policies: list[TlsPolicyData] = field(default_factory=list)

    @property
    def total_success(self) -> int:
        return sum(policy.total_success for policy in self.policies)

    @property
    def total_failure(self) -> int:
        return sum(policy.total_failure for policy in self.policies)


def _first(mapping: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _as_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if item]
    return []


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        stamp = float(value)
        if stamp > 10_000_000_000:
            stamp /= 1000.0
        return datetime.fromtimestamp(stamp, tz=timezone.utc)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise TlsParseError("empty date value")
        if raw.isdigit():
            return _parse_datetime(int(raw))
        normalized = raw.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise TlsParseError(f"invalid date {value!r}") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    raise TlsParseError(f"invalid date value {value!r}")


def _extract_mode(policy_string: list[str], explicit: Any) -> Optional[str]:
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip().lower()
    for line in policy_string:
        key, _, value = line.partition(":")
        if key.strip().lower() == "mode":
            return value.strip().lower()
    return None


def _extract_max_age(policy_string: list[str], explicit: Any) -> Optional[int]:
    if explicit is not None:
        return _as_int(explicit)
    for line in policy_string:
        key, _, value = line.partition(":")
        if key.strip().lower() == "max_age":
            return _as_int(value)
    return None


def parse_tlsrpt(data: bytes) -> TlsReportData:
    try:
        document = json.loads(data.decode("utf-8", errors="replace"))
    except ValueError as exc:
        raise TlsParseError(f"malformed JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise TlsParseError("TLS report root is not an object")

    date_range = document.get("date-range") or document.get("date_range") or {}
    if not isinstance(date_range, dict):
        raise TlsParseError("date-range is not an object")
    start = _first(date_range, "start-datetime", "start_datetime", "start")
    end = _first(date_range, "end-datetime", "end_datetime", "end")
    if start is None or end is None:
        raise TlsParseError("date-range is missing start/end datetimes")

    policies_raw = document.get("policies")
    if not isinstance(policies_raw, list) or not policies_raw:
        raise TlsParseError("report contains no <policies>")
    entries = [entry for entry in policies_raw if isinstance(entry, dict)]

    # RFC 8460 nests the published policy inside each policies[] entry. Some
    # reporters additionally emit a top-level "policy" object, so support both.
    policy_section = document.get("policy") if isinstance(document.get("policy"), dict) else {}
    first_policy = (
        entries[0].get("policy")
        if entries and isinstance(entries[0].get("policy"), dict)
        else {}
    )
    base_section = policy_section or first_policy
    policy_string = _as_list(_first(base_section, "policy-string", "policy_string", default=[]))
    mx_hosts = _as_list(_first(base_section, "mx-host", "mx_host", "mx-hosts", default=[]))
    mode = _extract_mode(policy_string, _first(base_section, "mode"))
    max_age = _extract_max_age(policy_string, _first(base_section, "max-age", "max_age"))

    org_name = str(
        _first(document, "organization-name", "organization_name", "org-name", default="unknown")
    ).strip()
    report_id = str(_first(document, "report-id", "report_id", default="")).strip()
    if not report_id:
        report_id = f"{org_name}-{int(_parse_datetime(start).timestamp())}"

    report = TlsReportData(
        org_name=org_name.lower(),
        report_id=report_id,
        contact_info=_first(document, "contact-info", "contact_info"),
        date_begin=_parse_datetime(start),
        date_end=_parse_datetime(end),
        policy_type=_first(base_section, "policy-type", "policy_type"),
        policy_mode=mode,
        policy_domain=_first(base_section, "policy-domain", "policy_domain"),
        policy_string=policy_string,
        mx_hosts=mx_hosts,
        max_age=max_age,
    )
    if report.date_end < report.date_begin:
        report.date_end = report.date_begin

    for entry in entries:
        entry_policy = entry.get("policy") if isinstance(entry.get("policy"), dict) else {}
        summary = entry.get("summary") if isinstance(entry.get("summary"), dict) else {}

        entry_type = _first(entry_policy, "policy-type", "policy_type") or report.policy_type
        entry_domain = _first(entry_policy, "policy-domain", "policy_domain") or report.policy_domain
        entry_hosts = _as_list(_first(entry_policy, "mx-host", "mx_host", "mx-hosts"))
        if not entry_hosts:
            entry_hosts = mx_hosts
        success = _as_int(
            _first(summary, "total-successful-session-count", "total-success-session-count", default=0)
        )
        failure = _as_int(
            _first(summary, "total-failure-session-count", "total-failed-session-count", default=0)
        )

        policy = TlsPolicyData(
            policy_type=entry_type,
            policy_domain=entry_domain,
            mx_hosts=entry_hosts,
            total_success=success,
            total_failure=failure,
        )
        details = summary.get("failure-details")
        if not isinstance(details, list):
            details = entry.get("failure-details") if isinstance(entry.get("failure-details"), list) else []
        for detail in details:
            if not isinstance(detail, dict):
                continue
            policy.failures.append(
                TlsFailureData(
                    result_type=str(
                        _first(detail, "result-type", "result_type", default="unknown")
                    ),
                    sending_mta_ip=_first(detail, "sending-mta-ip", "sending_mta_ip"),
                    receiving_mx=_first(
                        detail, "receiving-mx-hostname", "receiving-mx", "receiving_mx"
                    ),
                    failed_count=_as_int(
                        _first(detail, "failed-session-count", "failed_session_count", default=0)
                    ),
                    reason_code=_first(detail, "failure-reason-code", "failure_reason_code"),
                    additional_info=_first(detail, "additional-info", "additional_info"),
                )
            )
        report.policies.append(policy)

    if not report.policies:
        raise TlsParseError("report contains no usable policy entries")
    if not report.policy_domain:
        report.policy_domain = report.policies[0].policy_domain
    if not report.policy_domain:
        raise TlsParseError("report has no policy-domain")
    return report
