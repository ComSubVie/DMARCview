"""Definitions of the built-in alert rules.

The API exposes these specs so the UI can render the right inputs without
hardcoding thresholds in two places.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class FieldSpec:
    key: str
    label: str
    type: Literal["int", "float"]
    default: float
    minimum: float
    maximum: float
    unit: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "type": self.type,
            "default": self.default,
            "min": self.minimum,
            "max": self.maximum,
            "unit": self.unit,
        }


@dataclass(frozen=True)
class RuleSpec:
    kind: str
    label: str
    description: str
    severity: str
    fields: tuple[FieldSpec, ...]
    scope: Literal["domain", "global"] = "domain"

    def defaults(self) -> dict[str, Any]:
        return {field.key: field.default for field in self.fields}

    def clean(self, condition: dict[str, Any] | None) -> dict[str, Any]:
        cleaned = self.defaults()
        for field in self.fields:
            if not condition or field.key not in condition:
                continue
            raw = condition[field.key]
            try:
                value = float(raw)
            except (TypeError, ValueError):
                continue
            value = max(field.minimum, min(field.maximum, value))
            cleaned[field.key] = int(value) if field.type == "int" else round(value, 2)
        return cleaned

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "label": self.label,
            "description": self.description,
            "severity": self.severity,
            "scope": self.scope,
            "fields": [field.as_dict() for field in self.fields],
        }


SPECS: dict[str, RuleSpec] = {
    rule.kind: rule
    for rule in (
        RuleSpec(
            kind="compliance_drop",
            label="Compliance drop",
            description="Aligned DMARC percentage below the threshold in the recent window.",
            severity="critical",
            fields=(
                FieldSpec("threshold_pct", "Threshold", "float", 95, 1, 100, "%"),
                FieldSpec("min_messages", "Minimum messages", "int", 10, 1, 1_000_000, "msgs"),
                FieldSpec("window_hours", "Window", "int", 24, 6, 168, "h"),
            ),
        ),
        RuleSpec(
            kind="new_source",
            label="New sending source",
            description="An IP that has never been seen before is sending mail as this domain.",
            severity="info",
            fields=(
                FieldSpec("min_messages", "Minimum messages", "int", 5, 1, 1_000_000, "msgs"),
                FieldSpec("window_hours", "Window", "int", 24, 1, 168, "h"),
            ),
        ),
        RuleSpec(
            kind="dkim_break",
            label="DKIM break",
            description="A source that used to pass DKIM now fails it — usually a key rotation.",
            severity="critical",
            fields=(
                FieldSpec("min_messages", "Minimum messages", "int", 1, 1, 1_000_000, "msgs"),
                FieldSpec("window_hours", "Window", "int", 24, 1, 168, "h"),
                FieldSpec("lookback_days", "Lookback", "int", 14, 1, 90, "d"),
            ),
        ),
        RuleSpec(
            kind="tls_failure",
            label="TLS delivery failure",
            description="TLS-RPT success rate below the threshold for the recent window.",
            severity="warning",
            fields=(
                FieldSpec("threshold_pct", "Threshold", "float", 95, 1, 100, "%"),
                FieldSpec("min_sessions", "Minimum sessions", "int", 5, 1, 1_000_000, "sessions"),
                FieldSpec("window_hours", "Window", "int", 24, 6, 168, "h"),
            ),
        ),
        RuleSpec(
            kind="report_gap",
            label="Reports stopped",
            description="No DMARC report has arrived within the expected interval.",
            severity="critical",
            fields=(
                FieldSpec("grace_hours", "Grace over expected", "int", 0, 0, 336, "h"),
            ),
        ),
        RuleSpec(
            kind="volume_spike",
            label="Volume spike",
            description="Recent message volume is far above the trailing baseline.",
            severity="warning",
            fields=(
                FieldSpec("multiplier", "Multiplier", "float", 3, 1.1, 100, "×"),
                FieldSpec("min_z", "Anomaly threshold", "float", 3.5, 0, 20, "σ"),
                FieldSpec("baseline_days", "Baseline", "int", 28, 7, 90, "d"),
                FieldSpec("min_messages", "Minimum messages", "int", 20, 1, 1_000_000, "msgs"),
            ),
        ),
        RuleSpec(
            kind="policy_drift",
            label="Policy drift",
            description="The DMARC record in DNS differs from what receivers last reported.",
            severity="warning",
            fields=(),
        ),
        RuleSpec(
            kind="cert_expiry",
            label="Certificate expiring",
            description="A probed MX/submission/IMAP certificate expires soon.",
            severity="warning",
            fields=(
                FieldSpec("warn_days", "Warn before", "int", 21, 1, 120, "d"),
            ),
        ),
        RuleSpec(
            kind="starttls_broken",
            label="STARTTLS broken",
            description="A probe target that should speak TLS is failing to negotiate it.",
            severity="critical",
            fields=(),
        ),
        RuleSpec(
            kind="health_regression",
            label="Health check regression",
            description="A live DNS/HTTP/transport check moved from healthy to warning or failure.",
            severity="warning",
            fields=(),
        ),
        RuleSpec(
            kind="sync_failure",
            label="JMAP sync failing",
            description="Consecutive scheduled report syncs are failing; new reports may be missed.",
            severity="critical",
            fields=(
                FieldSpec("failures", "Consecutive failures", "int", 2, 1, 10, ""),
            ),
            scope="global",
        ),
        RuleSpec(
            kind="job_failure",
            label="Scheduled job failing",
            description="A scheduled health, probe or backup run is raising errors.",
            severity="critical",
            fields=(
                FieldSpec("failures", "Consecutive failures", "int", 1, 1, 10, ""),
            ),
            scope="global",
        ),
        RuleSpec(
            kind="backup_stale",
            label="Off-box backup stale",
            description="No successful off-box backup has completed within the expected interval. The threshold is at least twice BACKUP_INTERVAL_HOURS.",
            severity="warning",
            fields=(
                FieldSpec("hours", "Minimum maximum age", "int", 48, 1, 720, "h"),
            ),
            scope="global",
        ),
    )
}
