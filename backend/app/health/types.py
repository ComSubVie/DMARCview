"""Shared types for domain health checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Status(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"
    UNKNOWN = "unknown"
    NA = "n/a"

    @property
    def rank(self) -> int:
        return {"fail": 4, "warn": 3, "unknown": 2, "pass": 1, "info": 0, "n/a": 0}[self.value]


@dataclass
class CheckResult:
    key: str
    label: str
    status: Status
    summary: str
    details: list[str] = field(default_factory=list)
    remediation: str | None = None
    core: bool = False
    evidence: dict = field(default_factory=dict)
    duration_ms: int = 0

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "status": self.status.value,
            "summary": self.summary,
            "details": self.details,
            "remediation": self.remediation,
            "core": self.core,
            "evidence": self.evidence,
            "duration_ms": self.duration_ms,
        }


@dataclass
class HealthReport:
    domain: str
    checked_at: datetime
    overall: str
    score: float
    core_passed: int
    core_total: int
    results: list[CheckResult]
    duration_ms: int = 0
    error: str | None = None

    def as_dict(self) -> dict:
        return {
            "domain": self.domain,
            "checked_at": self.checked_at,
            "overall": self.overall,
            "score": self.score,
            "core_passed": self.core_passed,
            "core_total": self.core_total,
            "results": [result.as_dict() for result in self.results],
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


def overall_status(results: list[CheckResult]) -> tuple[str, float, int, int]:
    core = [result for result in results if result.core]
    passed = sum(1 for result in core if result.status is Status.PASS)
    total = len(core)
    if any(result.status is Status.FAIL for result in core):
        overall = "fail"
    elif any(result.status is Status.WARN for result in core):
        overall = "warn"
    elif core and all(result.status is Status.UNKNOWN for result in core) or not core:
        overall = "unknown"
    else:
        overall = "pass"
    return overall, round(passed / total, 3) if total else 0.0, passed, total
