"""Run all checks for one domain, concurrently and with per-check timeouts."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Optional

from .checks import CHECKS, CheckContext, CheckSpec
from .dns import BaseDnsClient, get_dns_client
from .http import BaseFetcher, get_http_fetcher
from .types import CheckResult, HealthReport, Status, overall_status


async def _run_one(spec: CheckSpec, ctx: CheckContext) -> CheckResult:
    started = time.perf_counter()
    try:
        result = await asyncio.wait_for(spec.runner(ctx), timeout=spec.timeout)
    except asyncio.TimeoutError:
        result = CheckResult(
            key=spec.key,
            label=spec.label,
            status=Status.UNKNOWN,
            summary=f"Check timed out after {spec.timeout:.0f}s",
            core=spec.core,
        )
    except Exception as exc:  # noqa: BLE001 - one broken check must not fail the report
        result = CheckResult(
            key=spec.key,
            label=spec.label,
            status=Status.UNKNOWN,
            summary=f"Check failed: {type(exc).__name__}",
            details=[str(exc)[:300]],
            core=spec.core,
        )
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    return result


async def run_health(
    domain: str,
    *,
    selectors: list[str],
    reported_policy: Optional[dict] = None,
    dns: Optional[BaseDnsClient] = None,
    http: Optional[BaseFetcher] = None,
    http_timeout: float = 6.0,
    discovered_selectors: Optional[list[tuple[str, str]]] = None,
    helo_hostname: str = "",
) -> HealthReport:
    started = time.perf_counter()
    ctx = CheckContext(
        domain=domain.lower().rstrip("."),
        dns=dns or get_dns_client(),
        http=http or get_http_fetcher(),
        selectors=selectors,
        discovered_selectors=discovered_selectors or [],
        reported_policy=reported_policy or {},
        http_timeout=http_timeout,
        helo_hostname=helo_hostname,
    )
    results = await asyncio.gather(*(_run_one(spec, ctx) for spec in CHECKS))
    overall, score, passed, total = overall_status(results)
    checked_at = datetime.now(timezone.utc)
    return HealthReport(
        domain=domain,
        checked_at=checked_at,
        overall=overall,
        score=score,
        core_passed=passed,
        core_total=total,
        results=list(results),
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
