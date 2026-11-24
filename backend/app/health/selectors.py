"""DKIM selector candidates.

Selectors cannot be enumerated through DNS, and Stalwart rotates them using a
date template (``v1-ed25519-20260101``). Two sources fill the gap:

* selectors seen in DMARC reports (``auth_results/dkim/selector``) — always real
* date variants of those selectors around today, for the window between a
  rotation and the next report arriving
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, timedelta

#: Stalwart's default template ends in a compact date; custom ones may too.
DATE_SUFFIX = re.compile(r"^(?P<prefix>.+-)(?P<date>\d{8})$")


@dataclass(frozen=True)
class SelectorCandidate:
    domain: str
    selector: str
    source: str  # "configured" | "report" | "rotation"


def rotation_variants(selector: str, today: date, back: int = 2, forward: int = 1) -> list[str]:
    """Return ``prefix<today±N>`` when the selector ends in ``YYYYMMDD``."""
    match = DATE_SUFFIX.match(selector)
    if not match:
        return []
    prefix = match.group("prefix")
    return [
        prefix + (today + timedelta(days=offset)).strftime("%Y%m%d")
        for offset in range(-back, forward + 1)
    ]


def build_candidates(
    configured: list[str],
    policy_domain: str,
    discovered: list[tuple[str, str]],
    today: date,
    limit: int = 24,
) -> list[SelectorCandidate]:
    """Merge configured, discovered and rotation candidates without duplicates."""
    seen: set[tuple[str, str]] = set()
    out: list[SelectorCandidate] = []

    def add(domain: str, selector: str, source: str) -> None:
        selector = selector.strip()
        domain = domain.strip().lower().rstrip(".")
        if not selector or not domain or len(selector) > 64:
            return
        key = (domain, selector.lower())
        if key in seen or len(out) >= limit:
            return
        seen.add(key)
        out.append(SelectorCandidate(domain=domain, selector=selector, source=source))

    for selector in configured:
        add(policy_domain, selector, "configured")
    for domain, selector in discovered:
        add(domain, selector, "report")
    for domain, selector in discovered:
        for variant in rotation_variants(selector, today):
            add(domain, variant, "rotation")
    return out
