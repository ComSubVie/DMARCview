"""RFC 9989 policy discovery helpers.

This is additive: the health check still uses the author-domain record when it
exists. Only when it does not does this module walk the parent labels to find
the organizational/PSD record.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .dns import BaseDnsClient

VALID_POLICIES = {"none", "quarantine", "reject"}
MAX_QUERIES = 8


def parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        if key:
            tags[key] = value.strip()
    return tags


@dataclass
class InheritedPolicy:
    record: str
    tags: dict[str, str]
    policy_domain: str
    org_domain: str
    psd_domain: Optional[str]
    effective_p: str
    author_exists: Optional[bool]
    queries: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    testing: str = ""
    sp: str = ""
    np: str = ""


def _child_below(target: str, domain: str) -> str:
    target_labels = target.split(".")
    domain_labels = domain.split(".")
    if len(target_labels) >= len(domain_labels):
        return domain
    index = len(domain_labels) - len(target_labels) - 1
    return ".".join(domain_labels[index:])


def _reduce_for_testing(policy: str, testing: str) -> str:
    if testing != "y":
        return policy
    return {"reject": "quarantine", "quarantine": "none"}.get(policy, policy)


async def _author_exists(dns: BaseDnsClient, domain: str) -> Optional[bool]:
    """True if the name exists, False on NXDOMAIN, None when DNS is inconclusive."""
    saw_nxdomain = False
    for rtype in ("A", "AAAA", "MX"):
        lookup = await dns.lookup(domain, rtype)
        if lookup.error:
            return None
        if lookup.values:
            return True
        if lookup.nxdomain:
            saw_nxdomain = True
        else:
            # NODATA means the name exists even though this type is absent.
            return True
    return not saw_nxdomain


async def discover_inherited_policy(
    dns: BaseDnsClient, domain: str
) -> Optional[InheritedPolicy]:
    """Walk parent labels for a valid DMARC record when the author has none."""
    labels = domain.rstrip(".").lower().split(".")
    if len(labels) < 2:
        return None
    start = 1 if len(labels) <= MAX_QUERIES else len(labels) - (MAX_QUERIES - 1)
    targets = [".".join(labels[index:]) for index in range(start, len(labels))][:MAX_QUERIES]

    queries: list[str] = []
    warnings: list[str] = []
    records: list[tuple[str, str, dict[str, str]]] = []
    for target in targets:
        queries.append(f"_dmarc.{target}")
        lookup = await dns.txt(f"_dmarc.{target}")
        if lookup.error:
            warnings.append(f"DNS error for _dmarc.{target}: {lookup.error}")
            continue
        valid = [
            value.strip()
            for value in lookup.values
            if value.strip().lower().startswith("v=dmarc1")
        ]
        if len(valid) > 1:
            warnings.append(f"Multiple DMARC records at _dmarc.{target}; ignored")
            continue
        if valid:
            records.append((target, valid[0], parse_tags(valid[0])))
    if not records:
        return None

    chosen: Optional[tuple[str, str, dict[str, str]]] = None
    org_domain = ""
    psd_domain = None
    for target, record, tags in records:
        psd = tags.get("psd", "").lower()
        if psd == "n":
            chosen = (target, record, tags)
            org_domain = target
            break
        if psd == "y" and target != domain:
            chosen = (target, record, tags)
            org_domain = _child_below(target, domain)
            psd_domain = target
            break
    if chosen is None:
        chosen = records[-1]
        org_domain = chosen[0]
    target, record, tags = chosen

    author_exists = await _author_exists(dns, domain)
    p = tags.get("p", "").lower()
    sp = tags.get("sp", "").lower()
    np = tags.get("np", "").lower()
    testing = tags.get("t", "").lower()
    if p not in VALID_POLICIES:
        warnings.append(f"Invalid or missing p= in _dmarc.{target}")
    if sp and sp not in VALID_POLICIES:
        warnings.append(f"Invalid sp= in _dmarc.{target}")
    if np and np not in VALID_POLICIES:
        warnings.append(f"Invalid np= in _dmarc.{target}")
    if tags.get("psd", "").lower() not in {"", "y", "n"}:
        warnings.append(f"Invalid psd= in _dmarc.{target}")
    for removed in ("pct", "rf", "ri"):
        if removed in tags:
            warnings.append(f"{removed}= is removed in DMARCbis")
    if not tags.get("rua"):
        warnings.append("No rua= address on the inherited record.")

    if author_exists is False and np in VALID_POLICIES:
        base = np
    elif sp in VALID_POLICIES:
        base = sp
    else:
        base = p
    effective = _reduce_for_testing(base, testing)
    if testing == "y":
        warnings.append("t=y testing mode reduces the applied policy one level.")

    return InheritedPolicy(
        record=record,
        tags=tags,
        policy_domain=target,
        org_domain=org_domain,
        psd_domain=psd_domain,
        effective_p=effective,
        author_exists=author_exists,
        queries=queries,
        warnings=warnings,
        testing=testing,
        sp=sp,
        np=np,
    )
