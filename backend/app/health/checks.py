"""The individual domain health checks.

Each check is a small async function returning a :class:`CheckResult`. DNS and
HTTP access go through injected clients so tests run entirely on fixtures.
"""

from __future__ import annotations

import base64
import ipaddress
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

from cryptography.hazmat.primitives.serialization import load_der_public_key

from .dmarcbis import VALID_POLICIES, discover_inherited_policy
from .dns import BaseDnsClient
from .http import BaseFetcher
from .selectors import build_candidates
from .types import CheckResult, Status


@dataclass
class CheckContext:
    domain: str
    dns: BaseDnsClient
    http: BaseFetcher
    selectors: list[str] = field(default_factory=list)
    discovered_selectors: list[tuple[str, str]] = field(default_factory=list)
    reported_policy: dict = field(default_factory=dict)
    http_timeout: float = 6.0
    helo_hostname: str = ""


@dataclass(frozen=True)
class CheckSpec:
    key: str
    label: str
    core: bool
    runner: Callable[[CheckContext], Awaitable[CheckResult]]
    timeout: float = 20.0


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


def _result(
    key: str,
    label: str,
    status: Status,
    summary: str,
    *,
    core: bool = False,
    details: Optional[list[str]] = None,
    remediation: Optional[str] = None,
    evidence: Optional[dict] = None,
) -> CheckResult:
    return CheckResult(
        key=key,
        label=label,
        status=status,
        summary=summary,
        details=details or [],
        remediation=remediation,
        core=core,
        evidence=evidence or {},
    )


# --------------------------------------------------------------------- DMARC
def _mailto_domain(uri: str) -> Optional[str]:
    value = uri.strip()
    if not value.lower().startswith("mailto:"):
        return None
    address = value[7:].split("!", 1)[0].strip()
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().strip(".").lower() or None


def _destinations(value: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for uri in (value or "").split(","):
        domain = _mailto_domain(uri)
        if domain:
            out.append((uri.strip(), domain))
    return out[:10]


async def _report_authorizations(
    dns: BaseDnsClient, policy_domain: str, rua: str, ruf: str
) -> list[dict]:
    """RFC 9990/9991 external destination verification for rua=/ruf=."""
    policy_domain = policy_domain.strip(".").lower()
    results: list[dict] = []
    for kind, value in (("rua", rua), ("ruf", ruf)):
        for uri, domain in _destinations(value):
            internal = domain == policy_domain or domain.endswith("." + policy_domain)
            item = {
                "kind": kind,
                "uri": uri,
                "domain": domain,
                "external": not internal,
                "authorized": True,
                "record": None,
                "error": None,
                "query": None,
            }
            if not internal:
                query = f"_report._dmarc.{domain}"
                item["query"] = query
                lookup = await dns.txt(query)
                item["error"] = lookup.error
                valid = [
                    record.strip()
                    for record in lookup.values
                    if record.strip().lower().startswith("v=dmarc1")
                ]
                item["authorized"] = bool(valid)
                item["record"] = valid[0] if valid else None
            results.append(item)
    return results


def _effective_policy(policy: str, testing: str) -> str:
    if testing != "y":
        return policy
    return {"reject": "quarantine", "quarantine": "none"}.get(policy, policy)


async def _inherited_result(ctx: CheckContext, inherited) -> CheckResult:
    tags = inherited.tags
    p = tags.get("p", "").lower()
    sp = (tags.get("sp") or p).lower()
    details = [
        f"No DMARC record at _dmarc.{ctx.domain}",
        f"Policy found at _dmarc.{inherited.policy_domain} via tree walk",
        f"org={inherited.org_domain}"
        + (f" · psd={inherited.psd_domain}" if inherited.psd_domain else ""),
        f"p={p or 'missing'} · sp={sp or 'missing'} · np={inherited.np or 'missing'}",
        f"effective={inherited.effective_p or 'none'}"
        + (f" · t={inherited.testing}" if inherited.testing else ""),
        f"rua={tags.get('rua') or 'none'}",
    ]
    if inherited.queries:
        details.append("Tree walk: " + " → ".join(inherited.queries))
    evidence = {
        "record": inherited.record,
        "p": p,
        "sp": sp,
        "np": inherited.np,
        "testing": inherited.testing,
        "psd": (tags.get("psd") or "").lower(),
        "effective_p": inherited.effective_p,
        "policy_domain": inherited.policy_domain,
        "org_domain": inherited.org_domain,
        "psd_domain": inherited.psd_domain,
        "discovery_method": "treewalk",
        "author_exists": inherited.author_exists,
        "rua": tags.get("rua", ""),
    }
    if inherited.effective_p not in VALID_POLICIES:
        return _result(
            "dmarc",
            "DMARC",
            Status.FAIL,
            "Inherited DMARC record has no valid policy",
            core=True,
            details=details + inherited.warnings,
            remediation="Fix p= (and sp=/np=) on the inherited DMARC record.",
            evidence=evidence,
        )
    external = await _report_authorizations(
        ctx.dns, inherited.policy_domain, tags.get("rua", ""), tags.get("ruf", "")
    )
    warnings = [
        f"No record at _dmarc.{ctx.domain}; inheriting from _dmarc.{inherited.policy_domain}."
    ] + inherited.warnings
    for item in external:
        if item["external"] and not item["authorized"]:
            warnings.append(
                f"External {item['kind']} destination {item['domain']} is not authorized "
                f"(publish {item['query']} TXT v=DMARC1)."
            )
    evidence["external_destinations"] = external
    evidence["deprecated_tags"] = [
        tag for tag in ("pct", "rf", "ri") if tag in tags
    ]
    reported = (ctx.reported_policy or {}).get("p")
    if reported and reported != p:
        warnings.append(f"Receivers report p={reported}, inherited DNS says p={p}.")
    return _result(
        "dmarc",
        "DMARC",
        Status.WARN,
        f"Inherited p={p} (effective {inherited.effective_p}) from {inherited.policy_domain}",
        core=True,
        details=details + warnings,
        remediation=(
            f"Publish a record at _dmarc.{ctx.domain} if this subdomain needs its own policy. "
            "Otherwise confirm the inherited policy is intended."
        ),
        evidence=evidence,
    )


async def check_dmarc(ctx: CheckContext) -> CheckResult:
    lookup = await ctx.dns.txt(f"_dmarc.{ctx.domain}")
    if lookup.error:
        return _result("dmarc", "DMARC", Status.UNKNOWN, f"DNS lookup failed: {lookup.error}", core=True)

    records = [value.strip() for value in lookup.values if value.strip().lower().startswith("v=dmarc1")]
    if not records:
        inherited = await discover_inherited_policy(ctx.dns, ctx.domain)
        if inherited is not None:
            return await _inherited_result(ctx, inherited)
        return _result(
            "dmarc",
            "DMARC",
            Status.FAIL,
            "No DMARC record published",
            core=True,
            details=[f"Checked TXT _dmarc.{ctx.domain}", "Aggregate reports cannot be requested without rua="],
            remediation="Publish a TXT record at _dmarc.<domain> starting with v=DMARC1; p=none; rua=mailto:dmarc@<domain>.",
        )
    if len(records) > 1:
        return _result(
            "dmarc",
            "DMARC",
            Status.FAIL,
            f"{len(records)} DMARC records published — receivers will ignore all but one",
            core=True,
            details=records,
            remediation="Keep exactly one DMARC TXT record.",
        )

    tags = parse_tags(records[0])
    p = tags.get("p", "").lower()
    sp = (tags.get("sp") or p).lower()
    np = (tags.get("np") or "").lower()
    testing = (tags.get("t") or "").lower()
    psd = (tags.get("psd") or "").lower()
    pct = tags.get("pct", "100")
    rua = tags.get("rua", "")
    effective = _effective_policy(p, testing)

    details = [
        f"p={p or 'missing'}",
        f"sp={sp or 'missing'}",
        f"np={np or 'missing'}",
        f"pct={pct} (legacy)",
        f"t={testing or 'n'} · psd={psd or 'unset'}",
        f"adkim={tags.get('adkim', 'r')} · aspf={tags.get('aspf', 'r')}",
        f"rua={rua or 'none'}",
    ]
    notes: list[str] = []
    if "pct" in tags:
        notes.append("pct= is removed in DMARCbis; legacy receivers may still apply it.")
    if "rf" in tags:
        notes.append("rf= is removed in DMARCbis.")
    if "ri" in tags:
        notes.append("ri= is removed in DMARCbis.")
    if np:
        notes.append("np= applies to non-existent subdomains; it has no effect on the author domain.")
    evidence = {
        "record": records[0],
        "p": p,
        "sp": sp,
        "np": np,
        "pct": pct,
        "testing": testing,
        "psd": psd,
        "effective_p": effective,
        "discovery_method": "author",
        "policy_domain": ctx.domain,
        "org_domain": ctx.domain,
        "rua": rua,
    }

    if p not in VALID_POLICIES:
        return _result(
            "dmarc",
            "DMARC",
            Status.FAIL,
            "Invalid or missing p= policy",
            core=True,
            details=details + notes,
            remediation="Set p=none, p=quarantine or p=reject.",
            evidence=evidence,
        )

    warnings: list[str] = []
    external = await _report_authorizations(ctx.dns, ctx.domain, rua, tags.get("ruf", ""))
    for item in external:
        if item["external"] and not item["authorized"]:
            warnings.append(
                f"External {item['kind']} destination {item['domain']} is not authorized "
                f"(publish {item['query']} TXT v=DMARC1)."
            )
    evidence["external_destinations"] = external
    evidence["deprecated_tags"] = [
        tag for tag in ("pct", "rf", "ri") if tag in tags
    ]

    if not rua:
        warnings.append("No rua= address; you will not receive aggregate reports.")
    if p == "none":
        warnings.append("Policy is p=none: failing mail is still delivered.")
    if sp and sp not in VALID_POLICIES:
        warnings.append(f"Invalid sp={sp}; subdomains fall back to p={p}.")
    if np and np not in VALID_POLICIES:
        warnings.append(f"Invalid np={np}; non-existent subdomains fall back to p={p}.")
    if psd and psd not in {"y", "n"}:
        warnings.append(f"Invalid psd={psd}; expected y or n.")
    if testing == "y":
        warnings.append(f"Testing mode t=y reduces the applied policy to {effective}.")
    reported = (ctx.reported_policy or {}).get("p")
    if reported and reported != p:
        warnings.append(f"Receivers report p={reported}, DNS says p={p} — the record changed recently.")
    if pct not in {"100", ""}:
        warnings.append(f"pct={pct} applies the policy to a fraction of mail.")

    if warnings:
        return _result(
            "dmarc",
            "DMARC",
            Status.WARN,
            f"p={p}" + (f" (testing → {effective})" if testing == "y" else ""),
            core=True,
            details=details + notes + warnings,
            remediation=(
                "Move to p=quarantine, then p=reject, once the sending sources look clean."
                if p == "none"
                else "Add a rua= address so aggregate reports reach you."
                if not rua
                else None
            ),
            evidence=evidence,
        )

    return _result(
        "dmarc",
        "DMARC",
        Status.PASS,
        f"p={p} · reports to {rua.split(',')[0].strip()}",
        core=True,
        details=details + notes,
        evidence=evidence,
    )


# ----------------------------------------------------------------------- SPF
@dataclass
class SpfEvaluation:
    record: Optional[str] = None
    lookups: int = 0
    voids: int = 0
    all_qualifier: Optional[str] = None
    includes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


async def evaluate_spf(
    ctx: CheckContext,
    domain: str,
    depth: int = 0,
    path: frozenset[str] = frozenset(),
) -> SpfEvaluation:
    if depth > 10:
        return SpfEvaluation(errors=["include chain deeper than 10 levels"])
    if domain in path:
        return SpfEvaluation(errors=[f"include loop through {domain}"])

    lookup = await ctx.dns.txt(domain)
    if lookup.error:
        return SpfEvaluation(errors=[f"DNS error for {domain}: {lookup.error}"])
    records = [value.strip() for value in lookup.values if value.strip().lower().startswith("v=spf1")]
    if not records:
        return SpfEvaluation(voids=1)
    if len(records) > 1:
        return SpfEvaluation(record=records[0], errors=[f"multiple SPF records at {domain}"])

    record = records[0]
    result = SpfEvaluation(record=record)
    terms = record.split()[1:]
    child_path = path | {domain}

    for term in terms:
        qualifier = term[0] if term[:1] in "+-~?" else "+"
        body = term[1:] if term[:1] in "+-~?" else term
        low = body.lower()
        if low.startswith(("ip4:", "ip6:")):
            continue
        if low == "all" or low.startswith("all/"):
            result.all_qualifier = qualifier
            continue
        if low.startswith("redirect="):
            target = body.split("=", 1)[1]
            result.lookups += 1
            child = await evaluate_spf(ctx, target, depth + 1, child_path)
            result.lookups += child.lookups
            result.voids += child.voids
            result.includes.append(f"redirect:{target}")
            result.errors.extend(child.errors)
            continue

        mechanism = low.split(":", 1)[0].split("/", 1)[0]
        if mechanism not in {"include", "a", "mx", "ptr", "exists"}:
            continue

        result.lookups += 1
        target = domain
        if ":" in body:
            target = body.split(":", 1)[1].split("/", 1)[0]
        if "%" in target or not target:
            result.errors.append(f"macro or empty domain in {term!r} is not evaluated")
            continue

        if mechanism == "include":
            child = await evaluate_spf(ctx, target, depth + 1, child_path)
            result.lookups += child.lookups
            result.voids += child.voids
            result.includes.append(f"include:{target}")
            result.errors.extend(child.errors)
        elif mechanism in {"a", "mx", "exists"}:
            if mechanism == "a":
                answer = await ctx.dns.addresses(target)
            elif mechanism == "mx":
                answer = await ctx.dns.mx(target)
            else:
                answer = await ctx.dns.addresses(target)
            if not answer.values and not answer.error:
                result.voids += 1
        # ptr lookups are counted but not evaluated (deprecated and slow).

        if result.lookups > 50:
            result.errors.append("lookup limit exceeded while evaluating")
            break

    return result


async def check_spf(ctx: CheckContext) -> CheckResult:
    evaluation = await evaluate_spf(ctx, ctx.domain)
    if evaluation.record is None:
        if evaluation.errors:
            return _result("spf", "SPF", Status.UNKNOWN, evaluation.errors[0], core=True)
        return _result(
            "spf",
            "SPF",
            Status.FAIL,
            "No SPF record published",
            core=True,
            remediation=f"Publish v=spf1 <your senders> -all as a TXT record at {ctx.domain}.",
        )

    details = [
        f"{evaluation.lookups} DNS lookups (limit 10)",
        f"{evaluation.voids} void lookups (limit 2)",
        f"all: {evaluation.all_qualifier or 'missing'}",
    ]
    if evaluation.includes:
        details.append("includes: " + ", ".join(evaluation.includes[:8]))
    details.extend(evaluation.errors[:4])
    evidence = {
        "record": evaluation.record,
        "lookups": evaluation.lookups,
        "voids": evaluation.voids,
        "all": evaluation.all_qualifier,
        "includes": evaluation.includes,
    }

    if evaluation.lookups > 10:
        return _result(
            "spf",
            "SPF",
            Status.FAIL,
            f"Too many DNS lookups ({evaluation.lookups}/10) — receivers return permerror",
            core=True,
            details=details,
            remediation="Flatten the record or remove unused includes so the total stays at or below 10.",
            evidence=evidence,
        )
    if evaluation.voids > 2:
        return _result(
            "spf",
            "SPF",
            Status.FAIL,
            f"Too many void lookups ({evaluation.voids}/2)",
            core=True,
            details=details,
            remediation="Remove mechanisms and includes that point at non-existent domains.",
            evidence=evidence,
        )
    if evaluation.errors:
        return _result(
            "spf",
            "SPF",
            Status.WARN,
            evaluation.errors[0],
            core=True,
            details=details,
            evidence=evidence,
        )
    if evaluation.all_qualifier in {"+", "?"}:
        return _result(
            "spf",
            "SPF",
            Status.WARN,
            f"all qualifier is '{evaluation.all_qualifier}' — this does not protect the domain",
            core=True,
            details=details,
            remediation="End the record with -all (or ~all while testing).",
            evidence=evidence,
        )
    if evaluation.all_qualifier is None:
        return _result(
            "spf",
            "SPF",
            Status.WARN,
            "Record has no all mechanism",
            core=True,
            details=details,
            remediation="End the record with -all.",
            evidence=evidence,
        )
    if evaluation.lookups >= 9:
        return _result(
            "spf",
            "SPF",
            Status.WARN,
            f"{evaluation.lookups}/10 DNS lookups used",
            core=True,
            details=details,
            remediation="One more include will break the record.",
            evidence=evidence,
        )
    return _result(
        "spf",
        "SPF",
        Status.PASS,
        f"{evaluation.lookups}/10 lookups · {evaluation.all_qualifier}all",
        core=True,
        details=details,
        evidence=evidence,
    )


# ---------------------------------------------------------------------- DKIM
def dkim_key_info(tags: dict[str, str]) -> tuple[str, Optional[int]]:
    key_type = tags.get("k", "rsa").lower()
    raw = tags.get("p", "").replace(" ", "").replace("\n", "")
    if not raw:
        return key_type, None
    try:
        der = base64.b64decode(raw + "=" * (-len(raw) % 4))
        key = load_der_public_key(der)
        return key_type, getattr(key, "key_size", None)
    except Exception:  # noqa: BLE001 - malformed keys are reported, not fatal
        return key_type, None


async def check_dkim(ctx: CheckContext) -> CheckResult:
    from datetime import date as _date

    candidates = build_candidates(
        ctx.selectors,
        ctx.domain,
        ctx.discovered_selectors,
        _date.today(),
    )
    found: list[tuple[str, str, dict[str, str], Optional[int]]] = []
    revoked: list[str] = []
    lookup_errors = 0

    for candidate in candidates:
        lookup = await ctx.dns.txt(f"{candidate.selector}._domainkey.{candidate.domain}")
        if lookup.error:
            lookup_errors += 1
            continue
        for value in lookup.values:
            tags = parse_tags(value)
            if "p" not in tags and "k" not in tags:
                continue
            if not tags.get("p"):
                revoked.append(f"{candidate.selector}@{candidate.domain}")
                continue
            key_type, bits = dkim_key_info(tags)
            found.append((candidate.selector, candidate.domain, tags, bits))

    counts = {source: sum(1 for item in candidates if item.source == source) for source in
              ("configured", "report", "rotation")}
    details = [
        f"checked {len(candidates)} selectors "
        f"({counts['configured']} configured, {counts['report']} from reports, "
        f"{counts['rotation']} rotation candidates)"
    ]
    if found:
        details.extend(
            f"{selector}@{domain}: {tags.get('k', 'rsa')}"
            + (f" {bits} bit" if bits else "")
            + (" (testing flag t=y)" if tags.get("t", "").lower().startswith("y") else "")
            for selector, domain, tags, bits in found
        )
    if revoked:
        details.extend(f"{item}: key revoked (empty p=)" for item in revoked[:3])
    evidence = {
        "selectors": [
            {"selector": selector, "domain": domain, "type": tags.get("k", "rsa"), "bits": bits}
            for selector, domain, tags, bits in found
        ],
        "candidates": [
            {"selector": item.selector, "domain": item.domain, "source": item.source}
            for item in candidates
        ],
        "checked": len(candidates),
    }

    if not candidates:
        return _result(
            "dkim",
            "DKIM",
            Status.FAIL,
            "No DKIM selectors configured or discovered",
            core=True,
            remediation=(
                "Sync a few DMARC reports (selectors are discovered from auth_results), or add "
                "your selector names in the domain settings."
            ),
            evidence=evidence,
        )

    if not found:
        if lookup_errors == len(candidates):
            return _result(
                "dkim",
                "DKIM",
                Status.UNKNOWN,
                "DNS lookups failed",
                core=True,
                details=details,
                evidence=evidence,
            )
        return _result(
            "dkim",
            "DKIM",
            Status.FAIL,
            "No DKIM key at the configured or discovered selectors",
            core=True,
            details=details,
            remediation=(
                "Selectors are discovered from report auth_results automatically. If your MTA "
                "rotated to a key no report has seen yet, add the selector here or wait for the "
                "next report."
            ),
            evidence=evidence,
        )

    weak = [f"{selector}@{domain} ({bits} bit)" for selector, domain, _, bits in found if bits and bits < 2048]
    testing = [f"{selector}@{domain}" for selector, domain, tags, _ in found if tags.get("t", "").lower().startswith("y")]
    if weak:
        return _result(
            "dkim",
            "DKIM",
            Status.WARN,
            f"Weak key: {', '.join(weak)}",
            core=True,
            details=details,
            remediation="Rotate to a 2048-bit RSA or Ed25519 DKIM key.",
            evidence=evidence,
        )
    if testing:
        return _result(
            "dkim",
            "DKIM",
            Status.WARN,
            f"Testing flag set (t=y) on {', '.join(testing)}",
            core=True,
            details=details,
            evidence=evidence,
        )
    label = ", ".join(selector for selector, _, _, _ in found[:3])
    if len(found) > 3:
        label += f" +{len(found) - 3}"
    return _result(
        "dkim",
        "DKIM",
        Status.PASS,
        f"{len(found)} key{'s' if len(found) != 1 else ''} found ({label})",
        core=True,
        details=details,
        evidence=evidence,
    )


# ------------------------------------------------------------------------ MX
async def check_mx(ctx: CheckContext) -> CheckResult:
    lookup = await ctx.dns.mx(ctx.domain)
    if lookup.error:
        return _result("mx", "MX", Status.UNKNOWN, f"DNS lookup failed: {lookup.error}", core=True)
    if not lookup.values:
        return _result(
            "mx",
            "MX",
            Status.FAIL,
            "No MX records — this domain cannot receive mail",
            core=True,
            remediation="Publish MX records pointing at your Stalwart host, or a null MX (0 .) if the domain does not receive mail.",
        )

    hosts: list[tuple[int, str]] = []
    for value in lookup.values:
        priority, _, host = value.partition(" ")
        host = host.strip().rstrip(".")
        try:
            hosts.append((int(priority), host))
        except ValueError:
            hosts.append((0, value.strip()))

    null_mx = [host for _, host in hosts if host in {"", "."}]
    if null_mx:
        return _result(
            "mx",
            "MX",
            Status.INFO,
            "Null MX published — the domain does not receive mail",
            core=True,
            details=[f"{priority} {host}" for priority, host in hosts],
        )

    details: list[str] = []
    unresolved: list[str] = []
    ptr_mismatch: list[str] = []
    for priority, host in sorted(hosts):
        answer = await ctx.dns.addresses(host)
        if answer.error:
            details.append(f"{priority} {host}: lookup failed ({answer.error})")
            unresolved.append(host)
            continue
        if not answer.values:
            details.append(f"{priority} {host}: no A/AAAA record")
            unresolved.append(host)
            continue
        details.append(f"{priority} {host} → {', '.join(answer.values[:3])}")
        for address in answer.values[:3]:
            reverse = await ctx.dns.ptr(address)
            names = [value.rstrip(".").lower() for value in (reverse.values or [])]
            if reverse.error:
                details.append(f"  {address}: PTR lookup failed ({reverse.error})")
            elif names and host.lower() not in names:
                details.append(f"  {address}: PTR {', '.join(names[:2])}")
                ptr_mismatch.append(host)
            elif not names:
                details.append(f"  {address}: PTR none")

    if unresolved:
        return _result(
            "mx",
            "MX",
            Status.FAIL,
            f"{len(unresolved)} MX host{'s' if len(unresolved) != 1 else ''} do not resolve",
            core=True,
            details=details,
            remediation="Fix the MX targets or remove them; senders cannot deliver to a host without an address.",
        )

    if ptr_mismatch:
        return _result(
            "mx",
            "MX",
            Status.WARN,
            "MX host PTR does not confirm its hostname",
            core=True,
            details=details,
            remediation="Give each MX address a PTR matching the MX hostname (forward-confirmed rDNS).",
        )

    return _result(
        "mx",
        "MX",
        Status.PASS,
        f"{len(hosts)} MX host{'s' if len(hosts) != 1 else ''}",
        core=True,
        details=details,
    )


# ------------------------------------------------------------------- MTA-STS
async def check_mta_sts(ctx: CheckContext) -> CheckResult:
    lookup = await ctx.dns.txt(f"_mta-sts.{ctx.domain}")
    if lookup.error:
        return _result("mta_sts", "MTA-STS", Status.UNKNOWN, f"DNS lookup failed: {lookup.error}")
    records = [value for value in lookup.values if value.strip().lower().startswith("v=stsv1")]
    if not records:
        return _result(
            "mta_sts",
            "MTA-STS",
            Status.INFO,
            "Not published",
            remediation="Optional, but it lets senders insist on TLS. Publish _mta-sts TXT and a policy at mta-sts.<domain>.",
        )

    tags = parse_tags(records[0])
    policy_id = tags.get("id", "").strip()
    if not policy_id:
        return _result(
            "mta_sts",
            "MTA-STS",
            Status.FAIL,
            "TXT record has no id=",
            remediation="Add a change marker, e.g. id=20261124000000Z, and update it whenever the policy changes.",
        )

    url = f"https://mta-sts.{ctx.domain}/.well-known/mta-sts.txt"
    fetched = await ctx.http.get(url, max_bytes=65536, timeout=ctx.http_timeout)
    if not fetched.ok:
        return _result(
            "mta_sts",
            "MTA-STS",
            Status.FAIL,
            f"Policy not reachable ({fetched.error or fetched.status})",
            details=[url, f"published id={policy_id}"],
            remediation="Serve the policy over HTTPS at the well-known URL.",
        )

    body = fetched.body
    lines = body.decode("utf-8", "replace").splitlines()
    fields: dict[str, str] = {}
    mx_hosts: list[str] = []
    for line in lines:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "mx":
            mx_hosts.append(value.lower())
        elif key:
            fields[key] = value

    mode = fields.get("mode", "").lower()
    max_age = fields.get("max_age", "")
    details = [
        f"mode={mode or 'missing'}",
        f"max_age={max_age or 'missing'}",
        "mx: " + (", ".join(mx_hosts[:5]) if mx_hosts else "missing"),
        f"id={policy_id}",
    ]
    evidence = {"mode": mode, "max_age": max_age, "mx": mx_hosts, "id": policy_id}

    if fields.get("version", "").lower() != "stsv1":
        return _result("mta_sts", "MTA-STS", Status.FAIL, "Policy version is not STSv1", details=details)
    if mode not in {"enforce", "testing", "none"}:
        return _result("mta_sts", "MTA-STS", Status.FAIL, f"Invalid mode {mode!r}", details=details)
    if not mx_hosts:
        return _result("mta_sts", "MTA-STS", Status.FAIL, "Policy has no mx: entries", details=details)

    mx_lookup = await ctx.dns.mx(ctx.domain)
    live_mx = {
        value.partition(" ")[2].strip().rstrip(".").lower()
        for value in (mx_lookup.values or [])
        if value.partition(" ")[2].strip().rstrip(".") not in {"", "."}
    }
    policy_mx = {host.rstrip(".").lower() for host in mx_hosts if host.strip()}
    if mx_lookup.error:
        details.append(f"DNS MX lookup failed: {mx_lookup.error}")
    elif not live_mx:
        details.append("DNS MX: none")
    else:
        details.append("DNS MX: " + ", ".join(sorted(live_mx)[:5]))
        missing = sorted(policy_mx - live_mx)
        extra = sorted(live_mx - policy_mx)
        if missing or extra:
            evidence["dns_mx"] = sorted(live_mx)
            parts = []
            if missing:
                parts.append("not in DNS MX: " + ", ".join(missing[:3]))
            if extra:
                parts.append("missing from policy: " + ", ".join(extra[:3]))
            return _result(
                "mta_sts",
                "MTA-STS",
                Status.WARN,
                "Policy MX list does not match DNS MX",
                details=details + parts,
                remediation="Make the policy mx: entries exactly match the domain's live MX hostnames.",
                evidence=evidence,
            )

    try:
        age = int(max_age)
    except ValueError:
        age = 0
    if mode != "enforce":
        return _result(
            "mta_sts",
            "MTA-STS",
            Status.WARN,
            f"mode={mode} — TLS is not enforced",
            details=details,
            remediation="Switch to mode: enforce once every MX host presents a valid certificate.",
            evidence=evidence,
        )
    if age < 86400:
        return _result(
            "mta_sts",
            "MTA-STS",
            Status.WARN,
            f"max_age is only {age}s",
            details=details,
            evidence=evidence,
        )
    return _result(
        "mta_sts",
        "MTA-STS",
        Status.PASS,
        f"enforce · {len(mx_hosts)} mx host{'s' if len(mx_hosts) != 1 else ''}",
        details=details,
        evidence=evidence,
    )


# -------------------------------------------------------------------- TLS-RPT
async def check_tlsrpt(ctx: CheckContext) -> CheckResult:
    lookup = await ctx.dns.txt(f"_smtp._tls.{ctx.domain}")
    if lookup.error:
        return _result("tls_rpt", "TLS-RPT", Status.UNKNOWN, f"DNS lookup failed: {lookup.error}")
    records = [value for value in lookup.values if value.strip().lower().startswith("v=tlsrptv1")]
    if not records:
        return _result(
            "tls_rpt",
            "TLS-RPT",
            Status.INFO,
            "Not published",
            remediation="Publish a TXT record at _smtp._tls.<domain> with v=TLSRPTv1; rua=mailto:tlsrpt@<domain>.",
        )

    tags = parse_tags(records[0])
    rua = tags.get("rua", "")
    if not rua:
        return _result(
            "tls_rpt",
            "TLS-RPT",
            Status.FAIL,
            "Record has no rua= address",
            details=[records[0]],
            remediation="Add rua=mailto:tlsrpt@<domain>.",
        )
    return _result(
        "tls_rpt",
        "TLS-RPT",
        Status.PASS,
        f"reports to {rua.split(',')[0].strip()}",
        details=[f"rua={rua}"],
    )


# -------------------------------------------------------------------- DNSSEC
async def check_dnssec(ctx: CheckContext) -> CheckResult:
    lookup = await ctx.dns.ds(ctx.domain)
    if lookup.error:
        return _result("dnssec", "DNSSEC", Status.UNKNOWN, f"DNS lookup failed: {lookup.error}")
    if not lookup.values:
        return _result(
            "dnssec",
            "DNSSEC",
            Status.INFO,
            "Zone is not signed",
            remediation="Optional for mail, but it enables DANE and protects the records themselves.",
        )
    if not lookup.ad:
        return _result(
            "dnssec",
            "DNSSEC",
            Status.WARN,
            "DS record exists but the resolver did not validate it",
            remediation="Check the DS/RRSIG chain, or point DNS_NAMESERVERS at a validating resolver.",
        )
    return _result("dnssec", "DNSSEC", Status.PASS, "signed and validated", details=["AD flag set"])


# ------------------------------------------------------------------------ CAA
async def check_caa(ctx: CheckContext) -> CheckResult:
    lookup = await ctx.dns.caa(ctx.domain)
    if lookup.error:
        return _result("caa", "CAA", Status.UNKNOWN, f"DNS lookup failed: {lookup.error}")
    records = [value.strip() for value in (lookup.values or []) if value.strip()]
    if not records:
        return _result(
            "caa",
            "CAA",
            Status.INFO,
            "Not published",
            remediation="Optional. A CAA policy restricts which CAs may issue certificates for the domain.",
        )
    details = records[:8]
    issue = [value for value in records if any(tag in value.lower() for tag in (" issue", " issuewild"))]
    if not issue:
        return _result(
            "caa",
            "CAA",
            Status.WARN,
            "CAA has no issue/issuewild policy",
            details=details,
            remediation="Add an issue tag for your CA, or an empty issue policy to deny all issuance.",
        )
    return _result("caa", "CAA", Status.PASS, f"CAA policy published ({len(issue)} issuer rules)", details=details)


# ------------------------------------------------------------------ HELO/EHLO
async def check_helo(ctx: CheckContext) -> CheckResult:
    host = (ctx.helo_hostname or "").strip().lower().rstrip(".")
    if not host:
        return _result(
            "helo",
            "HELO/EHLO DNS",
            Status.INFO,
            "Not configured",
            remediation="Set HELO_HOSTNAME (or the domain setting) to the EHLO/HELO FQDN Stalwart actually sends; this check only validates its DNS.",
        )
    if "." not in host or " " in host or host.startswith("-") or host.endswith("-"):
        return _result(
            "helo",
            "HELO/EHLO DNS",
            Status.FAIL,
            f"{host!r} is not a valid FQDN",
            remediation="Use a fully qualified hostname such as mail.example.com.",
        )
    try:
        ipaddress.ip_address(host)
        return _result(
            "helo",
            "HELO/EHLO DNS",
            Status.FAIL,
            "HELO/EHLO must be a hostname, not an IP address",
            remediation="Use a fully qualified hostname such as mail.example.com.",
        )
    except ValueError:
        pass

    answer = await ctx.dns.addresses(host)
    if answer.error:
        return _result("helo", "HELO/EHLO DNS", Status.UNKNOWN, f"Forward lookup failed: {answer.error}")
    addresses = [value for value in (answer.values or []) if value.strip()]
    if not addresses:
        return _result(
            "helo",
            "HELO/EHLO DNS",
            Status.FAIL,
            f"{host} has no A/AAAA record",
            remediation="Publish forward DNS for the HELO hostname before using it in SMTP.",
        )

    details = ["forward: " + ", ".join(addresses[:3])]
    confirmed = 0
    for address in addresses[:3]:
        reverse = await ctx.dns.ptr(address)
        if reverse.error:
            details.append(f"{address}: PTR lookup failed ({reverse.error})")
            continue
        names = [value.rstrip(".").lower() for value in (reverse.values or [])]
        details.append(f"{address}: PTR {', '.join(names[:2]) if names else 'none'}")
        if host not in names:
            continue
        forward = await ctx.dns.addresses(host)
        if forward.error:
            details.append(f"{host}: forward confirmation failed ({forward.error})")
        elif address in (forward.values or []):
            confirmed += 1

    if confirmed == len(addresses[:3]):
        return _result(
            "helo",
            "HELO/EHLO DNS",
            Status.PASS,
            "DNS preflight: FQDN with forward-confirmed reverse DNS",
            details=details,
            evidence={"hostname": host, "addresses": addresses[:3]},
        )
    return _result(
        "helo",
        "HELO/EHLO DNS",
        Status.WARN,
        "DNS preflight: HELO name is not forward-confirmed by every address",
        details=details,
        remediation="Point the HELO hostname at your sending IPs and give those IPs matching PTR records.",
        evidence={"hostname": host, "addresses": addresses[:3]},
    )


# ---------------------------------------------------------------------- BIMI
async def check_bimi(ctx: CheckContext) -> CheckResult:
    lookup = await ctx.dns.txt(f"default._bimi.{ctx.domain}")
    if lookup.error:
        return _result("bimi", "BIMI", Status.UNKNOWN, f"DNS lookup failed: {lookup.error}")
    records = [value for value in lookup.values if value.strip().lower().startswith("v=bimi1")]
    if not records:
        return _result(
            "bimi",
            "BIMI",
            Status.INFO,
            "Not published",
            remediation="Optional. Requires DMARC enforcement, a BIMI logo and often a VMC.",
        )

    tags = parse_tags(records[0])
    logo = tags.get("l", "")
    vmc = tags.get("a", "")
    details = [f"l={logo or 'missing'}", f"a={vmc or 'missing'}"]
    if not logo:
        return _result(
            "bimi",
            "BIMI",
            Status.WARN,
            "Record has no logo (l=)",
            details=details,
            remediation="Publish an SVG Tiny PS logo URL.",
        )

    fetched = await ctx.http.get(logo, max_bytes=65536, timeout=ctx.http_timeout)
    if not fetched.ok:
        return _result(
            "bimi",
            "BIMI",
            Status.WARN,
            f"Logo not reachable ({fetched.error or fetched.status})",
            details=details,
            remediation="Host a publicly readable SVG (SVG Tiny 1.2 PS).",
        )
    content_type = (fetched.content_type or "").split(";")[0].strip().lower()
    if "svg" not in content_type:
        return _result(
            "bimi",
            "BIMI",
            Status.WARN,
            f"Logo is served as {content_type or 'unknown type'}",
            details=details,
            remediation="Serve the logo with Content-Type: image/svg+xml.",
        )
    details.append(f"logo: {len(fetched.body)} bytes")
    if vmc:
        details.append("VMC present (not verified)")
    return _result("bimi", "BIMI", Status.PASS, "logo published", details=details)


CHECKS: tuple[CheckSpec, ...] = (
    CheckSpec("dmarc", "DMARC", True, check_dmarc),
    CheckSpec("spf", "SPF", True, check_spf),
    CheckSpec("dkim", "DKIM", True, check_dkim),
    CheckSpec("mx", "MX", True, check_mx),
    CheckSpec("mta_sts", "MTA-STS", False, check_mta_sts),
    CheckSpec("tls_rpt", "TLS-RPT", False, check_tlsrpt),
    CheckSpec("dnssec", "DNSSEC", False, check_dnssec),
    CheckSpec("bimi", "BIMI", False, check_bimi),
    CheckSpec("caa", "CAA", False, check_caa),
    CheckSpec("helo", "HELO/EHLO DNS", False, check_helo),
)
