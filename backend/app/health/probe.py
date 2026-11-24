"""Live transport probes: STARTTLS, certificate inspection and DANE.

Connections are made from a worker thread because the SMTP STARTTLS dance is
much clearer with a blocking socket. No authentication is attempted and no
message is ever sent.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
from contextlib import suppress
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from .dns import BaseDnsClient

SMTP_PORTS = {25, 587, 2525}
IMPLICIT_TLS_PORTS = {465, 993, 995, 443, 8443}

EXPIRY_WARN_DAYS = 21
EXPIRY_FAIL_DAYS = 7


def verification_context() -> ssl.SSLContext:
    """Prefer certifi's bundle: interpreter-bundled CA stores are often stale.

    httpx already depends on certifi, so this keeps probe trust aligned with the
    HTTP fetches (MTA-STS, BIMI) and with the container image.
    """
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:  # noqa: BLE001 - fall back to the interpreter store
        return ssl.create_default_context()


@dataclass(frozen=True)
class ProbeSpec:
    host: str
    port: int = 25
    mode: str = "smtp"


@dataclass
class ProbeOutcome:
    host: str
    port: int
    mode: str
    status: str = "unknown"
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    not_after: Optional[datetime] = None
    days_left: Optional[int] = None
    hostname_ok: Optional[bool] = None
    chain_ok: Optional[bool] = None
    dane_status: Optional[str] = None
    details: dict = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: int = 0


def parse_target(value: str) -> Optional[ProbeSpec]:
    """Parse ``host``, ``host:port`` or ``host:port:mode``."""
    raw = value.strip()
    if not raw:
        return None
    parts = raw.split(":")
    host = parts[0].strip()
    if not host:
        return None
    port = 25
    if len(parts) > 1 and parts[1].strip():
        try:
            port = int(parts[1])
        except ValueError:
            return None
    if not 1 <= port <= 65535:
        return None
    if len(parts) > 2 and parts[2].strip().lower() in {"smtp", "tls"}:
        mode = parts[2].strip().lower()
    else:
        mode = "smtp" if port in SMTP_PORTS else "tls"
    return ProbeSpec(host=host, port=port, mode=mode)


def targets_for(mx_values: list[str], extra: list[str]) -> list[ProbeSpec]:
    specs: list[ProbeSpec] = []
    for value in mx_values:
        _, _, host = value.partition(" ")
        host = host.strip().rstrip(".")
        if host and host != ".":
            specs.append(ProbeSpec(host=host, port=25, mode="smtp"))
    for value in extra:
        spec = parse_target(value)
        if spec is not None:
            specs.append(spec)
    seen: set[tuple[str, int]] = set()
    unique: list[ProbeSpec] = []
    for spec in specs:
        key = (spec.host.lower(), spec.port)
        if key in seen:
            continue
        seen.add(key)
        unique.append(spec)
    return unique


def _recv_line(sock: socket.socket, limit: int = 4096) -> str:
    data = bytearray()
    while len(data) < limit:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
        if chunk == b"\n":
            break
    return data.decode("utf-8", "replace").rstrip("\r\n")


def _recv_smtp_response(sock: socket.socket) -> str:
    lines: list[str] = []
    while True:
        line = _recv_line(sock)
        lines.append(line)
        if len(line) < 4 or line[3:4] != "-":
            break
    return "\n".join(lines)


def _open_tls(spec: ProbeSpec, context: ssl.SSLContext, timeout: float) -> ssl.SSLSocket:
    sock = socket.create_connection((spec.host, spec.port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        if spec.mode == "smtp":
            banner = _recv_line(sock)
            if not banner.startswith("220"):
                raise RuntimeError(f"unexpected SMTP banner: {banner[:120]!r}")
            sock.sendall("EHLO dmarcview.local\r\n".encode())
            capabilities = _recv_smtp_response(sock)
            if "starttls" not in capabilities.lower():
                raise RuntimeError("server does not advertise STARTTLS")
            sock.sendall(b"STARTTLS\r\n")
            response = _recv_line(sock)
            if not response.startswith("220"):
                raise RuntimeError(f"STARTTLS refused: {response[:120]!r}")
        return context.wrap_socket(sock, server_hostname=spec.host)
    except Exception:
        sock.close()
        raise


def _hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for name in names:
        candidate = name.lower().rstrip(".")
        if candidate == host:
            return True
        if candidate.startswith("*."):
            suffix = candidate[2:]
            if host.endswith("." + suffix) and host.count(".") == suffix.count(".") + 1:
                return True
    return False


def _cert_names(cert: x509.Certificate) -> list[str]:
    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names.extend(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    if not names:
        names.extend(
            attribute.value for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        )
    return names


def _inspect(cert: x509.Certificate, host: str) -> dict:
    public_key = cert.public_key()
    not_after = cert.not_valid_after_utc
    days_left = (not_after - datetime.now(timezone.utc)).days
    names = _cert_names(cert)
    spki = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "cert_subject": cert.subject.rfc4514_string()[:512],
        "cert_issuer": cert.issuer.rfc4514_string()[:512],
        "not_after": not_after,
        "days_left": days_left,
        "names": names,
        "hostname_match": _hostname_matches(host, names),
        "key_type": type(public_key).__name__,
        "key_bits": getattr(public_key, "key_size", None),
        "der": cert.public_bytes(serialization.Encoding.DER),
        "spki": spki,
    }


def probe_sync(spec: ProbeSpec, timeout: float = 8.0) -> ProbeOutcome:
    outcome = ProbeOutcome(host=spec.host, port=spec.port, mode=spec.mode)

    tls: Optional[ssl.SSLSocket] = None
    verification_error: Optional[str] = None
    try:
        try:
            tls = _open_tls(spec, verification_context(), timeout)
            outcome.chain_ok = True
            outcome.hostname_ok = True
        except ssl.SSLCertVerificationError as exc:
            verification_error = exc.verify_message or str(exc)
            outcome.chain_ok = False
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            tls = _open_tls(spec, context, timeout)
            outcome.hostname_ok = None
        except ssl.SSLError as exc:
            outcome.status = "fail"
            outcome.error = f"TLS handshake failed: {exc}"
            return outcome
    except RuntimeError as exc:
        outcome.status = "fail"
        outcome.error = str(exc)[:300]
        return outcome
    except (socket.timeout, TimeoutError):
        outcome.status = "fail"
        outcome.error = f"connection timed out after {timeout:.0f}s"
        return outcome
    except OSError as exc:
        outcome.status = "fail"
        outcome.error = f"connection failed: {exc}"
        return outcome

    try:
        assert tls is not None
        der = tls.getpeercert(binary_form=True)
        outcome.tls_version = tls.version()
        cipher = tls.cipher()
        outcome.cipher = cipher[0] if cipher else None
        if der:
            cert = x509.load_der_x509_certificate(der)
            info = _inspect(cert, spec.host)
            outcome.cert_subject = info["cert_subject"]
            outcome.cert_issuer = info["cert_issuer"]
            outcome.not_after = info["not_after"]
            outcome.days_left = info["days_left"]
            outcome.details = {
                "names": info["names"][:20],
                "key_type": info["key_type"],
                "key_bits": info["key_bits"],
                "der_sha256": hashlib.sha256(info["der"]).hexdigest(),
                "spki_sha256": hashlib.sha256(info["spki"]).hexdigest(),
            }
            if verification_error:
                outcome.hostname_ok = bool(info["hostname_match"])
            else:
                outcome.hostname_ok = True
        if spec.mode == "smtp":
            with suppress(OSError):
                tls.sendall(b"QUIT\r\n")
    except Exception as exc:  # noqa: BLE001 - report, never crash the batch
        outcome.status = "fail"
        outcome.error = f"could not inspect certificate: {exc}"
        return outcome
    finally:
        if tls is not None:
            with suppress(OSError):
                tls.close()

    details = outcome.details
    if verification_error:
        outcome.status = "fail"
        outcome.error = f"certificate verification failed: {verification_error}"
        if outcome.hostname_ok is False:
            outcome.error += " (hostname mismatch)"
        return outcome
    if outcome.days_left is not None and outcome.days_left < 0:
        outcome.status = "fail"
        outcome.error = f"certificate expired {abs(outcome.days_left)} days ago"
        return outcome
    if outcome.days_left is not None and outcome.days_left <= EXPIRY_FAIL_DAYS:
        outcome.status = "fail"
        outcome.error = f"certificate expires in {outcome.days_left} days"
        return outcome
    if outcome.days_left is not None and outcome.days_left <= EXPIRY_WARN_DAYS:
        outcome.status = "warn"
        outcome.error = f"certificate expires in {outcome.days_left} days"
        return outcome
    if outcome.tls_version in {"TLSv1", "TLSv1.1", "SSLv3"}:
        outcome.status = "warn"
        outcome.error = f"obsolete TLS version {outcome.tls_version}"
        return outcome
    if details.get("key_bits") and details["key_bits"] < 2048 and details.get("key_type") == "_RSAPublicKey":
        outcome.status = "warn"
        outcome.error = f"weak key ({details['key_bits']} bit)"
        return outcome

    outcome.status = "pass"
    return outcome


async def _dane_status(dns: BaseDnsClient, spec: ProbeSpec, outcome: ProbeOutcome) -> tuple[str, str]:
    lookup = await dns.tlsa(spec.host, spec.port)
    if lookup.error:
        return "unknown", lookup.error
    records = [value for value in lookup.values if value.strip()]
    if not records:
        return "none", ""

    der_sha = outcome.details.get("der_sha256")
    spki_sha = outcome.details.get("spki_sha256")
    if not der_sha:
        return "unknown", "no certificate to match"

    for record in records:
        parts = record.split()
        if len(parts) < 4:
            continue
        try:
            usage, selector, matching = int(parts[0]), int(parts[1]), int(parts[2])
        except ValueError:
            continue
        data = parts[3].lower()
        if usage != 3 or matching != 1:
            continue
        digest = spki_sha if selector == 1 else der_sha if selector == 0 else None
        if digest and digest == data:
            return "match", record
    return "mismatch", "TLSA records present but none match the presented certificate"


async def probe_target(
    spec: ProbeSpec,
    dns: Optional[BaseDnsClient] = None,
    timeout: float = 8.0,
) -> ProbeOutcome:
    started = time.perf_counter()
    outcome = await asyncio.to_thread(probe_sync, spec, timeout)
    outcome.duration_ms = int((time.perf_counter() - started) * 1000)
    if dns is not None and outcome.details.get("der_sha256"):
        dane_status, dane_detail = await _dane_status(dns, spec, outcome)
        outcome.dane_status = dane_status
        if dane_detail:
            outcome.details["dane_detail"] = dane_detail
        if dane_status == "mismatch":
            outcome.status = "fail"
            outcome.error = (outcome.error + "; " if outcome.error else "") + "DANE/TLSA mismatch"
    return outcome


async def probe_all(
    specs: list[ProbeSpec],
    dns: Optional[BaseDnsClient] = None,
    timeout: float = 8.0,
    concurrency: int = 3,
) -> list[ProbeOutcome]:
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def run(spec: ProbeSpec) -> ProbeOutcome:
        async with semaphore:
            return await probe_target(spec, dns, timeout)

    return list(await asyncio.gather(*(run(spec) for spec in specs)))
