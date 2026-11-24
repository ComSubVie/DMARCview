"""MIME plumbing: turn a raw report e-mail into report payloads.

Reporters are creative.  In the wild you will see:

* ``application/zip`` attachments (one or several XML files inside)
* ``application/gzip`` / ``application/x-gzip`` (``.xml.gz``, ``.json.gz``)
* ``application/tlsrpt+gzip`` and ``application/tlsrpt+json``
* the report inlined as the plain-text body
* ``application/octet-stream`` with only a filename hint
* forwarded ``message/rfc822`` wrappers

This module walks the MIME tree, unwraps archives (bounded, to avoid zip
bombs), and classifies the resulting bytes as DMARC XML or TLS-RPT JSON.
"""

from __future__ import annotations

import email
import gzip
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Literal

MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 64
MAX_DEPTH = 3

ZIP_TYPES = {"application/zip", "application/x-zip-compressed", "multipart/x-zip"}
GZIP_TYPES = {"application/gzip", "application/x-gzip", "application/tlsrpt+gzip"}
XML_TYPES = {"application/xml", "text/xml", "application/dmarc"}
JSON_TYPES = {"application/json", "application/tlsrpt+json"}


class MimeParseError(ValueError):
    pass


@dataclass
class ReportPayload:
    kind: Literal["dmarc", "tlsrpt"]
    data: bytes
    filename: str
    sha256: str
    source_type: str


@dataclass
class ParsedMessage:
    message_id: str | None
    subject: str | None
    sender: str | None
    received_at: datetime | None
    date_header: datetime | None
    payloads: list[ReportPayload] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def looks_like_report(self) -> bool:
        return bool(self.payloads)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_zip(data: bytes) -> bool:
    return data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06")


def _is_gzip(data: bytes) -> bool:
    return data.startswith(b"\x1f\x8b")


def _gunzip(data: bytes) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
        result = handle.read(MAX_PAYLOAD_BYTES + 1)
    if len(result) > MAX_PAYLOAD_BYTES:
        raise MimeParseError("gzip payload exceeds the size limit")
    return result


def _iter_zip(data: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as exc:
        raise MimeParseError(f"invalid zip attachment: {exc}") from exc
    total = 0
    with archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        if len(infos) > MAX_ENTRIES:
            raise MimeParseError("zip attachment has too many entries")
        for info in infos:
            name = info.filename
            base = name.rsplit("/", 1)[-1]
            if name.startswith("__MACOSX/") or base.startswith("._") or base in {".DS_Store"}:
                continue
            if info.file_size > MAX_PAYLOAD_BYTES:
                raise MimeParseError(f"zip entry {name} is too large")
            total += info.file_size
            if total > MAX_PAYLOAD_BYTES:
                raise MimeParseError("zip attachment expands beyond the size limit")
            out.append((name, archive.read(info)))
    return out


def _classify(data: bytes) -> Literal["dmarc", "tlsrpt"] | None:
    head = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head:
        return None
    if head[:1] == b"{":
        try:
            document = json.loads(head.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeDecodeError):
            return None
        if isinstance(document, dict) and (
            "policies" in document or "report-id" in document or "date-range" in document
        ):
            return "tlsrpt"
        return None
    if head[:1] == b"<":
        lowered = head[:8192].lower()
        if b"<feedback" in lowered or b"policy_published" in lowered or b"report_metadata" in lowered:
            return "dmarc"
        return None
    return None


def _unwrap(data: bytes, filename: str, source_type: str, depth: int = 0) -> list[ReportPayload]:
    if depth > MAX_DEPTH:
        return []
    if len(data) > MAX_PAYLOAD_BYTES:
        raise MimeParseError("payload exceeds the size limit")
    if _is_zip(data):
        payloads: list[ReportPayload] = []
        for name, entry in _iter_zip(data):
            inner_name = name or filename
            if _is_zip(entry) or _is_gzip(entry):
                payloads.extend(_unwrap(entry, inner_name, "zip", depth + 1))
                continue
            kind = _classify(entry)
            if kind:
                payloads.append(
                    ReportPayload(
                        kind=kind,
                        data=entry,
                        filename=inner_name,
                        sha256=_sha256(entry),
                        source_type=f"{source_type}+zip",
                    )
                )
        return payloads
    if _is_gzip(data):
        return _unwrap(_gunzip(data), filename, f"{source_type}+gzip", depth + 1)
    kind = _classify(data)
    if kind:
        return [
            ReportPayload(
                kind=kind,
                data=data,
                filename=filename,
                sha256=_sha256(data),
                source_type=source_type,
            )
        ]
    return []


def _part_bytes(part: Message) -> bytes | None:
    try:
        payload = part.get_payload(decode=True)
    except Exception:  # noqa: BLE001 - malformed base64 in the wild
        return None
    if payload is None:
        raw = part.get_payload()
        if isinstance(raw, str):
            return raw.encode("utf-8", errors="replace")
        return None
    return payload


def extract_payloads(raw: bytes) -> tuple[ParsedMessage, list[ReportPayload]]:
    """Parse a raw RFC822 message and collect unique report payloads."""
    message = email.message_from_bytes(raw, policy=policy.default)
    parsed = ParsedMessage(
        message_id=(str(message.get("Message-ID", "")) or None),
        subject=(str(message.get("Subject", "")) or None),
        sender=(str(message.get("From", "")) or None),
        received_at=_header_date(message),
        date_header=_parse_date(str(message.get("Date", "")) or None),
    )

    payloads: list[ReportPayload] = []
    seen: set[str] = set()

    def add(items: list[ReportPayload]) -> None:
        for item in items:
            if item.sha256 in seen:
                continue
            seen.add(item.sha256)
            payloads.append(item)

    for part in message.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename() or ""
        disposition = (part.get("Content-Disposition") or "").lower()

        if ctype in {"application/pgp-signature", "application/pkcs7-signature"}:
            continue
        # A forwarded HTML newsletter that merely quotes XML should not parse.
        if ctype == "text/html" and "attachment" not in disposition:
            continue

        data = _part_bytes(part)
        if not data:
            continue

        looks_zipped = _is_zip(data) or _is_gzip(data)
        hinted = (
            ctype in ZIP_TYPES | GZIP_TYPES | XML_TYPES | JSON_TYPES
            or filename.lower().endswith((".zip", ".gz", ".xml", ".json", ".txt"))
            or looks_zipped
        )
        if not hinted and ctype not in {"text/plain", "application/octet-stream"}:
            continue

        try:
            add(_unwrap(data, filename or f"inline-{ctype}", ctype))
        except MimeParseError as exc:
            parsed.notes.append(f"{filename or ctype}: {exc}")

    if not payloads:
        # Last resort: a single-part message whose body is the report itself.
        body = _part_bytes(message)
        if body:
            try:
                add(_unwrap(body, "message-body", "body"))
            except MimeParseError as exc:
                parsed.notes.append(f"body: {exc}")

    return parsed, payloads


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _header_date(message: Message) -> datetime | None:
    """Prefer the top-most ``Received`` date, fall back to ``Date``."""
    received = message.get_all("Received") or []
    if received:
        # The first Received header is the most recent hop.
        tail = str(received[0]).rsplit(";", 1)[-1].strip()
        parsed = _parse_date(tail)
        if parsed:
            return parsed
    return _parse_date(str(message.get("Date", "")) or None)
