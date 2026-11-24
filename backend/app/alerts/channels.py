"""Notification channels.

Configuration lives in the environment (not in the database) so credentials
are never written to SQLite or included in backups. The UI only shows whether
a channel is configured and lets the operator send a test message.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Optional

import httpx

from ..config import Settings
from ..ingest.jmap import JMAPClient, JMAPError


@dataclass
class ChannelResult:
    channel: str
    ok: bool
    error: Optional[str] = None

    def as_dict(self) -> dict:
        return {"channel": self.channel, "ok": self.ok, "error": self.error}


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.replace(";", ",").split(",") if item.strip()]


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 5:
        return "***"
    return f"{value[:3]}…{value[-2:]}"


def recipients(settings: Settings) -> list[str]:
    return _split(settings.alert_to)


def smtp_transport_configured(settings: Settings) -> bool:
    return bool(settings.smtp_host and (settings.smtp_from or settings.smtp_username))


def jmap_transport_configured(settings: Settings) -> bool:
    return bool(settings.jmap_url and (settings.jmap_token or settings.jmap_username))


def jmap_configured(settings: Settings) -> bool:
    return jmap_transport_configured(settings)


def _email_kind(settings: Settings, requested: Optional[str] = None) -> Optional[str]:
    if requested in {"smtp", "jmap"}:
        return requested if is_configured(requested, settings) else None
    transport = (settings.email_transport or "auto").lower()
    if transport == "smtp":
        return "smtp" if smtp_transport_configured(settings) else None
    if transport == "jmap":
        return "jmap" if jmap_transport_configured(settings) else None
    if smtp_transport_configured(settings):
        return "smtp"
    if jmap_transport_configured(settings):
        return "jmap"
    return None


def email_transport(settings: Settings) -> Optional[str]:
    return _email_kind(settings)


def is_configured(kind: str, settings: Settings) -> bool:
    if kind == "smtp":
        return smtp_transport_configured(settings) and bool(recipients(settings))
    if kind == "jmap":
        return jmap_transport_configured(settings) and bool(recipients(settings))
    if kind == "telegram":
        return bool(settings.telegram_bot_token and settings.telegram_chat_id)
    if kind == "signal":
        return bool(settings.signal_api_url and settings.signal_number and settings.signal_recipients)
    if kind == "webhook":
        return bool(settings.webhook_url)
    return False


def statuses(settings: Settings) -> list[dict]:
    return [
        {
            "kind": "smtp",
            "label": "Email (SMTP)",
            "configured": is_configured("smtp", settings),
            "target": _mask(", ".join(recipients(settings))),
            "hint": "SMTP_HOST, SMTP_FROM, ALERT_TO",
        },
        {
            "kind": "jmap",
            "label": "Email (JMAP)",
            "configured": is_configured("jmap", settings),
            "target": _mask(settings.jmap_from or "account identity"),
            "hint": "JMAP_URL, JMAP_TOKEN, JMAP_FROM, ALERT_TO",
        },
        {
            "kind": "telegram",
            "label": "Telegram",
            "configured": is_configured("telegram", settings),
            "target": _mask(settings.telegram_chat_id),
            "hint": "TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID",
        },
        {
            "kind": "signal",
            "label": "Signal (signal-cli)",
            "configured": is_configured("signal", settings),
            "target": _mask(settings.signal_recipients),
            "hint": "SIGNAL_API_URL, SIGNAL_NUMBER, SIGNAL_RECIPIENTS",
        },
        {
            "kind": "webhook",
            "label": "Webhook",
            "configured": is_configured("webhook", settings),
            "target": _mask(settings.webhook_url),
            "hint": "WEBHOOK_URL, optional WEBHOOK_SECRET",
        },
    ]


def any_configured(settings: Settings) -> bool:
    return any(item["configured"] for item in statuses(settings))


def send_smtp(
    settings: Settings,
    subject: str,
    body: str,
    *,
    html: Optional[str] = None,
    to: Optional[list[str]] = None,
) -> ChannelResult:
    """Send mail through the configured SMTP account.

    Kept separate from ``deliver`` so the weekly digest can use its own
    recipient list without changing alert routing.
    """
    to = to or recipients(settings)
    sender = settings.smtp_from or settings.smtp_username
    if not to or not sender:
        return ChannelResult("smtp", False, "SMTP is not fully configured")
    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(to)
    message["Subject"] = subject
    message.set_content(body)
    if html:
        message.add_alternative(html, subtype="html")
    try:
        if settings.smtp_security == "ssl":
            client = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=20)
        else:
            client = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20)
        with client:
            if settings.smtp_security == "starttls":
                client.starttls(context=ssl.create_default_context())
            if settings.smtp_username:
                client.login(settings.smtp_username, settings.smtp_password)
            client.send_message(message)
        return ChannelResult("smtp", True)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        return ChannelResult("smtp", False, f"{type(exc).__name__}: {exc}"[:400])


def _smtp_send(settings: Settings, subject: str, body: str) -> ChannelResult:
    return send_smtp(settings, subject, body)


async def send_jmap(
    settings: Settings,
    subject: str,
    body: str,
    *,
    html: Optional[str] = None,
    to: Optional[list[str]] = None,
) -> ChannelResult:
    recipients_to = to or recipients(settings)
    if not recipients_to:
        return ChannelResult("jmap", False, "no recipients configured")
    if not jmap_transport_configured(settings):
        return ChannelResult("jmap", False, "JMAP is not configured")
    client = JMAPClient(
        settings.jmap_url,
        settings.jmap_username,
        settings.jmap_password,
        settings.jmap_token,
    )
    try:
        await client.submit_message(
            subject,
            body,
            recipients_to,
            from_addr=settings.jmap_from,
            html=html,
        )
        return ChannelResult("jmap", True)
    except (JMAPError, OSError, ValueError) as exc:
        return ChannelResult("jmap", False, f"{type(exc).__name__}: {exc}"[:400])


async def send_email(
    settings: Settings,
    subject: str,
    body: str,
    *,
    html: Optional[str] = None,
    to: Optional[list[str]] = None,
) -> ChannelResult:
    if not (to or recipients(settings)):
        return ChannelResult("email", False, "no recipients configured")
    kind = _email_kind(settings)
    if kind == "smtp":
        result = await asyncio.to_thread(send_smtp, settings, subject, body, html=html, to=to)
        if not result.ok and settings.email_transport == "auto" and is_configured("jmap", settings):
            jmap_result = await send_jmap(settings, subject, body, html=html, to=to)
            if jmap_result.ok:
                return jmap_result
        return result
    if kind == "jmap":
        return await send_jmap(settings, subject, body, html=html, to=to)
    return ChannelResult("email", False, "no email transport configured")


async def _telegram_send(settings: Settings, subject: str, body: str) -> ChannelResult:
    url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                url,
                json={"chat_id": settings.telegram_chat_id, "text": f"{subject}\n\n{body}"[:4000]},
            )
        if response.status_code >= 400:
            return ChannelResult("telegram", False, f"HTTP {response.status_code}: {response.text[:200]}")
        return ChannelResult("telegram", True)
    except httpx.HTTPError as exc:
        return ChannelResult("telegram", False, f"{type(exc).__name__}: {exc}"[:400])


async def _signal_send(settings: Settings, subject: str, body: str) -> ChannelResult:
    url = f"{settings.signal_api_url.rstrip('/')}/v2/send"
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                url,
                json={
                    "message": f"{subject}\n\n{body}",
                    "number": settings.signal_number,
                    "recipients": _split(settings.signal_recipients),
                },
            )
        if response.status_code >= 400:
            return ChannelResult("signal", False, f"HTTP {response.status_code}: {response.text[:200]}")
        return ChannelResult("signal", True)
    except httpx.HTTPError as exc:
        return ChannelResult("signal", False, f"{type(exc).__name__}: {exc}"[:400])


async def _webhook_send(settings: Settings, subject: str, body: str, payload: dict) -> ChannelResult:
    document = json.dumps(
        {"event": "alert", "subject": subject, "message": body, "data": payload}, separators=(",", ":")
    ).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "DMARCView/1.0"}
    if settings.webhook_secret:
        signature = hmac.new(settings.webhook_secret.encode(), document, hashlib.sha256).hexdigest()
        headers["X-DMARCView-Signature"] = f"sha256={signature}"
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(settings.webhook_url, content=document, headers=headers)
        if response.status_code >= 400:
            return ChannelResult("webhook", False, f"HTTP {response.status_code}: {response.text[:200]}")
        return ChannelResult("webhook", True)
    except httpx.HTTPError as exc:
        return ChannelResult("webhook", False, f"{type(exc).__name__}: {exc}"[:400])


async def deliver(
    settings: Settings,
    subject: str,
    body: str,
    payload: dict,
    only: Optional[str] = None,
) -> list[ChannelResult]:
    tasks = []
    if only is None:
        if _email_kind(settings) is not None and recipients(settings):
            tasks.append(send_email(settings, subject, body))
    elif only in {"smtp", "jmap"}:
        if only == "smtp" and is_configured("smtp", settings):
            tasks.append(asyncio.to_thread(_smtp_send, settings, subject, body))
        elif only == "jmap" and is_configured("jmap", settings):
            tasks.append(send_jmap(settings, subject, body))
    if (only in (None, "telegram")) and is_configured("telegram", settings):
        tasks.append(_telegram_send(settings, subject, body))
    if (only in (None, "signal")) and is_configured("signal", settings):
        tasks.append(_signal_send(settings, subject, body))
    if (only in (None, "webhook")) and is_configured("webhook", settings):
        tasks.append(_webhook_send(settings, subject, body, payload))
    if not tasks:
        return []
    return list(await asyncio.gather(*tasks))
