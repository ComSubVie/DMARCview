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


def is_configured(kind: str, settings: Settings) -> bool:
    if kind == "smtp":
        return bool(settings.smtp_host and (settings.smtp_from or settings.smtp_username) and recipients(settings))
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


def _smtp_send(settings: Settings, subject: str, body: str) -> ChannelResult:
    to = recipients(settings)
    sender = settings.smtp_from or settings.smtp_username
    if not to or not sender:
        return ChannelResult("smtp", False, "SMTP is not fully configured")
    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(to)
    message["Subject"] = subject
    message.set_content(body)
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
    if (only in (None, "smtp")) and is_configured("smtp", settings):
        tasks.append(asyncio.to_thread(_smtp_send, settings, subject, body))
    if (only in (None, "telegram")) and is_configured("telegram", settings):
        tasks.append(_telegram_send(settings, subject, body))
    if (only in (None, "signal")) and is_configured("signal", settings):
        tasks.append(_signal_send(settings, subject, body))
    if (only in (None, "webhook")) and is_configured("webhook", settings):
        tasks.append(_webhook_send(settings, subject, body, payload))
    if not tasks:
        return []
    return list(await asyncio.gather(*tasks))
