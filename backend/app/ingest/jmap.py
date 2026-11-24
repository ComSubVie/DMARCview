"""Minimal, dependency-light JMAP client for Stalwart (JMAP Core + Mail).

Only what report ingestion needs:

1. discover the session (``/.well-known/jmap``)
2. find the report mailbox
3. page through ``Email/query`` for messages newer than a cursor
4. download the raw RFC 5322 message blob

If your server exposes reports through a shared mailbox, point
``JMAP_USERNAME``/``JMAP_PASSWORD`` at an account that can read it.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import quote, urljoin

import httpx

log = logging.getLogger(__name__)


def _utc_string(value: datetime) -> str:
    aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_unsupported_filter(exc: JMAPError) -> bool:
    payload = exc.payload if isinstance(exc.payload, dict) else {}
    if str(payload.get("type", "")).lower() == "unsupportedfilter":
        return True
    return "unsupportedfilter" in str(exc).lower()

CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"
USING = [CORE, MAIL]


class JMAPError(RuntimeError):
    def __init__(self, message: str, *, status: Optional[int] = None, payload: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.payload = payload


@dataclass
class JMAPSession:
    api_url: str
    download_url: str
    account_id: str
    username: str
    raw: dict[str, Any]


class JMAPClient:
    def __init__(
        self,
        base_url: str,
        username: str = "",
        password: str = "",
        token: str = "",
        *,
        timeout: float = 45.0,
        verify: bool = True,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        if not base_url:
            raise JMAPError("JMAP_URL is not configured")
        self.base_url = base_url.rstrip("/")
        self.username = username
        self._token = token
        self._password = password
        self._timeout = timeout
        self._verify = verify
        self._transport = transport
        self._session: Optional[JMAPSession] = None

    # ------------------------------------------------------------------ HTTP
    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "DMARCView/1.0"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        elif self.username:
            raw = f"{self.username}:{self._password}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        return headers

    async def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        headers = {**self._headers(), **kwargs.pop("headers", {})}
        last_error: Optional[Exception] = None
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout,
                    verify=self._verify,
                    follow_redirects=True,
                    transport=self._transport,
                ) as client:
                    response = await client.request(method, url, headers=headers, **kwargs)
                if response.status_code in (429, 502, 503, 504) and attempt < 2:
                    await asyncio.sleep(1.5 * (attempt + 1))
                    continue
                if response.status_code == 401:
                    raise JMAPError("JMAP authentication failed (401)", status=401)
                if response.status_code >= 400:
                    snippet = response.text[:400].replace("\n", " ")
                    raise JMAPError(
                        f"JMAP HTTP {response.status_code}: {snippet}", status=response.status_code
                    )
                return response
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt < 2:
                    await asyncio.sleep(1.5 * (attempt + 1))
                    continue
        raise JMAPError(f"could not reach JMAP server: {last_error}")

    # -------------------------------------------------------------- session
    async def session(self, refresh: bool = False) -> JMAPSession:
        if self._session is not None and not refresh:
            return self._session
        response = await self._request("GET", f"{self.base_url}/.well-known/jmap")
        try:
            data = response.json()
        except ValueError as exc:
            raise JMAPError("JMAP session endpoint did not return JSON") from exc

        api_url = data.get("apiUrl")
        if not api_url:
            raise JMAPError("JMAP session has no apiUrl")
        api_url = urljoin(self.base_url + "/", api_url)
        download_url = data.get("downloadUrl") or urljoin(
            self.base_url + "/", "/jmap/download/{accountId}/{blobId}/{name}?accept={type}"
        )
        accounts = data.get("primaryAccounts") or {}
        account_id = accounts.get(MAIL)
        if not account_id:
            all_accounts = data.get("accounts") or {}
            candidates = [
                key for key, value in all_accounts.items() if MAIL in (value.get("accountCapabilities") or {})
            ]
            account_id = candidates[0] if candidates else (next(iter(all_accounts), None))
        if not account_id:
            raise JMAPError("JMAP session exposes no mail account")

        self._session = JMAPSession(
            api_url=api_url,
            download_url=download_url,
            account_id=account_id,
            username=(data.get("username") or self.username),
            raw=data,
        )
        return self._session

    async def call(self, calls: list[list[Any]], using: Optional[list[str]] = None) -> dict[str, Any]:
        session = await self.session()
        payload = {"using": using or USING, "methodCalls": calls}
        response = await self._request("POST", session.api_url, json=payload)
        try:
            data = response.json()
        except ValueError as exc:
            raise JMAPError("JMAP API returned invalid JSON") from exc
        responses = data.get("methodResponses")
        if not isinstance(responses, list):
            raise JMAPError("JMAP API response has no methodResponses")
        mapped: dict[str, Any] = {}
        for entry in responses:
            if not isinstance(entry, list) or len(entry) < 3:
                continue
            name, args, tag = entry[0], entry[1], entry[2]
            if name == "error":
                raise JMAPError(f"JMAP method error: {args.get('type')} {args.get('description', '')}".strip(), payload=args)
            mapped[tag] = args
        return mapped

    # ------------------------------------------------------------- mailbox
    async def list_mailboxes(self) -> list[dict[str, Any]]:
        session = await self.session()
        result = await self.call(
            [["Mailbox/get", {"accountId": session.account_id, "ids": None}, "mb"]]
        )
        return result.get("mb", {}).get("list", []) or []

    async def find_mailbox(self, name: str) -> dict[str, Any]:
        mailboxes = await self.list_mailboxes()
        wanted = (name or "").strip().lower()
        if wanted in {"", "all", "any"}:
            for box in mailboxes:
                if (box.get("role") or "").lower() == "inbox":
                    return box
            raise JMAPError("no Inbox mailbox found")
        for box in mailboxes:
            if (box.get("name") or "").strip().lower() == wanted:
                return box
        for box in mailboxes:
            if wanted in (box.get("name") or "").strip().lower():
                return box
        names = ", ".join(sorted(box.get("name", "?") for box in mailboxes)[:25])
        raise JMAPError(f"mailbox {name!r} not found. Available mailboxes: {names}")

    # -------------------------------------------------------------- emails
    async def query_email_ids(
        self,
        mailbox_id: str,
        since: Optional[datetime] = None,
        *,
        max_messages: int = 1500,
        page_size: int = 100,
    ) -> list[str]:
        """Return message ids in the mailbox, oldest first.

        RFC 8621 filters by ``after``/``before`` on ``receivedAt``. Some servers
        (or older builds) reject that filter with ``unsupportedFilter``; in that
        case fall back to scanning the newest messages and filtering locally.
        """
        if since is None:
            return await self._query_ids(mailbox_id, None, max_messages, page_size)
        try:
            return await self._query_ids(mailbox_id, since, max_messages, page_size)
        except JMAPError as exc:
            if not _is_unsupported_filter(exc):
                raise
            log.info("JMAP server rejected the 'after' filter; scanning newest messages instead")
            return await self._query_ids_by_scan(mailbox_id, since, max_messages, page_size)

    async def _query_ids(
        self,
        mailbox_id: str,
        since: Optional[datetime],
        max_messages: int,
        page_size: int,
    ) -> list[str]:
        session = await self.session()
        email_filter: dict[str, Any] = {"inMailbox": mailbox_id}
        if since is not None:
            email_filter["after"] = _utc_string(since)
        ids: list[str] = []
        position = 0
        while len(ids) < max_messages:
            result = await self.call(
                [
                    [
                        "Email/query",
                        {
                            "accountId": session.account_id,
                            "filter": email_filter,
                            "sort": [{"property": "receivedAt", "isAscending": True}],
                            "limit": min(page_size, max_messages - len(ids)),
                            "position": position,
                        },
                        "q",
                    ]
                ]
            )
            batch = result.get("q", {}).get("ids") or []
            ids.extend(batch)
            position += len(batch)
            if len(batch) < page_size:
                break
        return ids

    async def _query_ids_by_scan(
        self,
        mailbox_id: str,
        since: datetime,
        max_messages: int,
        page_size: int,
    ) -> list[str]:
        """Fallback for servers without an ``after`` filter.

        Walk the mailbox newest-first and stop at the first message older than
        the cursor. The extra ``Email/get`` is only used on this path.
        """
        session = await self.session()
        cutoff = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
        ids: list[str] = []
        position = 0
        while len(ids) < max_messages:
            result = await self.call(
                [
                    [
                        "Email/query",
                        {
                            "accountId": session.account_id,
                            "filter": {"inMailbox": mailbox_id},
                            "sort": [{"property": "receivedAt", "isAscending": False}],
                            "limit": min(page_size, max_messages - len(ids)),
                            "position": position,
                        },
                        "q",
                    ]
                ]
            )
            batch = result.get("q", {}).get("ids") or []
            if not batch:
                break
            emails = await self.get_emails(batch)
            by_id = {email.get("id"): email for email in emails}
            reached_older = False
            for email_id in batch:
                received = _parse_utc(by_id.get(email_id, {}).get("receivedAt"))
                if received is None or received >= cutoff:
                    ids.append(email_id)
                else:
                    reached_older = True
                    break
            if reached_older:
                break
            position += len(batch)
            if len(batch) < page_size:
                break
        return list(reversed(ids))

    async def get_emails(self, ids: list[str]) -> list[dict[str, Any]]:
        if not ids:
            return []
        session = await self.session()
        result = await self.call(
            [
                [
                    "Email/get",
                    {
                        "accountId": session.account_id,
                        "ids": ids,
                        "properties": [
                            "id",
                            "blobId",
                            "messageId",
                            "subject",
                            "from",
                            "receivedAt",
                            "size",
                            "hasAttachment",
                        ],
                    },
                    "g",
                ]
            ]
        )
        return result.get("g", {}).get("list", []) or []

    async def download(self, blob_id: str, name: str = "report.eml", accept: str = "message/rfc822") -> bytes:
        session = await self.session()
        url = session.download_url
        url = url.replace("{accountId}", quote(session.account_id, safe=""))
        url = url.replace("{blobId}", quote(blob_id, safe=""))
        url = url.replace("{name}", quote(name, safe=""))
        url = url.replace("{type}", quote(accept, safe=""))
        url = urljoin(self.base_url + "/", url)
        response = await self._request("GET", url, headers={"Accept": accept})
        return response.content

    async def probe(self) -> dict[str, Any]:
        """Used by the settings screen to validate the connection."""
        session = await self.session(refresh=True)
        mailboxes = await self.list_mailboxes()
        report_box = None
        error = None
        try:
            report_box = await self.find_mailbox(_configured_mailbox())
        except JMAPError as exc:
            error = str(exc)
        account = (session.raw.get("accounts") or {}).get(session.account_id, {})
        return {
            "ok": error is None,
            "username": session.username,
            "account_name": account.get("name"),
            "api_url": session.api_url,
            "mailboxes": [{"name": box.get("name"), "id": box.get("id"), "role": box.get("role")} for box in mailboxes],
            "report_mailbox": report_box.get("name") if report_box else None,
            "report_mailbox_id": report_box.get("id") if report_box else None,
            "error": error,
        }


def _configured_mailbox() -> str:
    from ..config import get_settings

    return get_settings().jmap_mailbox
