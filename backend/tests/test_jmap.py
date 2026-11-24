"""JMAP client tests against an in-process mock server."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest

from app.ingest.jmap import MAIL, JMAPClient, JMAPError

SESSION_DOC = {
    "username": "dmarc@tgm.rocks",
    "apiUrl": "https://mail.example.com/jmap/api",
    "downloadUrl": "https://mail.example.com/download/{accountId}/{blobId}/{name}?accept={type}",
    "uploadUrl": "https://mail.example.com/upload/{accountId}/",
    "primaryAccounts": {MAIL: "acc1"},
    "accounts": {
        "acc1": {"name": "dmarc@tgm.rocks", "accountCapabilities": {MAIL: {}}},
    },
}


class MockServer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.authorization: str | None = None
        self.reject_after = False
        self.reject_patch = False
        self.uploaded: bytes = b""

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.authorization = request.headers.get("authorization")
        if request.method == "GET" and request.url.path == "/.well-known/jmap":
            return httpx.Response(200, json=SESSION_DOC)
        if request.method == "POST" and request.url.path == "/upload/acc1/":
            self.uploaded = request.content
            return httpx.Response(200, json={"accountId": "acc1", "blobId": "blob-send", "type": "message/rfc822", "size": len(request.content)})
        if request.url.path == "/jmap/api":
            payload = json.loads(request.content)
            responses = []
            for name, args, tag in payload["methodCalls"]:
                self.calls.append((name, args))
                if name == "Mailbox/get":
                    responses.append(
                        [
                            "Mailbox/get",
                            {
                                "accountId": "acc1",
                                "list": [
                                    {"id": "mb1", "name": "Inbox", "role": "inbox"},
                                    {"id": "mb2", "name": "DMARC", "role": None},
                                    {"id": "mb3", "name": "Drafts", "role": "drafts"},
                                    {"id": "mb4", "name": "Sent", "role": "sent"},
                                ],
                            },
                            tag,
                        ]
                    )
                elif name == "Email/query":
                    filters = args.get("filter") or {}
                    if self.reject_after and "after" in filters:
                        responses.append(
                            [
                                "error",
                                {"type": "unsupportedFilter", "description": "unknown filter"},
                                tag,
                            ]
                        )
                        continue
                    sort = args.get("sort") or []
                    ascending = True
                    if sort and sort[0].get("property") == "receivedAt":
                        ascending = sort[0].get("isAscending", True)
                    ids = ["e1", "e2"] if ascending else ["e2", "e1"]
                    responses.append(
                        ["Email/query", {"accountId": "acc1", "ids": ids, "position": 0}, tag]
                    )
                elif name == "Identity/get":
                    responses.append(
                        [
                            "Identity/get",
                            {
                                "accountId": "acc1",
                                "list": [{"id": "id1", "email": "dmarc@tgm.rocks", "name": "DMARC"}],
                            },
                            tag,
                        ]
                    )
                elif name == "Email/import":
                    responses.append(
                        ["Email/import", {"accountId": "acc1", "created": {"draft": {"id": "draft-1"}}}, tag]
                    )
                elif name == "EmailSubmission/set":
                    if self.reject_patch and "onSuccessUpdateEmail" in args:
                        responses.append(
                            [
                                "EmailSubmission/set",
                                {
                                    "accountId": "acc1",
                                    "notCreated": {
                                        "submission": {
                                            "type": "invalidProperties",
                                            "description": "Field could not be set.",
                                            "properties": ["onSuccessUpdateEmail"],
                                        }
                                    },
                                },
                                tag,
                            ]
                        )
                    else:
                        responses.append(
                            ["EmailSubmission/set", {"accountId": "acc1", "created": {"submission": {"id": "sub-1"}}}, tag]
                        )
                elif name == "Email/get":
                    responses.append(
                        [
                            "Email/get",
                            {
                                "accountId": "acc1",
                                "list": [
                                    {
                                        "id": "e1",
                                        "blobId": "blob-1",
                                        "subject": "Report domain: tgm.rocks",
                                        "receivedAt": "2026-11-19T02:00:00Z",
                                    },
                                    {
                                        "id": "e2",
                                        "blobId": "blob-2",
                                        "subject": "Report domain: aeroclub.example",
                                        "receivedAt": "2026-11-19T03:00:00Z",
                                    },
                                ],
                            },
                            tag,
                        ]
                    )
            return httpx.Response(200, json={"methodResponses": responses, "sessionState": "s1"})
        if request.url.path.startswith("/download/"):
            return httpx.Response(200, content=b"Subject: raw message\r\n\r\nbody")
        return httpx.Response(404, text="not found")


def build_client(server: MockServer) -> JMAPClient:
    return JMAPClient(
        "https://mail.example.com",
        "dmarc@tgm.rocks",
        "secret",
        transport=httpx.MockTransport(server.handler),
    )


def test_session_discovery():
    server = MockServer()
    client = build_client(server)

    async def run():
        return await client.session()

    session = __import__("asyncio").run(run())
    assert session.account_id == "acc1"
    assert session.api_url == "https://mail.example.com/jmap/api"
    assert server.authorization is not None
    assert server.authorization.startswith("Basic ")


def test_mailbox_lookup_and_query():
    server = MockServer()
    client = build_client(server)

    async def run():
        mailbox = await client.find_mailbox("dmarc")
        since = datetime(2026, 11, 18, tzinfo=timezone.utc)
        ids = await client.query_email_ids(mailbox["id"], since)
        emails = await client.get_emails(ids)
        raw = await client.download(emails[0]["blobId"], "e1.eml")
        return mailbox, ids, emails, raw

    mailbox, ids, emails, raw = __import__("asyncio").run(run())
    assert mailbox["id"] == "mb2"
    assert ids == ["e1", "e2"]
    assert emails[0]["blobId"] == "blob-1"
    assert raw.startswith(b"Subject: raw")

    query_call = next(args for name, args in server.calls if name == "Email/query")
    assert query_call["filter"]["inMailbox"] == "mb2"
    assert query_call["filter"]["after"] == "2026-11-18T00:00:00Z"
    assert query_call["sort"] == [{"property": "receivedAt", "isAscending": True}]


def test_query_falls_back_when_after_filter_is_unsupported():
    server = MockServer()
    server.reject_after = True
    client = build_client(server)

    async def run():
        return await client.query_email_ids(
            "mb2", datetime(2026, 11, 19, 2, 30, tzinfo=timezone.utc)
        )

    ids = __import__("asyncio").run(run())
    assert ids == ["e2"]  # e1 (02:00) is older than the cursor, e2 (03:00) is not

    query_calls = [args for name, args in server.calls if name == "Email/query"]
    assert "after" in query_calls[0]["filter"]
    assert "after" not in query_calls[1]["filter"]
    assert any(name == "Email/get" for name, _ in server.calls)


def test_unknown_mailbox_lists_alternatives():
    server = MockServer()
    client = build_client(server)

    async def run():
        await client.find_mailbox("does-not-exist")

    with pytest.raises(JMAPError) as excinfo:
        __import__("asyncio").run(run())
    assert "DMARC" in str(excinfo.value)


def test_unauthorized_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="no")

    client = JMAPClient("https://mail.example.com", "u", "p", transport=httpx.MockTransport(handler))

    async def run():
        await client.session()

    with pytest.raises(JMAPError) as excinfo:
        __import__("asyncio").run(run())
    assert excinfo.value.status == 401


def test_probe_reports_mailbox_state():
    server = MockServer()
    client = build_client(server)

    async def run():
        return await client.probe()

    result = __import__("asyncio").run(run())
    assert result["ok"] is True
    assert result["report_mailbox"] == "DMARC"
    assert len(result["mailboxes"]) == 4


def test_full_sync_against_fake_client(monkeypatch, session):
    """sync_jmap orchestration: run bookkeeping, cursor and idempotency."""
    import asyncio
    from dataclasses import replace

    from sqlmodel import func, select

    from app.ingest import service
    from app.models import IngestRun, Report, SyncState
    from tests.conftest import sample

    raw = sample("google-dmarc-tgm-2026-11-18.eml")

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def find_mailbox(self, name):
            return {"id": "mb2", "name": "DMARC"}

        async def query_email_ids(self, mailbox_id, since, **kwargs):
            return ["e1"]

        async def get_emails(self, ids):
            return [
                {
                    "id": "e1",
                    "blobId": "blob-1",
                    "subject": "Report domain: tgm.rocks",
                    "receivedAt": "2026-11-19T02:00:00Z",
                }
            ]

        async def download(self, blob_id, name="report.eml", accept="message/rfc822"):
            return raw

    monkeypatch.setattr(service, "JMAPClient", FakeClient)
    settings = replace(
        service.get_settings(),
        jmap_enabled=True,
        jmap_url="https://mail.example.com",
    )
    monkeypatch.setattr(service, "get_settings", lambda: settings)

    result = asyncio.run(service.sync_jmap(trigger="test"))
    assert result["reports"] == 1
    assert result["errors"] == []

    assert session.exec(select(func.count(Report.id))).one() == 1
    run = session.exec(select(IngestRun)).one()
    assert run.status == "ok"
    assert run.messages_seen == 1
    assert run.reports_created == 1

    cursor = session.get(SyncState, "jmap.last_received_at")
    assert cursor is not None
    assert cursor.value.startswith("2026-11-19")

    again = asyncio.run(service.sync_jmap(trigger="test"))
    assert again["reports"] == 0
    assert again["duplicates"] == 1
    assert session.exec(select(func.count(Report.id))).one() == 1


def test_submit_message_uploads_imports_and_submits():
    server = MockServer()
    client = build_client(server)

    async def run():
        return await client.submit_message(
            "Test digest",
            "Hello",
            ["ops@example.net"],
            from_addr="dmarc@tgm.rocks",
        )

    submission_id = __import__("asyncio").run(run())
    assert submission_id == "sub-1"
    assert server.uploaded.startswith(b"From: dmarc@tgm.rocks")
    assert b"Subject: Test digest" in server.uploaded
    names = [name for name, _args in server.calls]
    assert "Identity/get" in names
    assert "Email/import" in names
    assert "EmailSubmission/set" in names
    submission = next(args for name, args in server.calls if name == "EmailSubmission/set")
    assert submission["create"]["submission"]["envelope"]["rcptTo"] == [{"email": "ops@example.net"}]
    assert "onSuccessUpdateEmail" in submission
    assert "onSuccessUpdateEmail" not in submission["create"]["submission"]


def test_submit_message_retries_without_patch_when_server_rejects_it():
    server = MockServer()
    server.reject_patch = True
    client = build_client(server)

    async def run():
        return await client.submit_message("Digest", "Hello", ["ops@example.net"])

    assert __import__("asyncio").run(run()) == "sub-1"
    submissions = [args for name, args in server.calls if name == "EmailSubmission/set"]
    assert len(submissions) == 2
    assert "onSuccessUpdateEmail" in submissions[0]
    assert "onSuccessUpdateEmail" not in submissions[1]
