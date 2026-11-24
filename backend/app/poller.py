"""Background JMAP poller.

A single asyncio task wakes up every ``JMAP_POLL_SECONDS``.  Manual runs from
the UI share the same lock, so two syncs never overlap.  State is kept in
memory for status display; the durable history lives in ``ingest_runs``.
"""

from __future__ import annotations

import asyncio
import logging
import random
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any, Optional

from .config import get_settings
from .ingest.service import sync_jmap

log = logging.getLogger(__name__)

_lock = asyncio.Lock()
_task: Optional[asyncio.Task] = None
_state: dict[str, Any] = {
    "running": False,
    "trigger": None,
    "started_at": None,
    "finished_at": None,
    "last_error": None,
    "last_result": None,
}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat() + "Z"


def status() -> dict[str, Any]:
    return dict(_state)


def is_running() -> bool:
    return _state["running"]


async def run_sync(trigger: str = "manual") -> dict[str, Any]:
    if _lock.locked():
        raise RuntimeError("A sync is already running")
    async with _lock:
        _state.update(
            running=True,
            trigger=trigger,
            started_at=_now(),
            finished_at=None,
            last_error=None,
        )
        try:
            result = await sync_jmap(trigger=trigger)
            _state["last_result"] = result
            return result
        except Exception as exc:  # noqa: BLE001 - surfaced in the UI
            log.warning("JMAP sync failed: %s", exc)
            _state["last_error"] = str(exc)
            raise
        finally:
            _state["running"] = False
            _state["finished_at"] = _now()


async def poll_loop(stop_event: asyncio.Event) -> None:
    settings = get_settings()
    interval = settings.jmap_poll_seconds
    log.info("JMAP poller started (every %ss, mailbox %r)", interval, settings.jmap_mailbox)
    # Small initial delay so the web UI is responsive right after boot.
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=5)
        return
    except asyncio.TimeoutError:
        pass
    while not stop_event.is_set():
        # Already logged inside run_sync; keep the loop alive.
        with suppress(Exception):
            await run_sync("schedule")
        wait = interval * random.uniform(0.9, 1.1)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=wait)
        except asyncio.TimeoutError:
            continue


def start(stop_event: asyncio.Event) -> Optional[asyncio.Task]:
    global _task
    if _task is not None and not _task.done():
        return _task
    _task = asyncio.create_task(poll_loop(stop_event), name="jmap-poller")
    return _task


async def stop() -> None:
    global _task
    if _task is not None:
        _task.cancel()
        with suppress(asyncio.CancelledError, Exception):  # noqa: BLE001
            await _task
        _task = None
