"""Minimal HTTP fetcher for MTA-STS policies and BIMI logos.

Only HTTPS is allowed and responses are size-capped; the URL host is always
derived from the domain being checked, never supplied by a user.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from ..config import get_settings


@dataclass(frozen=True)
class FetchResult:
    status: Optional[int]
    body: bytes = b""
    content_type: Optional[str] = None
    error: Optional[str] = None
    final_url: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None and 200 <= self.status < 300


class BaseFetcher:
    async def get(self, url: str, *, max_bytes: int = 131072, timeout: float = 6.0) -> FetchResult:
        raise NotImplementedError


class HttpxFetcher(BaseFetcher):
    async def get(self, url: str, *, max_bytes: int = 131072, timeout: float = 6.0) -> FetchResult:
        if not url.lower().startswith("https://"):
            return FetchResult(status=None, error="only https URLs are fetched")
        try:
            async with httpx.AsyncClient(
                timeout=timeout, follow_redirects=False, headers={"User-Agent": "DMARCView/1.0"}
            ) as client, client.stream("GET", url) as response:
                if 300 <= response.status_code < 400:
                    return FetchResult(
                        status=response.status_code,
                        error=f"redirect to {response.headers.get('location', '?')} not followed",
                        final_url=str(response.url),
                    )
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        return FetchResult(
                            status=response.status_code,
                            body=b"".join(chunks),
                            content_type=response.headers.get("content-type"),
                            error=f"response exceeds {max_bytes} bytes",
                            final_url=str(response.url),
                        )
                    chunks.append(chunk)
                return FetchResult(
                    status=response.status_code,
                    body=b"".join(chunks),
                    content_type=response.headers.get("content-type"),
                    final_url=str(response.url),
                )
        except httpx.HTTPError as exc:
            return FetchResult(status=None, error=f"{type(exc).__name__}: {exc}"[:300])


_fetcher: Optional[HttpxFetcher] = None


def get_http_fetcher() -> BaseFetcher:
    global _fetcher
    if _fetcher is None:
        _fetcher = HttpxFetcher()
    return _fetcher


def default_fetch_timeout() -> float:
    return get_settings().http_timeout_seconds
