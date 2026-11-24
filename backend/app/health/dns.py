"""DNS access used by the health checks.

The client is a tiny interface (``lookup`` + helpers) so every check can run
against recorded fixtures in tests, and so a different resolver backend can be
added without touching check logic.
"""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass
from typing import Optional

from ..config import get_settings


@dataclass(frozen=True)
class Lookup:
    values: tuple[str, ...] = ()
    exists: bool = False
    ad: bool = False
    error: Optional[str] = None
    nxdomain: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None


class BaseDnsClient:
    async def lookup(self, name: str, rtype: str) -> Lookup:  # pragma: no cover - interface
        raise NotImplementedError

    async def txt(self, name: str) -> Lookup:
        return await self.lookup(name, "TXT")

    async def mx(self, name: str) -> Lookup:
        return await self.lookup(name, "MX")

    async def ds(self, name: str) -> Lookup:
        return await self.lookup(name, "DS")

    async def addresses(self, name: str) -> Lookup:
        answer = await self.lookup(name, "A")
        if answer.values or answer.error:
            return answer
        return await self.lookup(name, "AAAA")

    async def ptr(self, ip: str) -> Lookup:
        try:
            reverse = ipaddress.ip_address(ip).reverse_pointer
        except ValueError:
            return Lookup(error=f"invalid IP {ip!r}")
        return await self.lookup(reverse, "PTR")

    async def tlsa(self, host: str, port: int) -> Lookup:
        return await self.lookup(f"_{port}._tcp.{host}", "TLSA")


class DnspythonClient(BaseDnsClient):
    def __init__(
        self,
        nameservers: tuple[str, ...] = (),
        timeout: float = 4.0,
        lifetime: float = 6.0,
    ) -> None:
        import dns.resolver

        self._resolver = dns.resolver.Resolver(configure=True)
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime

    async def lookup(self, name: str, rtype: str) -> Lookup:
        return await asyncio.to_thread(self._lookup_sync, name, rtype)

    def _lookup_sync(self, name: str, rtype: str) -> Lookup:
        import dns.exception
        import dns.flags
        import dns.resolver

        try:
            answer = self._resolver.resolve(name, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return Lookup(exists=False, nxdomain=True)
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            return Lookup(error="DNS timeout")
        except dns.resolver.NoNameservers:
            return Lookup(error="no nameservers answered")
        except dns.exception.DNSException as exc:
            return Lookup(error=str(exc)[:200])

        ad = bool(answer.response.flags & dns.flags.AD)
        if answer.rrset is None:
            return Lookup(exists=False, ad=ad)

        values: list[str] = []
        for rdata in answer:
            if rtype == "TXT":
                chunks = getattr(rdata, "strings", ()) or ()
                if chunks:
                    values.append(b"".join(chunks).decode("utf-8", "replace"))
                else:
                    values.append(str(rdata))
            elif rtype == "MX":
                values.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
            elif rtype == "PTR":
                values.append(str(rdata.target).rstrip("."))
            elif rtype in {"A", "AAAA"}:
                values.append(str(rdata.address))
            elif rtype == "TLSA" or rtype == "DS":
                values.append(rdata.to_text())
            else:
                values.append(rdata.to_text())
        return Lookup(values=tuple(values), exists=True, ad=ad)


_client: Optional[DnspythonClient] = None


def get_dns_client() -> BaseDnsClient:
    global _client
    if _client is None:
        settings = get_settings()
        nameservers = tuple(
            item.strip() for item in settings.dns_nameservers.split(",") if item.strip()
        )
        _client = DnspythonClient(nameservers=nameservers)
    return _client


def reset_dns_client() -> None:
    global _client
    _client = None
