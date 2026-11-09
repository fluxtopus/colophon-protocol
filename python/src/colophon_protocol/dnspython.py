"""Live DNS through dnspython (install the ``dns`` extra). Kept out of the core on purpose."""

from __future__ import annotations

from typing import Any

from colophon_protocol.errors import DnsError
from colophon_protocol.model import KeyQuery, TxtAnswer

try:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "colophon_protocol.dnspython needs dnspython: pip install 'colophon-protocol[dns]'"
    ) from exc

__all__ = ["AsyncDnspythonResolver", "DnspythonResolver"]

LIFETIME = 2.0


def _answer(result: Any) -> TxtAnswer:
    rrset = result.rrset
    if rrset is None:
        return TxtAnswer(())
    return TxtAnswer((tuple(rdata.strings) for rdata in rrset), ttl=int(rrset.ttl))


class DnspythonResolver:
    """Blocking TXT lookups with a 2-second lifetime, retries included (§7.4).

    Wrap it in ``GuardedResolver`` for the cache and the miss limit.
    """

    def __init__(self, resolver: Any = None, *, lifetime: float = LIFETIME) -> None:
        self._resolver = resolver if resolver is not None else dns.resolver.Resolver()
        self._lifetime = lifetime

    def resolve_txt(self, query: KeyQuery) -> TxtAnswer:
        try:
            result = self._resolver.resolve(
                query.name + ".", "TXT", lifetime=self._lifetime, raise_on_no_answer=False
            )
        except dns.resolver.NXDOMAIN:
            return TxtAnswer(())
        except dns.exception.DNSException as exc:
            raise DnsError(f"{type(exc).__name__} for {query.name}") from None
        return _answer(result)


class AsyncDnspythonResolver:
    """``DnspythonResolver`` on dnspython's asyncio resolver."""

    def __init__(self, resolver: Any = None, *, lifetime: float = LIFETIME) -> None:
        self._resolver = resolver if resolver is not None else dns.asyncresolver.Resolver()
        self._lifetime = lifetime

    async def resolve_txt(self, query: KeyQuery) -> TxtAnswer:
        try:
            result = await self._resolver.resolve(
                query.name + ".", "TXT", lifetime=self._lifetime, raise_on_no_answer=False
            )
        except dns.resolver.NXDOMAIN:
            return TxtAnswer(())
        except dns.exception.DNSException as exc:
            raise DnsError(f"{type(exc).__name__} for {query.name}") from None
        return _answer(result)
