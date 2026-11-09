"""Resolvers: a fixed table for tests and files, and the §7.4 cache and miss limit around any
other resolver. Live DNS is in ``colophon_protocol.dnspython`` (the ``dns`` extra)."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from colophon_protocol.aio import AsyncTxtResolver
from colophon_protocol.blocking import TxtResolver
from colophon_protocol.errors import DnsError, DnsLimited
from colophon_protocol.model import KeyQuery, TxtAnswer
from colophon_protocol.sansio import select_domain_key

__all__ = [
    "AsyncGuardedResolver",
    "AsyncStaticResolver",
    "GuardedResolver",
    "StaticResolver",
]

NEGATIVE_TTL = 300
"""§7.4: a name with no usable record is cached for at least 5 minutes."""
MAX_POSITIVE_TTL = 3600
MISS_LIMIT = 20
MISS_WINDOW = 3600


class StaticResolver:
    """Answers from a table: name -> records, or None for a failed lookup. A name not in the
    table is NXDOMAIN. Names are compared in lowercase."""

    def __init__(self, table: Mapping[str, Sequence[str | bytes] | None]) -> None:
        self._table = {name.lower().rstrip("."): records for name, records in table.items()}

    def resolve_txt(self, query: KeyQuery) -> TxtAnswer:
        name = query.name.lower()
        if name not in self._table:
            return TxtAnswer(())
        records = self._table[name]
        if records is None:
            raise DnsError(f"lookup of {name} fails in this table")
        return TxtAnswer(records)


class AsyncStaticResolver:
    """``StaticResolver``, awaited."""

    def __init__(self, table: Mapping[str, Sequence[str | bytes] | None]) -> None:
        self._inner = StaticResolver(table)

    async def resolve_txt(self, query: KeyQuery) -> TxtAnswer:
        return self._inner.resolve_txt(query)


@dataclass
class _Window:
    started: float
    misses: int


class _GuardState:
    """The bookkeeping both guarded resolvers share. Bounded: least recently used entries go."""

    def __init__(self, clock: Callable[[], float], max_names: int, max_hosts: int) -> None:
        self.clock = clock
        self.max_names = max_names
        self.max_hosts = max_hosts
        self.cache: OrderedDict[str, tuple[float, TxtAnswer]] = OrderedDict()
        self.windows: OrderedDict[str, _Window] = OrderedDict()
        self.lock = threading.Lock()

    def cached(self, query: KeyQuery) -> TxtAnswer | None:
        """A fresh cached answer; or None, after checking the miss limit for the host."""
        now = self.clock()
        with self.lock:
            entry = self.cache.get(query.name)
            if entry is not None:
                if entry[0] > now:
                    self.cache.move_to_end(query.name)
                    return entry[1]
                del self.cache[query.name]
            window = self.windows.get(query.host)
            if window is not None and now - window.started >= MISS_WINDOW:
                del self.windows[query.host]
                window = None
            if window is not None and window.misses >= MISS_LIMIT:
                raise DnsLimited(f"{MISS_LIMIT} misses for {query.host} this hour")
            return None

    def record(self, query: KeyQuery, answer: TxtAnswer | None) -> None:
        """Cache an answer, and count a miss for an answer with no key or a failed lookup."""
        now = self.clock()
        usable = answer is not None and isinstance(select_domain_key(answer), bytes)
        with self.lock:
            if answer is not None:
                ttl = answer.ttl if answer.ttl is not None else NEGATIVE_TTL
                ttl = min(ttl, MAX_POSITIVE_TTL) if usable else max(ttl, NEGATIVE_TTL)
                if ttl > 0:
                    self.cache[query.name] = (now + ttl, answer)
                    self.cache.move_to_end(query.name)
                    while len(self.cache) > self.max_names:
                        self.cache.popitem(last=False)
            if usable:
                return
            window = self.windows.get(query.host)
            if window is None or now - window.started >= MISS_WINDOW:
                window = _Window(now, 0)
            window.misses += 1
            self.windows[query.host] = window
            self.windows.move_to_end(query.host)
            while len(self.windows) > self.max_hosts:
                self.windows.popitem(last=False)


class GuardedResolver:
    """§7.4 around a resolver: answers cached for their TTL (at most an hour), names with no
    usable record for at least 5 minutes, and after 20 misses for one host in an hour, uncached
    lookups for it refused as ``dns_limited``. A failed lookup counts as a miss.

    One instance serves every message; it is thread-safe. ``clock`` is monotonic seconds.
    """

    def __init__(
        self,
        inner: TxtResolver,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_names: int = 10_000,
        max_hosts: int = 10_000,
    ) -> None:
        self._inner = inner
        self._state = _GuardState(clock, max_names, max_hosts)

    def resolve_txt(self, query: KeyQuery) -> TxtAnswer:
        hit = self._state.cached(query)
        if hit is not None:
            return hit
        try:
            answer = self._inner.resolve_txt(query)
        except DnsLimited:
            raise
        except Exception:
            self._state.record(query, None)
            raise
        self._state.record(query, answer)
        return answer


class AsyncGuardedResolver:
    """``GuardedResolver`` for an awaited resolver. Use it from one event loop."""

    def __init__(
        self,
        inner: AsyncTxtResolver,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_names: int = 10_000,
        max_hosts: int = 10_000,
    ) -> None:
        self._inner = inner
        self._state = _GuardState(clock, max_names, max_hosts)

    async def resolve_txt(self, query: KeyQuery) -> TxtAnswer:
        hit = self._state.cached(query)
        if hit is not None:
            return hit
        try:
            answer = await self._inner.resolve_txt(query)
        except DnsLimited:
            raise
        except Exception:
            self._state.record(query, None)
            raise
        self._state.record(query, answer)
        return answer
