"""The asyncio adapter. Same steps as ``verify``; the resolver and the replay store are awaited.

The core is pure and fast (two Ed25519 verifications and a linear pass over the message), so it
runs inline on the event loop. For very large messages a caller may prefer
``asyncio.to_thread(sansio.start, ...)``; the core holds no state, so that is safe.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Protocol

from colophon_protocol.errors import DnsLimited
from colophon_protocol.model import DnsFailure, KeyQuery, Receipt, ReplayKey, TxtAnswer, Verdict
from colophon_protocol.sansio import NeedKey, NeedReplayCheck, start

__all__ = ["DNS_BUDGET", "AsyncReplayStore", "AsyncTxtResolver", "verify"]

DNS_BUDGET = 2.0
"""§7.4: seconds of wall clock a lookup has, retries included."""


class AsyncTxtResolver(Protocol):
    """As ``TxtResolver``, awaited. The adapter also cuts the lookup off at ``DNS_BUDGET``."""

    async def resolve_txt(self, query: KeyQuery) -> TxtAnswer: ...


class AsyncReplayStore(Protocol):
    """As ``ReplayStore``, awaited. ``claim`` must be atomic, for example Redis
    ``SET <key.digest()> 1 NX EXAT <expires_at + retention>`` (see ``replay.RETENTION``)."""

    async def claim(self, key: ReplayKey, expires_at: int) -> bool: ...


async def verify(
    message: bytes,
    receipt: Receipt,
    *,
    resolver: AsyncTxtResolver,
    replay_store: AsyncReplayStore,
    dns_budget: float = DNS_BUDGET,
    max_delay: int | None = None,
    clock: Callable[[], float] = time.time,
) -> Verdict:
    """Verify one delivery (§7.2). Never raises for anything in the message or the DNS answer.

    Cancellation propagates. An exception from ``replay_store`` gives ``replay_unchecked``;
    ``max_delay`` and ``clock`` are as in ``colophon_protocol.verify``.
    """
    step = start(message, receipt)
    if not isinstance(step, NeedKey):
        return step
    try:
        answer: TxtAnswer | DnsFailure = await asyncio.wait_for(
            resolver.resolve_txt(step.query), timeout=dns_budget
        )
    except DnsLimited:
        answer = DnsFailure.LIMITED
    except Exception:  # noqa: BLE001 - a timeout or any resolver failure is dns_error
        answer = DnsFailure.ERROR
    after = step.resume(answer)
    if not isinstance(after, NeedReplayCheck):
        return after
    if after.late(clock(), max_delay):
        return after.unchecked("verified more than D after arrival")
    try:
        first_time = await replay_store.claim(after.key, after.expires_at)
    except Exception:  # noqa: BLE001 - a store that cannot be read or written; not cancellation
        return after.unchecked()
    return after.resume(first_time)
