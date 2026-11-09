"""The blocking adapter: one call that drives the core with a resolver and a replay store."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

from colophon_protocol.errors import DnsLimited
from colophon_protocol.model import DnsFailure, KeyQuery, Receipt, ReplayKey, TxtAnswer, Verdict
from colophon_protocol.sansio import NeedKey, NeedReplayCheck, start

__all__ = ["ReplayStore", "TxtResolver", "verify"]


class TxtResolver(Protocol):
    """Looks up TXT records. Raise ``DnsError`` on a timeout or server failure, and ``DnsLimited``
    when a miss limit refuses the lookup. NXDOMAIN and no records are an empty ``TxtAnswer``.
    The lookup MUST finish within 2 seconds, retries included (§7.4)."""

    def resolve_txt(self, query: KeyQuery) -> TxtAnswer: ...


class ReplayStore(Protocol):
    """Remembers (mailbox, iss, sub, nonce) tuples (§7.6).

    ``claim`` atomically records ``key`` until ``expires_at`` (Unix seconds) if it is not already
    recorded, and returns True if this call recorded it. Two concurrent claims of one key must
    not both return True. ``ReplayKey.digest()`` is a fixed-size key for an external store.
    Keep entries past ``expires_at`` for D, the longest verification may lag arrival
    (``replay.RETENTION``): step 14 judges the arrival time, not the time of verifying. Raise if
    the store cannot be read or written: the verdict is ``replay_unchecked`` (§7.6).
    """

    def claim(self, key: ReplayKey, expires_at: int) -> bool: ...


def verify(
    message: bytes,
    receipt: Receipt,
    *,
    resolver: TxtResolver,
    replay_store: ReplayStore,
    max_delay: int | None = None,
    clock: Callable[[], float] = time.time,
) -> Verdict:
    """Verify one delivery (§7.2). Never raises for anything in the message or the DNS answer.

    An exception from ``replay_store`` gives ``replay_unchecked``, reported as ``temperror``
    (§7.6, §7.8): hold the message and verify it again once the store is back, within D.

    ``max_delay`` is D in seconds, the longest the verifier allows between ``receipt.arrival``
    and verification. When it is set, a message verified later than that on ``clock`` is
    ``replay_unchecked``: its tuple may already be gone from the store. Set it to the store's
    retention past ``expires_at`` (``replay.RETENTION`` for the memory stores). None skips the
    check, for callers that bound the delay themselves.
    """
    step = start(message, receipt)
    if not isinstance(step, NeedKey):
        return step
    try:
        answer: TxtAnswer | DnsFailure = resolver.resolve_txt(step.query)
    except DnsLimited:
        answer = DnsFailure.LIMITED
    except Exception:  # noqa: BLE001 - any resolver failure is dns_error
        answer = DnsFailure.ERROR
    after = step.resume(answer)
    if not isinstance(after, NeedReplayCheck):
        return after
    if after.late(clock(), max_delay):
        return after.unchecked("verified more than D after arrival")
    try:
        first_time = replay_store.claim(after.key, after.expires_at)
    except Exception:  # noqa: BLE001 - a store that cannot be read or written
        return after.unchecked()
    return after.resume(first_time)
