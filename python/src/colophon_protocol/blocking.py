"""The blocking adapter: one call that drives the core with a resolver and a replay store."""

from __future__ import annotations

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
    Keep entries past ``expires_at`` for as long as verification may lag arrival
    (``replay.RETENTION``): step 14 judges the arrival time, not the time of verifying.
    """

    def claim(self, key: ReplayKey, expires_at: int) -> bool: ...


def verify(
    message: bytes, receipt: Receipt, *, resolver: TxtResolver, replay_store: ReplayStore
) -> Verdict:
    """Verify one delivery (§7.2). Never raises for anything in the message or the DNS answer.

    An exception from ``replay_store`` propagates: with no store there is no verdict, and the
    message must not be reported as verified. Retry later, or handle it as plain email.
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
    return after.resume(replay_store.claim(after.key, after.expires_at))
