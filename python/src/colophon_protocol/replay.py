"""In-memory replay stores (§7.6), for one process. A service with several workers needs a
shared store with an atomic set-if-absent, such as Redis
``SET <digest> 1 NX EXAT <expires_at + retention>``.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable

from colophon_protocol.model import ReplayKey

__all__ = ["AsyncMemoryReplayStore", "MemoryReplayStore"]


RETENTION = 24 * 3600
"""Seconds an entry outlives ``expires_at``: the longest a verifier may lag behind arrival.

Step 14 compares the credential with the arrival time, not the time of verifying. A message
verified late, from a queue, can still pass step 14 after ``expires_at`` has gone by on the
clock, so an entry dropped exactly at ``expires_at`` would let its replay through.
"""


class MemoryReplayStore:
    """A dict of digests, purged as it grows. Thread-safe.

    A held entry always blocks a claim. Entries go only once ``expires_at + retention`` has
    passed on ``clock`` (Unix seconds). Only messages that passed both signatures reach the
    store (§7.6), so its size is bounded by verified traffic.
    """

    def __init__(
        self, *, clock: Callable[[], float] = time.time, retention: int = RETENTION
    ) -> None:
        self._clock = clock
        self._retention = retention
        self._entries: dict[str, int] = {}
        self._lock = threading.Lock()
        self._purge_at = 1024

    def claim(self, key: ReplayKey, expires_at: int) -> bool:
        digest = key.digest()
        with self._lock:
            if digest in self._entries:
                return False
            self._entries[digest] = expires_at
            if len(self._entries) >= self._purge_at:
                cutoff = self._clock() - self._retention
                self._entries = {d: t for d, t in self._entries.items() if t >= cutoff}
                self._purge_at = max(1024, 2 * len(self._entries))
            return True

    def __len__(self) -> int:
        return len(self._entries)


class AsyncMemoryReplayStore:
    """``MemoryReplayStore``, awaited. Claims never yield, so they are atomic on one loop."""

    def __init__(
        self, *, clock: Callable[[], float] = time.time, retention: int = RETENTION
    ) -> None:
        self._inner = MemoryReplayStore(clock=clock, retention=retention)

    async def claim(self, key: ReplayKey, expires_at: int) -> bool:
        await asyncio.sleep(0)
        return self._inner.claim(key, expires_at)

    def __len__(self) -> int:
        return len(self._inner)
