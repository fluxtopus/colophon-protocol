"""The DNS guard (§7.4), the replay stores (§7.6) and the adapters' error handling."""

from __future__ import annotations

import asyncio
from types import ModuleType

import pytest

from colophon_protocol import DnsError, DnsLimited, KeyQuery, Reason, TxtAnswer, aio, verify
from colophon_protocol.authres import colophon_result
from colophon_protocol.dns import (
    MISS_LIMIT,
    AsyncGuardedResolver,
    AsyncStaticResolver,
    GuardedResolver,
    StaticResolver,
)
from colophon_protocol.model import ReplayKey
from colophon_protocol.replay import RETENTION, AsyncMemoryReplayStore, MemoryReplayStore

from helpers import ISSUER, receipt


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _Counting:
    def __init__(self, answer: TxtAnswer | Exception) -> None:
        self.answer = answer
        self.calls = 0

    def resolve_txt(self, query: KeyQuery) -> TxtAnswer:
        self.calls += 1
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


Q = KeyQuery("s1", "acme.example")


def test_positive_answers_are_cached_for_their_ttl() -> None:
    clock, inner = _Clock(), _Counting(TxtAnswer([ISSUER.dns_record], ttl=60))
    guard = GuardedResolver(inner, clock=clock)
    guard.resolve_txt(Q)
    guard.resolve_txt(Q)
    assert inner.calls == 1
    clock.now += 61
    guard.resolve_txt(Q)
    assert inner.calls == 2


def test_negative_answers_are_cached_at_least_five_minutes() -> None:
    clock, inner = _Clock(), _Counting(TxtAnswer((), ttl=10))
    guard = GuardedResolver(inner, clock=clock)
    guard.resolve_txt(Q)
    clock.now += 299
    guard.resolve_txt(Q)
    assert inner.calls == 1
    clock.now += 2
    guard.resolve_txt(Q)
    assert inner.calls == 2


def test_miss_limit_per_host() -> None:
    clock, inner = _Clock(), _Counting(TxtAnswer(()))
    guard = GuardedResolver(inner, clock=clock)
    for n in range(20):
        guard.resolve_txt(KeyQuery(f"s{n}", "acme.example"))
    with pytest.raises(DnsLimited):
        guard.resolve_txt(KeyQuery("other", "acme.example"))
    guard.resolve_txt(KeyQuery("s0", "acme.example"))  # cached answers still come back
    guard.resolve_txt(KeyQuery("s1", "other.example"))  # another host is not limited
    clock.now += 3600
    guard.resolve_txt(KeyQuery("other", "acme.example"))


def test_failed_lookups_count_as_misses() -> None:
    inner = _Counting(DnsError("timeout"))
    guard = GuardedResolver(inner, clock=_Clock())
    for _ in range(20):
        with pytest.raises(DnsError):
            guard.resolve_txt(Q)
    with pytest.raises(DnsLimited):
        guard.resolve_txt(Q)
    assert inner.calls == 20


def test_cache_is_bounded() -> None:
    inner = _Counting(TxtAnswer([ISSUER.dns_record], ttl=600))
    guard = GuardedResolver(inner, clock=_Clock(), max_names=3)
    for n in range(10):
        guard.resolve_txt(KeyQuery(f"s{n}", "acme.example"))
    guard.resolve_txt(KeyQuery("s0", "acme.example"))
    assert inner.calls == 11


def test_dns_limited_verdict(sketch: ModuleType) -> None:
    class Limited:
        def resolve_txt(self, query: KeyQuery) -> TxtAnswer:
            raise DnsLimited("limit")

    verdict = verify(
        sketch.signed(), receipt(), resolver=Limited(), replay_store=MemoryReplayStore()
    )
    assert verdict.reason is Reason.DNS_LIMITED


def test_resolver_bugs_are_dns_errors(sketch: ModuleType) -> None:
    verdict = verify(
        sketch.signed(),
        receipt(),
        resolver=_Counting(RuntimeError("bug")),
        replay_store=MemoryReplayStore(),
    )
    assert verdict.reason is Reason.DNS_ERROR


class _Down:
    def claim(self, key: ReplayKey, expires_at: int) -> bool:
        raise ConnectionError("store down")


class _AsyncDown:
    async def claim(self, key: ReplayKey, expires_at: int) -> bool:
        raise ConnectionError("store down")


def _resolver() -> StaticResolver:
    return StaticResolver({ISSUER.dns_name: [ISSUER.dns_record]})


def test_replay_store_failure_is_replay_unchecked(sketch: ModuleType) -> None:
    verdict = verify(sketch.signed(), receipt(), resolver=_resolver(), replay_store=_Down())
    assert verdict.reason is Reason.REPLAY_UNCHECKED
    assert colophon_result(verdict) == "temperror"


async def test_async_replay_store_failure_is_replay_unchecked(sketch: ModuleType) -> None:
    verdict = await aio.verify(
        sketch.signed(),
        receipt(),
        resolver=AsyncStaticResolver({ISSUER.dns_name: [ISSUER.dns_record]}),
        replay_store=_AsyncDown(),
    )
    assert verdict.reason is Reason.REPLAY_UNCHECKED


@pytest.mark.parametrize(
    ("delay", "verified"), [(0, True), (RETENTION, True), (RETENTION + 1, False)]
)
def test_verified_later_than_d_is_replay_unchecked(
    sketch: ModuleType, delay: int, verified: bool
) -> None:
    r = receipt()
    store = MemoryReplayStore()
    verdict = verify(
        sketch.signed(),
        r,
        resolver=_resolver(),
        replay_store=store,
        max_delay=RETENTION,
        clock=lambda: float(r.arrival + delay),
    )
    assert verdict.verified is verified
    if not verified:
        assert verdict.reason is Reason.REPLAY_UNCHECKED
        assert len(store) == 0  # the store is not touched


async def test_async_verified_later_than_d(sketch: ModuleType) -> None:
    r = receipt()
    verdict = await aio.verify(
        sketch.signed(),
        r,
        resolver=AsyncStaticResolver({ISSUER.dns_name: [ISSUER.dns_record]}),
        replay_store=AsyncMemoryReplayStore(),
        max_delay=60,
        clock=lambda: float(r.arrival + 61),
    )
    assert verdict.reason is Reason.REPLAY_UNCHECKED


def test_twenty_misses_refuse_the_lookup(sketch: ModuleType) -> None:
    clock = _Clock()
    guard = GuardedResolver(_resolver(), clock=clock)
    for i in range(MISS_LIMIT - 1):
        guard.resolve_txt(KeyQuery(f"m{i}", "acme.example"))
    verdict = verify(sketch.signed(), receipt(), resolver=guard, replay_store=MemoryReplayStore())
    assert verdict.verified  # 19 misses: the lookup goes ahead
    guard = GuardedResolver(_resolver(), clock=clock)
    for i in range(MISS_LIMIT):
        guard.resolve_txt(KeyQuery(f"m{i}", "acme.example"))
    verdict = verify(sketch.signed(), receipt(), resolver=guard, replay_store=MemoryReplayStore())
    assert verdict.reason is Reason.DNS_LIMITED


async def test_async_dns_budget(sketch: ModuleType) -> None:
    class Slow:
        async def resolve_txt(self, query: KeyQuery) -> TxtAnswer:
            await asyncio.sleep(5)
            return TxtAnswer([ISSUER.dns_record])

    verdict = await aio.verify(
        sketch.signed(),
        receipt(),
        resolver=Slow(),
        replay_store=AsyncMemoryReplayStore(),
        dns_budget=0.05,
    )
    assert verdict.reason is Reason.DNS_ERROR


async def test_async_guard_and_concurrent_replays(sketch: ModuleType) -> None:
    class Inner:
        async def resolve_txt(self, query: KeyQuery) -> TxtAnswer:
            await asyncio.sleep(0)
            return TxtAnswer([ISSUER.dns_record], ttl=300)

    resolver, store = AsyncGuardedResolver(Inner()), AsyncMemoryReplayStore()
    verdicts = await asyncio.gather(
        *(
            aio.verify(sketch.signed(), receipt(), resolver=resolver, replay_store=store)
            for _ in range(10)
        )
    )
    assert sum(v.verified for v in verdicts) == 1
    assert {v.reason for v in verdicts if not v.verified} == {Reason.REPLAY}


def test_replay_entries_outlive_expiry() -> None:
    clock = _Clock()
    store = MemoryReplayStore(clock=clock, retention=100)
    key = ReplayKey("m", "acme.example", "a", "n" * 16)
    assert store.claim(key, expires_at=1000)
    clock.now = 1050
    assert not store.claim(key, expires_at=1000)


def test_replay_store_purges_old_entries() -> None:
    clock = _Clock()
    store = MemoryReplayStore(clock=clock, retention=10)
    for n in range(1023):
        assert store.claim(ReplayKey("m", "i", "s", f"{n:016d}"), expires_at=0)
    clock.now = 100
    store.claim(ReplayKey("m", "i", "s", "x" * 16), expires_at=1000)
    assert len(store) == 1


def test_replay_keys_are_per_mailbox() -> None:
    store = MemoryReplayStore()
    assert store.claim(ReplayKey("m1", "i", "s", "n" * 16), 0)
    assert store.claim(ReplayKey("m2", "i", "s", "n" * 16), 0)
