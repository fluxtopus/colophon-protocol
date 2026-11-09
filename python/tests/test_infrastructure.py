"""The DNS guard (§7.4), the replay stores (§7.6) and the adapters' error handling."""

from __future__ import annotations

import asyncio
from types import ModuleType

import pytest

from colophon_protocol import DnsError, DnsLimited, KeyQuery, Reason, TxtAnswer, aio, verify
from colophon_protocol.dns import AsyncGuardedResolver, GuardedResolver, StaticResolver
from colophon_protocol.model import ReplayKey
from colophon_protocol.replay import AsyncMemoryReplayStore, MemoryReplayStore

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


def test_replay_store_failure_propagates(sketch: ModuleType) -> None:
    class Down:
        def claim(self, key: ReplayKey, expires_at: int) -> bool:
            raise ConnectionError("store down")

    resolver = StaticResolver({ISSUER.dns_name: [ISSUER.dns_record]})
    with pytest.raises(ConnectionError):
        verify(sketch.signed(), receipt(), resolver=resolver, replay_store=Down())


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
