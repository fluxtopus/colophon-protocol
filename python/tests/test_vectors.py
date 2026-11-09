"""Every vector in reference/vectors.json, through the blocking, asyncio and sans-IO drivers.

Each delivery checks the verdict, the reason, and the §7.8 resinfo, exactly."""

from __future__ import annotations

import pytest

from colophon_protocol import (
    KeyQuery,
    NotVerified,
    Receipt,
    ReplayKey,
    TxtAnswer,
    Verified,
    aio,
    sansio,
    verify,
)
from colophon_protocol.authres import colophon_resinfo
from colophon_protocol.dns import (
    MISS_LIMIT,
    AsyncGuardedResolver,
    AsyncStaticResolver,
    GuardedResolver,
    StaticResolver,
)
from colophon_protocol.model import DnsFailure
from colophon_protocol.replay import AsyncMemoryReplayStore, MemoryReplayStore

from conftest import Case, Delivery, load_cases

CASES = load_cases()


def _receipt(d: Delivery) -> Receipt:
    return Receipt(
        arrival=d.accepted_at,
        dkim_pass_domains=d.dkim_pass_domains,
        mailbox=d.mailbox,
        mailbox_addresses=d.mailbox_addresses,
    )


def _misses(d: Delivery, host: str) -> list[KeyQuery]:
    """Lookups that miss: NXDOMAIN at names not in the delivery's DNS (§7.4)."""
    return [KeyQuery(f"-miss-{i}", host) for i in range(min(d.dns_misses, MISS_LIMIT))]


class _Guarded:
    """The library's guard, with the delivery's misses counted before the lookup."""

    def __init__(self, d: Delivery) -> None:
        self._d, self._guard = d, GuardedResolver(StaticResolver(d.dns_txt), clock=lambda: 0.0)

    def resolve_txt(self, query: KeyQuery) -> TxtAnswer:
        for miss in _misses(self._d, query.host):
            self._guard.resolve_txt(miss)
        return self._guard.resolve_txt(query)


class _AsyncGuarded:
    def __init__(self, d: Delivery) -> None:
        self._d = d
        self._guard = AsyncGuardedResolver(AsyncStaticResolver(d.dns_txt), clock=lambda: 0.0)

    async def resolve_txt(self, query: KeyQuery) -> TxtAnswer:
        for miss in _misses(self._d, query.host):
            await self._guard.resolve_txt(miss)
        return await self._guard.resolve_txt(query)


class _Down:
    def claim(self, key: ReplayKey, expires_at: int) -> bool:
        raise ConnectionError("replay store unavailable")


class _AsyncDown:
    async def claim(self, key: ReplayKey, expires_at: int) -> bool:
        raise ConnectionError("replay store unavailable")


def _outcome(verdict: Verified | NotVerified) -> tuple[str, str]:
    verdict_or_reason = "verified" if isinstance(verdict, Verified) else verdict.reason.value
    resinfo = colophon_resinfo(verdict)
    assert verdict.to_json()["authentication_results"] == resinfo
    return verdict_or_reason, resinfo


def _expected(case: Case) -> list[tuple[str, str]]:
    return [(d.expected, d.expected_authentication_results) for d in case.deliveries]


def test_vector_count() -> None:
    assert len(CASES) == 115
    deliveries = [d for c in CASES for d in c.deliveries]
    assert len(deliveries) == 118
    results = [d.expected_authentication_results.split()[0] for d in deliveries]
    assert results.count("colophon=pass") == 32
    assert results.count("colophon=fail") == 82
    assert results.count("colophon=none") == 1
    assert results.count("colophon=temperror") == 3


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_blocking(case: Case) -> None:
    store = MemoryReplayStore(clock=lambda: 0.0)
    got = [
        _outcome(
            verify(
                case.message,
                _receipt(d),
                resolver=_Guarded(d),
                replay_store=store if d.replay_store_available else _Down(),
            )
        )
        for d in case.deliveries
    ]
    assert got == _expected(case)


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_asyncio(case: Case) -> None:
    store = AsyncMemoryReplayStore(clock=lambda: 0.0)
    got = []
    for d in case.deliveries:
        verdict = await aio.verify(
            case.message,
            _receipt(d),
            resolver=_AsyncGuarded(d),
            replay_store=store if d.replay_store_available else _AsyncDown(),
        )
        got.append(_outcome(verdict))
    assert got == _expected(case)


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_sansio(case: Case) -> None:
    seen: set[str] = set()
    got = []
    for d in case.deliveries:
        step: sansio.Step = sansio.start(case.message, _receipt(d))
        if isinstance(step, sansio.NeedKey):
            records = d.dns_txt.get(step.query.name, [])
            if d.dns_misses >= MISS_LIMIT:
                step = step.resume(DnsFailure.LIMITED)
            else:
                step = step.resume(DnsFailure.ERROR if records is None else TxtAnswer(records))
        if isinstance(step, sansio.NeedReplayCheck) and not d.replay_store_available:
            step = step.unchecked()
        elif isinstance(step, sansio.NeedReplayCheck):
            first = step.key.digest() not in seen
            seen.add(step.key.digest())
            step = step.resume(first)
        assert isinstance(step, (Verified, NotVerified))
        if isinstance(step, NotVerified):
            assert not step.detail.startswith("internal error"), step.detail
        got.append(_outcome(step))
    assert got == _expected(case)
