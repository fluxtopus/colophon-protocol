"""Every vector in reference/vectors.json, through the blocking, asyncio and sans-IO drivers."""

from __future__ import annotations

import pytest

from colophon_protocol import NotVerified, Receipt, TxtAnswer, Verified, aio, sansio, verify
from colophon_protocol.dns import AsyncStaticResolver, StaticResolver
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


def _outcome(verdict: Verified | NotVerified) -> str:
    return "verified" if isinstance(verdict, Verified) else verdict.reason.value


def test_vector_count() -> None:
    assert len(CASES) == 77
    assert sum(len(c.deliveries) for c in CASES) == 80


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_blocking(case: Case) -> None:
    store = MemoryReplayStore(clock=lambda: 0.0)
    got = [
        _outcome(
            verify(
                case.message, _receipt(d), resolver=StaticResolver(d.dns_txt), replay_store=store
            )
        )
        for d in case.deliveries
    ]
    assert got == [d.expected for d in case.deliveries]


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_asyncio(case: Case) -> None:
    store = AsyncMemoryReplayStore(clock=lambda: 0.0)
    got = []
    for d in case.deliveries:
        verdict = await aio.verify(
            case.message, _receipt(d), resolver=AsyncStaticResolver(d.dns_txt), replay_store=store
        )
        got.append(_outcome(verdict))
    assert got == [d.expected for d in case.deliveries]


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_sansio(case: Case) -> None:
    seen: set[str] = set()
    got = []
    for d in case.deliveries:
        step: sansio.Step = sansio.start(case.message, _receipt(d))
        if isinstance(step, sansio.NeedKey):
            records = d.dns_txt.get(step.query.name, [])
            step = step.resume(DnsFailure.ERROR if records is None else TxtAnswer(records))
        if isinstance(step, sansio.NeedReplayCheck):
            first = step.key.digest() not in seen
            seen.add(step.key.digest())
            step = step.resume(first)
        assert isinstance(step, (Verified, NotVerified))
        if isinstance(step, NotVerified):
            assert not step.detail.startswith("internal error"), step.detail
        got.append(_outcome(step))
    assert got == [d.expected for d in case.deliveries]
