"""Differential tests: the library against the reference sketch on mutated messages.

Each mutation edits the draft's example; the sketch signs the result over its own reading of it.
Both then verify, and must give the same verdict and reason: since v0-06 the draft fixes every
reading the two used to differ on (line ends, header syntax, Content-Type, multipart, 8-bit
bodies). The one allowance is a sketch crash, which is a sketch defect, never a library verdict.
When both verify they report the same agent.
"""

from __future__ import annotations

import random
from collections import Counter
from types import ModuleType

import pytest

from colophon_protocol import NotVerified, Verified, verify
from colophon_protocol.replay import MemoryReplayStore
from mutations import mutate

from helpers import receipt, resolver

SEEDS = range(3000)


def _sketch_verdict(sketch: ModuleType, message: bytes) -> str:
    try:
        return str(sketch.verify(message, sketch.arrival(set())).reason)
    except Exception as exc:  # noqa: BLE001 - a sketch crash is one of the categories
        return f"raised {type(exc).__name__}"


def _classify(theirs: str) -> str | None:
    return "sketch raises (sketch defect)" if theirs.startswith("raised") else None


def _case(sketch: ModuleType, seed: int) -> tuple[bytes, str, Verified | NotVerified]:
    rng = random.Random(seed)
    unsigned, _ = mutate(sketch.example_unsigned(), rng, rounds=rng.choice([1, 1, 2]))
    try:
        message = sketch.signed(unsigned=unsigned)
    except Exception:  # noqa: BLE001 - keep the original signature; parsing still differs
        original = sketch.signed()
        message = original[: original.index(b"From:")] + unsigned
    ours = verify(message, receipt(), resolver=resolver(), replay_store=MemoryReplayStore())
    return message, _sketch_verdict(sketch, message), ours


def test_differential(sketch: ModuleType) -> None:
    unexplained: list[str] = []
    categories: Counter[str] = Counter()
    agreed = 0
    for seed in SEEDS:
        message, theirs, ours = _case(sketch, seed)
        mine = "verified" if isinstance(ours, Verified) else ours.reason.value
        if mine == theirs:
            agreed += 1
            if isinstance(ours, Verified):
                agent = sketch.verify(message, sketch.arrival(set())).agent
                assert agent["sub"] == ours.agent.sub
                assert agent["iss"] == ours.agent.iss
            continue
        category = _classify(theirs)
        if isinstance(ours, Verified):
            # The library must not accept what the sketch refuses, bar the sketch's own defects.
            assert category is not None, f"seed {seed}: library verified, sketch said {theirs}"
            assert "sketch" in category, f"seed {seed}: library verified, sketch said {theirs}"
        if category is None:
            detail = ours.detail if isinstance(ours, NotVerified) else ""
            unexplained.append(f"seed {seed}: sketch {theirs}, library {mine} ({detail})")
        else:
            categories[category] += 1
    print(f"\n{agreed} of {len(SEEDS)} agree; disagreements: {dict(categories)}")
    assert not unexplained, "\n".join(unexplained[:20])
    assert agreed > len(SEEDS) * 0.7


@pytest.mark.parametrize("body", [b"Caf\xc3\xa9 for 2\r\n"])
def test_eight_bit_body_octets_as_they_are(sketch: ModuleType, body: bytes) -> None:
    """§6.4: body octets are taken as they are. v0-05's sketch called a UTF-8 body sent as 8bit
    malformed; v0-06's agrees with the library."""
    from colophon_protocol import sign

    from helpers import AGENT_KEY, SIGNED, credential

    unsigned = (
        b"From: maple-tiger-27@acme.example\r\nTo: reservations@bistro.example\r\nSubject: x\r\n"
        b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: 8bit\r\n\r\n" + body
    )
    signed = sign(unsigned, credential=credential(), agent_key=AGENT_KEY, signed_at=SIGNED)
    ours = verify(signed, receipt(), resolver=resolver(), replay_store=MemoryReplayStore())
    theirs = _sketch_verdict(sketch, signed)
    assert theirs == ("verified" if isinstance(ours, Verified) else ours.reason.value)
