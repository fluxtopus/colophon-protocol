"""Differential tests: the library against the reference sketch on mutated messages.

Each mutation edits the draft's example; the sketch signs the result over its own reading of it.
Both then verify. They must agree, or disagree for a reason listed in ``KNOWN``: each entry is a
place where the draft does not say which reading is right (reported as a spec issue), or a known
sketch defect. The safety property holds without exception: the library never verifies a message
the sketch rejects, unless the sketch rejected it for one of its defects, and when both verify
they report the same agent.
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

# Library detail prefix -> the issue it belongs to. The library is stricter in each.
KNOWN = {
    "a bare CR in the header section": "line ends: bare CR (spec issue)",
    "a header line is not a field": "header syntax (spec issue)",
    "Content-Type does not parse": "Content-Type grammar (spec issue)",
    "Content-Type has an RFC 2231 parameter": "Content-Type grammar (spec issue)",
    "multipart has no close delimiter": "multipart structure (spec issue)",
    "a part after the body is not marked": "multipart structure (spec issue)",
    "charset ": "charset octets (sketch accepts a non-ASCII charset name)",
}


def _sketch_verdict(sketch: ModuleType, message: bytes) -> str:
    try:
        return str(sketch.verify(message, sketch.arrival(set())).reason)
    except Exception as exc:  # noqa: BLE001 - a sketch crash is one of the categories
        return f"raised {type(exc).__name__}"


def _classify(message: bytes, theirs: str, ours: Verified | NotVerified) -> str | None:
    body = message.partition(b"\r\n\r\n")[2] or message.partition(b"\n\n")[2]
    if theirs.startswith("raised"):
        return "sketch raises (sketch defect)"
    if theirs in ("malformed", "no_signature") and not body.isascii():
        return "sketch rejects 8-bit body octets (sketch defect)"
    if b"\r" in message.replace(b"\r\n", b""):
        return "line ends: bare CR (spec issue)"
    if isinstance(ours, NotVerified):
        for prefix, category in KNOWN.items():
            if ours.detail.startswith(prefix):
                return category
        if ours.reason.value == "signature_invalid":
            return "the sketch could not sign; the library reads further (ordering)"
    return None


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
        category = _classify(message, theirs, ours)
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
def test_eight_bit_body_is_a_sketch_defect(sketch: ModuleType, body: bytes) -> None:
    """The sketch reads a part's payload through compat32's get_payload(decode=False), which
    decodes non-ASCII octets with the part's charset; encoding that back as ASCII then fails, so
    the sketch calls every UTF-8 body sent as 8bit malformed. The library verifies it."""
    from colophon_protocol import sign

    from helpers import AGENT_KEY, SIGNED, credential

    unsigned = (
        b"From: maple-tiger-27@acme.example\r\nTo: reservations@bistro.example\r\nSubject: x\r\n"
        b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: 8bit\r\n\r\n" + body
    )
    signed = sign(unsigned, credential=credential(), agent_key=AGENT_KEY, signed_at=SIGNED)
    ours = verify(signed, receipt(), resolver=resolver(), replay_store=MemoryReplayStore())
    assert isinstance(ours, Verified)
    assert _sketch_verdict(sketch, signed) == "malformed"
