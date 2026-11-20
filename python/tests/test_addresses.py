"""§6.4 item 3: the characters a local part may hold, and §7.2's signature count."""

from __future__ import annotations

from types import ModuleType

import pytest

from colophon_protocol import NotVerified, Reason, sansio
from colophon_protocol._addresses import (
    _NOT_IN_LOCAL_PART,
    _NOT_IN_LOCAL_PART_RANGES,
    valid_canonical_address,
)
from colophon_protocol._mime import count_fields

from helpers import receipt

EXCLUDED = ["\x85", "\xa0", "\xad", "\u200b", "\u200d", "\u202e", "\u2066", "\ufe0f", "\ufeff"]
EXCLUDED += ["\U000e0041", "\U000e0100", "\u3164", "\u115f"]


@pytest.mark.parametrize("ch", EXCLUDED, ids=[f"U+{ord(c):04X}" for c in EXCLUDED])
def test_excluded_characters(ch: str) -> None:
    assert not valid_canonical_address(f"a{ch}b@acme.example")
    assert not valid_canonical_address(f"{ch}@acme.example")


@pytest.mark.parametrize(
    "local", ["jos\u00e9", "\u30d1\u30f3", "a.\u00fc", "\u00df", "\u00a1", "\u0100"]
)
def test_other_non_ascii_is_allowed(local: str) -> None:
    assert valid_canonical_address(f"{local}@acme.example")


def test_the_list_is_the_sketch_list(sketch: ModuleType) -> None:
    """Every code point in or next to an excluded range gets the same answer from both."""
    edges = {
        c + d for low, high in _NOT_IN_LOCAL_PART_RANGES for c in (low, high) for d in (-1, 0, 1)
    }
    for c in sorted(edges):
        ch = chr(c)
        library = valid_canonical_address(f"a{ch}@acme.example")
        assert library == bool(sketch.LOCAL_PART.fullmatch(f"a{ch}")), f"U+{c:04X}"
        excluded = ch in _NOT_IN_LOCAL_PART or c <= 0x7F  # U+007F, DEL, is not atext
        assert library is not excluded, f"U+{c:04X}"


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"Colophon-Signature: v=0\r\n\r\n", 1),
        (b"colophon-signature:v=0\r\nCOLOPHON-SIGNATURE: v=0\r\n\r\n", 2),
        (b"Colophon-Signature : v=0\r\n\r\n", 0),  # space before the colon: not the field
        (b"X-Note: Colophon-Signature: v=0\r\n\r\n", 0),
        (b"To: a\rb\r\nColophon-Signature: v=0\r\n\r\n", 1),  # bare CR elsewhere
        (b"\r\nColophon-Signature: v=0\r\n", 0),  # after the empty line: body
        (b"Colophon-Signature: v=0\nColophon-Signature: v=0\n\n", 2),
        (b"", 0),
        (b"\x00" * 10, 0),
    ],
)
def test_count_fields(data: bytes, expected: int) -> None:
    assert count_fields(data, "Colophon-Signature") == expected


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        (b"\x00" * 10, Reason.NO_SIGNATURE),
        (b"From: a@acme.example\r\nnot a field\r\n\r\n", Reason.NO_SIGNATURE),
        (
            b"Colophon-Signature: v=0\r\nColophon-Signature: v=0\r\nnot a field\r\n\r\n",
            Reason.MULTIPLE_SIGNATURES,
        ),
        (b"Colophon-Signature: v=0\r\nnot a field\r\n\r\n", Reason.MALFORMED),
    ],
)
def test_count_before_header_check(message: bytes, reason: Reason) -> None:
    """Steps 1, 2 come before step 3, whatever else is wrong with the header section."""
    verdict = sansio.start(message, receipt())
    assert isinstance(verdict, NotVerified)
    assert verdict.reason is reason
