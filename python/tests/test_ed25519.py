"""§6.5: the public-key and R checks the library adds to OpenSSL's Ed25519."""

from __future__ import annotations

import pytest

from colophon_protocol import AgentKey, DomainKey
from colophon_protocol._ed25519 import small_order, valid_public_key

P = 2**255 - 19
IDENTITY = (1).to_bytes(32, "little")  # y = 1, x = 0
ORDER_2 = (P - 1).to_bytes(32, "little")  # y = -1, x = 0
ZERO = bytes(32)  # y = 0: a point of order 4


@pytest.mark.parametrize("point", [IDENTITY, ORDER_2, ZERO])
def test_small_order_points(point: bytes) -> None:
    assert small_order(point)
    assert not valid_public_key(point)


@pytest.mark.parametrize(
    "encoding",
    [
        P.to_bytes(32, "little"),  # y = p: not canonical
        (P + 1).to_bytes(32, "little"),  # y = p + 1, the identity written another way
        (2**255 - 1).to_bytes(32, "little"),
        IDENTITY[:-1] + bytes([0x80]),  # x = 0 with the sign bit set
        bytes(31),  # wrong length
    ],
)
def test_encodings_that_do_not_decode(encoding: bytes) -> None:
    assert not small_order(encoding)
    assert not valid_public_key(encoding)


def test_generated_keys_are_valid() -> None:
    for _ in range(20):
        assert valid_public_key(DomainKey.generate().public_bytes)
        assert valid_public_key(AgentKey.generate().public_bytes)
