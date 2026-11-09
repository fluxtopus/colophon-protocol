"""§6.5: the Ed25519 checks RFC 8032 leaves open, made exact.

OpenSSL, under the ``cryptography`` package, already checks S < L and uses the equation without
the cofactor, and an R that is not canonical fails its octet-for-octet comparison. What it does
not reject are public keys that are not canonical or are of small order, and an R of small
order. This module adds those checks, with the point arithmetic of RFC 8032 §5.1.3 and §5.1.4.
"""

from __future__ import annotations

_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P

_Point = tuple[int, int, int, int]  # extended coordinates (X, Y, Z, T)


def _decode(data: bytes) -> _Point | None:
    """RFC 8032 §5.1.3. None when decoding fails, a y of p or more (not canonical) included."""
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if (x * x - x2) % _P or (x == 0 and sign):
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def _double(a: _Point) -> _Point:
    """RFC 8032 §5.1.4, the point added to itself."""
    x1, y1, z1, t1 = a
    aa, bb = (y1 - x1) * (y1 - x1) % _P, (y1 + x1) * (y1 + x1) % _P
    cc, dd = 2 * t1 * t1 * _D % _P, 2 * z1 * z1 % _P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def small_order(data: bytes) -> bool:
    """True if ``data`` decodes to a point P with 8P the identity."""
    point = _decode(data)
    if point is None:
        return False
    for _ in range(3):
        point = _double(point)
    x, y, z, _ = point
    return x % _P == 0 and (y - z) % _P == 0


def valid_public_key(data: bytes) -> bool:
    """§6.5: the canonical encoding of a point that is not of small order."""
    return _decode(data) is not None and not small_order(data)
