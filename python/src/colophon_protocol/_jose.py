"""Compact JWS (RFC 7515) with EdDSA (RFC 8037), only as Colophon uses it."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from colophon_protocol._codec import b64url_decode, b64url_encode, jcs, parse_ijson
from colophon_protocol._ed25519 import small_order


@dataclass(frozen=True, slots=True)
class CompactJws:
    """A compact JWS split into its parts, its header and payload parsed as JSON objects.

    ``payload_b64`` is empty, and ``payload`` is ``{}``, for a detached payload (RFC 7515
    Appendix F).
    """

    header_b64: str
    payload_b64: str
    header: dict[str, Any] = field(repr=False)
    payload: dict[str, Any] = field(repr=False)
    signature: bytes = field(repr=False)


def parse_compact(token: str, *, detached: bool) -> CompactJws:
    """Three strict base64url parts, I-JSON objects (§5.1). ValueError otherwise.

    With ``detached`` the payload part must be empty, otherwise it must be a JSON object.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWS")
    header_b64, payload_b64, signature_b64 = parts
    header = parse_ijson(b64url_decode(header_b64))
    if not isinstance(header, dict):
        raise ValueError("JWS protected header is not a JSON object")
    payload: dict[str, Any] = {}
    if detached:
        if payload_b64:
            raise ValueError("payload is not detached")
    else:
        value = parse_ijson(b64url_decode(payload_b64))
        if not isinstance(value, dict):
            raise ValueError("JWS payload is not a JSON object")
        payload = value
    signature = b64url_decode(signature_b64)
    return CompactJws(header_b64, payload_b64, header, payload, signature)


def verify_ed25519(public_key: bytes, signature: bytes, header_b64: str, payload_b64: str) -> bool:
    """Ed25519 over ``ASCII(header_b64 || "." || payload_b64)``, as §6.5 makes it exact.
    False on any failure. OpenSSL checks S < L and the equation without the cofactor; an R of
    small order is rejected here. Keys are checked where they are read."""
    if len(signature) == 64 and small_order(signature[:32]):
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(signature, f"{header_b64}.{payload_b64}".encode("ascii"))
    except (InvalidSignature, ValueError):
        return False
    return True


def sign_ed25519(key: Ed25519PrivateKey, header: dict[str, Any], payload: bytes) -> tuple[str, str]:
    """Sign; return (header_b64.payload_b64, signature_b64). The header is serialized with JCS."""
    signing_input = f"{b64url_encode(jcs(header))}.{b64url_encode(payload)}"
    return signing_input, b64url_encode(key.sign(signing_input.encode("ascii")))
