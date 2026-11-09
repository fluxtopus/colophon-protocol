"""Ed25519 keys for the two roles: the domain key (§4) and the agent key (§5.1 ``cnf``)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from colophon_protocol._codec import b64url_decode, b64url_encode
from colophon_protocol._credential import jwk_thumbprint

__all__ = ["AgentKey", "DomainKey"]

_K = TypeVar("_K", bound="_Ed25519Key")


class _Ed25519Key:
    """A private Ed25519 key. ``repr`` never shows it."""

    __slots__ = ("_key", "_public")

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key
        self._public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @classmethod
    def generate(cls: type[_K]) -> _K:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls: type[_K], seed: bytes) -> _K:
        """From the 32-octet private key (RFC 8032 §5.1.5 seed)."""
        if len(seed) != 32:
            raise ValueError("an Ed25519 seed is 32 octets")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_jwk(cls: type[_K], jwk: Mapping[str, Any] | str) -> _K:
        """From a private OKP JWK (RFC 8037), as a mapping or JSON text. The ``x`` member, when
        present, must match ``d``."""
        data = json.loads(jwk) if isinstance(jwk, str) else jwk
        if (
            not isinstance(data, Mapping)
            or data.get("kty") != "OKP"
            or data.get("crv") != "Ed25519"
        ):
            raise ValueError("not an Ed25519 OKP JWK")
        d = data.get("d")
        if not isinstance(d, str):
            raise ValueError("the JWK has no private part (d)")
        key = cls.from_seed(b64url_decode(d))
        x = data.get("x")
        if x is not None and x != b64url_encode(key.public_bytes):
            raise ValueError("the JWK's x does not match its d")
        return key

    @property
    def public_bytes(self) -> bytes:
        """The raw 32-octet public key."""
        return self._public

    def public_jwk(self) -> dict[str, str]:
        return {"crv": "Ed25519", "kty": "OKP", "x": b64url_encode(self._public)}

    def private_jwk(self) -> dict[str, str]:
        """The private key as a JWK. Store it as a secret."""
        seed = self._key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return {**self.public_jwk(), "d": b64url_encode(seed)}

    def thumbprint(self) -> str:
        """RFC 7638 JWK thumbprint (SHA-256, base64url) of the public key."""
        return jwk_thumbprint(self._public)

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)

    @property
    def private_key(self) -> Ed25519PrivateKey:
        return self._key

    def __repr__(self) -> str:
        return f"{type(self).__name__}(thumbprint={self.thumbprint()!r})"

    def __eq__(self, other: object) -> bool:
        return type(other) is type(self) and other.public_bytes == self._public

    def __hash__(self) -> int:
        return hash((type(self), self._public))


class DomainKey(_Ed25519Key):
    """A domain key: it signs credentials, and its public half is in DNS (§4.1)."""

    __slots__ = ()


class AgentKey(_Ed25519Key):
    """An agent key: it signs messages, and a credential certifies its public half (§5.1)."""

    __slots__ = ()
