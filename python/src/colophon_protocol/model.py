"""The values a caller passes in and gets back. All are immutable."""

from __future__ import annotations

import enum
import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import ClassVar, Literal

from colophon_protocol._addresses import AddressError, canonical_addr_spec
from colophon_protocol._codec import ascii_lower, jcs
from colophon_protocol.authres import colophon_resinfo

__all__ = [
    "Agent",
    "DnsFailure",
    "KeyQuery",
    "Named",
    "NotVerified",
    "Principal",
    "Pseudonymous",
    "Reason",
    "Receipt",
    "ReplayKey",
    "TxtAnswer",
    "Verdict",
    "Verified",
    "Withheld",
]


class Reason(str, enum.Enum):
    """Why a message is not verified: the reason codes of §7.2."""

    NO_SIGNATURE = "no_signature"
    MULTIPLE_SIGNATURES = "multiple_signatures"
    MALFORMED = "malformed"
    DKIM_UNALIGNED = "dkim_unaligned"
    UNSUPPORTED_VERSION = "unsupported_version"
    CREDENTIAL_INVALID = "credential_invalid"
    DNS_ERROR = "dns_error"
    DNS_LIMITED = "dns_limited"
    KEY_NOT_FOUND = "key_not_found"
    KEY_REVOKED = "key_revoked"
    CREDENTIAL_EXPIRED = "credential_expired"
    FROM_MISMATCH = "from_mismatch"
    LAYOUT = "layout"
    SIGNATURE_INVALID = "signature_invalid"
    NOT_ADDRESSED = "not_addressed"
    REPLAY = "replay"
    REPLAY_UNCHECKED = "replay_unchecked"

    def __str__(self) -> str:
        return self.value


# ---------------------------------------------------------------- principal disclosure (§5.3)


@dataclass(frozen=True, slots=True)
class Withheld:
    """The issuer says it knows the principal, and nothing more."""

    mode: ClassVar[Literal["withheld"]] = "withheld"

    def to_json(self) -> dict[str, str]:
        return {"mode": self.mode}


@dataclass(frozen=True, slots=True)
class Pseudonymous:
    """A pseudonym for the principal that only this counterparty sees."""

    id: str
    mode: ClassVar[Literal["pseudonymous"]] = "pseudonymous"

    def to_json(self) -> dict[str, str]:
        return {"mode": self.mode, "id": self.id}


@dataclass(frozen=True, slots=True)
class Named:
    """The principal's name or address, as the issuer attests it. Sender text: show it as such."""

    name: str
    mode: ClassVar[Literal["named"]] = "named"

    def to_json(self) -> dict[str, str]:
        return {"mode": self.mode, "name": self.name}


Principal = Withheld | Pseudonymous | Named


# ---------------------------------------------------------------- verdicts (§7.3)


@dataclass(frozen=True, slots=True)
class Agent:
    """The verified agent (§7.3). Every string here was written by the sender's side (§9)."""

    iss: str
    """The issuing domain: the From host, which passed aligned DKIM."""
    sub: str
    """The agent ID, unique within the issuer."""
    address: str
    """The agent's address, in canonical form (the credential's ``from``)."""
    principal: Principal
    scope: str | None
    key_thumbprint: str
    """RFC 7638 JWK thumbprint (SHA-256, base64url) of the agent key."""

    def to_json(self) -> dict[str, object]:
        out: dict[str, object] = {
            "iss": self.iss,
            "sub": self.sub,
            "from": self.address,
            "principal": self.principal.to_json(),
            "key_thumbprint": self.key_thumbprint,
        }
        if self.scope is not None:
            out["scope"] = self.scope
        return out


@dataclass(frozen=True, slots=True)
class Verified:
    """Both proofs hold (§3), for this mailbox, for the first time (§7.6)."""

    agent: Agent
    selector: str
    """The selector of the domain key the credential verified against: the credential's ``kid``."""
    credential_hash: str
    """Base64url of the SHA-256 of the credential ``c``, as carried: the signing input's
    ``credential`` member (§6.3), reported as ``header.cred`` (§7.8)."""
    domain_key: bytes = field(repr=False)
    """The raw Ed25519 domain key. §9: keep it beside the message if proof is needed later."""
    credential_issued_at: int
    credential_expires_at: int
    signed_at: int
    """The signature's ``iat``. Advisory: the signer's clock, checked only against arrival."""
    nonce: str

    verified: ClassVar[Literal[True]] = True
    reason: ClassVar[None] = None

    def to_json(self) -> dict[str, object]:
        return {
            "verdict": "verified",
            "agent": self.agent.to_json(),
            "selector": self.selector,
            "credential_hash": self.credential_hash,
            "credential_issued_at": self.credential_issued_at,
            "credential_expires_at": self.credential_expires_at,
            "signed_at": self.signed_at,
            "nonce": self.nonce,
            "authentication_results": colophon_resinfo(self),
        }


@dataclass(frozen=True, slots=True)
class NotVerified:
    """Not verified, with the §7.2 reason. The message is plain email (§7.3)."""

    reason: Reason
    detail: str = field(default="", compare=False)
    """A human-readable note on the failing check, for logs and diagnosis only. Not stable."""

    verified: ClassVar[Literal[False]] = False

    def to_json(self) -> dict[str, object]:
        out: dict[str, object] = {"verdict": "not_verified", "reason": self.reason.value}
        if self.detail:
            out["detail"] = self.detail
        out["authentication_results"] = colophon_resinfo(self)
        return out


Verdict = Verified | NotVerified


# ---------------------------------------------------------------- receiver inputs (§7.1)


@dataclass(frozen=True, slots=True, init=False)
class Receipt:
    """The receiver's own facts about one delivery (§7.1). The message never supplies these.

    ``arrival`` is when the receiver's mail server accepted the message in SMTP, in Unix seconds.
    ``dkim_pass_domains`` holds the ``d=`` of every DKIM signature the receiver's own checks
    passed. ``mailbox`` is the receiver's stable identifier for the mailbox this copy reached, and
    ``mailbox_addresses`` every address that mailbox receives at: its own and its aliases.
    """

    arrival: int
    dkim_pass_domains: frozenset[str]
    mailbox: str
    mailbox_addresses: frozenset[str]

    def __init__(
        self,
        *,
        arrival: int,
        dkim_pass_domains: Iterable[str],
        mailbox: str,
        mailbox_addresses: Iterable[str],
    ) -> None:
        if type(arrival) is not int:
            raise TypeError("arrival must be an int (Unix seconds)")
        if not isinstance(mailbox, str) or not mailbox:
            raise ValueError("mailbox must be a non-empty string")
        domains = _string_set(dkim_pass_domains, "dkim_pass_domains")
        addresses = _string_set(mailbox_addresses, "mailbox_addresses")
        try:
            canonical = frozenset(canonical_addr_spec(a) for a in addresses)
        except AddressError as exc:
            raise ValueError(f"mailbox_addresses holds an invalid address: {exc}") from None
        object.__setattr__(self, "arrival", arrival)
        object.__setattr__(self, "dkim_pass_domains", frozenset(ascii_lower(d) for d in domains))
        object.__setattr__(self, "mailbox", mailbox)
        object.__setattr__(self, "mailbox_addresses", canonical)


def _string_set(values: Iterable[str], name: str) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{name} must be a collection of strings, not a single string")
    out = frozenset(values)
    if not all(isinstance(v, str) for v in out):
        raise TypeError(f"{name} must hold strings")
    return out


# ---------------------------------------------------------------- what the core asks the caller


@dataclass(frozen=True, slots=True)
class KeyQuery:
    """The one DNS lookup a message needs (§7.2 step 9): TXT at ``<selector>._colophon.<host>``."""

    selector: str
    host: str

    @property
    def name(self) -> str:
        return f"{self.selector}._colophon.{self.host}"


@dataclass(frozen=True, slots=True, init=False)
class TxtAnswer:
    """The TXT records found at a name. No records at all (NXDOMAIN, or no TXT) is ``()``.

    Each record is held with its character strings already joined, as §4.1 requires.
    ``ttl`` is the answer's TTL in seconds when the resolver knows it; caches use it.
    """

    records: tuple[bytes, ...]
    ttl: int | None

    def __init__(
        self, records: Iterable[bytes | str | Sequence[bytes]] = (), ttl: int | None = None
    ):
        joined: list[bytes] = []
        for record in records:
            if isinstance(record, str):
                joined.append(record.encode("utf-8"))
            elif isinstance(record, (bytes, bytearray)):
                joined.append(bytes(record))
            else:
                joined.append(b"".join(bytes(s) for s in record))
        if ttl is not None and (type(ttl) is not int or ttl < 0):
            raise ValueError("ttl must be a non-negative int or None")
        object.__setattr__(self, "records", tuple(joined))
        object.__setattr__(self, "ttl", ttl)


class DnsFailure(enum.Enum):
    """A lookup that gave no answer: a timeout or server failure, or one the miss limit refused."""

    ERROR = "dns_error"
    LIMITED = "dns_limited"


@dataclass(frozen=True, slots=True)
class ReplayKey:
    """The tuple §7.6 remembers: (mailbox, iss, sub, nonce)."""

    mailbox: str
    iss: str
    sub: str
    nonce: str

    def digest(self) -> str:
        """A fixed-length key for an external store: SHA-256 hex over the JCS of the tuple.

        It keeps addresses and agent IDs out of the store's key space and bounds the key size.
        """
        return hashlib.sha256(jcs([self.mailbox, self.iss, self.sub, self.nonce])).hexdigest()
