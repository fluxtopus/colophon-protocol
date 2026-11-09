"""The issuer's side (§4, §5): the DNS record, and credentials for agent addresses."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from colophon_protocol._addresses import AddressError, canonical_addr_spec, valid_canonical_address
from colophon_protocol._carriage import MAX_CREDENTIAL_BYTES
from colophon_protocol._codec import b64url_encode, jcs, parse_ijson
from colophon_protocol._credential import (
    CREDENTIAL_TYPE,
    MAX_LIFETIME,
    check_claims,
    parse_principal,
)
from colophon_protocol._fail import Fail
from colophon_protocol._grammar import MAX_SCOPE_BYTES, is_agent_id, is_plain_text, is_selector
from colophon_protocol._jose import parse_compact, sign_ed25519
from colophon_protocol._record import format_record, format_revoked_record
from colophon_protocol.errors import IssueError
from colophon_protocol.keys import AgentKey, DomainKey
from colophon_protocol.model import Principal, Withheld

__all__ = ["Credential", "Issuer"]

_RESERVED = frozenset({"iss", "sub", "from", "cnf", "principal", "scope", "iat", "exp"})


@dataclass(frozen=True, slots=True)
class Credential:
    """A credential (§5.1): the compact JWS and what it says. ``str()`` gives the token."""

    token: str
    selector: str
    iss: str
    sub: str
    address: str
    principal: Principal
    scope: str | None
    issued_at: int
    expires_at: int
    agent_public_key: bytes = field(repr=False)

    def __str__(self) -> str:
        return self.token

    @classmethod
    def parse(cls, token: str) -> Credential:
        """Read a credential's header and claims, checking their grammar (§7.2 steps 7, 8, 13)
        but NOT its signature: this is for the signer's own credential. ValueError if invalid."""
        if len(token.encode("utf-8")) > MAX_CREDENTIAL_BYTES:
            raise ValueError(f"credential is over {MAX_CREDENTIAL_BYTES} octets")
        jws = parse_compact(token, detached=False)
        header, claims = jws.header, jws.payload
        selector = header.get("kid")
        if header.get("alg") != "EdDSA" or header.get("typ") != CREDENTIAL_TYPE:
            raise ValueError("not a Colophon credential")
        if "crit" in header or not isinstance(selector, str) or not is_selector(selector):
            raise ValueError("credential header is invalid")
        try:
            checked = check_claims(claims)
        except Fail as exc:
            raise ValueError(exc.detail) from None
        if checked.iss != checked.address.rpartition("@")[2]:
            raise ValueError("iss is not the host of from")
        return cls(
            token=token,
            selector=selector,
            iss=checked.iss,
            sub=checked.sub,
            address=checked.address,
            principal=checked.principal,
            scope=checked.scope,
            issued_at=checked.issued_at,
            expires_at=checked.expires_at,
            agent_public_key=checked.agent_key,
        )


def _host(value: str) -> str:
    try:
        return canonical_addr_spec(f"x@{value}").rpartition("@")[2]
    except AddressError:
        raise IssueError(f"{value!r} is not a host in the v0 subset (§6.4)") from None


@dataclass(frozen=True, slots=True)
class Issuer:
    """One domain key under one selector at one host."""

    host: str
    selector: str
    key: DomainKey = field(repr=False)

    def __post_init__(self) -> None:
        if _host(self.host) != self.host:
            raise IssueError("host must be in lowercase")
        if not is_selector(self.selector):
            raise IssueError("a selector is one lowercase DNS label (§4.1)")

    @property
    def dns_name(self) -> str:
        """Where the record goes: ``<selector>._colophon.<host>``."""
        return f"{self.selector}._colophon.{self.host}"

    @property
    def dns_record(self) -> str:
        """The TXT record value."""
        return format_record(self.key.public_bytes)

    @property
    def revoked_record(self) -> str:
        """The TXT record value that revokes this selector (§4.2)."""
        return format_revoked_record()

    def issue(
        self,
        *,
        sub: str,
        address: str,
        agent_key: AgentKey | bytes,
        issued_at: int,
        principal: Principal | None = None,
        scope: str | None = None,
        lifetime: int = MAX_LIFETIME,
        extensions: Mapping[str, Any] | None = None,
    ) -> Credential:
        """Issue a credential (§5). ``agent_key`` is the agent's key or its raw public key: an
        issuer certifies only a key it holds or has proof of possession for (§5.5).

        ``extensions`` are extra claims; each name must contain a colon (§5.1, §11).
        """
        if not is_agent_id(sub):
            raise IssueError("sub must match [A-Za-z0-9._-]{1,64}")
        try:
            canonical = canonical_addr_spec(address)
        except AddressError:
            raise IssueError(f"{address!r} is not an address in the v0 subset (§6.4)") from None
        if not valid_canonical_address(canonical) or canonical.rpartition("@")[2] != self.host:
            raise IssueError(f"the address must be at {self.host}")
        public = agent_key.public_bytes if isinstance(agent_key, AgentKey) else bytes(agent_key)
        if len(public) != 32:
            raise IssueError("an Ed25519 public key is 32 octets")
        principal = Withheld() if principal is None else principal
        if parse_principal(principal.to_json()) != principal:
            raise IssueError("the principal does not meet §5.3")
        if scope is not None and not is_plain_text(scope, MAX_SCOPE_BYTES):
            raise IssueError("scope must be 1 to 280 octets of plain text (§5.4)")
        if type(issued_at) is not int or type(lifetime) is not int:
            raise IssueError("issued_at and lifetime are integers")
        if not 0 < lifetime <= MAX_LIFETIME:
            raise IssueError("lifetime must be more than 0 and at most 86400 seconds")
        claims: dict[str, Any] = {
            "iss": self.host,
            "sub": sub,
            "from": canonical,
            "cnf": {"jwk": {"crv": "Ed25519", "kty": "OKP", "x": b64url_encode(public)}},
            "principal": principal.to_json(),
            "iat": issued_at,
            "exp": issued_at + lifetime,
        }
        if scope is not None:
            claims["scope"] = scope
        for name, value in (extensions or {}).items():
            if ":" not in name or name in _RESERVED or name in claims:
                raise IssueError(f"extension claim {name!r} must contain a colon")
            claims[name] = value
        try:
            payload = jcs(claims)
            parse_ijson(payload)  # the verifier's JSON rules (§5.1)
        except ValueError as exc:
            raise IssueError(f"claims are not I-JSON: {exc}") from None
        header = {"alg": "EdDSA", "kid": self.selector, "typ": CREDENTIAL_TYPE}
        signing_input, signature = sign_ed25519(self.key.private_key, header, payload)
        token = f"{signing_input}.{signature}"
        if len(token) > MAX_CREDENTIAL_BYTES:
            raise IssueError(f"the credential is {len(token)} octets; the cap is 2048 (§5.1)")
        return Credential.parse(token)
