"""§5: the credential's header (step 8) and claims (step 13)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from colophon_protocol._addresses import valid_canonical_address
from colophon_protocol._codec import b64url_decode, b64url_encode, b64url_sha256, jcs
from colophon_protocol._fail import Fail
from colophon_protocol._grammar import (
    MAX_NAME_BYTES,
    MAX_SCOPE_BYTES,
    is_agent_id,
    is_plain_text,
    is_selector,
)
from colophon_protocol.model import Named, Principal, Pseudonymous, Reason, Withheld

CREDENTIAL_TYPE = "colophon-cred+jwt"
MAX_LIFETIME = 24 * 3600


def check_header(header: dict[str, Any], claims: dict[str, Any], host: str) -> str:
    """Step 8. Returns the selector."""
    selector = header.get("kid")
    if header.get("alg") != "EdDSA":
        raise Fail(Reason.CREDENTIAL_INVALID, "credential alg is not EdDSA")
    if header.get("typ") != CREDENTIAL_TYPE:
        raise Fail(Reason.CREDENTIAL_INVALID, f"credential typ is not {CREDENTIAL_TYPE}")
    if "crit" in header:
        raise Fail(Reason.CREDENTIAL_INVALID, "credential header has crit")
    if not isinstance(selector, str) or not is_selector(selector):
        raise Fail(Reason.CREDENTIAL_INVALID, "kid is not a valid selector")
    if claims.get("iss") != host:
        raise Fail(Reason.CREDENTIAL_INVALID, "iss is not the From host")
    return selector


def parse_principal(value: object) -> Principal | None:
    """§5.3: one of three objects with no other members. None if it is none of them."""
    if not isinstance(value, dict):
        return None
    mode = value.get("mode")
    if mode == "withheld" and value.keys() == {"mode"}:
        return Withheld()
    if mode == "pseudonymous" and value.keys() == {"mode", "id"}:
        pid = value["id"]
        return Pseudonymous(pid) if isinstance(pid, str) and is_agent_id(pid) else None
    if mode == "named" and value.keys() == {"mode", "name"}:
        name = value["name"]
        return Named(name) if is_plain_text(name, MAX_NAME_BYTES) else None
    return None


def jwk_thumbprint(public_key: bytes) -> str:
    """RFC 7638 thumbprint of an Ed25519 public key (RFC 8037 §2): SHA-256, base64url."""
    return b64url_sha256(jcs({"crv": "Ed25519", "kty": "OKP", "x": b64url_encode(public_key)}))


@dataclass(frozen=True, slots=True)
class Claims:
    """The claims after step 13: every one has its type and grammar."""

    iss: str
    sub: str
    address: str
    principal: Principal
    scope: str | None
    issued_at: int
    expires_at: int
    agent_key: bytes


def check_claims(claims: dict[str, Any]) -> Claims:
    """Step 13. ``iss`` was checked at step 8."""

    def invalid(detail: str) -> Fail:
        return Fail(Reason.CREDENTIAL_INVALID, detail)

    iat, exp = claims.get("iat"), claims.get("exp")
    if type(iat) is not int or type(exp) is not int:  # bool is not an integer here
        raise invalid("iat and exp must be integers")
    if not 0 < exp - iat <= MAX_LIFETIME:
        raise invalid("exp - iat must be more than 0 and at most 86400")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not is_agent_id(sub):
        raise invalid("sub does not match its grammar")
    address = claims.get("from")
    if not isinstance(address, str) or not valid_canonical_address(address):
        raise invalid("from is not a canonical address")
    principal = parse_principal(claims.get("principal"))
    if principal is None:
        raise invalid("principal is not a valid disclosure")
    scope = claims.get("scope")
    if "scope" in claims and not is_plain_text(scope, MAX_SCOPE_BYTES):
        raise invalid("scope is not plain text of 1 to 280 octets")
    cnf = claims.get("cnf")
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise invalid("cnf.jwk is not an Ed25519 OKP key")
    x = jwk.get("x")
    try:
        key = b64url_decode(x) if isinstance(x, str) else b""
    except ValueError:
        key = b""
    if len(key) != 32:
        raise invalid("cnf.jwk.x is not 32 octets of base64url")
    return Claims(
        iss=str(claims["iss"]),
        sub=sub,
        address=address,
        principal=principal,
        scope=scope if isinstance(scope, str) else None,
        issued_at=iat,
        expires_at=exp,
        agent_key=key,
    )
