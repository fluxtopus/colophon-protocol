"""The verifier as a pure state machine: no I/O, no clock, no globals.

§7.2 needs two things from outside the message: one DNS answer (step 9) and one atomic
check-and-remember in the replay store (step 21). The core stops at each and hands the caller
a request; the caller performs it however it likes, sync or async, and resumes::

    step = start(message, receipt)               # steps 1 to 8
    if isinstance(step, NeedKey):
        step = step.resume(answer)               # steps 9 to 20; answer: TxtAnswer | DnsFailure
    if isinstance(step, NeedReplayCheck):
        step = step.resume(first_time)           # step 21
    verdict = step                               # Verified | NotVerified

Nothing here raises. Every failure, including one this code did not foresee, is a NotVerified.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from colophon_protocol import _carriage, _credential, _mime, _signing_input
from colophon_protocol._codec import b64url_encode, jcs
from colophon_protocol._credential import Claims
from colophon_protocol._fail import Fail
from colophon_protocol._grammar import is_nonce
from colophon_protocol._jose import CompactJws, parse_compact, verify_ed25519
from colophon_protocol._record import select_domain_key
from colophon_protocol.model import (
    Agent,
    DnsFailure,
    KeyQuery,
    NotVerified,
    Reason,
    Receipt,
    ReplayKey,
    TxtAnswer,
    Verdict,
    Verified,
)

__all__ = ["GRACE", "SKEW", "NeedKey", "NeedReplayCheck", "Step", "select_domain_key", "start"]

SKEW = 300
GRACE = 2 * 3600
SIGNATURE_TYPE = "colophon-sig"


@dataclass(frozen=True, slots=True)
class _AfterStep8:
    entity: _mime.Entity
    receipt: Receipt
    sender: str
    host: str
    selector: str
    credential: str
    cred: CompactJws
    sig: CompactJws


@dataclass(frozen=True, slots=True)
class NeedKey:
    """Steps 1 to 8 passed. Look up ``query`` (§7.4) and resume with the answer.

    Resume with a ``TxtAnswer`` (empty for NXDOMAIN or no TXT records), ``DnsFailure.ERROR`` for
    a timeout or server failure, or ``DnsFailure.LIMITED`` when the miss limit refused it.
    """

    query: KeyQuery
    _state: _AfterStep8 = field(repr=False)

    def resume(self, answer: TxtAnswer | DnsFailure) -> NeedReplayCheck | NotVerified:
        return _guard(lambda: _steps_9_to_20(self._state, answer))


@dataclass(frozen=True, slots=True)
class NeedReplayCheck:
    """Steps 1 to 20 passed. Atomically record ``key`` if it is not already recorded, and resume
    with True if this call recorded it (§7.6). Keep it until ``expires_at`` (Unix seconds, the
    credential's ``exp`` plus the grace) plus however long verification may lag arrival."""

    key: ReplayKey
    expires_at: int
    _verified: Verified = field(repr=False)

    def resume(self, first_time: bool) -> Verdict:
        if first_time is True:
            return self._verified
        return NotVerified(Reason.REPLAY, "this mailbox verified the tuple before")


Step = NeedKey | NeedReplayCheck | Verified | NotVerified
"""Whatever the core returns next: a request to the caller, or a final verdict."""

_T = TypeVar("_T")


def start(message: bytes, receipt: Receipt) -> NeedKey | NotVerified:
    """Run steps 1 to 8 on the octets as this receiver's server accepted them."""
    return _guard(lambda: _steps_1_to_8(message, receipt))


def _guard(run: Callable[[], _T]) -> _T | NotVerified:
    try:
        return run()
    except Fail as failed:
        return NotVerified(failed.reason, failed.detail)
    except Exception as exc:  # noqa: BLE001 - verify never raises: a bug is a verdict too
        return NotVerified(Reason.MALFORMED, f"internal error: {type(exc).__name__}")


def _steps_1_to_8(message: bytes, receipt: Receipt) -> NeedKey:
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise Fail(Reason.MALFORMED, "the message must be bytes")
    if not isinstance(receipt, Receipt):
        raise Fail(Reason.MALFORMED, "the receipt must be a Receipt")
    entity = _mime.parse_entity(bytes(message))

    # 1, 2. exactly one signature
    carriage_field = _carriage.locate(entity)

    # 3. exactly one From address; H is its host
    sender = _signing_input.from_address(entity)
    host = sender.rpartition("@")[2]

    # 4. aligned DKIM, before any DNS lookup
    if host not in receipt.dkim_pass_domains:
        raise Fail(Reason.DKIM_UNALIGNED, f"no DKIM pass for {host}")

    # 5, 6, and step 7's presence and size rules
    carried = _carriage.read(carriage_field)

    # 7. two compact JWS, b detached; I-JSON objects
    try:
        cred = parse_compact(carried.credential, detached=False)
        sig = parse_compact(carried.signature, detached=True)
    except ValueError as exc:
        raise Fail(Reason.MALFORMED, f"JWS: {exc}") from None

    # 8. the credential header, and iss
    selector = _credential.check_header(cred.header, cred.payload, host)

    state = _AfterStep8(entity, receipt, sender, host, selector, carried.credential, cred, sig)
    return NeedKey(KeyQuery(selector, host), state)


def _steps_9_to_20(s: _AfterStep8, answer: TxtAnswer | DnsFailure) -> NeedReplayCheck:
    # 9. the lookup's outcome
    if answer is DnsFailure.ERROR:
        raise Fail(Reason.DNS_ERROR, "the lookup failed")
    if answer is DnsFailure.LIMITED:
        raise Fail(Reason.DNS_LIMITED, "the miss limit refused the lookup")
    if not isinstance(answer, TxtAnswer):
        raise Fail(Reason.DNS_ERROR, "the resolver gave no TxtAnswer")

    # 10, 11. the one Colophon record
    domain_key = select_domain_key(answer)
    if isinstance(domain_key, Reason):
        raise Fail(domain_key, f"at {s.selector}._colophon.{s.host}")

    # 12. the credential's signature
    cred = s.cred
    if not verify_ed25519(domain_key, cred.signature, cred.header_b64, cred.payload_b64):
        raise Fail(Reason.CREDENTIAL_INVALID, "the credential signature does not verify")

    # 13. the claims
    claims = _credential.check_claims(cred.payload)

    # 14. the arrival window
    arrival = s.receipt.arrival
    if not claims.issued_at - SKEW <= arrival <= claims.expires_at + GRACE:
        raise Fail(Reason.CREDENTIAL_EXPIRED, "arrival is outside the credential's window")

    # 15. the address
    if claims.address != s.sender:
        raise Fail(Reason.FROM_MISMATCH, "from is not the From address")

    # 16, 17. the layout, then the signing input
    layout = _mime.layout(s.entity)
    payload = jcs(_signing_input.build(s.entity, layout, s.credential))

    # 18, 19. the agent signature
    sig = s.sig
    signed_at, nonce = _check_signature_header(sig.header, claims, arrival)
    if not verify_ed25519(claims.agent_key, sig.signature, sig.header_b64, b64url_encode(payload)):
        raise Fail(Reason.SIGNATURE_INVALID, "the agent signature does not verify")

    # 20. addressed to this mailbox
    listed = set(_signing_input.address_list(s.entity, "to"))
    listed.update(_signing_input.address_list(s.entity, "cc"))
    if listed.isdisjoint(s.receipt.mailbox_addresses):
        raise Fail(Reason.NOT_ADDRESSED, "To and Cc list no address of this mailbox")

    # 21 is the caller's: hand back the key to record
    verified = Verified(
        agent=Agent(
            iss=s.host,
            sub=claims.sub,
            address=s.sender,
            principal=claims.principal,
            scope=claims.scope,
            key_thumbprint=_credential.jwk_thumbprint(claims.agent_key),
        ),
        selector=s.selector,
        domain_key=domain_key,
        credential_issued_at=claims.issued_at,
        credential_expires_at=claims.expires_at,
        signed_at=signed_at,
        nonce=nonce,
    )
    key = ReplayKey(s.receipt.mailbox, s.host, claims.sub, nonce)
    return NeedReplayCheck(key, claims.expires_at + GRACE, verified)


def _check_signature_header(
    header: dict[str, Any], claims: Claims, arrival: int
) -> tuple[int, str]:
    """Step 18. Returns (iat, nonce)."""
    iat, nonce = header.get("iat"), header.get("nonce")
    if header.get("alg") != "EdDSA":
        raise Fail(Reason.SIGNATURE_INVALID, "signature alg is not EdDSA")
    if header.get("typ") != SIGNATURE_TYPE:
        raise Fail(Reason.SIGNATURE_INVALID, f"signature typ is not {SIGNATURE_TYPE}")
    if "crit" in header:
        raise Fail(Reason.SIGNATURE_INVALID, "signature header has crit")
    if not isinstance(nonce, str) or not is_nonce(nonce):
        raise Fail(Reason.SIGNATURE_INVALID, "nonce does not match its grammar")
    if type(iat) is not int:
        raise Fail(Reason.SIGNATURE_INVALID, "signature iat is not an integer")
    if iat > min(claims.expires_at, arrival + SKEW):
        raise Fail(Reason.SIGNATURE_INVALID, "signed after exp, or in the future")
    return iat, nonce
