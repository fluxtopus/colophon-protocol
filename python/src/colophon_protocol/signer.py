"""The signer's side (§6.6): sign the exact octets that will be sent."""

from __future__ import annotations

import secrets

from colophon_protocol import _carriage, _mime, _signing_input
from colophon_protocol._codec import b64url_encode, jcs
from colophon_protocol._fail import Fail
from colophon_protocol._grammar import is_nonce
from colophon_protocol._jose import sign_ed25519
from colophon_protocol.errors import SigningError
from colophon_protocol.issuer import Credential
from colophon_protocol.keys import AgentKey

__all__ = ["MIN_REMAINING", "new_nonce", "sign"]

MIN_REMAINING = 6 * 3600
"""§6.6: a signer SHOULD NOT sign with less credential life left than this."""


def new_nonce() -> str:
    """128 random bits in base64url: 22 characters (§6.5 asks for at least 96)."""
    return b64url_encode(secrets.token_bytes(16))


def sign(
    message: bytes,
    *,
    credential: Credential | str,
    agent_key: AgentKey,
    signed_at: int,
    nonce: str | None = None,
    min_remaining: int = MIN_REMAINING,
) -> bytes:
    """Return ``message`` with its signature added. Hand the result to the mail system as is,
    for example as SES raw message data; DKIM with ``d=`` the From host is added after (§6.6).

    ``message`` is the final message: footers, banners and subject tags already added, the
    subject already encoded as it will be sent. Raises ``SigningError`` when a verifier would
    reject the result for anything in the sender's hands.
    """
    cred = credential if isinstance(credential, Credential) else _parse(credential)
    if agent_key.public_bytes != cred.agent_public_key:
        raise SigningError("the agent key is not the key the credential certifies")
    if type(signed_at) is not int:
        raise SigningError("signed_at is an integer, Unix seconds")
    if not cred.issued_at - 300 <= signed_at <= cred.expires_at:
        raise SigningError("signed_at is outside the credential's lifetime", "credential_expired")
    if cred.expires_at - signed_at < min_remaining:
        raise SigningError(
            f"the credential has {cred.expires_at - signed_at} s left; sign with at least "
            f"{min_remaining} s left (§6.6)"
        )
    nonce = new_nonce() if nonce is None else nonce
    if not is_nonce(nonce):
        raise SigningError("nonce must match [A-Za-z0-9_-]{16,64}")
    try:
        entity = _mime.parse_entity(bytes(message))
        if entity.count(_carriage.HEADER_NAME.lower()):
            raise SigningError("the message is already signed", "multiple_signatures")
        sender = _signing_input.from_address(entity)
        if sender != cred.address:
            raise SigningError(
                f"From is {sender}, the credential is for {cred.address}", "from_mismatch"
            )
        if not (
            _signing_input.address_list(entity, "to") or _signing_input.address_list(entity, "cc")
        ):
            raise SigningError("no recipient in To or Cc can verify it (§7.5)", "not_addressed")
        payload = jcs(_signing_input.build(entity, _mime.layout(entity), cred.token))
    except Fail as failed:
        raise SigningError(failed.detail or failed.reason.value, failed.reason.value) from None
    header = {"alg": "EdDSA", "iat": signed_at, "nonce": nonce, "typ": "colophon-sig"}
    signing_input, signature = sign_ed25519(agent_key.private_key, header, payload)
    detached = f"{signing_input.partition('.')[0]}..{signature}"
    value = _carriage.header_value(cred.token, detached)
    if len(value) > _carriage.MAX_HEADER_BYTES:
        raise SigningError("the signature header is over 2560 octets (§6.2)", "malformed")
    return _carriage.attach(bytes(message), cred.token, detached)


def _parse(token: str) -> Credential:
    try:
        return Credential.parse(token)
    except ValueError as exc:
        raise SigningError(f"the credential is invalid: {exc}", "credential_invalid") from None
