"""Keys, issuing, composing and signing, checked by verifying what they produce."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from colophon_protocol import (
    AgentKey,
    Credential,
    DomainKey,
    IssueError,
    Issuer,
    Named,
    NotVerified,
    Reason,
    SigningError,
    Verified,
    Withheld,
    sign,
    verify,
)
from colophon_protocol.compose import Attachment, compose_message
from colophon_protocol.replay import MemoryReplayStore
from colophon_protocol.signer import new_nonce

from helpers import AGENT_KEY, ARRIVED, ISSUED, ISSUER, SIGNED, credential, receipt, resolver


def _message(**changes: object) -> bytes:
    args: dict[str, object] = {
        "sender": "Booking agent <maple-tiger-27@acme.example>",
        "to": ["Reservations <reservations@bistro.example>"],
        "subject": "Table for 2 — Friday",
        "text": "Hello,\n\nA table for 2, please.\n",
        "message_id": "<t-1@acme.example>",
        "date": datetime(2026, 11, 5, 9, 15, tzinfo=timezone.utc),
        **changes,
    }
    return compose_message(**args)  # type: ignore[arg-type]


def _verify(message: bytes, **changes: object) -> Verified | NotVerified:
    return verify(
        message, receipt(**changes), resolver=resolver(), replay_store=MemoryReplayStore()
    )


# ---------------------------------------------------------------- keys


def test_key_repr_hides_the_private_key() -> None:
    key = DomainKey.generate()
    assert key.private_jwk()["d"] not in repr(key)
    assert "thumbprint" in repr(key)


def test_jwk_round_trip() -> None:
    key = AgentKey.generate()
    assert AgentKey.from_jwk(key.private_jwk()) == key
    assert "d" not in key.public_jwk()


@pytest.mark.parametrize(
    "jwk",
    [
        {"kty": "EC", "crv": "Ed25519", "d": "AA"},
        {"kty": "OKP", "crv": "Ed25519"},
        {"kty": "OKP", "crv": "Ed25519", "d": "not base64url!"},
        {"kty": "OKP", "crv": "Ed25519", "d": "AAAA"},
    ],
)
def test_bad_jwk(jwk: dict[str, str]) -> None:
    with pytest.raises(ValueError, match=r"."):
        AgentKey.from_jwk(jwk)


def test_jwk_x_must_match_d() -> None:
    jwk = AgentKey.generate().private_jwk()
    jwk["x"] = AgentKey.generate().public_jwk()["x"]
    with pytest.raises(ValueError, match="does not match"):
        AgentKey.from_jwk(jwk)


# ---------------------------------------------------------------- issuing


def test_dns_record() -> None:
    assert ISSUER.dns_name == "s1._colophon.acme.example"
    assert ISSUER.dns_record.startswith("v=COLOPHON0; k=ed25519; p=")
    assert ISSUER.revoked_record == "v=COLOPHON0; k=ed25519; p="


def test_issued_credential_reads_back() -> None:
    cred = Credential.parse(credential())
    assert cred.selector == "s1"
    assert cred.iss == "acme.example"
    assert cred.address == "maple-tiger-27@acme.example"
    assert cred.expires_at - cred.issued_at == 86400
    assert cred.agent_public_key == AGENT_KEY.public_bytes
    assert str(cred) == cred.token


def test_issue_canonicalises_the_address() -> None:
    cred = ISSUER.issue(
        sub="a1", address="Maple-Tiger-27@ACME.example", agent_key=AGENT_KEY, issued_at=ISSUED
    )
    assert cred.address == "maple-tiger-27@acme.example"
    assert cred.principal == Withheld()


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"sub": "has space"}, "sub"),
        ({"address": "agent@other.example"}, "at acme.example"),
        ({"address": "not an address"}, "subset"),
        ({"agent_key": b"short"}, "32 octets"),
        ({"principal": Named("")}, "§5.3"),
        ({"scope": "x" * 281}, "scope"),
        ({"scope": "line\nbreak"}, "scope"),
        ({"lifetime": 86401}, "lifetime"),
        ({"lifetime": 0}, "lifetime"),
        ({"extensions": {"plain": 1}}, "colon"),
        ({"extensions": {"x:f": 1.5}}, "I-JSON"),
    ],
)
def test_issue_refuses(changes: dict[str, object], match: str) -> None:
    with pytest.raises(IssueError, match=match):
        credential(**changes)


def test_issuer_validates_host_and_selector() -> None:
    with pytest.raises(IssueError):
        Issuer("acme.example", "Bad_Selector", DomainKey.generate())
    with pytest.raises(IssueError):
        Issuer("localhost", "s1", DomainKey.generate())


def test_extension_claims_verify() -> None:
    token = credential(extensions={"example.com:tier": "gold"})
    signed = sign(_message(), credential=token, agent_key=AGENT_KEY, signed_at=SIGNED)
    assert isinstance(_verify(signed), Verified)


# ---------------------------------------------------------------- signing


def test_compose_sign_verify() -> None:
    signed = sign(_message(), credential=credential(), agent_key=AGENT_KEY, signed_at=SIGNED)
    verdict = _verify(signed)
    assert isinstance(verdict, Verified), verdict
    assert verdict.agent.scope is not None


def test_attachments_and_cc() -> None:
    message = _message(
        to=[],
        cc=["reservations+web@bistro.example"],
        reply_to=["Desk <desk@acme.example>"],
        attachments=[Attachment(b"a,b\n1,2\n", "text/csv", "t.csv")],
    )
    signed = sign(message, credential=credential(), agent_key=AGENT_KEY, signed_at=SIGNED)
    assert isinstance(_verify(signed), Verified)


def test_compose_refuses_nested_parts() -> None:
    with pytest.raises(ValueError, match="not allowed"):
        _message(attachments=[Attachment(b"", "message/rfc822", "m.eml")])


def test_lf_only_message() -> None:
    message = _message().replace(b"\r\n", b"\n")
    signed = sign(message, credential=credential(), agent_key=AGENT_KEY, signed_at=SIGNED)
    assert b"\r\n" not in signed
    assert isinstance(_verify(signed), Verified)


def test_random_nonces_differ() -> None:
    assert new_nonce() != new_nonce()
    assert len(new_nonce()) == 22


def test_two_signatures_of_one_message_are_not_replays() -> None:
    store = MemoryReplayStore()
    for _ in range(2):
        signed = sign(_message(), credential=credential(), agent_key=AGENT_KEY, signed_at=SIGNED)
        verdict = verify(signed, receipt(), resolver=resolver(), replay_store=store)
        assert isinstance(verdict, Verified)


def test_tampering_is_caught() -> None:
    signed = sign(_message(), credential=credential(), agent_key=AGENT_KEY, signed_at=SIGNED)
    tampered = signed.replace(b"table for 2", b"table for 9")
    assert tampered != signed
    assert _verify(tampered) == NotVerified(Reason.SIGNATURE_INVALID)


def test_late_arrival_is_expired() -> None:
    signed = sign(_message(), credential=credential(), agent_key=AGENT_KEY, signed_at=SIGNED)
    assert _verify(signed, arrival=ISSUED + 86400 + 7200 + 1).reason is Reason.CREDENTIAL_EXPIRED
    assert isinstance(_verify(signed, arrival=ARRIVED), Verified)


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"agent_key": AgentKey.generate()}, None),
        ({"signed_at": ISSUED - 301}, "credential_expired"),
        ({"signed_at": ISSUED + 86400 - 3600}, None),
        ({"nonce": "short"}, None),
        ({"credential": "a.b.c"}, "credential_invalid"),
    ],
)
def test_sign_refuses(kwargs: dict[str, object], reason: str | None) -> None:
    args: dict[str, object] = {
        "credential": credential(),
        "agent_key": AGENT_KEY,
        "signed_at": SIGNED,
        **kwargs,
    }
    with pytest.raises(SigningError) as info:
        sign(_message(), **args)  # type: ignore[arg-type]
    assert info.value.reason == reason


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        (_message(sender="other@acme.example"), "from_mismatch"),
        (_message(to=[]), "not_addressed"),
        (
            b"From: maple-tiger-27@acme.example\r\nTo: a@b.example\r\nContent-Type: text/html\r\n"
            b"\r\n<p>hi</p>\r\n",
            "layout",
        ),
    ],
)
def test_sign_refuses_messages(message: bytes, reason: str) -> None:
    with pytest.raises(SigningError) as info:
        sign(message, credential=credential(), agent_key=AGENT_KEY, signed_at=SIGNED)
    assert info.value.reason == reason


def test_sign_refuses_a_signed_message() -> None:
    signed = sign(_message(), credential=credential(), agent_key=AGENT_KEY, signed_at=SIGNED)
    with pytest.raises(SigningError) as info:
        sign(signed, credential=credential(), agent_key=AGENT_KEY, signed_at=SIGNED)
    assert info.value.reason == "multiple_signatures"


def test_header_is_folded() -> None:
    signed = sign(_message(), credential=credential(), agent_key=AGENT_KEY, signed_at=SIGNED)
    head = signed.split(b"\r\n\r\n", 1)[0]
    assert all(len(line) <= 78 for line in head.split(b"\r\n"))
    assert signed.startswith(b"Colophon-Signature: v=0;\r\n c=")
