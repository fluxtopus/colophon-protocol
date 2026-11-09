"""The pure core's contract: it asks for one DNS answer and one replay claim, and never raises."""

from __future__ import annotations

from types import ModuleType

import pytest

from colophon_protocol import NotVerified, Reason, TxtAnswer, Verified, sansio
from colophon_protocol.model import DnsFailure, KeyQuery

from helpers import ISSUER, receipt


def _need_key(sketch: ModuleType) -> sansio.NeedKey:
    step = sansio.start(sketch.signed(), receipt())
    assert isinstance(step, sansio.NeedKey)
    return step


def test_asks_for_the_selector(sketch: ModuleType) -> None:
    step = _need_key(sketch)
    assert step.query == KeyQuery("s1", "acme.example")
    assert step.query.name == ISSUER.dns_name


def test_resume_twice_is_pure(sketch: ModuleType) -> None:
    step = _need_key(sketch)
    first = step.resume(TxtAnswer([ISSUER.dns_record]))
    second = step.resume(TxtAnswer([ISSUER.dns_record]))
    assert isinstance(first, sansio.NeedReplayCheck)
    assert first == second
    assert first.expires_at == 1793865600 + 86400 + sansio.GRACE  # exp + grace (§7.6)


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (DnsFailure.ERROR, Reason.DNS_ERROR),
        (DnsFailure.LIMITED, Reason.DNS_LIMITED),
        (TxtAnswer(()), Reason.KEY_NOT_FOUND),
        (TxtAnswer(["v=COLOPHON0; k=ed25519; p="]), Reason.KEY_REVOKED),
        (TxtAnswer([b"v=COLOPHON0; k=ed25519; p=\xff"]), Reason.KEY_NOT_FOUND),
    ],
)
def test_dns_outcomes(sketch: ModuleType, answer: TxtAnswer | DnsFailure, reason: Reason) -> None:
    assert _need_key(sketch).resume(answer) == NotVerified(reason)


def test_split_character_strings(sketch: ModuleType) -> None:
    record = ISSUER.dns_record.encode()
    answer = TxtAnswer([[record[:20], record[20:]]])
    assert isinstance(_need_key(sketch).resume(answer), sansio.NeedReplayCheck)


@pytest.mark.parametrize("first_time", [False, None, 1, "yes"])
def test_replay_claim_fails_closed(sketch: ModuleType, first_time: object) -> None:
    step = _need_key(sketch).resume(TxtAnswer([ISSUER.dns_record]))
    assert isinstance(step, sansio.NeedReplayCheck)
    assert step.resume(first_time) == NotVerified(Reason.REPLAY)  # type: ignore[arg-type]


def test_verified(sketch: ModuleType) -> None:
    step = _need_key(sketch).resume(TxtAnswer([ISSUER.dns_record]))
    assert isinstance(step, sansio.NeedReplayCheck)
    assert step.key.mailbox == "mbx-reservations"
    assert len(step.key.digest()) == 64
    verdict = step.resume(True)
    assert isinstance(verdict, Verified)
    assert verdict.domain_key == ISSUER.key.public_bytes
    assert "domain_key" not in repr(verdict)
    assert verdict.to_json()["verdict"] == "verified"


def test_wrong_answer_type_is_a_dns_error(sketch: ModuleType) -> None:
    verdict = _need_key(sketch).resume("not an answer")  # type: ignore[arg-type]
    assert isinstance(verdict, NotVerified)
    assert verdict.reason is Reason.DNS_ERROR


@pytest.mark.parametrize("message", [b"", b"\x00" * 10, b"\r\n\r\n", b"Colophon-Signature: v=0"])
def test_garbage(message: bytes) -> None:
    assert isinstance(sansio.start(message, receipt()), NotVerified)


def test_not_bytes() -> None:
    verdict = sansio.start("text", receipt())  # type: ignore[arg-type]
    assert isinstance(verdict, NotVerified)


def test_receipt_validation() -> None:
    with pytest.raises(TypeError):
        receipt(arrival=1.5)
    with pytest.raises(TypeError):
        receipt(mailbox_addresses="reservations@bistro.example")
    with pytest.raises(ValueError, match="invalid address"):
        receipt(mailbox_addresses=["not an address"])
    assert receipt(mailbox_addresses=["A@Bistro.Example"]).mailbox_addresses == {"a@bistro.example"}
