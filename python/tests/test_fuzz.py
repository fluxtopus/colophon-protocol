"""Property tests: the verifier never raises and never fails on its own bugs, whatever it's given.

"internal error" in a verdict's detail means an exception escaped a check; those are failures.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from colophon_protocol import NotVerified, TxtAnswer, Verified, sansio
from colophon_protocol.authres import dkim_pass_domains
from colophon_protocol.model import DnsFailure

from conftest import load_sketch
from helpers import ISSUER, receipt

SIGNED = load_sketch().signed()
RECORD = TxtAnswer([ISSUER.dns_record])
SETTINGS = settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def _drive(message: bytes, answer: TxtAnswer | DnsFailure = RECORD) -> Verified | NotVerified:
    step: sansio.Step = sansio.start(message, receipt())
    if isinstance(step, sansio.NeedKey):
        step = step.resume(answer)
    if isinstance(step, sansio.NeedReplayCheck):
        step = step.resume(True)
    assert isinstance(step, (Verified, NotVerified))
    if isinstance(step, NotVerified):
        assert not step.detail.startswith("internal error"), step.detail
    return step


@SETTINGS
@given(st.binary(max_size=4096))
def test_random_bytes(data: bytes) -> None:
    _drive(data)


@SETTINGS
@given(st.binary(max_size=2048))
def test_signed_header_then_random_body(data: bytes) -> None:
    head = SIGNED.split(b"\r\n\r\n", 1)[0]
    _drive(head + b"\r\n\r\n" + data)


@SETTINGS
@given(st.integers(0, len(SIGNED) - 1), st.integers(0, 255))
def test_one_byte_changed(position: int, value: int) -> None:
    mutated = SIGNED[:position] + bytes([value]) + SIGNED[position + 1 :]
    verdict = _drive(mutated)
    if mutated != SIGNED and isinstance(verdict, Verified):
        # Only octets outside the signed content may change: header whitespace and ignored
        # fields. The signed claims must come back unchanged.
        assert verdict.agent.sub == "ag_7Hq2"


@SETTINGS
@given(st.integers(0, len(SIGNED)), st.integers(0, 64), st.binary(max_size=64))
def test_splice(position: int, cut: int, insert: bytes) -> None:
    _drive(SIGNED[:position] + insert + SIGNED[position + cut :])


@SETTINGS
@given(st.lists(st.binary(max_size=300), max_size=4))
def test_random_dns(records: list[bytes]) -> None:
    _drive(SIGNED, TxtAnswer(records))


@SETTINGS
@given(st.text(max_size=500))
def test_authentication_results(value: str) -> None:
    dkim_pass_domains(value, authserv_id="mx.example")
