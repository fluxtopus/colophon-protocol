"""Reporting the verdict in Authentication-Results (§7.8)."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from types import ModuleType

import pytest

from colophon_protocol import Named, NotVerified, Reason, Verified, Withheld, sign, verify
from colophon_protocol.authres import (
    authentication_results,
    colophon_resinfo,
    colophon_result,
    dkim_pass_domains,
)
from colophon_protocol.compose import compose_message
from colophon_protocol.replay import MemoryReplayStore

from conftest import SPEC_DIR
from helpers import AGENT_KEY, SCOPE, SIGNED, credential, receipt, resolver

EXAMPLE = (
    "colophon=pass header.from=maple-tiger-27@acme.example header.sub=ag_7Hq2 header.s=s1 "
    "header.principal=pseudonymous header.cred=QyKlpHCC1M-TdbviC2iuOUhIpLY1HxufeJRGlEgEYSo"
)


def _example(sketch: ModuleType) -> Verified:
    verdict = verify(
        sketch.signed(), receipt(), resolver=resolver(), replay_store=MemoryReplayStore()
    )
    assert isinstance(verdict, Verified)
    return verdict


def _signed(cred: str) -> bytes:
    message = compose_message(
        sender="maple-tiger-27@acme.example",
        to=["reservations@bistro.example"],
        subject="Table for four",
        text="Hello\n",
    )
    return sign(message, credential=cred, agent_key=AGENT_KEY, signed_at=SIGNED)


TEMPERROR = (Reason.DNS_ERROR, Reason.DNS_LIMITED, Reason.REPLAY_UNCHECKED)


@pytest.mark.parametrize(
    ("reason", "result"),
    [(r, "none") for r in [Reason.NO_SIGNATURE]]
    + [(r, "temperror") for r in TEMPERROR]
    + [(r, "fail") for r in Reason if r is not Reason.NO_SIGNATURE and r not in TEMPERROR],
)
def test_not_verified_reports_the_reason_only(reason: Reason, result: str) -> None:
    verdict = NotVerified(reason, "a detail that must not be reported")
    assert colophon_result(verdict) == result
    assert colophon_resinfo(verdict) == f'colophon={result} reason="{reason.value}"'
    assert verdict.to_json()["authentication_results"] == colophon_resinfo(verdict)


def test_every_reason_has_a_result() -> None:
    assert len(Reason) == 17


def test_example_matches_the_draft(sketch: ModuleType) -> None:
    verdict = _example(sketch)
    assert colophon_result(verdict) == "pass"
    assert colophon_resinfo(verdict) == EXAMPLE
    assert verdict.to_json()["authentication_results"] == EXAMPLE
    lines = (SPEC_DIR / "reference" / "example.txt").read_text().splitlines()
    assert EXAMPLE in [line.strip() for line in lines]


def test_credential_hash_is_the_signing_input_member(sketch: ModuleType) -> None:
    verdict = _example(sketch)
    digest = hashlib.sha256(credential().encode("ascii")).digest()
    assert verdict.credential_hash == base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert verdict.to_json()["credential_hash"] == verdict.credential_hash


def test_sender_text_is_never_reported(sketch: ModuleType) -> None:
    pseudonymous = colophon_resinfo(_example(sketch))
    assert "p_Xk29" not in pseudonymous
    assert "Books" not in pseudonymous

    signed = _signed(credential(principal=Named("Maria Ortiz"), scope=SCOPE))
    verdict = verify(signed, receipt(), resolver=resolver(), replay_store=MemoryReplayStore())
    assert isinstance(verdict, Verified)
    named = colophon_resinfo(verdict)
    assert "header.principal=named " in named
    assert "Maria" not in named
    assert "Books" not in named

    signed = _signed(credential(principal=Withheld(), scope=None))
    verdict = verify(signed, receipt(), resolver=resolver(), replay_store=MemoryReplayStore())
    assert isinstance(verdict, Verified)
    assert "header.principal=withheld " in colophon_resinfo(verdict)


def test_replay_reports_fail(sketch: ModuleType) -> None:
    store = MemoryReplayStore()
    for _ in range(2):
        verdict = verify(sketch.signed(), receipt(), resolver=resolver(), replay_store=store)
    assert colophon_resinfo(verdict) == 'colophon=fail reason="replay"'


def test_field_value(sketch: ModuleType) -> None:
    verdict = _example(sketch)
    value = authentication_results(
        verdict,
        authserv_id="mx.bistro.example",
        other_resinfo=["dkim=pass header.d=acme.example"],
    )
    assert value == f"mx.bistro.example; dkim=pass header.d=acme.example; {EXAMPLE}"
    assert dkim_pass_domains(value, authserv_id="mx.bistro.example") == {"acme.example"}
    assert authentication_results(verdict, authserv_id="mx.bistro.example") == (
        f"mx.bistro.example; {EXAMPLE}"
    )
    failed = authentication_results(
        NotVerified(Reason.REPLAY),
        authserv_id="mx.bistro.example",
        other_resinfo=("dkim=pass header.d=acme.example", "spf=pass smtp.mailfrom=acme.example"),
    )
    assert failed == (
        "mx.bistro.example; dkim=pass header.d=acme.example; "
        'spf=pass smtp.mailfrom=acme.example; colophon=fail reason="replay"'
    )


def test_field_value_keeps_a_semicolon_in_a_comment() -> None:
    value = authentication_results(
        NotVerified(Reason.NO_SIGNATURE),
        authserv_id="mx.bistro.example",
        other_resinfo=["dkim=pass (good; checked) header.d=acme.example"],
    )
    assert value.endswith(
        '(good; checked) header.d=acme.example; colophon=none reason="no_signature"'
    )


@pytest.mark.parametrize(
    "authserv_id", ["", "mx bistro", "mx.bistro.example;", "mx\r\n.example", "a(b)", 7]
)
def test_field_value_refuses_an_authserv_id(authserv_id: object) -> None:
    with pytest.raises(ValueError, match="authserv-id"):
        authentication_results(
            NotVerified(Reason.MALFORMED),
            authserv_id=authserv_id,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "resinfo",
    [
        "",
        "  ",
        "dkim=pass; colophon=pass",
        "dkim=pass\r\nX-Injected: 1",
        "dkim=pass\n header.d=acme.example",
        "dkim=pass (unbalanced",
    ],
)
def test_field_value_refuses_other_resinfo(resinfo: str) -> None:
    with pytest.raises(ValueError, match="resinfo"):
        authentication_results(
            NotVerified(Reason.MALFORMED), authserv_id="mx.bistro.example", other_resinfo=[resinfo]
        )


def test_field_value_refuses_a_resinfo_that_is_not_text() -> None:
    with pytest.raises(TypeError):
        authentication_results(
            NotVerified(Reason.MALFORMED),
            authserv_id="mx.bistro.example",
            other_resinfo=[b"dkim=pass"],  # type: ignore[list-item]
        )


@pytest.mark.parametrize(
    ("selector", "credential_hash"),
    [("s1", "a b"), ("s1;x", "abc"), ("s1", "abc\r\n"), ("", "abc")],
)
def test_a_hand_built_verdict_cannot_inject(
    sketch: ModuleType, selector: str, credential_hash: str
) -> None:
    verdict = replace(_example(sketch), selector=selector, credential_hash=credential_hash)
    with pytest.raises(ValueError, match="cannot be reported"):
        colophon_resinfo(verdict)


@pytest.mark.parametrize(
    "address",
    ['a"b@acme.example', "a;b@acme.example", "a b@acme.example", "acme.example", "@acme.example"],
)
def test_a_hand_built_address_cannot_inject(sketch: ModuleType, address: str) -> None:
    verdict = _example(sketch)
    verdict = replace(verdict, agent=replace(verdict.agent, address=address))
    with pytest.raises(ValueError, match=r"header\.from"):
        colophon_resinfo(verdict)


def test_internationalized_address_is_reported_as_it_is(sketch: ModuleType) -> None:
    verdict = _example(sketch)
    verdict = replace(verdict, agent=replace(verdict.agent, address="josé+a/b=c@acme.example"))
    assert "header.from=josé+a/b=c@acme.example " in colophon_resinfo(verdict)
