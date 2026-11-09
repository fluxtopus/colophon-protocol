"""Reading dkim=pass from the receiver's own Authentication-Results field."""

from __future__ import annotations

import time

import pytest

from colophon_protocol.authres import dkim_identity_domain, dkim_pass_domains

MX = "mx.bistro.example"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (f"{MX}; dkim=pass header.d=acme.example header.s=s1", {"acme.example"}),
        (
            f"{MX}; dkim=pass header.d=ACME.example; dkim=pass header.d=ses.example",
            {"acme.example", "ses.example"},
        ),
        (f"{MX}; dkim=fail header.d=acme.example", set()),
        (f"{MX}; spf=pass smtp.mailfrom=acme.example", set()),
        (f"{MX} 1; dkim = pass (good sig) header.d = acme.example", {"acme.example"}),
        (f'{MX}; dkim=pass header.d="acme.example"', {"acme.example"}),
        (f"{MX}; dkim=pass (a comment; with a semicolon) header.d=acme.example", {"acme.example"}),
        (f"{MX}; dkim=pass header.i=@acme.example", set()),
        ("other.example; dkim=pass header.d=acme.example", set()),
        (f"{MX}; dkim=pass (unbalanced header.d=acme.example", set()),
        ("", set()),
    ],
)
def test_dkim_pass_domains(value: str, expected: set[str]) -> None:
    assert dkim_pass_domains(value, authserv_id=MX) == expected


def _message(*signatures: bytes) -> bytes:
    fields = b"".join(b"DKIM-Signature: " + sig + b"\r\n" for sig in signatures)
    return fields + b"From: maple-tiger-27@acme.example\r\n\r\nHello\r\n"


SIG_D = b"v=1; a=ed25519-sha256; d=acme.example; s=k1; h=from; bh=AA; b=AA"
SIG_I = b"v=1; a=ed25519-sha256; d=acme.example; i=bot@mail.acme.example; s=k1; bh=AA; b=AA"


def test_header_i_alone_does_not_count() -> None:
    value = f"{MX}; dkim=pass header.i=@acme.example header.s=s1"
    assert dkim_pass_domains(value, authserv_id=MX) == frozenset()


def test_header_i_recovers_d_from_the_message() -> None:
    value = f"{MX}; dkim=pass header.i=bot@MAIL.acme.example"
    message = _message(SIG_I)
    assert dkim_pass_domains(value, authserv_id=MX, message=message) == {"acme.example"}


def test_header_d_wins_over_header_i() -> None:
    value = f"{MX}; dkim=pass header.i=@sub.acme.example header.d=acme.example"
    assert dkim_pass_domains(value, authserv_id=MX, message=_message()) == {"acme.example"}


@pytest.mark.parametrize(
    ("signatures", "header_i", "expected"),
    [
        ([SIG_D], "@acme.example", "acme.example"),
        ([SIG_D], "@ACME.Example", "acme.example"),  # domains ignore case
        ([SIG_I], "bot@mail.acme.example", "acme.example"),
        ([SIG_I], "Bot@mail.acme.example", None),  # local parts are octet for octet
        ([SIG_I], "@mail.acme.example", None),
        ([SIG_I], "@acme.example", None),  # i= present: the identity is i=, not @d=
        ([SIG_D, SIG_D], "@acme.example", None),  # two fields with that identity
        ([SIG_D, SIG_I], "@acme.example", "acme.example"),
        ([b"d=acme.example; i=bot=40x@acme.example"], "bot@x@acme.example", "acme.example"),
        ([b"d=acme.example; i = bot@acme.\r\n example ;"], "bot@acme.example", "acme.example"),
        ([b"d=acme.example; d=other.example"], "@acme.example", None),  # repeated tag
        ([b"d=acme.example; garbage"], "@acme.example", None),
        ([b"d=acme.example; i=bot=4@acme.example"], "bot=4@acme.example", None),
        ([b"i=@acme.example"], "@acme.example", None),  # no d=
        ([], "@acme.example", None),
    ],
)
def test_dkim_identity_domain(signatures: list[bytes], header_i: str, expected: str | None) -> None:
    assert dkim_identity_domain(_message(*signatures), header_i) == expected


def test_dkim_identity_domain_parent_and_subdomain() -> None:
    """A parent-domain signature with i= in a subdomain and a subdomain signature share an
    identity: neither counts (§15, choice 10)."""
    parent = b"d=acme.example; i=@mail.acme.example"
    child = b"d=mail.acme.example"
    assert dkim_identity_domain(_message(parent, child), "@mail.acme.example") is None


def test_dkim_identity_domain_malformed_message() -> None:
    assert (
        dkim_identity_domain(b"DKIM-Signature: d=acme.example\rX\r\n\r\n", "@acme.example") is None
    )


@pytest.mark.parametrize("chunk", [" ", "(", "=", ";", '"', "\\", " =", "( ("])
def test_linear_time(chunk: str) -> None:
    value = MX + "; dkim=pass " + chunk * 30_000
    start = time.perf_counter()
    dkim_pass_domains(value, authserv_id=MX)
    assert time.perf_counter() - start < 1.0


def test_oversized_value() -> None:
    assert dkim_pass_domains(MX + "; " + "x" * 70_000, authserv_id=MX) == frozenset()
