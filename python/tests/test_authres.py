"""Reading dkim=pass from the receiver's own Authentication-Results field."""

from __future__ import annotations

import time

import pytest

from colophon_protocol.authres import dkim_pass_domains

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


def test_header_i_on_request() -> None:
    value = f"{MX}; dkim=pass header.i=@acme.example header.s=s1"
    assert dkim_pass_domains(value, authserv_id=MX, use_header_i=True) == {"acme.example"}


def test_header_d_wins_over_header_i() -> None:
    value = f"{MX}; dkim=pass header.i=@sub.acme.example header.d=acme.example"
    assert dkim_pass_domains(value, authserv_id=MX, use_header_i=True) == {"acme.example"}


@pytest.mark.parametrize("chunk", [" ", "(", "=", ";", '"', "\\", " =", "( ("])
def test_linear_time(chunk: str) -> None:
    value = MX + "; dkim=pass " + chunk * 30_000
    start = time.perf_counter()
    dkim_pass_domains(value, authserv_id=MX)
    assert time.perf_counter() - start < 1.0


def test_oversized_value() -> None:
    assert dkim_pass_domains(MX + "; " + "x" * 70_000, authserv_id=MX) == frozenset()
