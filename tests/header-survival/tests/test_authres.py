from email import policy
from email.parser import BytesParser

from survival import authres


def test_dkim_pass_from_header_d_and_header_i():
    ar = authres.parse(
        "mx.google.com;\r\n dkim=pass header.i=@colophon-protocol.org header.s=abc header.b=xyz;\r\n"
        " dkim=pass (2048-bit key) header.d=amazonses.com header.s=def;\r\n"
        " dkim=fail header.d=evil.example;\r\n spf=pass smtp.mailfrom=amazonses.com"
    )
    assert ar.authserv_id == "mx.google.com"
    assert ar.dkim_pass_domains() == {"colophon-protocol.org", "amazonses.com"}
    assert [r.method for r in ar.results] == ["dkim", "dkim", "dkim", "spf"]


def test_comments_quotes_and_versions():
    ar = authres.parse(
        'authserv.example 1 (a comment; with semicolon); dkim/1=pass (why "not") header.d="Quoted.Example" ; '
        "auth=none; none"
    )
    assert ar.dkim_pass_domains() == {"quoted.example"}
    assert ar.results[1] == authres.MethodResult("auth", "none", {})


def test_none_only():
    ar = authres.parse("mx.example; none")
    assert ar.results == ()
    assert ar.dkim_pass_domains() == set()


def test_empty_is_an_error():
    try:
        authres.parse("   ")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def _msg(*fields: str):
    return BytesParser(policy=policy.compat32).parsebytes(
        ("\r\n".join(fields) + "\r\n\r\nbody\r\n").encode()
    )


def test_receiver_results_take_the_topmost_authserv():
    msg = _msg(
        "Authentication-Results: mx.ours.example; dkim=pass header.d=a.example",
        "Authentication-Results: mx.ours.example; arc=none",
        "Authentication-Results: mx.theirs.example; dkim=pass header.d=b.example",
        "From: x@a.example",
    )
    r = authres.receiver_results(msg)
    assert r.authserv_id == "mx.ours.example"
    assert r.dkim_pass_domains == {"a.example"}
    assert len(r.considered) == 2


def test_receiver_results_by_authserv_id_and_suffix():
    msg = _msg(
        "Authentication-Results: mx.theirs.example; dkim=pass header.d=b.example",
        "Authentication-Results: mx1.ours.example; dkim=pass header.d=a.example",
        "From: x@a.example",
    )
    r = authres.receiver_results(msg, ["ours.example"])
    assert r.dkim_pass_domains == {"a.example"}
    r = authres.receiver_results(msg, ["nobody.example"])
    assert r.dkim_pass_domains == frozenset()
    assert "topmost is mx.theirs.example" in r.note


def test_receiver_results_without_any_field():
    r = authres.receiver_results(_msg("From: x@a.example"))
    assert r.dkim_pass_domains == frozenset()
    assert r.note == "no Authentication-Results field"
