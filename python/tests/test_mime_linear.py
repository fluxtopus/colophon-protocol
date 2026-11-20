"""The body steps of §6.4 and the multipart split of §6.1 as whole-buffer operations.

Each is checked against the line-by-line code it replaced, which the draft's prose follows
directly, and is bounded in time and memory on bodies built to be expensive."""

from __future__ import annotations

import contextlib
import time
import tracemalloc

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from colophon_protocol import _mime
from colophon_protocol._fail import Fail
from colophon_protocol._mime import ContentType, Entity, Part

_WSP = b" \t"
_HEX = frozenset(b"0123456789ABCDEFabcdef")


def _old_quoted_printable(data: bytes) -> bytes:
    out = bytearray()
    pos, n = 0, len(data)
    while True:
        lf = data.find(b"\n", pos)
        last = lf < 0
        end = n if last else lf
        if not last and end > pos and data[end - 1] == 0x0D:
            end -= 1
        line = data[pos:end].rstrip(_WSP)
        soft = line.endswith(b"=")
        if soft:
            line = line[:-1]
        i = 0
        while i < len(line):
            eq = line.find(b"=", i)
            if eq < 0:
                out += line[i:]
                break
            out += line[i:eq]
            pair = line[eq + 1 : eq + 3]
            if len(pair) != 2 or pair[0] not in _HEX or pair[1] not in _HEX:
                raise ValueError("bad escape")
            out.append(int(pair, 16))
            i = eq + 3
        if last:
            return bytes(out)
        if not soft:
            out += b"\r\n"
        pos = lf + 1


def _old_canonical_text(text: str) -> bytes:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    lines = [line.rstrip(" \t") for line in lines]
    while lines and lines[-1] == "":
        lines.pop()
    return "".join(line + "\r\n" for line in lines).encode("utf-8")


def _old_split_multipart(body: bytes, boundary: str) -> list[bytes]:
    dash = b"--" + boundary.encode("ascii")
    parts: list[bytes] = []
    start: int | None = None
    closed = False
    pos, n = 0, len(body)
    while pos < n:
        end = body.find(b"\n", pos)
        nxt = n if end == -1 else end + 1
        line = body[pos:] if end == -1 else body[pos:end].removesuffix(b"\r")
        if line.startswith(dash):
            rest = line[len(dash) :]
            close = rest.startswith(b"--")
            if closed:
                raise ValueError("after close")
            if (rest[2:] if close else rest).strip(_WSP):
                raise ValueError("not a delimiter")
            if start is not None:
                if pos == start:
                    raise ValueError("two delimiters")
                cut = pos - 2 if body[pos - 2 : pos] == b"\r\n" else pos - 1
                parts.append(body[start:cut])
            start, closed = nxt, close
        pos = nxt
    if not closed:
        raise ValueError("no close")
    if not parts:
        raise ValueError("no parts")
    return parts


def _outcome(fn: object, *args: object) -> object:
    try:
        return fn(*args)  # type: ignore[operator]
    except (Fail, ValueError):
        return "error"


def _part(body: bytes, *, charset: str = "utf-8", encoding: str = "8bit") -> Part:
    return Part(Entity((), body), ContentType("text/plain", {"charset": charset}), encoding)


_QP = st.lists(st.sampled_from([b"a", b"=", b"3D", b"4", b"g", b" ", b"\t", b"\r", b"\n", b"\xc3"]))
_TEXT = st.lists(st.sampled_from(["a", "é", "\U0001f600", " ", "\t", "\r", "\n", "\r\n"]))
_MULTIPART = st.lists(st.sampled_from([b"--b", b"--", b"x", b" ", b"\t", b"\r", b"\n", b"\r\n"]))


@settings(max_examples=3000, deadline=None)
@given(_QP)
def test_quoted_printable_matches_line_by_line(pieces: list[bytes]) -> None:
    data = b"".join(pieces)
    assert _outcome(_mime._decode_quoted_printable, data) == _outcome(_old_quoted_printable, data)


@settings(max_examples=3000, deadline=None)
@given(_TEXT)
def test_canonical_text_matches_line_by_line(pieces: list[str]) -> None:
    text = "".join(pieces)
    assert _mime.canonical_text(_part(text.encode("utf-8"))) == _old_canonical_text(text)


@settings(max_examples=3000, deadline=None)
@given(_MULTIPART)
def test_split_multipart_matches_line_by_line(pieces: list[bytes]) -> None:
    body = b"".join(pieces)
    assert _outcome(_mime.split_multipart, body, "b") == _outcome(_old_split_multipart, body, "b")


@pytest.mark.parametrize(
    ("body", "charset"),
    [(b"\xff", "utf-8"), (b"\xc3", "utf-8"), (b"\xed\xa0\x80", "utf-8"), (b"\xc3\xa9", "us-ascii")],
)
def test_charset_is_checked(body: bytes, charset: str) -> None:
    with pytest.raises(Fail):
        _mime.canonical_text(_part(body, charset=charset))


def test_utf8_across_chunks() -> None:
    body = b"a" * (_mime._CHUNK - 1) + "é".encode() + b"\n"
    assert _mime.canonical_text(_part(body)) == body[:-1] + b"\r\n"


SIZE = 8 * 1024 * 1024


@pytest.mark.parametrize(
    ("body", "encoding"),
    [
        (b"a\n" * (SIZE // 2), "8bit"),
        (b"a \n" * (SIZE // 3), "8bit"),
        (b"\n" * SIZE, "8bit"),
        (b" " * SIZE + b"x", "8bit"),
        (b"a=\n" * (SIZE // 3), "quoted-printable"),
        (b"=41" * (SIZE // 3), "quoted-printable"),
        (b"\n" * SIZE, "quoted-printable"),
        (b"\t" * SIZE + b"=4", "quoted-printable"),
    ],
    ids=[
        "short-lines",
        "trailing-spaces",
        "empty-lines",
        "long-space-run",
        "soft-breaks",
        "escapes",
        "qp-lines",
        "qp-bad",
    ],
)
def test_hostile_bodies_are_cheap(body: bytes, encoding: str) -> None:
    """Linear time at C speed, and memory under 8 times the body: the per-line code took
    seconds and about 35 times the body on the first of these. Time and memory are measured
    in separate runs, because tracemalloc slows every allocation and would be timed too."""
    part = _part(body, encoding=encoding)
    start = time.perf_counter()
    with contextlib.suppress(Fail):
        _mime.canonical_text(part)
    elapsed = time.perf_counter() - start
    tracemalloc.start()
    with contextlib.suppress(Fail):
        _mime.canonical_text(part)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert elapsed < 2.0
    assert peak < 8 * len(body)


def test_many_lines_between_delimiters_are_cheap() -> None:
    body = b"--b\r\n" + b"a\r\n" * (SIZE // 3) + b"--b--\r\n"
    start = time.perf_counter()
    assert len(_mime.split_multipart(body, "b")) == 1
    assert time.perf_counter() - start < 1.0
