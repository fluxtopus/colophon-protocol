"""Structured mutations of the draft's example, for differential tests against the sketch.

Each mutation edits the unsigned message; the sketch then signs the result (non-strict), so a
signature over the sketch's own reading is present and any disagreement is in parsing or rules.
"""

from __future__ import annotations

import random
from collections.abc import Callable

Mutation = Callable[[bytes, random.Random], bytes]

_HEADERS = [
    b"From",
    b"To",
    b"Cc",
    b"Reply-To",
    b"Subject",
    b"Content-Type",
    b"Content-Transfer-Encoding",
    b"MIME-Version",
    b"Content-Disposition",
    b"Date",
]
_ADDRESSES = [
    b"maple-tiger-27@acme.example",
    b"Maple-Tiger-27@ACME.EXAMPLE",
    b"<maple-tiger-27@acme.example>",
    b'"Agent, booking" <maple-tiger-27@acme.example>',
    b"maple-tiger-27@acme.example (comment)",
    b"reservations@bistro.example",
    b"Reservations <reservations+web@bistro.example>",
    b"a@b.example, c@d.example",
    b"group: a@b.example;",
    b"=?utf-8?q?Caf=C3=A9?= <a@acme.example>",
    b"a@[127.0.0.1]",
    b"a@localhost",
    b'"quoted local"@acme.example',
    b"a..b@acme.example",
    b"<a@acme.example> <b@acme.example>",
    b"",
    b" ",
    b"a@acme.example,",
    b",a@acme.example",
    b"Caf\xc3\xa9 <a@acme.example>",
    b"a@acme.example\r\n\tb@acme.example",
]
_SUBJECTS = [
    b"",
    b" ",
    b"=?utf-8?q?caf=C3=A9?=",
    b"=?UTF-8?B?Y2Fmw6k=?=",
    b"=?utf-8?q?caf=C3?=",
    b"=?iso-8859-1?q?caf=E9?=",
    b"caf\xc3\xa9",
    b"caf\xe9",
    b"a\r\n b",
    b"a\r\n\tb",
    b"=?utf-8?q?a?= =?utf-8?q?b?=",
    b"=?utf-8?q?a?=  b",
    b"x" * 500,
    b"tab\there",
]
_TYPES = [
    b"text/plain",
    b"text/plain; charset=utf-8",
    b"text/plain; charset=US-ASCII",
    b"text/plain; charset=latin-1",
    b'text/plain; charset="utf-8"',
    b"TEXT/PLAIN",
    b"text/plain; format=flowed",
    b"text/html",
    b"text/plain; charset=utf-8; charset=utf-8",
    b"text/plain;",
    b"text/plain; charset",
    b"text",
    b"text/plain (comment)",
    b"multipart/alternative; boundary=x",
    b"application/octet-stream",
    b"text/plain; charset*=utf-8''x",
]
_ENCODINGS = [
    b"7bit",
    b"8bit",
    b"binary",
    b"quoted-printable",
    b"base64",
    b"BASE64",
    b"x-uuencode",
    b"",
]
_DISPOSITIONS = [
    b"attachment",
    b"inline",
    b"attachment; filename=a.csv",
    b"ATTACHMENT",
    b"",
    b"weird",
]


def _split(raw: bytes) -> tuple[list[bytes], bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines: list[bytes] = []
    for line in head.split(b"\r\n"):
        if line[:1] in (b" ", b"\t") and lines:
            lines[-1] += b"\r\n" + line
        else:
            lines.append(line)
    return lines, body


def _join(lines: list[bytes], body: bytes) -> bytes:
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def _set(raw: bytes, name: bytes, value: bytes) -> bytes:
    lines, body = _split(raw)
    lower = name.lower() + b":"
    kept = [line for line in lines if not line.lower().startswith(lower)]
    return _join([*kept, name + b": " + value], body)


def set_from(raw: bytes, rng: random.Random) -> bytes:
    return _set(raw, b"From", rng.choice([*_ADDRESSES[:5], rng.choice(_ADDRESSES)]))


def set_to(raw: bytes, rng: random.Random) -> bytes:
    return _set(raw, rng.choice([b"To", b"Cc", b"Reply-To"]), rng.choice(_ADDRESSES))


def set_subject(raw: bytes, rng: random.Random) -> bytes:
    return _set(raw, b"Subject", rng.choice(_SUBJECTS))


def duplicate_header(raw: bytes, rng: random.Random) -> bytes:
    lines, body = _split(raw)
    i = rng.randrange(len(lines))
    return _join([*lines[: i + 1], lines[i], *lines[i + 1 :]], body)


def drop_header(raw: bytes, rng: random.Random) -> bytes:
    lines, body = _split(raw)
    del lines[rng.randrange(len(lines))]
    return _join(lines, body)


def odd_header_syntax(raw: bytes, rng: random.Random) -> bytes:
    lines, body = _split(raw)
    i = rng.randrange(len(lines))
    name, _, value = lines[i].partition(b":")
    lines[i] = rng.choice(
        [
            name + b" :" + value,
            name.upper() + b":" + value,
            name + b":" + value.strip(),
            name + b":\t" + value,
            name + b":" + value + b"  ",
            name + b":\r\n" + value,
            b"junk line",
            name + b":" + value.replace(b" ", b"\r\n ", 1),
        ]
    )
    return _join(lines, body)


def _replace_part_header(raw: bytes, rng: random.Random, name: bytes, values: list[bytes]) -> bytes:
    target = name + b": "
    starts = [i for i in range(len(raw)) if raw.startswith(target, i)]
    if not starts:
        return raw
    i = rng.choice(starts)
    end = raw.find(b"\r\n", i)
    while end >= 0 and raw[end + 2 : end + 3] in (b" ", b"\t"):
        end = raw.find(b"\r\n", end + 2)
    if end < 0:
        return raw
    return raw[:i] + target + rng.choice(values) + raw[end:]


def content_type(raw: bytes, rng: random.Random) -> bytes:
    return _replace_part_header(raw, rng, b"Content-Type", _TYPES)


def transfer_encoding(raw: bytes, rng: random.Random) -> bytes:
    return _replace_part_header(raw, rng, b"Content-Transfer-Encoding", _ENCODINGS)


def disposition(raw: bytes, rng: random.Random) -> bytes:
    return _replace_part_header(raw, rng, b"Content-Disposition", _DISPOSITIONS)


def body_bytes(raw: bytes, rng: random.Random) -> bytes:
    head, sep, body = raw.partition(b"\r\n\r\n")
    i = rng.randrange(len(body) + 1)
    insert = rng.choice(
        [
            b"=",
            b"=0",
            b"=ZZ",
            b"=\r\n",
            b"= \r\n",
            b"\r",
            b"\n",
            b" \r\n",
            b"\t",
            b"\x00",
            b"\xc3",
            b"\xe9",
            b"\xef\xbb\xbf",
            b"--=_colophon_example_1\r\n",
            b"--=_colophon_example_1--\r\n",
            b"\r\n.\r\n",
            b"\xe2\x80\xae",
            b"\r\n\r\n",
            b"====",
        ]
    )
    return head + sep + body[:i] + insert + body[i:]


def boundary(raw: bytes, rng: random.Random) -> bytes:
    choice = rng.choice(
        [
            (b"--=_colophon_example_1--", b""),
            (b"--=_colophon_example_1--", b"--=_colophon_example_1"),
            (b'boundary="=_colophon_example_1"', b'boundary="=_colophon_example_1"; boundary=y'),
            (b'boundary="=_colophon_example_1"', b"boundary=="),
            (b'boundary="=_colophon_example_1"', b""),
            (b"--=_colophon_example_1\r\n", b"--=_colophon_example_1 \r\n"),
            (b"\r\n--=_colophon_example_1--", b"\r\n--=_colophon_example_1--trailing"),
        ]
    )
    return raw.replace(choice[0], choice[1], 1)


def line_endings(raw: bytes, rng: random.Random) -> bytes:
    return rng.choice(
        [
            raw.replace(b"\r\n", b"\n"),
            raw.replace(b"\r\n", b"\r"),
            raw.replace(b"\r\n", b"\n", rng.randrange(1, 20)),
        ]
    )


MUTATIONS: list[Mutation] = [
    set_from,
    set_to,
    set_subject,
    duplicate_header,
    drop_header,
    odd_header_syntax,
    content_type,
    transfer_encoding,
    disposition,
    body_bytes,
    boundary,
    line_endings,
]


def mutate(raw: bytes, rng: random.Random, rounds: int = 1) -> tuple[bytes, list[str]]:
    names = []
    for _ in range(rounds):
        mutation = rng.choice(MUTATIONS)
        names.append(mutation.__name__)
        raw = mutation(raw, rng)
    return raw, names
