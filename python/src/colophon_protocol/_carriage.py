"""Where the signature travels. v0 carries it in one header field (§6.2).

Everything that knows the header's name, its tag list or its folding is here, so a later version
can move the signature (to a MIME part, say) without touching the verifier's other steps.
"""

from __future__ import annotations

from dataclasses import dataclass

from colophon_protocol._fail import Fail
from colophon_protocol._grammar import parse_tags, remove_whitespace
from colophon_protocol._mime import Entity, Field, field_text
from colophon_protocol.model import Reason

HEADER_NAME = "Colophon-Signature"
MAX_HEADER_BYTES = 2560
MAX_CREDENTIAL_BYTES = 2048
_LOWER_NAME = HEADER_NAME.lower()


@dataclass(frozen=True, slots=True)
class Carried:
    """What the carriage holds, unchecked beyond steps 5 to 7's size and presence rules."""

    credential: str
    signature: str


def locate(entity: Entity) -> Field:
    """Steps 1 and 2."""
    found = entity.all(_LOWER_NAME)
    if not found:
        raise Fail(Reason.NO_SIGNATURE)
    if len(found) > 1:
        raise Fail(Reason.MULTIPLE_SIGNATURES)
    return found[0]


def read(field: Field) -> Carried:
    """Steps 5 and 6, and the presence and size rules of step 7."""
    value = remove_whitespace(field_text(field))
    if len(value.encode("utf-8")) > MAX_HEADER_BYTES:
        raise Fail(Reason.MALFORMED, f"{HEADER_NAME} is over {MAX_HEADER_BYTES} octets")
    try:
        tags = parse_tags(value)
    except ValueError:
        raise Fail(Reason.MALFORMED, f"{HEADER_NAME} is not a tag list") from None
    if "v" not in tags:
        raise Fail(Reason.MALFORMED, f"{HEADER_NAME} has no v tag")
    if tags["v"] != "0":
        raise Fail(Reason.UNSUPPORTED_VERSION, f"version {tags['v'][:16]!r}")
    if "c" not in tags or "b" not in tags:
        raise Fail(Reason.MALFORMED, f"{HEADER_NAME} lacks c or b")
    if len(tags["c"].encode("utf-8")) > MAX_CREDENTIAL_BYTES:
        raise Fail(Reason.MALFORMED, f"credential is over {MAX_CREDENTIAL_BYTES} octets")
    return Carried(tags["c"], tags["b"])


def header_value(credential: str, signature: str) -> str:
    return f"v=0; c={credential}; b={signature}"


def attach(message: bytes, credential: str, signature: str) -> bytes:
    """Prepend the header, folded so no line passes 78 characters. Folding is free: verifiers
    remove all whitespace. Lines end as the message's own do: CRLF, or LF for an LF-only file."""
    newline = b"\r\n" if b"\r\n" in message or b"\n" not in message else b"\n"
    return _fold(HEADER_NAME, header_value(credential, signature), newline) + message


def _fold(name: str, value: str, newline: bytes) -> bytes:
    lines: list[str] = []
    current = name + ":"
    items = value.split("; ")
    for i, item in enumerate(items):
        piece = item + (";" if i < len(items) - 1 else "")
        if len(current) + 1 + len(piece) <= 78:
            current += " " + piece
            continue
        lines.append(current)
        while len(piece) > 77:
            lines.append(" " + piece[:77])
            piece = piece[77:]
        current = " " + piece
    lines.append(current)
    return newline.join(line.encode("ascii") for line in lines) + newline
