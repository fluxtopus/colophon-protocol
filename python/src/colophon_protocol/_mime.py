"""The message as octets: header sections, the two layouts of §6.1, and transfer decoding.

This is a small, strict MIME reader for exactly what v0 allows, not a general email parser. Every
function is one forward pass over its input. Lines end in CRLF, or in LF alone for messages kept
in files. A bare CR is malformed in a header section and an ordinary octet in a body.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from colophon_protocol._codec import mime_base64_decode
from colophon_protocol._fail import Fail
from colophon_protocol.model import Reason


def _malformed(detail: str) -> Fail:
    return Fail(Reason.MALFORMED, detail)


def _layout(detail: str) -> Fail:
    return Fail(Reason.LAYOUT, detail)


# ---------------------------------------------------------------- header sections

_FTEXT = frozenset(range(33, 127)) - {ord(":")}
_WSP = b" \t"


@dataclass(frozen=True, slots=True)
class Field:
    """One header field. ``raw`` is everything after the colon, folding line breaks included."""

    name: str  # lowercase
    raw: bytes

    def unfolded(self) -> bytes:
        """§6.4: every CRLF (or LF) followed by SP or HTAB is removed."""
        raw = self.raw
        if b"\n" not in raw:
            return raw
        out = bytearray()
        i, n = 0, len(raw)
        while i < n:
            b = raw[i]
            if b == 0x0D and i + 2 < n and raw[i + 1] == 0x0A and raw[i + 2] in _WSP:
                i += 2
                continue
            if b == 0x0A and i + 1 < n and raw[i + 1] in _WSP:
                i += 1
                continue
            out.append(b)
            i += 1
        return bytes(out)

    def text(self) -> str:
        """The unfolded value as UTF-8 (RFC 6532). ValueError if the octets are not UTF-8."""
        return self.unfolded().decode("utf-8")


def field_text(field: Field) -> str:
    """The unfolded value as UTF-8 (RFC 6532), or malformed (§6.4)."""
    try:
        return field.text()
    except UnicodeDecodeError:
        raise _malformed(f"{field.name} is not valid UTF-8") from None


@dataclass(frozen=True, slots=True)
class Entity:
    """A message or a body part: its header fields in order, and its body octets."""

    fields: tuple[Field, ...]
    body: bytes

    def all(self, name: str) -> list[Field]:
        return [f for f in self.fields if f.name == name]

    def count(self, name: str) -> int:
        return sum(1 for f in self.fields if f.name == name)


def _line_end(data: bytes, start: int) -> tuple[int, int]:
    """(end of line content, start of next line) for the line at ``start``."""
    lf = data.find(b"\n", start)
    if lf < 0:
        return len(data), len(data)
    end = lf - 1 if lf > start and data[lf - 1] == 0x0D else lf
    return end, lf + 1


def parse_entity(data: bytes) -> Entity:
    """Split header section and body at the first empty line. Every line before it is a field
    (``name:value``, the name 1 or more printable ASCII characters other than ``:``) or a
    continuation of the field above (it starts with SP or HTAB). Anything else is malformed.
    Without an empty line, the whole input is the header section and the body is empty.
    A CR that does not end a line is malformed here: other parsers read it as a line end."""
    fields: list[Field] = []
    pos, n = 0, len(data)
    name: str | None = None
    value_start = value_end = 0
    while pos < n:
        end, nxt = _line_end(data, pos)
        if end == pos:  # the empty line
            if name is not None:
                fields.append(Field(name, data[value_start:value_end]))
            return Entity(tuple(fields), data[nxt:])
        if b"\r" in data[pos:end]:
            raise _malformed("a bare CR in the header section")
        if data[pos] in _WSP:
            if name is None:
                raise _malformed("header section starts with a continuation line")
            value_end = end
        else:
            colon = data.find(b":", pos, end)
            if colon <= pos or not all(b in _FTEXT for b in data[pos:colon]):
                raise _malformed("a header line is not a field")
            if name is not None:
                fields.append(Field(name, data[value_start:value_end]))
            name = data[pos:colon].decode("ascii").lower()
            value_start, value_end = colon + 1, end
        pos = nxt
    if name is not None:
        fields.append(Field(name, data[value_start:value_end]))
    return Entity(tuple(fields), b"")


# ---------------------------------------------------------------- Content-Type (RFC 2045 §5.1)

_TOKEN = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`{|}~"
)


@dataclass(frozen=True, slots=True)
class ContentType:
    type: str  # "text/plain", lowercase
    params: dict[str, str]  # names lowercase; values as written, quotes removed

    @property
    def maintype(self) -> str:
        return self.type.partition("/")[0]


DEFAULT_CONTENT_TYPE = ContentType("text/plain", {})


class _Scanner:
    __slots__ = ("data", "i")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.i = 0

    def skip_wsp(self) -> None:
        while self.i < len(self.data) and self.data[self.i] in _WSP:
            self.i += 1

    def token(self) -> str:
        start = self.i
        while self.i < len(self.data) and self.data[self.i] in _TOKEN:
            self.i += 1
        if self.i == start:
            raise _malformed("Content-Type does not parse: token expected")
        return self.data[start : self.i].decode("ascii")

    def quoted(self) -> str:
        self.i += 1  # the opening quote
        out = bytearray()
        while self.i < len(self.data):
            b = self.data[self.i]
            if b == 0x22:
                self.i += 1
                return out.decode("latin-1")
            if b == 0x5C:
                if self.i + 1 >= len(self.data):
                    break
                out.append(self.data[self.i + 1])
                self.i += 2
                continue
            if b in (0x0D, 0x0A):
                break
            out.append(b)
            self.i += 1
        raise _malformed("Content-Type does not parse: unterminated quoted string")

    def at(self, char: bytes) -> bool:
        return self.i < len(self.data) and self.data[self.i] == char[0]

    def done(self) -> bool:
        return self.i >= len(self.data)


def parse_content_type(value: bytes, *, read_params: bool) -> ContentType:
    """``type/subtype *(; name=value)``: tokens, quoted strings, SP and HTAB between them.

    No comments. Parameters are read only where Colophon uses them, in the top level and the
    body part (``read_params``); elsewhere only ``type/subtype`` must parse, followed by ``;`` or
    the end. Where they are read, they follow RFC 2045 §5.1 strictly: a parameter without ``=``,
    a value that is neither a token nor a quoted string, or a repeated name does not parse.
    Empty items (``text/plain;``) are allowed. An RFC 2231 name (``charset*``) is kept as written;
    the layout decides what it means (:func:`extended`).
    """
    s = _Scanner(value)
    s.skip_wsp()
    maintype = s.token().lower()
    if not s.at(b"/"):
        raise _malformed("Content-Type does not parse: no subtype")
    s.i += 1
    subtype = s.token().lower()
    params: dict[str, str] = {}
    s.skip_wsp()
    if not s.done() and not s.at(b";"):
        raise _malformed("Content-Type does not parse: ';' expected")
    while read_params and not s.done():
        if not s.at(b";"):
            raise _malformed("Content-Type does not parse: ';' expected")
        s.i += 1
        s.skip_wsp()
        if s.done() or s.at(b";"):
            continue
        name = s.token().lower()
        s.skip_wsp()
        if not s.at(b"="):
            raise _malformed("Content-Type does not parse: parameter without '='")
        s.i += 1
        s.skip_wsp()
        val = s.quoted() if s.at(b'"') else s.token()
        if name in params:
            raise _malformed(f"Content-Type does not parse: parameter {name} repeated")
        params[name] = val
        s.skip_wsp()
    return ContentType(f"{maintype}/{subtype}", params)


def extended(params: dict[str, str], *names: str) -> bool:
    """True if a parameter Colophon reads has an RFC 2231 form (``name*``, ``name*0``,
    ``name*0*``). That is ``layout``: a mail client may read it as the parameter it extends,
    so ignoring it would let the sender show one value and sign another (§6.1)."""
    return any("*" in key and key.split("*", 1)[0] in names for key in params)


# ---------------------------------------------------------------- multipart (RFC 2046 §5.1)

# RFC 2046 §5.1.1: 1 to 70 characters, the last not a space.
_BOUNDARY = re.compile(r"[0-9A-Za-z'()+_,./:=? -]{0,69}[0-9A-Za-z'()+_,./:=?-]")


def split_multipart(body: bytes, boundary: str | None) -> list[bytes]:
    """The body parts between the delimiters, RFC 2046 §5.1.1 strictly (§6.1). The preamble and
    the epilogue are dropped.

    A line ends at LF, with an optional CR before it. A line that starts with ``--boundary`` is a
    delimiter: after the boundary it has optional SP and HTAB, or ``--`` and then optional SP and
    HTAB for the close delimiter. The line end just before a delimiter belongs to it. All of these
    are malformed: a missing or invalid boundary, a line that starts with ``--boundary`` but is
    not a delimiter, a delimiter after the close one, two delimiter lines with no line end between
    them, no close delimiter, and no parts.
    """
    if boundary is None or not _BOUNDARY.fullmatch(boundary):
        raise _malformed("multipart/mixed has no valid boundary parameter")
    dash = b"--" + boundary.encode("ascii")
    parts: list[bytes] = []
    start: int | None = None  # where the current part begins; None in the preamble
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
                raise _malformed("a delimiter line after the close delimiter")
            if (rest[2:] if close else rest).strip(_WSP):
                raise _malformed("a line starts with the delimiter but is not one")
            if start is not None:
                if pos == start:
                    raise _malformed("two delimiter lines with no line end between them")
                cut = pos - 2 if body[pos - 2 : pos] == b"\r\n" else pos - 1
                parts.append(body[start:cut])
            start, closed = nxt, close
        pos = nxt
    if not closed:
        raise _malformed("multipart has no close delimiter")
    if not parts:
        raise _malformed("multipart has no parts")
    return parts


# ---------------------------------------------------------------- layout (§6.1, §7.2 step 16)

_TRANSFER_ENCODINGS = frozenset({"7bit", "8bit", "binary", "quoted-printable", "base64"})


@dataclass(frozen=True, slots=True)
class Part:
    entity: Entity
    content_type: ContentType
    transfer_encoding: str


@dataclass(frozen=True, slots=True)
class Layout:
    body: Part
    attachments: tuple[Part, ...]


def _single(entity: Entity, name: str) -> Field | None:
    found = entity.all(name)
    if len(found) > 1:
        raise _malformed(f"{name} appears more than once in a part")
    return found[0] if found else None


def _part(entity: Entity, *, read_params: bool = False) -> tuple[Part, str | None]:
    """Check a part's Content-* fields (malformed), then its transfer encoding (layout).
    Returns the part and its disposition type, lowercase, or None."""
    ctype_field = _single(entity, "content-type")
    cte_field = _single(entity, "content-transfer-encoding")
    disposition_field = _single(entity, "content-disposition")
    ctype = DEFAULT_CONTENT_TYPE
    if ctype_field is not None:
        ctype = parse_content_type(ctype_field.unfolded(), read_params=read_params)
    cte = "7bit"
    if cte_field is not None:
        cte = cte_field.unfolded().strip(_WSP).decode("latin-1").lower()
    disposition = None
    if disposition_field is not None:
        raw = disposition_field.unfolded().split(b";", 1)[0]
        disposition = raw.strip(_WSP).decode("latin-1").lower()
    if cte not in _TRANSFER_ENCODINGS:
        raise _layout(f"transfer encoding {cte!r} is not allowed")
    return Part(entity, ctype, cte), disposition


def _body_part(entity: Entity) -> Part:
    part, disposition = _part(entity, read_params=True)
    params = part.content_type.params
    if part.content_type.type != "text/plain":
        raise _layout(f"the body is {part.content_type.type}, not text/plain")
    if disposition == "attachment":
        raise _layout("the body is marked as an attachment")
    if extended(params, "charset", "format"):
        raise _layout("the body part has charset or format in RFC 2231 form")
    charset = params.get("charset", "us-ascii").lower()
    if charset not in ("utf-8", "us-ascii"):
        raise _layout(f"charset {charset!r} is not utf-8 or us-ascii")
    if params.get("format", "fixed").lower() == "flowed":
        raise _layout("format=flowed is not allowed")
    return part


def layout(message: Entity) -> Layout:
    """§6.1, checked from the top as §7.2 step 16 says; the first failure gives the reason.
    Parameters are read at the top level and in the body part, never in an attachment."""
    top, _ = _part(message, read_params=True)
    if top.content_type.type == "text/plain":
        return Layout(_body_part(message), ())
    if top.content_type.type != "multipart/mixed":
        raise _layout(f"top-level type {top.content_type.type} is not allowed")
    if top.transfer_encoding not in ("7bit", "8bit", "binary"):
        raise _layout(f"multipart/mixed with transfer encoding {top.transfer_encoding!r}")
    if extended(top.content_type.params, "boundary"):
        raise _layout("boundary in RFC 2231 form")
    children = split_multipart(message.body, top.content_type.params.get("boundary"))
    body = _body_part(parse_entity(children[0]))
    attachments: list[Part] = []
    for raw in children[1:]:
        part, disposition = _part(parse_entity(raw))
        if part.content_type.maintype in ("multipart", "message"):
            raise _layout(f"attachment of type {part.content_type.type}")
        if disposition != "attachment":
            raise _layout("a part after the body is not marked as an attachment")
        attachments.append(part)
    return Layout(body, tuple(attachments))


# ---------------------------------------------------------------- transfer decoding (§6.4)

_HEX = frozenset(b"0123456789ABCDEFabcdef")


def _decode_quoted_printable(data: bytes) -> bytes:
    """RFC 2045 §6.7 as §6.4 makes it strict. Trailing SP and HTAB on a line are dropped; a line
    then ending in '=' joins the next; every other line end becomes CRLF; '=' must be followed
    by two hex digits."""
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
                raise _malformed("'=' not followed by two hex digits")
            out.append(int(pair, 16))
            i = eq + 3
        if last:
            return bytes(out)
        if not soft:
            out += b"\r\n"
        pos = lf + 1


def decoded(part: Part) -> bytes:
    """The part's body with its transfer encoding removed (§6.4 Text, step 1)."""
    data = part.entity.body
    if part.transfer_encoding == "base64":
        try:
            return mime_base64_decode(data)
        except ValueError:
            raise _malformed("invalid base64") from None
    if part.transfer_encoding == "quoted-printable":
        return _decode_quoted_printable(data)
    return data


def canonical_text(part: Part) -> bytes:
    """§6.4 Text, steps 2 to 7."""
    charset = part.content_type.params.get("charset", "us-ascii").lower()
    try:
        text = decoded(part).decode("utf-8" if charset == "utf-8" else "ascii")
    except UnicodeDecodeError:
        raise _malformed(f"body octets are not valid {charset}") from None
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    lines = [line.rstrip(" \t") for line in lines]
    while lines and lines[-1] == "":
        lines.pop()
    return "".join(line + "\r\n" for line in lines).encode("utf-8")
