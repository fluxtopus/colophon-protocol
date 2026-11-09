"""Colophon v0 reference sketch: sign and verify a message as the draft specifies.

Not a library. It exists so the draft's examples are real bytes that verify, and so a reader can
check their reading of the spec against running code. It does not check DKIM or query DNS: the
verifier is given the receiving system's DKIM result, DNS answers and mailbox, as §7.1 describes.

Run:  uv run --with cryptography python colophon_v0.py [--example | --json]
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

HEADER = "Colophon-Signature"
VERSION = 0
GRACE = 2 * 3600  # seconds after a credential's exp that it is still accepted on arrival
SKEW = 5 * 60  # clocks may run this fast
MIN_REMAINING = 6 * 3600  # a signer SHOULD NOT sign with less credential life left (not checked)
MAX_LIFETIME = 24 * 3600
MAX_SCOPE_BYTES = 280
MAX_NAME_BYTES = 128
MAX_HEADER_BYTES = 2560  # the Colophon-Signature value, whitespace removed
MAX_CREDENTIAL_BYTES = 2048  # the c tag value
MAX_INT = 2**53 - 1
MISS_LIMIT = 20  # DNS misses per domain per hour (RECOMMENDED; the vectors use it)

# Every grammar is matched against the whole value (fullmatch), never with match() or a $ anchor.
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
AGENT_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
NONCE = re.compile(r"[A-Za-z0-9_-]{16,64}")
B64URL = re.compile(r"[A-Za-z0-9_-]*")
TAG_NAME = re.compile(r"[a-z][a-z0-9_]*")
ATEXT = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]"
LOCAL_PART = re.compile(rf"(?:{ATEXT}|[^\x00-\x7f])+(?:\.(?:{ATEXT}|[^\x00-\x7f])+)*")
LDH = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
DOMAIN = re.compile(rf"{LDH}(?:\.{LDH})+")
PHRASE = re.compile(rf"(?:{ATEXT}|[ \t.]|[^\x00-\x7f]|\"(?:[^\"\\\r\n]|\\.)*\")*")
FIELD_NAME = re.compile(rb"[\x21-\x39\x3b-\x7e]+")  # RFC 5322 ftext: printable ASCII but ':'
TOKEN = r"[A-Za-z0-9!#$%&'*+.^_`{|}~-]+"
MEDIA_TYPE = re.compile(rf"[ \t]*({TOKEN})/({TOKEN})[ \t]*(?=;|\Z)")
PARAMETER = re.compile(
    rf'[ \t]*;[ \t]*(?:({TOKEN})[ \t]*=[ \t]*({TOKEN}|"(?:[^"\\]|\\.)*")[ \t]*)?', re.DOTALL
)
BOUNDARY_CHARS = re.compile(r"[0-9A-Za-z'()+_,./:=? -]{0,69}[0-9A-Za-z'()+_,./:=?-]")  # RFC 2046
TRANSFER_ENCODINGS = {"7bit", "8bit", "binary", "quoted-printable", "base64"}
BASE64 = re.compile(rb"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
# C0, DEL, C1 and the bidirectional controls: not allowed in scope or a named principal (§5.4).
FORBIDDEN_TEXT = re.compile("[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


class Fail(Exception):
    """A step failed: the verdict is not verified, with this reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------- encodings


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: object) -> bytes:
    """Strict base64url (§2): URL-safe alphabet, no padding, no stray bits. ValueError otherwise."""
    if not isinstance(text, str) or not B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("not base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u(data) != text:
        raise ValueError("non-canonical base64url")
    return data


def strict_json(data: bytes) -> object:
    """I-JSON (RFC 7493) as v0 uses it: unique member names, numbers are integers within
    +/-(2^53 - 1), and no string holds a surrogate or a noncharacter. ValueError otherwise."""

    def pairs(items: list[tuple[str, object]]) -> dict:
        out: dict = {}
        for k, v in items:
            if k in out:
                raise ValueError("duplicate member")
            out[k] = v
        return out

    def not_an_integer(text: str) -> float:
        raise ValueError(f"not an integer: {text}")

    def integer(text: str) -> int:
        value = int(text)
        if abs(value) > MAX_INT:
            raise ValueError("integer out of range")
        return value

    def check_strings(value: object) -> None:
        """RFC 7493 §2.1: no surrogate or noncharacter, written as is or as a \\u escape."""
        if isinstance(value, dict):
            for k, v in value.items():
                check_strings(k)
                check_strings(v)
        elif isinstance(value, list):
            for v in value:
                check_strings(v)
        elif isinstance(value, str) and any(bad_code_point(ord(ch)) for ch in value):
            raise ValueError("surrogate or noncharacter")

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_float=not_an_integer,
            parse_int=integer,
            parse_constant=not_an_integer,
        )
        check_strings(value)
        return value
    except RecursionError:
        raise ValueError("nested too deeply") from None


def bad_code_point(c: int) -> bool:
    return 0xD800 <= c <= 0xDFFF or 0xFDD0 <= c <= 0xFDEF or c & 0xFFFE == 0xFFFE


def jcs(value: object) -> bytes:
    """RFC 8785 for the values Colophon uses: objects, arrays, strings and integers.

    Keys are ASCII in Colophon, so sorting by code point equals JCS's UTF-16 order."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def sha256(data: bytes) -> str:
    return b64u(hashlib.sha256(data).digest())


def public_x(key: Ed25519PrivateKey) -> str:
    return b64u(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


class SigningKey(Protocol):
    """An Ed25519 private key, or anything that signs like one (the vectors' crafted signatures)."""

    def sign(self, data: bytes) -> bytes: ...


def jws_sign(header: dict, payload: bytes, key: SigningKey) -> tuple[str, str, str]:
    h = b64u(jcs(header))
    p = b64u(payload)
    s = b64u(key.sign(f"{h}.{p}".encode("ascii")))
    return h, p, s


def jws_check(h: str, p: str, s: str, public: bytes) -> bool:
    """Ed25519 as §6.5 makes it exact. The cryptography package checks S < L and the equation
    without the cofactor; the check on R is added here. Keys are checked where they are read."""
    try:
        sig = unb64u(s)
        if len(sig) == 64 and small_order(sig[:32]):
            return False
        Ed25519PublicKey.from_public_bytes(public).verify(sig, f"{h}.{p}".encode("ascii"))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- Ed25519 points (§6.5)

ED_P = 2**255 - 19
ED_L = 2**252 + 27742317777372353535851937790883648493  # the group order
ED_D = -121665 * pow(121666, ED_P - 2, ED_P) % ED_P
Point = tuple[int, int, int, int]  # extended coordinates (X, Y, Z, T)


def decode_point(data: bytes) -> Point | None:
    """RFC 8032 §5.1.3. None if decoding fails, a y of p or more (not canonical) included."""
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if len(data) != 32 or y >= ED_P:
        return None
    x2 = (y * y - 1) * pow(ED_D * y * y + 1, ED_P - 2, ED_P) % ED_P
    x = pow(x2, (ED_P + 3) // 8, ED_P)
    if (x * x - x2) % ED_P:
        x = x * pow(2, (ED_P - 1) // 4, ED_P) % ED_P
    if (x * x - x2) % ED_P or (x == 0 and sign):
        return None
    if x & 1 != sign:
        x = ED_P - x
    return (x, y, 1, x * y % ED_P)


def add_points(a: Point, b: Point) -> Point:
    """RFC 8032 §5.1.4."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    p = ED_P
    aa, bb = (y1 - x1) * (y2 - x2) % p, (y1 + x1) * (y2 + x2) % p
    cc, dd = 2 * t1 * t2 * ED_D % p, 2 * z1 * z2 % p
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % p, g * h % p, f * g % p, e * h % p)


def small_order(data: bytes) -> bool:
    """True if `data` decodes to a point P with 8P the identity."""
    point = decode_point(data)
    if point is None:
        return False
    for _ in range(3):
        point = add_points(point, point)
    x, y, z, _ = point
    return x % ED_P == 0 and (y - z) % ED_P == 0


def valid_key(data: bytes) -> bool:
    """§6.5: a public key is the canonical encoding of a point that is not of small order."""
    return decode_point(data) is not None and not small_order(data)


def tags(value: str) -> dict[str, str]:
    """A tag list (§6.2, §4.1): whitespace removed, `name=value` items split at `;`, names in
    lowercase, no duplicates. Fail("malformed") otherwise."""
    out: dict[str, str] = {}
    for item in re.sub(r"[ \t\r\n]+", "", value).split(";"):
        if item:
            k, sep, v = item.partition("=")
            if not sep or not TAG_NAME.fullmatch(k) or k in out:
                raise Fail("malformed")
            out[k] = v
    return out


# ---------------------------------------------------------------- header sections


@dataclass
class Part:
    """A message or a MIME part: its header fields, unfolded, and its body octets."""

    fields: list[tuple[str, bytes]]
    body: bytes


def parse_part(data: bytes, strict: bool = True) -> Part:
    """§6.1: a header section, then the body. A line ends at CRLF or at LF alone. Each line is a
    field (a name, then a colon) or continues the one before it (it starts with SP or HTAB). The
    first empty line ends the section. Anything else, a CR alone included, is malformed.

    strict=False skips what is not a field, to count fields before the check (§7.2 steps 1, 2)."""
    fields: list[tuple[str, bytes]] = []
    pos = 0
    while pos < len(data):
        end = data.find(b"\n", pos)
        if end == -1:
            line, pos = data[pos:], len(data)
        else:
            line, pos = data[pos:end], end + 1
            if line.endswith(b"\r"):
                line = line[:-1]
        if line == b"":
            return Part(fields, data[pos:])
        if strict and b"\r" in line:
            raise Fail("malformed")
        if line[:1] in (b" ", b"\t"):
            if fields:
                last, value = fields[-1]
                fields[-1] = (last, value + line)  # unfolded: the line end is removed (§6.4)
                continue
        else:
            name, colon, value = line.partition(b":")
            if colon and FIELD_NAME.fullmatch(name):
                fields.append((name.decode("ascii"), value))
                continue
        if strict:
            raise Fail("malformed")
    return Part(fields, b"")


def raw_values(part: Part, name: str) -> list[str]:
    """Each instance of a header field, unfolded, as text. Header octets must be UTF-8 (RFC 6532)."""
    out = []
    for key, value in part.fields:
        if key.lower() == name.lower():
            try:
                out.append(value.decode("utf-8"))
            except UnicodeError:
                raise Fail("malformed") from None
    return out


def split_address_list(value: str) -> list[str]:
    """Split at top-level commas. Groups, comments, domain literals and routes are malformed."""
    items: list[str] = []
    cur: list[str] = []
    quoted = escaped = angle = False
    for ch in value:
        if quoted:
            cur.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
            continue
        if ch == '"':
            quoted = True
        elif ch == "<":
            if angle:
                raise Fail("malformed")
            angle = True
        elif ch == ">":
            if not angle:
                raise Fail("malformed")
            angle = False
        elif ch in "():;[]\\":
            raise Fail("malformed")
        elif ch == "," and not angle:
            items.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    if quoted or angle:
        raise Fail("malformed")
    items.append("".join(cur))
    return [i.strip(" \t") for i in items]


def canonical_addr_spec(addr: str) -> str:
    """§6.4: a dot-atom local part, and a domain of ASCII labels (A-labels for IDNs)."""
    local, at, domain = addr.rpartition("@")
    if not at or not LOCAL_PART.fullmatch(local) or not DOMAIN.fullmatch(domain):
        raise Fail("malformed")
    ascii_lower = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
    return f"{local.translate(ascii_lower)}@{domain.lower()}"


def canonical_mailbox(item: str) -> str:
    if item.endswith(">"):
        i = item.index("<")
        if not PHRASE.fullmatch(item[:i]):
            raise Fail("malformed")
        return canonical_addr_spec(item[i + 1 : -1])
    return canonical_addr_spec(item)


def address_list(msg: Part, name: str) -> list[str]:
    values = raw_values(msg, name)
    if len(values) > 1:
        raise Fail("malformed")
    if not values:
        return []
    out: list[str] = []
    for item in split_address_list(values[0]):
        addr = canonical_mailbox(item)
        if addr not in out:
            out.append(addr)
    return out


def canonical_subject(msg: Part) -> str:
    """The raw value (§6.4): unfolded, whitespace collapsed, trimmed. Encoded words are not decoded."""
    values = raw_values(msg, "Subject")
    if len(values) > 1:
        raise Fail("malformed")
    if not values:
        return ""
    return re.sub(r"[ \t]+", " ", values[0]).strip(" ")


def canonical_text(text: str) -> bytes:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    lines = [line.rstrip(" \t") for line in lines]
    while lines and lines[-1] == "":
        lines.pop()
    return ("".join(line + "\r\n" for line in lines)).encode("utf-8")


# ---------------------------------------------------------------- MIME


def content_field(part: Part, name: str) -> str | None:
    """A Content-* field's value. Octets that are not UTF-8 stay opaque: no grammar matches them."""
    values = [v for k, v in part.fields if k.lower() == name.lower()]
    return values[0].decode("utf-8", "surrogateescape") if values else None


def content_type(part: Part, read_params: bool) -> tuple[str, dict[str, str]]:
    """§6.1: `type/subtype`, lowercase. Parameters are read only where Colophon uses them, in the
    top level and the body part: there they follow RFC 2045 §5.1, or the message is malformed."""
    value = content_field(part, "Content-Type")
    if value is None:
        return "text/plain", {}
    m = MEDIA_TYPE.match(value)
    if not m:
        raise Fail("malformed")
    params: dict[str, str] = {}
    pos = m.end()
    while read_params and pos < len(value):
        p = PARAMETER.match(value, pos)
        if not p or (p.end() < len(value) and value[p.end()] != ";"):
            raise Fail("malformed")  # no `=`, or a value that is neither token nor quoted string
        if p[1] is not None:  # an empty item, such as a trailing `;`, is ignored
            name, v = p[1].lower(), p[2]
            if name in params:
                raise Fail("malformed")
            params[name] = re.sub(r"\\(.)", r"\1", v[1:-1], flags=re.DOTALL) if v[0] == '"' else v
        pos = p.end()
    return f"{m[1]}/{m[2]}".lower(), params


def extended(params: dict[str, str], names: tuple[str, ...]) -> bool:
    """An RFC 2231 form (`name*`, `name*0`, `name*0*`) of a parameter Colophon reads."""
    return any("*" in k and k.split("*")[0] in names for k in params)


def disposition(part: Part) -> str:
    return (content_field(part, "Content-Disposition") or "").split(";")[0].strip(" \t").lower()


def part_headers(part: Part, read_params: bool = False) -> tuple[str, dict[str, str], str]:
    """§6.1, step 16: the Content-* fields appear at most once and Content-Type parses
    (malformed), then the transfer encoding is one of five (layout)."""
    for name in ("Content-Type", "Content-Transfer-Encoding", "Content-Disposition"):
        if sum(1 for k, _ in part.fields if k.lower() == name.lower()) > 1:
            raise Fail("malformed")
    media, params = content_type(part, read_params)
    cte = (content_field(part, "Content-Transfer-Encoding") or "7bit").strip(" \t").lower()
    if cte not in TRANSFER_ENCODINGS:
        raise Fail("layout")
    return media, params, cte


def check_body_part(part: Part) -> str:
    """The body part's type, disposition, charset and format (§6.1). Returns the charset."""
    media, params, _ = part_headers(part, read_params=True)
    if media != "text/plain" or disposition(part) == "attachment":
        raise Fail("layout")
    if extended(params, ("charset", "format")):
        raise Fail("layout")
    charset = params.get("charset", "us-ascii").lower()
    if charset not in ("us-ascii", "utf-8"):
        raise Fail("layout")  # names only: no aliases such as utf8
    if params.get("format", "fixed").lower() == "flowed":
        raise Fail("layout")
    return charset


def split_multipart(body: bytes, boundary: str | None) -> list[bytes]:
    """§6.1: RFC 2046 §5.1.1, strictly. Returns each part's octets."""
    if boundary is None or not BOUNDARY_CHARS.fullmatch(boundary):
        raise Fail("malformed")
    dash = b"--" + boundary.encode("ascii")
    out: list[bytes] = []
    start: int | None = None  # where the current part begins; None in the preamble
    closed = False
    pos = 0
    while pos < len(body):
        end = body.find(b"\n", pos)
        line = body[pos:] if end == -1 else body[pos:end].removesuffix(b"\r")
        nxt = len(body) if end == -1 else end + 1
        if line.startswith(dash):
            rest = line[len(dash) :]
            close = rest.startswith(b"--")
            if closed or (rest[2:] if close else rest).strip(b" \t"):
                raise Fail("malformed")  # a delimiter after the close one, or `--boundaryX`
            if start is not None:
                if pos == start:
                    raise Fail("malformed")  # two delimiter lines with no line end between
                cut = pos - 2 if body[pos - 2 : pos] == b"\r\n" else pos - 1
                out.append(body[start:cut])  # the line end before a delimiter belongs to it
            start, closed = nxt, close
        pos = nxt
    if not closed or not out:
        raise Fail("malformed")
    return out


def parts(msg: Part) -> tuple[Part, list[Part]]:
    """§7.2 step 16: walk the parts from the top; the first failure gives the reason."""
    media, params, cte = part_headers(msg, read_params=True)
    if media == "text/plain":
        check_body_part(msg)
        return msg, []
    if media != "multipart/mixed" or cte not in ("7bit", "8bit", "binary"):
        raise Fail("layout")
    if extended(params, ("boundary",)):
        raise Fail("layout")
    chunks = split_multipart(msg.body, params.get("boundary"))
    body = parse_part(chunks[0])
    check_body_part(body)
    attachments = []
    for chunk in chunks[1:]:
        child = parse_part(chunk)
        media, _, _ = part_headers(child)
        if media.split("/")[0] in ("multipart", "message") or disposition(child) != "attachment":
            raise Fail("layout")
        attachments.append(child)
    return body, attachments


def decode_qp(data: bytes) -> bytes:
    """Quoted-printable per RFC 2045 §6.7, strictly: '=' not followed by two hex digits or a line
    end is malformed."""
    out = bytearray()
    lines = re.split(rb"\r\n|\n", data)
    for n, line in enumerate(lines):
        line = line.rstrip(b" \t")  # rule 3: trailing whitespace is not content
        soft = line.endswith(b"=")
        if soft:
            line = line[:-1]
        i = 0
        while i < len(line):
            if line[i : i + 1] == b"=":
                pair = line[i + 1 : i + 3]
                if not re.fullmatch(rb"[0-9A-Fa-f]{2}", pair):
                    raise Fail("malformed")
                out.append(int(pair, 16))
                i += 3
            else:
                out += line[i : i + 1]
                i += 1
        if not soft and n < len(lines) - 1:
            out += b"\r\n"
    return bytes(out)


def decoded(part: Part) -> bytes:
    """A part's body with its transfer encoding removed (§6.4). 8-bit octets are kept as sent."""
    _, _, cte = part_headers(part)
    data = part.body
    if cte == "base64":
        compact = re.sub(rb"[ \t\r\n]+", b"", data)
        if not BASE64.fullmatch(compact):
            raise Fail("malformed")
        return base64.b64decode(compact)
    if cte == "quoted-printable":
        return decode_qp(data)
    return data


def body_text(part: Part) -> str:
    charset = check_body_part(part)
    try:
        return decoded(part).decode(charset)  # a BOM is content
    except UnicodeError:
        raise Fail("malformed") from None


def signing_input(msg: Part, credential: str) -> dict:
    """§6.3. Layout first (step 16), then the rest (step 17)."""
    body, attachments = parts(msg)
    froms = address_list(msg, "From")
    if len(froms) != 1:
        raise Fail("malformed")
    return {
        "attachments": [{"sha256": sha256(decoded(a)), "type": part_headers(a)[0]} for a in attachments],
        "cc": address_list(msg, "Cc"),
        "credential": sha256(credential.encode("ascii")),
        "from": froms[0],
        "reply_to": address_list(msg, "Reply-To"),
        "subject": canonical_subject(msg),
        "text": sha256(canonical_text(body_text(body))),
        "to": address_list(msg, "To"),
        "v": VERSION,
    }


# ---------------------------------------------------------------- issuing and signing


def dns_record(domain_key: Ed25519PrivateKey) -> str:
    return f"v=COLOPHON0; k=ed25519; p={public_x(domain_key)}"


def issue_credential(domain_key: SigningKey, selector: str, claims: dict) -> str:
    header = {"alg": "EdDSA", "kid": selector, "typ": "colophon-cred+jwt"}
    h, p, s = jws_sign(header, jcs(claims), domain_key)
    return f"{h}.{p}.{s}"


def fold_header(name: str, value: str) -> bytes:
    """Fold at '; ' and inside long values so no line passes 78 characters. Verifiers remove all
    whitespace before parsing, so where a signer folds does not matter."""
    lines, cur = [], name + ":"
    items = value.split("; ")
    for i, item in enumerate(items):
        piece = item + (";" if i < len(items) - 1 else "")
        if len(cur) + 1 + len(piece) <= 78:
            cur += " " + piece
            continue
        lines.append(cur)
        while len(piece) > 77:
            lines.append(" " + piece[:77])
            piece = piece[77:]
        cur = " " + piece
    lines.append(cur)
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def sign(
    raw: bytes,
    credential: str,
    agent_key: SigningKey,
    iat: int,
    nonce: str,
    strict: bool = True,
) -> bytes:
    """Sign the bytes that will be sent, and return them with Colophon-Signature prepended.

    strict=False skips the signer-side rules, so vectors can build messages a signer must not."""
    if strict:
        claims = strict_json(unb64u(credential.split(".")[1]))
        if claims["exp"] - iat < MIN_REMAINING:
            raise ValueError("credential too close to expiry to sign with")
    payload = jcs(signing_input(parse_part(raw), credential))
    header = {"alg": "EdDSA", "iat": iat, "nonce": nonce, "typ": "colophon-sig"}
    h, _, s = jws_sign(header, payload, agent_key)
    value = f"v={VERSION}; c={credential}; b={h}..{s}"
    if strict and (len(credential) > MAX_CREDENTIAL_BYTES or len(value) > MAX_HEADER_BYTES):
        raise ValueError("Colophon-Signature over the size cap")
    return fold_header(HEADER, value) + raw


# ---------------------------------------------------------------- DKIM identity (§7.1)

DKIM_TAG_NAME = re.compile(rb"[A-Za-z][A-Za-z0-9_]*")  # RFC 6376 §3.2
DKIM_QP_ESCAPE = re.compile(rb"=([0-9A-Fa-f]{2})")


def dkim_identity(value: bytes) -> tuple[bytes, bytes] | None:
    """A DKIM-Signature field's d= and identity (§7.1): its i=, decoded from DKIM quoted-printable
    (RFC 6376 §2.11), or `@` and its d=. None when the tag list does not parse (RFC 6376 §3.2), a
    tag repeats, d= is missing or empty, or i= has an `=` not followed by two hex digits."""
    found: dict[bytes, bytes] = {}
    for item in value.split(b";"):
        name, eq, v = item.partition(b"=")
        name = name.strip(b" \t\r\n")
        if not eq:
            if name:
                return None  # an item without `=`
            continue  # an empty item, such as after the last `;`
        if not DKIM_TAG_NAME.fullmatch(name) or name in found:
            return None
        found[name] = re.sub(rb"[ \t\r\n]+", b"", v)
    d = found.get(b"d")
    if not d or not d.isascii():
        return None
    if b"i" not in found:
        return d, b"@" + d
    i = found[b"i"]
    if i.count(b"=") != len(DKIM_QP_ESCAPE.findall(i)):
        return None  # malformed quoted-printable: no identity
    return d, DKIM_QP_ESCAPE.sub(lambda m: bytes.fromhex(m[1].decode()), i)


def same_identity(a: bytes, b: bytes) -> bool:
    """Local parts equal octet for octet, domains equal ignoring case (§7.1)."""
    local_a, at_a, domain_a = a.rpartition(b"@")
    local_b, at_b, domain_b = b.rpartition(b"@")
    return bool(at_a and at_b) and local_a == local_b and domain_a.lower() == domain_b.lower()


def dkim_identity_domain(msg: Part, header_i: str) -> str | None:
    """§7.1: the d= of the one DKIM-Signature field whose identity equals header.i, or None."""
    wanted = header_i.encode("utf-8")
    matches = []
    for key, value in msg.fields:
        found = dkim_identity(value) if key.lower() == "dkim-signature" else None
        if found and same_identity(found[1], wanted):
            matches.append(found[0].decode("ascii").lower())
    return matches[0] if len(matches) == 1 else None


# ---------------------------------------------------------------- verifying


@dataclass
class Arrival:
    """What the receiving system supplies (§7.1). The message never supplies these."""

    accepted_at: int  # when the receiver's mail server accepted the message in SMTP
    dkim_pass_domains: set[str]  # d= of every DKIM signature that passed, from the receiver's checks
    mailbox: str  # the receiver's stable identifier for the mailbox this copy was delivered to
    mailbox_addresses: set[str]  # every address that mailbox receives at: its own and its aliases
    dns: dict[str, list[str] | None]  # TXT answers; a missing name is NXDOMAIN, None a failed lookup
    envelope_recipient: str = ""  # the RCPT TO; the receiver maps it to the mailbox. Not used here.
    dns_misses: int = 0  # misses for the From host this hour, before this message (§7.4)
    replay_store_available: bool = True  # whether the replay store can be read and written (§7.6)
    seen: set[tuple] = field(default_factory=set)  # the replay store for the mailbox
    # header.i of each passing DKIM signature reported without header.d (§7.1)
    dkim_pass_identities: set[str] = field(default_factory=set)


@dataclass
class Verdict:
    verified: bool
    reason: str
    agent: dict | None = None
    properties: dict | None = None  # what §7.8 reports with pass


AR_PROPERTIES = ("from", "sub", "s", "principal", "cred")
TEMPERROR = {"dns_error", "dns_limited", "replay_unchecked"}


def authentication_results(verdict: Verdict) -> str:
    """§7.8: the colophon result as one resinfo of an Authentication-Results field, unfolded."""
    if verdict.verified:
        assert verdict.properties is not None
        props = " ".join(f"header.{k}={verdict.properties[k]}" for k in AR_PROPERTIES)
        return f"colophon=pass {props}"
    if verdict.reason == "no_signature":
        result = "none"
    elif verdict.reason in TEMPERROR:
        result = "temperror"
    else:
        result = "fail"
    return f'colophon={result} reason="{verdict.reason}"'


def domain_key(answers: list[str]) -> bytes:
    """§7.4: the one Colophon record at the name, or Fail."""
    records = []
    for answer in answers:
        if not answer.isascii():
            continue  # records are octets, never decoded: a non-ASCII one is not a Colophon record
        try:
            record = tags(answer)
        except Fail:
            continue  # not a tag list, or a duplicate tag: not a Colophon record
        if record.get("v") == "COLOPHON0":
            records.append(record)
    if len(records) != 1:
        raise Fail("key_not_found")
    record = records[0]
    if record.get("k") != "ed25519" or "p" not in record:
        raise Fail("key_not_found")
    if record["p"] == "":
        raise Fail("key_revoked")
    try:
        key = unb64u(record["p"])
    except ValueError:
        raise Fail("key_not_found") from None
    if len(key) != 32 or not valid_key(key):
        raise Fail("key_not_found")
    return key


def is_int(value: object) -> bool:
    return type(value) is int  # not bool


def plain_text(value: object, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value.encode()) <= limit and not FORBIDDEN_TEXT.search(value)


def valid_principal(p: object) -> bool:
    if not isinstance(p, dict):
        return False
    mode = p.get("mode")
    if mode == "withheld":
        return set(p) == {"mode"}
    if mode == "pseudonymous":
        pid = p.get("id")
        return set(p) == {"mode", "id"} and isinstance(pid, str) and bool(AGENT_ID.fullmatch(pid))
    if mode == "named":
        return set(p) == {"mode", "name"} and plain_text(p["name"], MAX_NAME_BYTES)
    return False


def agent_key(claims: dict) -> bytes:
    """§7.2 step 13: each claim has its JSON type and matches its grammar in full."""
    iat, exp = claims.get("iat"), claims.get("exp")
    if not (is_int(iat) and is_int(exp) and iat < exp <= iat + MAX_LIFETIME):
        raise Fail("credential_invalid")
    sub, sender = claims.get("sub"), claims.get("from")
    if not isinstance(sub, str) or not AGENT_ID.fullmatch(sub):
        raise Fail("credential_invalid")
    if not isinstance(sender, str):
        raise Fail("credential_invalid")
    try:
        canonical = canonical_addr_spec(sender)
    except Fail:
        raise Fail("credential_invalid") from None
    if canonical != sender:
        raise Fail("credential_invalid")
    if not valid_principal(claims.get("principal")):
        raise Fail("credential_invalid")
    if "scope" in claims and not plain_text(claims["scope"], MAX_SCOPE_BYTES):
        raise Fail("credential_invalid")
    cnf = claims.get("cnf")
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise Fail("credential_invalid")
    try:
        key = unb64u(jwk.get("x"))
    except ValueError:
        raise Fail("credential_invalid") from None
    if len(key) != 32 or not valid_key(key):
        raise Fail("credential_invalid")
    return key


def verify(raw: bytes, arrival: Arrival) -> Verdict:
    try:
        agent, properties = _verify(raw, arrival)
        return Verdict(True, "verified", agent, properties)
    except Fail as failed:
        return Verdict(False, failed.reason)


def _verify(raw: bytes, arrival: Arrival) -> tuple[dict, dict]:
    """§7.2, step by step. The first failing step gives the reason."""
    t_arr = arrival.accepted_at

    # 1, 2. exactly one Colophon-Signature, counted before the header section is checked
    count = sum(1 for key, _ in parse_part(raw, strict=False).fields if key.lower() == HEADER.lower())
    if count == 0:
        raise Fail("no_signature")
    if count > 1:
        raise Fail("multiple_signatures")

    # 3. a well-formed header section (§6.1), and exactly one From address; H is its host
    msg = parse_part(raw)
    froms = address_list(msg, "From")
    if len(froms) != 1:
        raise Fail("malformed")
    sender = froms[0]
    host = sender.rpartition("@")[2]

    # 4. aligned DKIM, before any DNS lookup. A signature reported only by header.i counts for
    # the d= that §7.1 recovers from the message.
    passed = {d.lower() for d in arrival.dkim_pass_domains}
    passed |= {d for i in arrival.dkim_pass_identities if (d := dkim_identity_domain(msg, i))}
    if host not in passed:
        raise Fail("dkim_unaligned")

    # 5. the tag list, within its size cap, with a v tag
    value = re.sub(r"[ \t\r\n]+", "", raw_values(msg, HEADER)[0])
    if len(value.encode()) > MAX_HEADER_BYTES:
        raise Fail("malformed")
    t = tags(value)
    if "v" not in t:
        raise Fail("malformed")

    # 6. the version
    if t["v"] != "0":
        raise Fail("unsupported_version")

    # 7. c and b: two compact JWS, b with its payload detached; I-JSON objects
    if "c" not in t or "b" not in t or len(t["c"]) > MAX_CREDENTIAL_BYTES:
        raise Fail("malformed")
    credential, sig = t["c"], t["b"]
    try:
        ch, cp, cs = credential.split(".")
        sh, sp, ss = sig.split(".")
        cred_header, claims = strict_json(unb64u(ch)), strict_json(unb64u(cp))
        sig_header = strict_json(unb64u(sh))
        unb64u(cs), unb64u(ss)
    except ValueError:
        raise Fail("malformed") from None
    if sp != "" or not all(isinstance(x, dict) for x in (cred_header, claims, sig_header)):
        raise Fail("malformed")

    # 8. the credential's header and issuer
    selector = cred_header.get("kid")
    if (
        cred_header.get("alg") != "EdDSA"
        or cred_header.get("typ") != "colophon-cred+jwt"
        or "crit" in cred_header
        or not isinstance(selector, str)
        or not LABEL.fullmatch(selector)
        or claims.get("iss") != host
    ):
        raise Fail("credential_invalid")

    # 9 to 11. the domain key. Nothing is cached here, so every lookup counts against the budget.
    name = f"{selector}._colophon.{host}"
    if arrival.dns_misses >= MISS_LIMIT:
        raise Fail("dns_limited")
    if name in arrival.dns and arrival.dns[name] is None:
        raise Fail("dns_error")
    key = domain_key(arrival.dns.get(name) or [])

    # 12. the credential's signature
    if not jws_check(ch, cp, cs, key):
        raise Fail("credential_invalid")

    # 13 to 15. the claims, the arrival time, the address
    public = agent_key(claims)
    if not claims["iat"] - SKEW <= t_arr <= claims["exp"] + GRACE:
        raise Fail("credential_expired")
    if claims["from"] != sender:
        raise Fail("from_mismatch")

    # 16, 17. the layout, then the signing input
    payload = jcs(signing_input(msg, credential))

    # 18, 19. the agent signature
    sig_iat, nonce = sig_header.get("iat"), sig_header.get("nonce")
    if (
        sig_header.get("alg") != "EdDSA"
        or sig_header.get("typ") != "colophon-sig"
        or "crit" in sig_header
        or not isinstance(nonce, str)
        or not NONCE.fullmatch(nonce)
        or not is_int(sig_iat)
        or sig_iat > min(claims["exp"], t_arr + SKEW)
    ):
        raise Fail("signature_invalid")
    if not jws_check(sh, b64u(payload), ss, public):
        raise Fail("signature_invalid")

    # 20. addressed to this mailbox
    listed = set(address_list(msg, "To")) | set(address_list(msg, "Cc"))
    if not listed & {canonical_addr_spec(a) for a in arrival.mailbox_addresses}:
        raise Fail("not_addressed")

    # 21. not verified before for this mailbox
    seen_key = (arrival.mailbox, host, claims["sub"], nonce)
    if not arrival.replay_store_available:
        raise Fail("replay_unchecked")  # never verified without the check
    if seen_key in arrival.seen:
        raise Fail("replay")
    arrival.seen.add(seen_key)

    agent = {"iss": host, "sub": claims["sub"], "from": sender, "principal": claims["principal"]}
    if "scope" in claims:
        agent["scope"] = claims["scope"]
    properties = {
        "from": sender,
        "sub": claims["sub"],
        "s": selector,
        "principal": claims["principal"]["mode"],
        "cred": sha256(credential.encode("ascii")),
    }
    return agent, properties


# ---------------------------------------------------------------- the draft's example


def test_key(label: str) -> Ed25519PrivateKey:
    """Deterministic test keys: never use these for anything but vectors."""
    seed = hashlib.sha256(f"colophon-v0 test key {label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


ISSUED = 1793865600  # 2026-11-05T08:00:00Z
SIGNED = ISSUED + 4500  # 2026-11-05T09:15:00Z
ARRIVED = ISSUED + 4510  # 2026-11-05T09:15:10Z
EXAMPLE_NONCE = "Zm9yLWV4YW1wbGUtb25seQ"
DOMAIN_KEY = test_key("domain acme.example s1")
AGENT_KEY = test_key("agent maple-tiger-27")
DNS_NAME = "s1._colophon.acme.example"
BOUNDARY = "=_colophon_example_1"


def example_claims(**patch: object) -> dict:
    """The example's claims. A patch value of None removes the claim."""
    claims = {
        "cnf": {"jwk": {"crv": "Ed25519", "kty": "OKP", "x": public_x(AGENT_KEY)}},
        "exp": ISSUED + MAX_LIFETIME,
        "from": "maple-tiger-27@acme.example",
        "iat": ISSUED,
        "iss": "acme.example",
        "principal": {"id": "p_Xk29", "mode": "pseudonymous"},
        "scope": "Books restaurant tables for one person, up to $500 per booking.",
        "sub": "ag_7Hq2",
    }
    for k, v in patch.items():
        if v is None:
            claims.pop(k, None)
        else:
            claims[k] = v
    return claims


def example_unsigned(subject: str = "Table for 2, Friday 7 November, 19:30") -> bytes:
    msg = EmailMessage()
    msg["From"] = "Booking agent <Maple-Tiger-27@acme.example>"
    msg["To"] = "Reservations <reservations@bistro.example>"
    msg["Subject"] = subject
    msg["Message-ID"] = "<example-1@acme.example>"
    msg["Date"] = "Thu, 05 Nov 2026 09:15:00 +0000"
    msg.set_content(
        "Hello,\n\nCould you hold a table for 2 this Friday, 7 November, at 19:30?\n"
        "One guest is vegetarian.\n\nThank you\n",
        charset="utf-8",
        cte="quoted-printable",
    )
    msg.add_attachment(
        b"date,time,party\n2026-11-07,19:30,2\n",
        maintype="text",
        subtype="csv",
        filename="booking.csv",
    )
    msg.set_boundary(BOUNDARY)
    return msg.as_bytes(policy=policy.SMTP)


def signed(
    claims: dict | None = None,
    unsigned: bytes | None = None,
    iat: int = SIGNED,
    credential: str | None = None,
    agent: SigningKey = AGENT_KEY,
) -> bytes:
    if credential is None:
        credential = issue_credential(DOMAIN_KEY, "s1", claims or example_claims())
    raw = unsigned or example_unsigned()
    return sign(raw, credential, agent, iat=iat, nonce=EXAMPLE_NONCE, strict=False)


def credential_with_payload(payload: bytes) -> str:
    """A credential over exact payload bytes, for vectors whose JSON JCS cannot produce."""
    h, p, s = jws_sign({"alg": "EdDSA", "kid": "s1", "typ": "colophon-cred+jwt"}, payload, DOMAIN_KEY)
    return f"{h}.{p}.{s}"


class Crafted:
    """Stands in for a private key: `sign` returns whatever signature a vector needs."""

    def __init__(self, sign: Callable[[bytes], bytes]) -> None:
        self.sign = sign


def ed_mul(n: int, point: Point) -> Point:
    out: Point = (0, 1, 1, 0)
    while n:
        if n & 1:
            out = add_points(out, point)
        point, n = add_points(point, point), n >> 1
    return out


def ed_encode(point: Point) -> bytes:
    x, y, z, _ = point
    zi = pow(z, ED_P - 2, ED_P)
    x, y = x * zi % ED_P, y * zi % ED_P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def base_point() -> Point:
    point = decode_point((4 * pow(5, ED_P - 2, ED_P) % ED_P).to_bytes(32, "little"))
    assert point is not None
    return point


ED_BASE = base_point()
IDENTITY = ed_encode((0, 1, 1, 0))  # a public key that every signature R = identity, S = 0 verifies under
ORDER_8 = bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")


def secret_scalar(key: Ed25519PrivateKey) -> int:
    """RFC 8032 §5.1.5: the scalar a, with A = aB."""
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    a = int.from_bytes(hashlib.sha512(seed).digest()[:32], "little")
    return (a & ((1 << 254) - 8)) | (1 << 254)


def agent_signature(r_point: Point, s_of: Callable[[int], int]) -> Crafted:
    """An agent signature with a chosen R, and S computed from k = SHA-512(R || A || M) mod L."""
    public = AGENT_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(data: bytes) -> bytes:
        r = ed_encode(r_point)
        k = int.from_bytes(hashlib.sha512(r + public + data).digest(), "little") % ED_L
        return r + (s_of(k) % ED_L).to_bytes(32, "little")

    return Crafted(sign)


def non_canonical_key() -> bytes:
    """The encoding y + p of a point of large order with a small y: decoders that reduce y accept it."""
    for y in range(2, 19):
        good = y.to_bytes(32, "little")
        if decode_point(good) is not None and not small_order(good):
            return (y + ED_P).to_bytes(32, "little")
    raise AssertionError


MAILBOX = {
    "mailbox": "mbx-reservations",
    "mailbox_addresses": {"reservations@bistro.example", "reservations+web@bistro.example"},
}


def arrival(seen: set, **changes: object) -> Arrival:
    base: dict = {
        "accepted_at": ARRIVED,
        "dkim_pass_domains": {"acme.example"},
        **MAILBOX,
        "dns": {DNS_NAME: [dns_record(DOMAIN_KEY)]},
        "envelope_recipient": "reservations@bistro.example",
    }
    return Arrival(**{**base, **changes}, seen=seen)


Step = tuple[dict, str]  # arrival changes, expected reason
Case = tuple[str, bytes, list[Step]]


# A split character, a language tag and another charset: a decoder would have to rule on each.
ODD_SUBJECT = b"=?utf-8?q?caf=C3?= =?utf-8?q?=A9?= =?utf-8*en?q?Table?= =?iso-8859-1?q?caf=E9?="


def vectors() -> list[Case]:
    raw = signed()
    crlf = b"\r\n"
    record = dns_record(DOMAIN_KEY)
    unsigned = example_unsigned()
    utf8_claims = example_claims(**{"from": "jos\u00e9@acme.example"})
    c_start = raw.index(b"c=")
    c_end = raw[raw.index(b";", c_start) - 7 : raw.index(b";", c_start) + 1]  # the end of c, then ";"

    def edit(old: bytes, new: bytes, data: bytes = raw) -> bytes:
        assert old in data, old
        return data.replace(old, new, 1)

    def before(field_name: bytes, line: bytes) -> bytes:
        return edit(field_name, line + crlf + field_name)

    def set_header(name: bytes, value: bytes, data: bytes = raw) -> bytes:
        start = data.index(name + b": ")
        end = data.index(crlf, start)
        return data[:start] + name + b": " + value + data[end:]

    def one(name: str, data: bytes, want: str, **changes: object) -> Case:
        return (name, data, [(changes, want)])

    def claims(name: str, want: str, **patch: object) -> Case:
        return one(name, signed(example_claims(**patch)), want)

    def dkim_field(i: bytes | None) -> bytes:
        tag = b"" if i is None else b" i=" + i + b";"
        start = b"DKIM-Signature: v=1; a=ed25519-sha256; d=acme.example; s=mail;"
        return start + tag + b" h=from:to; bh=AAAA; b=AAAA"

    def by_identity(name: str, fields: list[bytes], header_i: str, want: str) -> Case:
        data = b"".join(f + crlf for f in fields) + raw
        return one(name, data, want, dkim_pass_domains=set(), dkim_pass_identities={header_i})

    def dns(name: str, answers: list[str] | None, want: str) -> Case:
        return one(name, raw, want, dns={DNS_NAME: answers})

    payload = jcs(example_claims())
    attachment_part = b'Content-Type: text/csv\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="booking.csv"'
    rfc822_part = b"Content-Type: message/rfc822\r\nContent-Disposition: attachment"
    forwarded = b"From: a@partner.example\r\nSubject: hi\r\n\r\nhello\r\n"
    rfc822 = edit(
        b"ZGF0ZSx0aW1lLHBhcnR5CjIwMjYtMTEtMDcsMTk6MzAsMgo=",
        forwarded.rstrip(),
        edit(attachment_part, rfc822_part),
    )
    veg = "végétarien".encode()
    eight_bit = edit(b"vegetarian", veg, edit(b"quoted-printable", b"8bit", unsigned))
    surrogate = payload.replace(b'"sub":"ag_7Hq2"', b'"sub":"ag_\\ud800"')
    nonchar = payload.replace(b'"scope":"Books', '"scope":"￿Books'.encode())
    delimiter = f"--{BOUNDARY}\r\n".encode()
    close = f"--{BOUNDARY}--\r\n".encode()
    boundary_70 = (BOUNDARY + "x" * (70 - len(BOUNDARY))).encode()
    # Ed25519 (§6.5): keys and signatures that RFC 8032's equation alone lets through
    forge = Crafted(lambda data: IDENTITY + bytes(32))  # R = identity, S = 0
    identity_agent = example_claims(cnf={"jwk": {"crv": "Ed25519", "kty": "OKP", "x": b64u(IDENTITY)}})
    a = secret_scalar(AGENT_KEY)
    r = int.from_bytes(hashlib.sha256(b"colophon-v0 test r").digest(), "little") % ED_L
    order_8 = decode_point(ORDER_8)
    assert order_8 is not None and small_order(ORDER_8)

    def s_plus_l(data: bytes) -> bytes:
        sig = AGENT_KEY.sign(data)
        return sig[:32] + (int.from_bytes(sig[32:], "little") + ED_L).to_bytes(32, "little")

    other_mailbox = {
        "mailbox": "mbx-tables",
        "mailbox_addresses": {"tables@bistro.example", "reservations@bistro.example"},
    }
    return [
        (
            "replay: one mailbox, its alias, and a second mailbox",
            raw,
            [
                ({}, "verified"),
                ({}, "replay"),
                ({"envelope_recipient": "reservations+web@bistro.example"}, "replay"),
                ({**other_mailbox, "envelope_recipient": "tables@bistro.example"}, "verified"),
            ],
        ),
        # what does not change the verdict
        one("Colophon-Signature refolded in transit", edit(b";" + crlf + b" b=", b"; b="), "verified"),
        one("display name changed", edit(b"From: Booking agent", b"From: Bank"), "verified"),
        one("trailing spaces on a body line", edit(b"Thank you", b"Thank you  "), "verified"),
        one("charset name in capitals", edit(b'charset="utf-8"', b'charset="UTF-8"'), "verified"),
        one("attachment renamed (names are not signed)", edit(b"booking.csv", b"invoice.csv"), "verified"),
        one(
            "subject refolded in transit",
            edit(b"Subject: Table for 2,", b"Subject: Table for 2,\r\n "),
            "verified",
        ),
        one(
            "spaces in the subject collapsed",
            edit(b"Subject: Table for 2,", b"Subject:  Table  for 2,\t"),
            "verified",
        ),
        one(
            "encoded words that decoders disagree on, signed as sent (never decoded)",
            signed(unsigned=set_header(b"Subject", ODD_SUBJECT, example_unsigned())),
            "verified",
        ),
        one(
            "non-ASCII subject, as the signer encoded it",
            signed(unsigned=example_unsigned("Réservation pour 2, vendredi")),
            "verified",
        ),
        one("unrelated TXT beside the record", raw, "verified", dns={DNS_NAME: ["hello world", record]}),
        one(
            "a Colophon record with a duplicate tag beside the record",
            raw,
            "verified",
            dns={DNS_NAME: ["v=COLOPHON0; v=COLOPHON0; k=ed25519; p=", record]},
        ),
        one("arrived exactly at exp + grace", raw, "verified", accepted_at=ISSUED + MAX_LIFETIME + GRACE),
        one("signed 1 hour before the credential's iat", signed(iat=ISSUED - 3600), "verified"),
        one("body in 8bit with non-ASCII text", signed(unsigned=eight_bit), "verified"),
        one(
            "8-bit octets inside a quoted-printable body",
            signed(unsigned=edit(b"vegetarian", veg, unsigned)),
            "verified",
        ),
        one("lines end in LF alone", raw.replace(crlf, b"\n"), "verified"),
        one("a CR alone ends a body line", edit(b"vegetarian.\r\n", b"vegetarian.\r"), "verified"),
        one("empty display name in To", set_header(b"To", b"<reservations@bistro.example>"), "verified"),
        one("quoted-pair in the charset", edit(b'charset="utf-8"', b'charset="utf\\-8"'), "verified"),
        one("empty parameter items", edit(b'charset="utf-8"', b'; charset="utf-8";'), "verified"),
        one(
            "attachment name in RFC 2231 form",
            edit(b"Content-Type: text/csv", b"Content-Type: text/csv; name*=utf-8''r%C3%A9servation.csv"),
            "verified",
        ),
        one(
            "attachment parameter that does not parse (not read)",
            edit(b"Content-Type: text/csv", "Content-Type: text/csv; name=réservation csv".encode()),
            "verified",
        ),
        one("boundary of 70 characters", raw.replace(BOUNDARY.encode(), boundary_70), "verified"),
        one(
            "preamble and epilogue",
            edit(b"\r\n\r\n" + delimiter, b"\r\n\r\nThis is a multi-part message.\r\n" + delimiter)
            + b"Epilogue\r\n",
            "verified",
        ),
        one(
            "agent signature with another valid R (R need not be the RFC 8032 one)",
            signed(agent=agent_signature(ed_mul(r, ED_BASE), lambda k: r + k * a)),
            "verified",
        ),
        one(
            "a non-ASCII Colophon record beside the record (not a Colophon record)",
            raw,
            "verified",
            dns={DNS_NAME: ["v=COLOPHON0; k=ed25519; n=clé; p=", record]},
        ),
        one("19 DNS misses for the host this hour", raw, "verified", dns_misses=19),
        # covered content changed
        one("subject changed", edit(b"Subject: Table for 2", b"Subject: Table for 4"), "signature_invalid"),
        one(
            "subject re-encoded as an encoded word after signing",
            set_header(b"Subject", b"=?UTF-8?Q?Table_for_2=2C_Friday_7_November=2C_19=3A30?="),
            "signature_invalid",
        ),
        one("text changed", edit(b"for 2 this", b"for 4 this"), "signature_invalid"),
        one("Reply-To added", before(b"Subject:", b"Reply-To: x@evil.example"), "signature_invalid"),
        one("Cc added", before(b"Subject:", b"Cc: x@evil.example"), "signature_invalid"),
        one(
            "attachment changed",
            edit(b"MTk6MzAsMgo=", b"MTk6MzAsOAo="),
            "signature_invalid",
        ),
        one(
            "body starts with a BOM (a BOM is content)",
            edit(b"Hello,", b"=EF=BB=BFHello,"),
            "signature_invalid",
        ),
        # layout
        one("HTML part added", add_html(raw), "layout"),
        one("body in ISO-8859-1", edit(b'charset="utf-8"', b'charset="iso-8859-1"'), "layout"),
        one("charset alias utf8", edit(b'charset="utf-8"', b'charset="utf8"'), "layout"),
        one(
            "body marked format=flowed", edit(b'charset="utf-8"', b'charset="utf-8"; format=flowed'), "layout"
        ),
        one("unknown transfer encoding", edit(b"quoted-printable", b"x-uuencode"), "layout"),
        one("message/rfc822 attachment", rfc822, "layout"),
        one("charset in RFC 2231 form", edit(b'charset="utf-8"', b"charset*=utf-8''utf-8"), "layout"),
        one(
            "transfer encoding on the multipart",
            before(b"Content-Type: multipart", b"Content-Transfer-Encoding: base64"),
            "layout",
        ),
        # malformed
        one("second To field", before(b"Subject:", b"To: x@evil.example"), "malformed"),
        one("second Subject field", before(b"Message-ID:", b"Subject: Table for 8"), "malformed"),
        one(
            "second Content-Type in the body part",
            edit(
                b"Content-Transfer-Encoding: quoted-printable",
                b"Content-Type: text/plain; format=flowed\r\nContent-Transfer-Encoding: quoted-printable",
            ),
            "malformed",
        ),
        one("quoted local part in Cc", before(b"Subject:", b'Cc: "a b"@partner.example'), "malformed"),
        one("quoted local part in From", edit(b"<Maple-Tiger-27@", b'<"Maple-Tiger-27"@'), "malformed"),
        one("group in To", set_header(b"To", b"Team: reservations@bistro.example;"), "malformed"),
        one("domain literal in Cc", before(b"Subject:", b"Cc: bob@[192.0.2.1]"), "malformed"),
        one("non-ASCII domain in Cc", before(b"Subject:", "Cc: bob@café.example".encode()), "malformed"),
        one("comment in To", set_header(b"To", b"reservations@bistro.example (front desk)"), "malformed"),
        one(
            "unquoted @ in a display name",
            set_header(b"To", b"reservations@bistro.example <reservations@bistro.example>"),
            "malformed",
        ),
        one(
            "empty member in To",
            set_header(b"To", b"reservations@bistro.example, , x@bistro.example"),
            "malformed",
        ),
        one("invalid UTF-8 in the subject", set_header(b"Subject", b"Table for 2 \xff"), "malformed"),
        one("bad quoted-printable in the body", edit(b"Hello,", b"Hello=ZZ,"), "malformed"),
        one("bad base64 in the attachment", edit(b"MTk6MzAsMgo=", b"MTk6MzAs*go="), "malformed"),
        one("missing v tag", edit(b"Colophon-Signature: v=0;", b"Colophon-Signature:"), "malformed"),
        one(
            "tag name in capitals", edit(b"Colophon-Signature: v=0", b"Colophon-Signature: V=0"), "malformed"
        ),
        one("padded base64url in c", edit(c_end, c_end[:-1] + b"==;"), "malformed"),
        one(
            "a fraction in exp",
            signed(
                credential=credential_with_payload(
                    payload.replace(b'"exp":1793952000', b'"exp":1793952000.0')
                )
            ),
            "malformed",
        ),
        one(
            "a duplicate claim",
            signed(credential=credential_with_payload(payload.replace(b'"sub":', b'"sub":"x","sub":'))),
            "malformed",
        ),
        one(
            "credential over 2,048 octets",
            signed(example_claims(**{"example.com:pad": "x" * 1200})),
            "malformed",
        ),
        one("escaped surrogate in sub", signed(credential=credential_with_payload(surrogate)), "malformed"),
        one("noncharacter U+FFFF in scope", signed(credential=credential_with_payload(nonchar)), "malformed"),
        one("a CR alone in To", edit(b"To: Reservations", b"To: Reserv\rations"), "malformed"),
        one("a header line that is not a field", before(b"Subject:", b"X-Note"), "malformed"),
        one(
            "charset given twice", edit(b'charset="utf-8"', b'charset="utf-8"; charset=utf-8'), "malformed"
        ),
        one("a parameter without a value", edit(b'charset="utf-8"', b'charset="utf-8"; flowed'), "malformed"),
        one(
            "boundary given twice",
            edit(f'boundary="{BOUNDARY}"'.encode(), f'boundary="{BOUNDARY}"; boundary=x'.encode()),
            "malformed",
        ),
        one("boundary of 71 characters", raw.replace(BOUNDARY.encode(), boundary_70 + b"x"), "malformed"),
        one("no close delimiter", edit(close, b""), "malformed"),
        one("two delimiter lines in a row", edit(delimiter, delimiter + delimiter), "malformed"),
        one(
            "a line that starts with the delimiter",
            edit(b"Thank you", f"Thank you\r\n--{BOUNDARY}x".encode()),
            "malformed",
        ),
        one("a delimiter in the epilogue", raw + delimiter, "malformed"),
        # count, DKIM, version
        one("second Colophon-Signature", before(b"From:", b"Colophon-Signature: v=0"), "multiple_signatures"),
        one("no Colophon-Signature", raw[raw.index(b"From:") :], "no_signature"),
        one(
            "DKIM passes only for mail.acme.example",
            raw,
            "dkim_unaligned",
            dkim_pass_domains={"mail.acme.example"},
        ),
        one(
            "DKIM passes for mail.acme.example and acme.example",
            raw,
            "verified",
            dkim_pass_domains={"mail.acme.example", "acme.example"},
        ),
        one(
            "DKIM passes for two unaligned domains",
            raw,
            "dkim_unaligned",
            dkim_pass_domains={"mail.acme.example", "esp.example"},
        ),
        one("DKIM passes for ACME.EXAMPLE", raw, "verified", dkim_pass_domains={"ACME.EXAMPLE"}),
        by_identity(
            "DKIM reported by header.i only, i= with an encoded octet",
            [dkim_field(b"bookings=2Bagent@acme.example")],
            "bookings+agent@acme.example",
            "verified",
        ),
        by_identity(
            "DKIM reported by header.i only, i= with malformed quoted-printable",
            [dkim_field(b"bookings=2Gagent@acme.example")],
            "bookings=2Gagent@acme.example",
            "dkim_unaligned",
        ),
        by_identity(
            "DKIM reported by header.i only, no i=, domain in another case",
            [dkim_field(None)],
            "@Acme.Example",
            "verified",
        ),
        by_identity(
            "DKIM reported by header.i only, two fields with that identity",
            [dkim_field(None), dkim_field(None)],
            "@acme.example",
            "dkim_unaligned",
        ),
        by_identity(
            "DKIM reported by header.i only, beside a field whose tags do not parse",
            [dkim_field(b"@acme.example") + b"; x", dkim_field(b"@acme.example")],
            "@acme.example",
            "verified",
        ),
        one("v=1", edit(b"Colophon-Signature: v=0", b"Colophon-Signature: v=1"), "unsupported_version"),
        # DNS
        dns("DNS lookup failed", None, "dns_error"),
        one("no record at the selector", raw, "key_not_found", dns={}),
        dns("two Colophon records", [record, dns_record(test_key("other"))], "key_not_found"),
        dns(
            "a k=rsa Colophon record beside the record",
            [record, "v=COLOPHON0; k=rsa; p=AAAA"],
            "key_not_found",
        ),
        dns("record without p", ["v=COLOPHON0; k=ed25519"], "key_not_found"),
        dns("key of the wrong length", ["v=COLOPHON0; k=ed25519; p=AAAA"], "key_not_found"),
        dns("key in padded base64", [record + "="], "key_not_found"),
        dns("record with empty p=", ["v=COLOPHON0; k=ed25519; p="], "key_revoked"),
        dns("the record with a non-ASCII tag added", [record + "; n=clé"], "key_not_found"),
        one(
            "domain key is the identity point (every credential verifies under it)",
            signed(credential=issue_credential(forge, "s1", example_claims())),
            "key_not_found",
            dns={DNS_NAME: [f"v=COLOPHON0; k=ed25519; p={b64u(IDENTITY)}"]},
        ),
        dns(
            "domain key of 32 zero octets (small order)",
            [f"v=COLOPHON0; k=ed25519; p={b64u(bytes(32))}"],
            "key_not_found",
        ),
        dns(
            "domain key not in canonical encoding",
            [f"v=COLOPHON0; k=ed25519; p={b64u(non_canonical_key())}"],
            "key_not_found",
        ),
        one("20 DNS misses for the host this hour", raw, "dns_limited", dns_misses=20),
        dns("record holds a different key", [dns_record(test_key("other"))], "credential_invalid"),
        # credential contents
        claims("iss in capitals", "credential_invalid", iss="ACME.EXAMPLE"),
        claims("sub with a trailing newline", "credential_invalid", sub="ag_7Hq2\n"),
        claims("sub as a number", "credential_invalid", sub=12345),
        claims("no from claim", "credential_invalid", **{"from": None}),
        claims(
            "from claim not in canonical form",
            "credential_invalid",
            **{"from": "Maple-Tiger-27@acme.example"},
        ),
        claims("lifetime of 25 hours", "credential_invalid", exp=ISSUED + 25 * 3600),
        claims("bidi control in scope", "credential_invalid", scope="Books tables \u202eFOR FREE"),
        claims(
            "agent key of 31 octets",
            "credential_invalid",
            cnf={"jwk": {"crv": "Ed25519", "kty": "OKP", "x": b64u(b"\x01" * 31)}},
        ),
        one(
            "agent key is the identity point (every signature verifies under it)",
            signed(identity_agent, agent=forge),
            "credential_invalid",
        ),
        one("agent signature with S + L in place of S", signed(agent=Crafted(s_plus_l)), "signature_invalid"),
        one(
            "agent signature with R the identity point",
            signed(agent=agent_signature((0, 1, 1, 0), lambda k: k * a)),
            "signature_invalid",
        ),
        one(
            "agent signature that only a cofactored check accepts",
            signed(agent=agent_signature(add_points(ed_mul(r, ED_BASE), order_8), lambda k: r + k * a)),
            "signature_invalid",
        ),
        # time and address
        one(
            "arrived 1 second after exp + grace",
            raw,
            "credential_expired",
            accepted_at=ISSUED + MAX_LIFETIME + GRACE + 1,
        ),
        one(
            "From is another address on the same host",
            edit(b"<Maple-Tiger-27@", b"<oak-fox-11@"),
            "from_mismatch",
        ),
        one(
            "SMTPUTF8 local part, ASCII letters lowercased",
            signed(
                utf8_claims, set_header(b"From", "Booking agent <Jos\u00e9@acme.example>".encode(), unsigned)
            ),
            "verified",
        ),
        one(
            "SMTPUTF8 local part with non-ASCII in another case",
            signed(
                utf8_claims, set_header(b"From", "Booking agent <JOS\u00c9@acme.example>".encode(), unsigned)
            ),
            "from_mismatch",
        ),
        one("signature iat 10 minutes after arrival", signed(iat=ARRIVED + 600), "signature_invalid"),
        one(
            "delivered to a mailbox not in To or Cc (Bcc)",
            raw,
            "not_addressed",
            mailbox="mbx-x",
            mailbox_addresses={"x@bistro.example"},
            envelope_recipient="x@bistro.example",
        ),
        one("replay store unavailable", raw, "replay_unchecked", replay_store_available=False),
    ]


def add_html(raw: bytes) -> bytes:
    end = f"--{BOUNDARY}--".encode()
    html = f"--{BOUNDARY}\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Table for 8</p>\r\n"
    return raw.replace(end, html.encode() + end)


def run(cases: list[Case]) -> list[tuple[str, int, str, str]]:
    """Run every step of every case. A case's steps share one replay store."""
    results = []
    for name, data, steps in cases:
        seen: set = set()
        for n, (changes, want) in enumerate(steps):
            got = verify(data, arrival(seen, **changes)).reason
            results.append((name, n, want, got))
    return results


def vector_json(cases: list[Case]) -> list[dict]:
    out = []
    for name, data, steps in cases:
        deliveries = []
        seen: set = set()
        for changes, want in steps:
            a = arrival(set(), **changes)
            report = authentication_results(verify(data, arrival(seen, **changes)))
            deliveries.append(
                {
                    "accepted_at": a.accepted_at,
                    "dkim_pass_domains": sorted(a.dkim_pass_domains),
                    "dkim_pass_identities": sorted(a.dkim_pass_identities),
                    "envelope_recipient": a.envelope_recipient,
                    "mailbox": a.mailbox,
                    "mailbox_addresses": sorted(a.mailbox_addresses),
                    "dns_txt": a.dns,
                    "dns_misses": a.dns_misses,
                    "replay_store_available": a.replay_store_available,
                    "expected": want,
                    "expected_authentication_results": report,
                }
            )
        out.append({"name": name, "message": base64.b64encode(data).decode(), "deliveries": deliveries})
    return out


def print_example() -> None:
    raw = signed()
    parsed = parse_part(raw)
    value = tags(raw_values(parsed, HEADER)[0])
    credential = value["c"]
    print("## DNS\n")
    print(f'{DNS_NAME}. TXT "{dns_record(DOMAIN_KEY)}"\n')
    print("## Credential protected header\n")
    print(unb64u(credential.split(".")[0]).decode(), "\n")
    print("## Credential claims\n")
    print(json.dumps(strict_json(unb64u(credential.split(".")[1])), indent=2), "\n")
    print("## Credential (compact)\n")
    print(credential, "\n")
    print("## Signing input (JCS, one line)\n")
    print(jcs(signing_input(parsed, credential)).decode(), "\n")
    print("## Agent signature (tag b)\n")
    print(value["b"], "\n")
    print("## Message as sent, before the issuer's DKIM signature\n")
    print(raw.decode().replace("\r\n", "\n"))
    print("## Authentication-Results method result at mbx-reservations (§7.8)\n")
    print(authentication_results(verify(raw, arrival(set()))), "\n")


def main() -> int:
    cases = vectors()
    if "--json" in sys.argv:
        doc = {
            "about": "Colophon v0 test vectors. Each message is base64 of the octets as accepted. "
            "Deliveries run in order and share one replay store; a missing DNS name is "
            "NXDOMAIN, null is a failed lookup, and a TXT string stands for its UTF-8 octets. "
            "dkim_pass_identities holds the header.i of each passing DKIM signature reported "
            "without header.d, whose d= the verifier recovers from the message (section 7.1). "
            "dns_misses counts the From host's misses this hour before the delivery, with no "
            "key cached (section 7.4); replay_store_available false means the replay store "
            "cannot be read or written (section 7.6). expected_authentication_results is the "
            "colophon resinfo of section 7.8, unfolded.",
            "cases": vector_json(cases),
        }
        print(json.dumps(doc, indent=1, ensure_ascii=False))
        return 0
    if "--example" in sys.argv:
        print_example()
    failed = 0
    for name, n, want, got in run(cases):
        ok = got == want
        failed += not ok
        label = name if n == 0 else f"  ... delivery {n + 1}"
        print(f"{'ok  ' if ok else 'FAIL'}  {want:<20} {label}" + ("" if ok else f"  (got {got})"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
