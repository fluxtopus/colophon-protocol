"""Encodings Colophon uses: strict base64url (§2), MIME base64 (§6.4), I-JSON (§5.1) and JCS.

Every decoder here is a single linear pass or a library call on bounded input. None of them
raises anything but ``ValueError``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping, Sequence

MAX_SAFE_INT = 2**53 - 1

_B64URL_ALPHABET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_B64_ALPHABET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
_MIME_B64_SPACE = b" \t\r\n"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Strict base64url (§2): the URL-safe alphabet, no padding, unused bits zero."""
    raw = text.encode("ascii", "strict") if text.isascii() else None
    if raw is None or len(raw) % 4 == 1 or not _B64URL_ALPHABET.issuperset(raw):
        raise ValueError("not base64url")
    data = base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
    if b64url_encode(data).encode("ascii") != raw:
        raise ValueError("base64url with unused bits set")
    return data


def b64url_sha256(data: bytes) -> str:
    return b64url_encode(hashlib.sha256(data).digest())


def mime_base64_decode(data: bytes) -> bytes:
    """§6.4: drop SP, HTAB, CR and LF, then RFC 4648 §4 with padding. Unused bits are ignored."""
    compact = data.translate(None, _MIME_B64_SPACE)
    body = compact.rstrip(b"=")
    if len(compact) % 4 or len(compact) - len(body) > 2 or not _B64_ALPHABET.issuperset(body):
        raise ValueError("invalid base64")
    try:
        return base64.b64decode(compact, validate=True)
    except binascii.Error as exc:  # pragma: no cover - excluded by the checks above
        raise ValueError("invalid base64") from exc


# ---------------------------------------------------------------- I-JSON


def _reject_float(text: str) -> object:
    raise ValueError(f"JSON number is not an integer: {text[:16]}")


def _safe_int(text: str) -> int:
    value = int(text)
    if abs(value) > MAX_SAFE_INT:
        raise ValueError("JSON integer out of range")
    return value


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for name, value in pairs:
        if name in out:
            raise ValueError("duplicate JSON member name")
        out[name] = value
    return out


def _is_noncharacter(cp: int) -> bool:
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


def _check_ijson_string(text: str) -> None:
    """RFC 7493 §2.1: no surrogate or noncharacter code points, escaped or not."""
    for ch in text:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF or _is_noncharacter(cp):
            raise ValueError("JSON string holds a surrogate or a noncharacter")


def parse_ijson(data: bytes) -> object:
    """Parse I-JSON (RFC 7493) as §5.1 makes it exact. ValueError otherwise.

    Member names are unique; numbers are integers within +/-(2^53 - 1) written without a fraction
    or exponent; strings hold no surrogates or noncharacters. The input is UTF-8 without a BOM.
    """
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_members,
            parse_float=_reject_float,
            parse_int=_safe_int,
            parse_constant=_reject_float,
        )
    except RecursionError as exc:
        raise ValueError("JSON nested too deeply") from exc
    except UnicodeDecodeError as exc:
        raise ValueError("JSON is not UTF-8") from exc
    # json.loads raises JSONDecodeError (a ValueError) for everything else.
    stack: list[object] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            _check_ijson_string(item)
        elif isinstance(item, dict):
            for name, member in item.items():
                _check_ijson_string(name)
                stack.append(member)
        elif isinstance(item, list):
            stack.extend(item)
    return value


def jcs(value: object) -> bytes:
    """RFC 8785 for the JSON Colophon uses: objects, arrays, strings, integers, booleans, null.

    Raises ValueError for anything else, including floats and integers outside I-JSON's range.
    Python's json module writes strings exactly as RFC 8785 §3.2.2.2 requires when
    ``ensure_ascii`` is off; member names sort by UTF-16 code units as §3.2.3 requires.
    """
    out: list[str] = []
    # An explicit stack keeps deep values from exhausting the interpreter stack.
    work: list[object] = [value]
    while work:
        item = work.pop()
        if isinstance(item, _Literal):
            out.append(item.text)
        elif item is None:
            out.append("null")
        elif item is True:
            out.append("true")
        elif item is False:
            out.append("false")
        elif isinstance(item, int):
            if abs(item) > MAX_SAFE_INT:
                raise ValueError("integer out of I-JSON range")
            out.append(str(item))
        elif isinstance(item, str):
            _check_encodable(item)
            out.append(json.dumps(item, ensure_ascii=False))
        elif isinstance(item, Mapping):
            names = list(item.keys())
            if not all(isinstance(n, str) for n in names):
                raise ValueError("JSON member names must be strings")
            names.sort(key=lambda n: n.encode("utf-16-be"))
            pending: list[object] = [_Literal("{")]
            for i, name in enumerate(names):
                _check_encodable(name)
                prefix = "," if i else ""
                pending.append(_Literal(prefix + json.dumps(name, ensure_ascii=False) + ":"))
                pending.append(item[name])
            pending.append(_Literal("}"))
            work.extend(reversed(pending))
        elif isinstance(item, Sequence) and not isinstance(item, (bytes, bytearray)):
            pending = [_Literal("[")]
            for i, member in enumerate(item):
                if i:
                    pending.append(_Literal(","))
                pending.append(member)
            pending.append(_Literal("]"))
            work.extend(reversed(pending))
        else:
            raise ValueError(f"cannot serialize {type(item).__name__} as JCS")
    return "".join(out).encode("utf-8")


class _Literal:
    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text


def _check_encodable(text: str) -> None:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("string holds a lone surrogate") from exc


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def ascii_lower(text: str) -> str:
    """Lowercase A to Z only, as Colophon compares hosts and addresses (§6.4)."""
    return text.translate(_ASCII_LOWER)
