"""The small grammars of §4.1, §5 and §6.5, as character-set checks rather than regexes."""

from __future__ import annotations

_LOWER_LDH = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_AGENT_ID = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_TAG_FIRST = frozenset("abcdefghijklmnopqrstuvwxyz")
_TAG_REST = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_")

# §5.4: C0, DEL, C1 and the bidirectional controls.
_FORBIDDEN = frozenset(
    [chr(c) for c in range(0x20)]
    + [chr(c) for c in range(0x7F, 0xA0)]
    + [chr(0x061C), chr(0x200E), chr(0x200F)]
    + [chr(c) for c in range(0x202A, 0x202F)]
    + [chr(c) for c in range(0x2066, 0x206A)]
)

MAX_SCOPE_BYTES = 280
MAX_NAME_BYTES = 128


def is_selector(text: str) -> bool:
    """§4.1: ``[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?``."""
    return (
        1 <= len(text) <= 63
        and text[0] != "-"
        and text[-1] != "-"
        and all(ch in _LOWER_LDH for ch in text)
    )


def is_agent_id(text: str) -> bool:
    """§5.1 ``sub`` and §5.3 pseudonym ``id``: ``[A-Za-z0-9._-]{1,64}``."""
    return 1 <= len(text) <= 64 and all(ch in _AGENT_ID for ch in text)


def is_nonce(text: str) -> bool:
    """§6.5: ``[A-Za-z0-9_-]{16,64}``."""
    return 16 <= len(text) <= 64 and all(ch in _B64URL for ch in text)


def is_tag_name(text: str) -> bool:
    """§6.2: ``[a-z][a-z0-9_]*``."""
    return bool(text) and text[0] in _TAG_FIRST and all(ch in _TAG_REST for ch in text[1:])


def is_plain_text(value: object, limit: int) -> bool:
    """§5.4: a string of 1 to ``limit`` UTF-8 octets without the forbidden characters."""
    if not isinstance(value, str) or not value or _FORBIDDEN.intersection(value):
        return False
    try:
        return len(value.encode("utf-8")) <= limit
    except UnicodeEncodeError:  # a lone surrogate
        return False


def is_int(value: object) -> bool:
    """A JSON integer. ``bool`` is a subclass of ``int`` in Python and is not one."""
    return type(value) is int


_WHITESPACE = {ord(" "): None, ord("\t"): None, ord("\r"): None, ord("\n"): None}


def remove_whitespace(text: str) -> str:
    """§6.2: SP, HTAB, CR and LF are removed before a tag list is parsed."""
    return text.translate(_WHITESPACE)


def parse_tags(text: str) -> dict[str, str]:
    """§6.2 tag list, whitespace already removed. ValueError if it does not parse."""
    out: dict[str, str] = {}
    for item in text.split(";"):
        if not item:
            continue
        name, eq, value = item.partition("=")
        if not eq or not is_tag_name(name) or name in out:
            raise ValueError("not a tag list")
        out[name] = value
    return out
