"""Address lists in the strict RFC 5322 subset of §6.4. Hand-written scanners, linear time."""

from __future__ import annotations

from colophon_protocol._codec import ascii_lower

# atext (RFC 5322 §3.2.3)
_ATEXT = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-/=?^_`{|}~"
)
_LDH = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-")
_SPECIALS_OUTSIDE_QUOTES = frozenset("():;[]\\")


class AddressError(ValueError):
    """The value is outside §6.4's subset. The message is malformed."""


def _is_atom_char(ch: str) -> bool:
    return ch in _ATEXT or ord(ch) > 0x7F


def _valid_dot_atom(text: str) -> bool:
    """A dot-atom of atext and non-ASCII characters (RFC 6532)."""
    if not text:
        return False
    previous_dot = True  # no leading dot
    for ch in text:
        if ch == ".":
            if previous_dot:
                return False
            previous_dot = True
        elif _is_atom_char(ch):
            previous_dot = False
        else:
            return False
    return not previous_dot  # no trailing dot


def _valid_domain(text: str) -> bool:
    """Two or more LDH labels of 1 to 63 ASCII characters, no hyphen at either end."""
    labels = text.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not 1 <= len(label) <= 63 or label[0] == "-" or label[-1] == "-":
            return False
        if not all(ch in _LDH for ch in label):
            return False
    return True


def canonical_addr_spec(addr: str) -> str:
    """§6.4 items 3 and 5: validate ``local@domain`` and lowercase its ASCII letters."""
    local, at, domain = addr.rpartition("@")
    if not at or not _valid_dot_atom(local) or not _valid_domain(domain):
        raise AddressError("not an addr-spec in the v0 subset")
    return f"{ascii_lower(local)}@{ascii_lower(domain)}"


def valid_canonical_address(addr: str) -> bool:
    """True when ``addr`` is an addr-spec already in canonical form (the ``from`` claim)."""
    try:
        return canonical_addr_spec(addr) == addr
    except AddressError:
        return False


def _valid_display_name(text: str) -> bool:
    """§6.4 item 2: atext, '.', SP, HTAB, non-ASCII characters and quoted strings."""
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            i += 1
            while True:
                if i >= n:
                    return False
                ch = text[i]
                if ch == "\\":
                    if i + 1 >= n or text[i + 1] in "\r\n":
                        return False
                    i += 2
                    continue
                if ch in "\r\n":
                    return False
                i += 1
                if ch == '"':
                    break
            continue
        if not (_is_atom_char(ch) or ch in ". \t"):
            return False
        i += 1
    return True


def _split_mailboxes(value: str) -> list[str]:
    """Split at top-level commas, rejecting the syntax §6.4 item 4 rules out.

    Outside quoted strings: ``( ) : ; [ ] \\`` are malformed, as is any ``<`` or ``>`` beyond one
    pair per mailbox.
    """
    items: list[str] = []
    start = 0
    quoted = escaped = in_angle = False
    pairs = 0
    for i, ch in enumerate(value):
        if quoted:
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
            if in_angle or pairs:
                raise AddressError("more than one '<' in a mailbox")
            in_angle = True
        elif ch == ">":
            if not in_angle:
                raise AddressError("'>' without '<'")
            in_angle = False
            pairs = 1
        elif ch in _SPECIALS_OUTSIDE_QUOTES:
            raise AddressError(f"{ch!r} outside a quoted string")
        elif ch == "," and not in_angle:
            items.append(value[start:i])
            start = i + 1
            pairs = 0
    if quoted or in_angle:
        raise AddressError("unterminated quoted string or angle bracket")
    items.append(value[start:])
    return [item.strip(" \t") for item in items]


def _canonical_mailbox(item: str) -> str:
    if not item:
        raise AddressError("empty member in an address list")
    if item.endswith(">"):
        i = item.find("<")
        if i < 0 or not _valid_display_name(item[:i]):
            raise AddressError("display name outside the v0 subset")
        return canonical_addr_spec(item[i + 1 : -1])
    return canonical_addr_spec(item)


def canonical_address_list(value: str) -> list[str]:
    """§6.4 items 1 to 6: the canonical addresses of one header value, in order, deduplicated."""
    seen: dict[str, None] = {}
    for item in _split_mailboxes(value):
        seen.setdefault(_canonical_mailbox(item), None)
    return list(seen)
