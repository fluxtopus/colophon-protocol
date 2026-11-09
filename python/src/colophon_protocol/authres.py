"""Reading DKIM results from an ``Authentication-Results`` header field (RFC 8601).

Only trust a field your own border added: match ``authserv_id`` to it, and make sure the border
removes fields with that ID from incoming mail (RFC 8601 §5). Anything else is the sender's text.
"""

from __future__ import annotations

from colophon_protocol._codec import ascii_lower

__all__ = ["dkim_pass_domains"]

_MAX_VALUE = 64 * 1024
_SPACE = " \t\r\n"


def _tighten_equals(value: str) -> str:
    """Drop whitespace on either side of every ``=`` (CFWS is allowed there). One pass."""
    out: list[str] = []
    pending: list[str] = []
    skip = False
    for ch in value:
        if ch in _SPACE:
            if not skip:
                pending.append(ch)
            continue
        if ch == "=":
            pending.clear()
            out.append(ch)
            skip = True
            continue
        out.extend(pending)
        pending.clear()
        out.append(ch)
        skip = False
    out.extend(pending)
    return "".join(out)


def _strip_comments(value: str) -> str:
    """Remove RFC 5322 comments, nested, outside quoted strings. Linear; unbalanced is ``""``."""
    out: list[str] = []
    depth = 0
    quoted = escaped = False
    for ch in value:
        if escaped:
            escaped = False
            if depth == 0:
                out.append(ch)
            continue
        if ch == "\\" and (quoted or depth):
            escaped = True
            if depth == 0:
                out.append(ch)
            continue
        if quoted:
            out.append(ch)
            if ch == '"':
                quoted = False
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                return ""
            depth -= 1
        elif depth == 0:
            if ch == '"':
                quoted = True
            out.append(ch)
    return "" if depth or quoted else "".join(out)


def _split(value: str, sep: str) -> list[str]:
    """Split at ``sep`` outside quoted strings."""
    items: list[str] = []
    current: list[str] = []
    quoted = escaped = False
    for ch in value:
        if escaped:
            escaped = False
        elif ch == "\\" and quoted:
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif ch == sep and not quoted:
            items.append("".join(current))
            current = []
            continue
        current.append(ch)
    items.append("".join(current))
    return items


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        inner, out, i = value[1:-1], [], 0
        while i < len(inner):
            if inner[i] == "\\" and i + 1 < len(inner):
                i += 1
            out.append(inner[i])
            i += 1
        return "".join(out)
    return value


def dkim_pass_domains(
    value: str, *, authserv_id: str, use_header_i: bool = False
) -> frozenset[str]:
    """The ``header.d`` of every ``dkim=pass`` result, lowercased, from one field's value.

    Returns an empty set when the field's authserv-id is not ``authserv_id``, or the value does
    not parse. ``use_header_i`` also reads the domain of ``header.i``, for servers (Gmail among
    them) that report only that; the i= domain may be a subdomain of d=, so prefer ``header.d``.
    """
    if len(value) > _MAX_VALUE:
        return frozenset()
    items = _split(_tighten_equals(_strip_comments(value)), ";")
    head = items[0].split()
    if not head or ascii_lower(head[0]) != ascii_lower(authserv_id):
        return frozenset()
    found: set[str] = set()
    for item in items[1:]:
        words = item.split()
        if not words:
            continue
        method, eq, result = words[0].partition("=")
        if not eq or ascii_lower(method.split("/")[0]) != "dkim" or ascii_lower(result) != "pass":
            continue
        props: dict[str, str] = {}
        for word in words[1:]:
            name, eq, prop = word.partition("=")
            if eq:
                props.setdefault(ascii_lower(name), _unquote(prop))
        domain = props.get("header.d")
        if domain is None and use_header_i and "header.i" in props:
            domain = props["header.i"].rpartition("@")[2]
        if domain:
            found.add(ascii_lower(domain))
    return frozenset(found)
