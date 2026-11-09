"""Authentication-Results (RFC 8601), as far as the test needs it: which DKIM signatures the
receiver's own boundary server saw pass, and for which `d=`.

The parser is lenient about what it ignores and strict about what it uses. Comments in parentheses
are removed, quoted strings are honoured, and each `method=result` with its `ptype.pname=value`
properties is kept. Fields with a `none` result have no methods."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.message import Message

FIELD = "Authentication-Results"


@dataclass(frozen=True)
class MethodResult:
    method: str
    result: str
    properties: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthRes:
    authserv_id: str
    results: tuple[MethodResult, ...]

    def dkim_pass_domains(self) -> set[str]:
        """The `d=` of every DKIM pass. When a receiver reports only `header.i`, its domain is
        taken from the part after `@` (RFC 8601 section 2.7.1 lets either stand for the signer)."""
        out: set[str] = set()
        for r in self.results:
            if r.method != "dkim" or r.result != "pass":
                continue
            domain = r.properties.get("header.d")
            if not domain:
                i = r.properties.get("header.i", "")
                domain = i.rpartition("@")[2] if i else ""
            if domain:
                out.add(domain.rstrip(".").lower())
        return out


def strip_comments(value: str) -> str:
    """Remove CFWS comments, nested, honouring quoted strings and backslash escapes."""
    out: list[str] = []
    depth = 0
    quoted = escaped = False
    for ch in value:
        if quoted:
            if depth == 0:
                out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
            continue
        if ch == '"' and depth == 0:
            quoted = True
            out.append(ch)
        elif ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def _split_semicolons(value: str) -> list[str]:
    items, cur, quoted, escaped = [], [], False, False
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
            cur.append(ch)
        elif ch == ";":
            items.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    items.append("".join(cur))
    return [i.strip() for i in items if i.strip()]


_TOKEN = r"[^\s=;\"]+"
_VALUE = r'(?:"(?:[^"\\]|\\.)*"|[^\s;"]+)'
_METHOD = re.compile(rf"^({_TOKEN}?)(?:/\d+)?\s*=\s*({_TOKEN})(.*)$", re.DOTALL)
_PROPERTY = re.compile(rf"([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\s*=\s*({_VALUE})")


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return re.sub(r"\\(.)", r"\1", value[1:-1])
    return value


def parse(value: str) -> AuthRes:
    """One Authentication-Results field value. Raises ValueError when there is no authserv-id."""
    text = re.sub(r"\s+", " ", strip_comments(value.replace("\r\n", "")))
    items = _split_semicolons(text)
    if not items:
        raise ValueError("empty Authentication-Results")
    authserv = items[0].split()[0].strip().rstrip(".").lower()
    results: list[MethodResult] = []
    for item in items[1:]:
        if item.lower() == "none":
            continue
        m = _METHOD.match(item)
        if not m:
            continue  # not a resinfo this parser understands; ignored
        method, result, rest = m.group(1).lower(), m.group(2).lower(), m.group(3)
        props = {k.lower(): _unquote(v) for k, v in _PROPERTY.findall(rest)}
        results.append(MethodResult(method, result, props))
    return AuthRes(authserv, tuple(results))


def fields(msg: Message) -> list[AuthRes]:
    """Every Authentication-Results field of the message, topmost first, unparsable ones skipped."""
    out = []
    for key, value in msg.raw_items():
        if key.lower() != FIELD.lower():
            continue
        try:
            out.append(parse(str(value)))
        except ValueError:
            continue
    return out


@dataclass(frozen=True)
class ReceiverResults:
    authserv_id: str  # the authserv-id the harness took as the receiver's own
    considered: tuple[AuthRes, ...]
    dkim_pass_domains: frozenset[str]
    note: str = ""


def receiver_results(msg: Message, authserv_ids: list[str] | None = None) -> ReceiverResults:
    """The receiver's own results (spec section 7.1, input 3).

    With `authserv_ids`, only fields whose authserv-id equals one of them, or ends with one of them
    after a dot, count. Without, the topmost field is the receiver's: the boundary server adds its
    field above everything that came with the message. Fields with the same authserv-id below it
    count too, because some receivers add one per check."""
    all_fields = fields(msg)
    if not all_fields:
        return ReceiverResults("", (), frozenset(), "no Authentication-Results field")
    if authserv_ids:
        wanted = [a.lower() for a in authserv_ids]

        def ours(ar: AuthRes) -> bool:
            return any(ar.authserv_id == w or ar.authserv_id.endswith("." + w) for w in wanted)

        chosen = [ar for ar in all_fields if ours(ar)]
        note = (
            ""
            if chosen
            else f"no field from {', '.join(authserv_ids)}; topmost is {all_fields[0].authserv_id}"
        )
    else:
        chosen = [ar for ar in all_fields if ar.authserv_id == all_fields[0].authserv_id]
        note = "authserv-id taken from the topmost field"
    domains: set[str] = set()
    for ar in chosen:
        domains |= ar.dkim_pass_domains()
    authserv = chosen[0].authserv_id if chosen else ""
    return ReceiverResults(authserv, tuple(chosen), frozenset(domains), note)
