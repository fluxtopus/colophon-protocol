"""The ``Authentication-Results`` header field (RFC 8601): reading DKIM, reporting Colophon.

Reading: :func:`dkim_pass_domains` takes the DKIM results your own server reported. Only trust a
field your own border added: match ``authserv_id`` to it, and make sure the border removes fields
with that ID from incoming mail (RFC 8601 §5). Anything else is the sender's text. A passing
signature counts for its ``d=`` (§7.1); :func:`dkim_identity_domain` recovers that ``d=`` from
the message when the server reports only ``header.i``.

Reporting (§7.8): :func:`colophon_resinfo` writes a verdict as the ``colophon`` method's result,
and :func:`authentication_results` writes the whole field value under your authserv-id. Both are
pure functions of the verdict: no I/O, no clock.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from colophon_protocol._codec import ascii_lower

if TYPE_CHECKING:
    from colophon_protocol.model import Verdict

__all__ = [
    "ColophonResult",
    "authentication_results",
    "colophon_resinfo",
    "colophon_result",
    "dkim_identity_domain",
    "dkim_pass_domains",
]

_MAX_VALUE = 64 * 1024
_SPACE = " \t\r\n"


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


@dataclass(frozen=True, slots=True)
class _Token:
    """A lexical item of an Authentication-Results value: ``;``, ``=``, or a value."""

    kind: Literal[";", "=", "value"]
    text: str  # a quoted string's content, unescaped; otherwise as written
    raw: str  # as written, quotes included
    spaced: bool  # whitespace or a comment comes before it


_VALUE_STOP = frozenset(' \t\r\n();="')


def _lex(value: str) -> list[_Token] | None:
    """Split a value into tokens by RFC 8601 §2.2: comments are whitespace, a quoted string is
    one value, and ``;`` and ``=`` stand alone. None when a comment or a quoted string does not
    close, a ``)`` has no ``(``, or a control character is outside a quoted string. Linear."""
    tokens: list[_Token] = []
    i, n = 0, len(value)
    spaced = False
    while i < n:
        ch = value[i]
        if ch in " \t\r\n":
            spaced = True
            i += 1
        elif ch == "(":
            depth = 0
            while True:
                if i >= n:
                    return None
                c = value[i]
                if c == "\\":
                    i += 2
                    continue
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            spaced = True
        elif ch == ")":
            return None
        elif ch in ";=":
            tokens.append(_Token(";" if ch == ";" else "=", ch, ch, spaced))
            spaced = False
            i += 1
        elif ch == '"':
            start, out = i, []
            i += 1
            while True:
                if i >= n:
                    return None
                c = value[i]
                if c == "\\":
                    if i + 1 >= n:
                        return None
                    out.append(value[i + 1])
                    i += 2
                    continue
                i += 1
                if c == '"':
                    break
                if c not in "\r\n":  # a folded line end inside the string is removed
                    out.append(c)
            tokens.append(_Token("value", "".join(out), value[start:i], spaced))
            spaced = False
        else:
            start = i
            while i < n and value[i] not in _VALUE_STOP:
                if _has_control(value[i]):
                    return None
                i += 1
            tokens.append(_Token("value", value[start:i], value[start:i], spaced))
            spaced = False
    return tokens


def _split_tokens(tokens: list[_Token]) -> list[list[_Token]]:
    groups: list[list[_Token]] = [[]]
    for token in tokens:
        if token.kind == ";":
            groups.append([])
        else:
            groups[-1].append(token)
    return groups


def _is_own_field(head: list[_Token], authserv_id: str) -> bool:
    """The authserv-id is ``authserv_id``, ignoring ASCII case, with at most a version ``1``."""
    if not head or head[0].kind != "value":
        return False
    if ascii_lower(head[0].text) != ascii_lower(authserv_id):
        return False
    rest = head[1:]
    if not rest:
        return True
    return len(rest) == 1 and rest[0].kind == "value" and rest[0].spaced and rest[0].raw == "1"


def _resinfo(group: list[_Token]) -> tuple[str, str, dict[str, str]] | None:
    """(method, result, properties) of one resinfo, names in lowercase. None when it does not
    parse, or a property appears twice. A value is the tokens written together with no space:
    one quoted string gives its content, anything else is kept as written."""
    if len(group) < 3 or [t.kind for t in group[:3]] != ["value", "=", "value"]:
        return None
    method, result = ascii_lower(group[0].text), ascii_lower(group[2].text)
    props: dict[str, str] = {}
    i, n = 3, len(group)
    while i < n:
        if i + 2 >= n or group[i].kind != "value" or group[i + 1].kind != "=":
            return None
        name = ascii_lower(group[i].raw)
        j = i + 2
        if group[j].kind != "value":
            return None
        parts = [group[j]]
        j += 1
        while j < n and group[j].kind == "value" and not group[j].spaced:
            parts.append(group[j])
            j += 1
        if j < n and not group[j].spaced:
            return None  # a value followed at once by '='
        value = parts[0].text if len(parts) == 1 else "".join(p.raw for p in parts)
        if name in props:
            return None
        props[name] = value
        i = j
    return method, result, props


def dkim_pass_domains(
    value: str, *, authserv_id: str, message: bytes | None = None
) -> frozenset[str]:
    """The ``d=`` of every ``dkim=pass`` result, lowercased, from one field's value (§7.1).

    The value is read by RFC 8601's grammar: comments are removed, and a quoted string is one
    value, whatever it holds. The field counts only when its authserv-id is ``authserv_id``,
    ignoring ASCII case, followed by nothing but an optional version ``1``. A result counts when
    its method is ``dkim`` (or ``dkim/1``), its result ``pass``, and it parses with no property
    given twice.

    A result counts for its ``header.d``. A result with ``header.i`` and no ``header.d`` counts
    only when ``message`` is given and :func:`dkim_identity_domain` finds its ``d=`` there:
    ``header.i`` alone may name a subdomain of ``d=``, so its domain never counts on its own.

    Returns an empty set when the field is not your server's, or its comments or quoted strings
    do not close.
    """
    if len(value) > _MAX_VALUE:
        return frozenset()
    tokens = _lex(value)
    if tokens is None:
        return frozenset()
    head, *results = _split_tokens(tokens)
    if not _is_own_field(head, authserv_id):
        return frozenset()
    found: set[str] = set()
    for group in results:
        parsed = _resinfo(group) if group else None
        if parsed is None:
            continue
        method, result, props = parsed
        if method not in ("dkim", "dkim/1") or result != "pass":
            continue
        domain = props.get("header.d")
        if domain is None and message is not None and "header.i" in props:
            domain = dkim_identity_domain(message, props["header.i"])
        if domain:
            found.add(ascii_lower(domain))
    return frozenset(found)


_TAG_NAME = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
_HEX = frozenset(b"0123456789ABCDEFabcdef")
_FWS = b" \t\r\n"


def _dkim_tags(value: bytes) -> dict[str, bytes] | None:
    """A DKIM-Signature tag list (RFC 6376 §3.2), with all whitespace removed from each value.
    None when it does not parse or a tag repeats: such a field has no identity."""
    tags: dict[str, bytes] = {}
    for spec in value.split(b";"):
        name, eq, tag_value = spec.partition(b"=")
        name = name.strip(_FWS)
        if not eq:
            if name:
                return None
            continue  # an empty item, such as after the last ';'
        text = name.decode("latin-1")
        if not text or not text[0].isascii() or not text[0].isalpha():
            return None
        if any(ch not in _TAG_NAME for ch in text) or text in tags:
            return None
        tags[text] = bytes(b for b in tag_value if b not in _FWS)
    return tags


def _dkim_qp_decode(value: bytes) -> bytes | None:
    """RFC 6376 §2.11 dkim-quoted-printable, whitespace already removed. None if invalid."""
    out = bytearray()
    i = 0
    while i < len(value):
        if value[i] == 0x3D:
            pair = value[i + 1 : i + 3]
            if len(pair) != 2 or pair[0] not in _HEX or pair[1] not in _HEX:
                return None
            out.append(int(pair, 16))
            i += 3
        else:
            out.append(value[i])
            i += 1
    return bytes(out)


def _same_identity(a: bytes, b: bytes) -> bool:
    """Local parts equal octet for octet, domains equal ignoring ASCII case (§7.1)."""
    local_a, at_a, domain_a = a.rpartition(b"@")
    local_b, at_b, domain_b = b.rpartition(b"@")
    return bool(at_a and at_b) and local_a == local_b and domain_a.lower() == domain_b.lower()


def dkim_identity_domain(message: bytes, header_i: str) -> str | None:
    """The ``d=``, lowercased, of the one ``DKIM-Signature`` field in ``message`` whose identity
    equals ``header_i`` (§7.1). None when no field or more than one has that identity, and
    None when any ``DKIM-Signature`` field has no identity: the server may have read that field
    differently, so the verifier cannot tell which field it checked.

    For a server that reports a passing signature with ``header.i`` and no ``header.d``. A
    field's identity is its ``i=`` (dkim-quoted-printable, decoded), or ``@`` and its ``d=`` when
    it has no ``i=``. Identities are equal when their local parts are equal octet for octet and
    their domains are equal ignoring case. A field has no identity when its tag list does not
    parse, it has no ``d=``, or its identity's domain is neither ``d=`` nor under it (RFC 6376
    §3.5). ``message`` is the octets as accepted, as for ``verify``.
    """
    # Imported here: model imports this module for reporting, and the parser imports model.
    from colophon_protocol import _mime  # noqa: PLC0415
    from colophon_protocol._fail import Fail  # noqa: PLC0415

    try:
        entity = _mime.parse_entity(bytes(message))
    except Fail:
        return None
    wanted = header_i.encode("utf-8", "surrogateescape")
    found: list[bytes] = []
    for field in entity.all("dkim-signature"):
        identity = _identity(field.unfolded())
        if identity is None:
            return None  # the server may have read this field differently
        if _same_identity(identity[1], wanted):
            found.append(identity[0])
    if len(found) != 1:
        return None
    return ascii_lower(found[0].decode("ascii"))


def _identity(value: bytes) -> tuple[bytes, bytes] | None:
    """A DKIM-Signature field's (d=, identity), or None when it has no identity (§7.1)."""
    tags = _dkim_tags(value)
    if tags is None or not tags.get("d") or not tags["d"].isascii():
        return None
    d = tags["d"]
    identity = _dkim_qp_decode(tags["i"]) if "i" in tags else b"@" + d
    if identity is None or b"@" not in identity:
        return None
    domain, parent = identity.rpartition(b"@")[2].lower(), d.lower()
    if domain != parent and not domain.endswith(b"." + parent):
        return None  # the identity is not in d= or under it (RFC 6376 §3.5)
    return d, identity


# ---------------------------------------------------------------- reporting the verdict (§7.8)

ColophonResult = Literal["pass", "none", "temperror", "fail"]
"""The results of the ``colophon`` method (§7.8)."""

_TEMPERROR = frozenset({"dns_error", "dns_limited", "replay_unchecked"})
_TSPECIALS = frozenset('()<>@,;:\\"/[]?=')


def colophon_result(verdict: Verdict) -> ColophonResult:
    """The §7.8 result for a verdict.

    ``pass`` for a verified message. Otherwise by the §7.2 reason: ``none`` for
    ``no_signature``, ``temperror`` for ``dns_error``, ``dns_limited`` and ``replay_unchecked``,
    which may pass on a later attempt and are never evidence against the sender (§7.4, §7.6): a
    receiver may hold the message and verify it again within its delay D. ``fail`` for every other
    reason. ``fail`` is not evidence of forgery: a ``Bcc`` copy, or a text a mail system
    rewrote, fails as a forgery does. Handle it as mail with no Colophon signature.
    """
    if verdict.verified:
        return "pass"
    if verdict.reason == "no_signature":
        return "none"
    if verdict.reason in _TEMPERROR:
        return "temperror"
    return "fail"


def colophon_resinfo(verdict: Verdict) -> str:
    """The ``colophon`` resinfo for a verdict (§7.8), unfolded, as the vectors spell it.

    With ``pass``, and only with ``pass``, it carries five properties of ptype ``header``, in
    this order: ``from``, the verified address in canonical form (§6.4), as it is in an
    internationalized message (RFC 6532); ``sub``, the agent ID; ``s``, the selector (the
    credential's ``kid``); ``principal``, the principal's mode only; and ``cred``, base64url of
    the SHA-256 of the credential, the signing input's ``credential`` member (§6.3)::

        colophon=pass header.from=maple-tiger-27@acme.example header.sub=ag_7Hq2 header.s=s1
            header.principal=pseudonymous header.cred=QyKlpHCC1M-TdbviC2iuOUhIpLY1HxufeJRGlEgEYSo

    ``iss`` is not reported: it is the host of ``header.from``. Every other result carries only
    its §7.2 reason code, ``colophon=fail reason="replay"``, so a result that is not ``pass``
    never echoes data an attacker chose. The pseudonym ``id``, the named principal's name and the
    scope are never reported: they are sender text. A consumer that needs them decodes the
    credential from the message's ``Colophon-Signature`` and checks its SHA-256 against
    ``header.cred``. It does not verify the message again, which would trip the replay check.

    A result holds for one delivered copy: steps 20 and 21 depend on the mailbox (§7.8).
    Raises ``ValueError`` only for a hand-built ``Verified`` whose values the property grammar
    cannot carry; a verdict from ``verify()`` always has carriable values.
    """
    result = colophon_result(verdict)
    if not verdict.verified:
        return f'colophon={result} reason="{verdict.reason.value}"'
    agent = verdict.agent
    values = (
        ("from", agent.address),
        ("sub", agent.sub),
        ("s", verdict.selector),
        ("principal", agent.principal.mode),
        ("cred", verdict.credential_hash),
    )
    for name, value in values:
        if not _is_bare_pvalue(value, address=name == "from"):
            raise ValueError(f"header.{name} cannot be reported unquoted: {value!r}")
    return "colophon=pass " + " ".join(f"header.{name}={value}" for name, value in values)


def authentication_results(
    verdict: Verdict, *, authserv_id: str, other_resinfo: Iterable[str] = ()
) -> str:
    """The value of an ``Authentication-Results`` field reporting ``verdict`` (§7.8).

    ``authserv_id`` names your server, as in ``mx.bistro.example``. ``other_resinfo`` are
    results your server reports beside Colophon, each one method's resinfo without the ``;``,
    such as ``"dkim=pass header.d=acme.example"``. They come first, in the order given, and the
    ``colophon`` resinfo last::

        mx.bistro.example; dkim=pass header.d=acme.example; colophon=pass header.from=...

    The value is one line, unfolded, without the field name. Fold it at whitespace if your mail
    library does not. Raises ``ValueError`` for an authserv-id or a resinfo that is empty,
    holds a control character, or would start another resinfo or a new field.

    Add the field under your own authserv-id, once per delivered copy: a server that adds it
    before it expands recipients MUST evaluate each recipient separately, or leave the method
    out. Remove any incoming field that claims your authserv-id (RFC 8601 §5). Consumers trust a
    ``colophon`` result only under an authserv-id they trust: a sender can write
    ``colophon=pass`` into its own message.
    """
    if not _is_authserv_id(authserv_id):
        raise ValueError(f"not an authserv-id: {authserv_id!r}")
    items = [authserv_id]
    for resinfo in other_resinfo:
        if not isinstance(resinfo, str):
            raise TypeError("each resinfo must be a string")
        text = resinfo.strip(" \t")
        bare = _strip_comments(text).strip(" \t")  # "" when a comment or quote is unclosed
        if not bare or _has_control(text) or len(_split(bare, ";")) != 1:
            raise ValueError(f"not one resinfo: {resinfo!r}")
        items.append(text)
    items.append(colophon_resinfo(verdict))
    return "; ".join(items)


def _has_control(text: str) -> bool:
    return any(ord(ch) < 0x20 or 0x7F <= ord(ch) < 0xA0 for ch in text)


def _is_authserv_id(text: object) -> bool:
    """An RFC 2045 token, as a host name is; non-ASCII allowed for U-labels (RFC 8616)."""
    return (
        isinstance(text, str)
        and bool(text)
        and not _has_control(text)
        and not any(ch == " " or ch in _TSPECIALS for ch in text)
    )


def _is_bare_pvalue(text: str, *, address: bool) -> bool:
    """A pvalue written without quotes: a token, or for ``from`` a dot-atom ``local@domain``."""
    if not text or _has_control(text) or " " in text:
        return False
    if address:
        local, at, domain = text.rpartition("@")
        return bool(at and local and domain) and not any(
            ch in '()<>,;:\\"[]@' for ch in local + domain
        )
    return not any(ch in _TSPECIALS for ch in text)
