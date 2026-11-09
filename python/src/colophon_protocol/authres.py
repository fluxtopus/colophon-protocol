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
    value: str, *, authserv_id: str, message: bytes | None = None
) -> frozenset[str]:
    """The ``d=`` of every ``dkim=pass`` result, lowercased, from one field's value (§7.1).

    A result counts for its ``header.d``. A result with ``header.i`` and no ``header.d`` counts
    only when ``message`` is given and :func:`dkim_identity_domain` finds its ``d=`` there:
    ``header.i`` alone may name a subdomain of ``d=``, so its domain never counts on its own.

    Returns an empty set when the field's authserv-id is not ``authserv_id``, or the value does
    not parse.
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
    equals ``header_i`` (§7.1). None when no field or more than one has that identity.

    For a server that reports a passing signature with ``header.i`` and no ``header.d``. A
    field's identity is its ``i=`` (dkim-quoted-printable, decoded), or ``@`` and its ``d=`` when
    it has no ``i=``. Identities are equal when their local parts are equal octet for octet and
    their domains are equal ignoring case. A field whose tag list does not parse, or that has no
    ``d=``, has no identity. ``message`` is the octets as accepted, as for ``verify``.
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
        tags = _dkim_tags(field.unfolded())
        if tags is None or not tags.get("d"):
            continue
        identity = _dkim_qp_decode(tags["i"]) if "i" in tags else b"@" + tags["d"]
        if identity is not None and _same_identity(identity, wanted):
            found.append(tags["d"])
    if len(found) != 1 or not found[0].isascii():
        return None
    return ascii_lower(found[0].decode("ascii"))


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
