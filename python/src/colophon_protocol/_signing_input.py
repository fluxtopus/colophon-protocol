"""§6.3 and §6.4: the header fields a verifier reads, and the signing input built from them."""

from __future__ import annotations

import re
from typing import Any

from colophon_protocol._addresses import AddressError, canonical_address_list
from colophon_protocol._codec import b64url_sha256
from colophon_protocol._fail import Fail
from colophon_protocol._mime import Entity, Layout, canonical_text, decoded, field_text
from colophon_protocol.model import Reason

VERSION = 0
_WSP_RUN = re.compile(r"[ \t]+")  # one character class: linear, no backtracking


def _malformed(detail: str) -> Fail:
    return Fail(Reason.MALFORMED, detail)


def address_list(entity: Entity, name: str) -> list[str]:
    """§6.4 Addresses, items 1 to 7."""
    found = entity.all(name)
    if len(found) > 1:
        raise _malformed(f"{name} appears more than once")
    if not found:
        return []
    try:
        return canonical_address_list(field_text(found[0]))
    except AddressError as exc:
        raise _malformed(f"{name}: {exc}") from None


def from_address(entity: Entity) -> str:
    """§7.2 step 3: exactly one From address."""
    addresses = address_list(entity, "from")
    if len(addresses) != 1:
        raise _malformed("From does not have exactly one address")
    return addresses[0]


def subject(entity: Entity) -> str:
    """§6.4 Subject: raw, unfolded, runs of SP and HTAB collapsed, trimmed."""
    found = entity.all("subject")
    if len(found) > 1:
        raise _malformed("Subject appears more than once")
    if not found:
        return ""
    return _WSP_RUN.sub(" ", field_text(found[0])).strip(" ")


def build(entity: Entity, layout: Layout, credential: str) -> dict[str, Any]:
    """§7.2 step 17 (layout was step 16): the signing input as a JSON value, before JCS."""
    return {
        "v": VERSION,
        "from": from_address(entity),
        "to": address_list(entity, "to"),
        "cc": address_list(entity, "cc"),
        "reply_to": address_list(entity, "reply-to"),
        "subject": subject(entity),
        "text": b64url_sha256(canonical_text(layout.body)),
        "attachments": [
            {"type": part.content_type.type, "sha256": b64url_sha256(decoded(part))}
            for part in layout.attachments
        ],
        "credential": b64url_sha256(credential.encode("ascii")),
    }
