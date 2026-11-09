"""§4.1 and §7.4: the domain key record, written and chosen."""

from __future__ import annotations

from colophon_protocol._codec import b64url_decode, b64url_encode
from colophon_protocol._ed25519 import valid_public_key
from colophon_protocol._grammar import parse_tags, remove_whitespace
from colophon_protocol.model import Reason, TxtAnswer

RECORD_VERSION = "COLOPHON0"


def format_record(public_key: bytes) -> str:
    """The TXT record value for a domain key."""
    return f"v={RECORD_VERSION}; k=ed25519; p={b64url_encode(public_key)}"


def format_revoked_record() -> str:
    """The TXT record value that revokes a selector (§4.2): an empty ``p``."""
    return f"v={RECORD_VERSION}; k=ed25519; p="


def select_domain_key(answer: TxtAnswer) -> bytes | Reason:
    """§7.4 "Which record is the key": the 32-octet domain key, or the step 10/11 reason.

    Records are octets, never decoded as text. A record with an octet above 0x7F is not a
    Colophon record (§4.1, §7.4 step 3). The key must be valid (§6.5, §7.4 step 7).
    """
    found: list[dict[str, str]] = []
    for record in answer.records:
        if not record.isascii():
            continue
        try:
            tags = parse_tags(remove_whitespace(record.decode("ascii")))
        except ValueError:
            continue
        if tags.get("v") == RECORD_VERSION:
            found.append(tags)
    if len(found) != 1:
        return Reason.KEY_NOT_FOUND
    tags = found[0]
    if tags.get("k") != "ed25519" or "p" not in tags:
        return Reason.KEY_NOT_FOUND
    if tags["p"] == "":
        return Reason.KEY_REVOKED
    try:
        key = b64url_decode(tags["p"])
    except ValueError:
        return Reason.KEY_NOT_FOUND
    if len(key) != 32 or not valid_public_key(key):
        return Reason.KEY_NOT_FOUND
    return key
