"""Build a message in the layout §6.1 allows, with the standard library.

Optional: any message in that layout can be signed. This one puts the text in quoted-printable
UTF-8, which survives relays that rewrap long lines (§6.1).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid

__all__ = ["Attachment", "compose_message"]


@dataclass(frozen=True, slots=True)
class Attachment:
    content: bytes
    media_type: str  # "text/csv"
    filename: str


def compose_message(
    *,
    sender: str,
    to: Sequence[str],
    subject: str,
    text: str,
    cc: Sequence[str] = (),
    reply_to: Sequence[str] = (),
    attachments: Iterable[Attachment] = (),
    message_id: str | None = None,
    date: datetime | None = None,
    extra_headers: Sequence[tuple[str, str]] = (),
) -> bytes:
    """The octets of a text/plain message, or multipart/mixed when there are attachments.

    ``sender`` and the address lists take ``addr-spec`` or ``Display Name <addr-spec>``.
    ``date`` is a timezone-aware ``datetime``; without one, no Date header is added (the mail
    system adds it). Lines end in CRLF.
    """
    msg = EmailMessage(policy=policy.SMTP)
    msg["From"] = sender
    if to:
        msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    if reply_to:
        msg["Reply-To"] = ", ".join(reply_to)
    msg["Subject"] = subject
    msg["Message-ID"] = message_id or make_msgid(domain=sender.rpartition("@")[2].rstrip(">"))
    if date is not None:
        msg["Date"] = format_datetime(date)
    for name, value in extra_headers:
        msg[name] = value
    msg.set_content(text, charset="utf-8", cte="quoted-printable")
    for item in attachments:
        maintype, _, subtype = item.media_type.partition("/")
        if maintype in ("multipart", "message") or not subtype:
            raise ValueError(f"attachment type {item.media_type!r} is not allowed (§6.1)")
        msg.add_attachment(item.content, maintype=maintype, subtype=subtype, filename=item.filename)
    return msg.as_bytes(policy=policy.SMTP)
