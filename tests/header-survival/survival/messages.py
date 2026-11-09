"""The three messages of the test plan (spec section 15, issue 1), signed with the reference sketch.

- `minimal`: the smallest legal credential, a withheld principal and no scope, one text/plain part.
- `cap`: a 128-octet named principal, a 280-octet scope, and an extension claim that pads the
  Colophon-Signature value to exactly 2,560 octets with whitespace removed.
- `attachments`: a pseudonymous principal with a scope, the text and two attachments.

Each message is signed for one recipient, since the signing input covers `To`. A run therefore
signs three messages per receiver. Message-ID and Date are set here but Amazon SES replaces both on
sending; the harness matches captures by the X-Colophon-Test header, which is not signed, and by
the run token in the subject, which is."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .keys import Keys
from .reference import ref

LABELS = ("minimal", "cap", "attachments")
SELECTOR = "s1"
AGENT_ID = "header-test"
TRACKING_HEADER = "X-Colophon-Test"
PAD_CLAIM = "colophon-protocol.org:pad"

TEXT = (
    "Hello,\n\n"
    "This message is part of the Colophon header-survival test. It carries a Colophon-Signature\n"
    "header and asks nothing of you. The test checks whether that header reaches this mailbox\n"
    "unchanged. Details: https://colophon-protocol.org/v0/\n\n"
    "Thank you\n"
)

SCOPE = (
    "Sends test messages for the Colophon header-survival test. It writes only to the project's "
    "own test mailboxes, never to anyone else, and it makes no commitments, requests or payments "
    "on behalf of anyone."
)
NAMED_PRINCIPAL = "Colophon header-survival test (a test identity, not a person)"

CSV_ATTACHMENT = b"message,label\nheader-survival,attachments\n"
# A one-page PDF with no text: a binary attachment that must travel in base64.
PDF_ATTACHMENT = (
    b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
    b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
    b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 100] >> endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n0000000015 00000 n \n0000000062 00000 n \n"
    b"0000000117 00000 n \ntrailer << /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF\n"
)


def exact_octets(text: str, n: int) -> str:
    """`text` padded with a counter, or cut, to exactly n UTF-8 octets. Padding is ASCII."""
    data = text.encode("utf-8")
    if len(data) > n:
        return data[:n].decode("utf-8", "ignore")
    filler = []
    i = 0
    while len(data) + len("".join(filler)) < n:
        filler.append(f" {i}")
        i += 1
    out = text + "".join(filler)
    return out.encode("utf-8")[:n].decode("utf-8")


@dataclass(frozen=True)
class Built:
    label: str
    recipient: str
    raw: bytes  # the message as handed to the mail system, Colophon-Signature included
    credential: str
    header_value: str  # the Colophon-Signature value with whitespace removed
    nonce: str

    @property
    def header_octets(self) -> int:
        return len(self.header_value.encode())

    @property
    def credential_octets(self) -> int:
        return len(self.credential)


def nonce(length: int = 22) -> str:
    """At least 96 random bits in base64url; 22 characters carry 132."""
    return ref.b64u(secrets.token_bytes(48))[:length]


def claims(
    *,
    host: str,
    sender: str,
    agent_key: Ed25519PrivateKey,
    iat: int,
    principal: dict,
    scope: str | None = None,
    pad: int | None = None,
) -> dict:
    out = {
        "cnf": {"jwk": {"crv": "Ed25519", "kty": "OKP", "x": ref.public_x(agent_key)}},
        "exp": iat + ref.MAX_LIFETIME,
        "from": sender,
        "iat": iat,
        "iss": host,
        "principal": principal,
        "sub": AGENT_ID,
    }
    if scope is not None:
        out["scope"] = scope
    if pad is not None:
        out[PAD_CLAIM] = "0" * pad
    return out


def unsigned(
    *,
    sender: str,
    display: str,
    recipient: str,
    subject: str,
    tracking: str,
    attachments: bool,
) -> bytes:
    msg = EmailMessage()
    msg["From"] = f"{display} <{sender}>"
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain=sender.rpartition("@")[2])
    msg["Date"] = formatdate(usegmt=True)
    msg[TRACKING_HEADER] = tracking
    msg.set_content(TEXT, charset="utf-8", cte="quoted-printable")
    if attachments:
        msg.add_attachment(CSV_ATTACHMENT, maintype="text", subtype="csv", filename="test.csv")
        msg.add_attachment(
            PDF_ATTACHMENT, maintype="application", subtype="pdf", filename="blank.pdf"
        )
    return msg.as_bytes(policy=policy.SMTP)


def _signed(
    raw: bytes, credential: str, keys: Keys, iat: int, used_nonce: str
) -> tuple[bytes, str]:
    signed = ref.sign(raw, credential, keys.agent, iat=iat, nonce=used_nonce, strict=True)
    parsed = ref.parse_part(signed)
    value = ref.re.sub(r"[ \t\r\n]+", "", ref.raw_values(parsed, ref.HEADER)[0])
    return signed, value


def build(
    label: str,
    *,
    keys: Keys,
    sender: str,
    recipient: str,
    run_id: str,
    now: int,
    display: str = "Colophon header test",
    selector: str = SELECTOR,
) -> Built:
    if label not in LABELS:
        raise ValueError(f"unknown message label {label!r}; one of {LABELS}")
    host = sender.rpartition("@")[2]
    sender = ref.canonical_addr_spec(sender)
    subject = f"Colophon header test: {label} [{run_id}]"
    raw = unsigned(
        sender=sender,
        display=display,
        recipient=recipient,
        subject=subject,
        tracking=f"{run_id}/{label}",
        attachments=label == "attachments",
    )
    common = {"host": host, "sender": sender, "agent_key": keys.agent, "iat": now}

    if label == "minimal":
        credential = ref.issue_credential(
            keys.domain, selector, claims(**common, principal={"mode": "withheld"})
        )
        used = nonce()
        signed, value = _signed(raw, credential, keys, now, used)
        return Built(label, recipient, signed, credential, value, used)

    if label == "attachments":
        credential = ref.issue_credential(
            keys.domain,
            selector,
            claims(**common, principal={"id": "p_test", "mode": "pseudonymous"}, scope=SCOPE),
        )
        used = nonce()
        signed, value = _signed(raw, credential, keys, now, used)
        return Built(label, recipient, signed, credential, value, used)

    return _at_cap(raw, keys, common, recipient, selector)


def _at_cap(raw: bytes, keys: Keys, common: dict, recipient: str, selector: str) -> Built:
    """The cap message: every variable field at its limit, padded to exactly 2,560 octets.

    With the credential at its own cap of 2,048 octets, a signature tag with only the four
    members of section 6.5 is at most 254 octets, so the value stops near 2,310. The header cap
    is reached only through members the verifier ignores. The padding claim takes the credential
    to 2,048, then an extension member in the signature's protected header, together with the
    nonce's length (16 to 64), takes the whitespace-removed value to 2,560 exactly."""
    principal = {"mode": "named", "name": exact_octets(NAMED_PRINCIPAL, ref.MAX_NAME_BYTES)}
    scope = exact_octets(SCOPE, ref.MAX_SCOPE_BYTES)
    credential = ""
    for pad in range(1500):
        candidate = ref.issue_credential(
            keys.domain, selector, claims(**common, principal=principal, scope=scope, pad=pad)
        )
        if len(candidate) > ref.MAX_CREDENTIAL_BYTES:
            break
        credential = candidate
    assert len(credential) <= ref.MAX_CREDENTIAL_BYTES
    # "v=0;c=<c>;b=<b>" with whitespace removed: 9 octets of tags and separators.
    target_b = ref.MAX_HEADER_BYTES - 9 - len(credential)
    base = ref.b64u(secrets.token_bytes(48))
    for ext in range(600):
        for length in range(16, 65):
            header = {
                "alg": "EdDSA",
                "iat": common["iat"],
                "nonce": base[:length],
                "typ": "colophon-sig",
            }
            if ext:
                header[PAD_CLAIM] = "0" * ext
            # <header>..<64-octet signature>: the signature is always 86 characters.
            if len(ref.b64u(ref.jcs(header))) + 2 + 86 == target_b:
                return _signed_with_header(raw, credential, keys, header, recipient)
    raise AssertionError("no padding reaches the header cap")


def _signed_with_header(
    raw: bytes, credential: str, keys: Keys, header: dict, recipient: str
) -> Built:
    """ref.sign with a caller-supplied protected header. The steps are the sketch's own."""
    parsed = ref.parse_part(raw)
    payload = ref.jcs(ref.signing_input(parsed, credential))
    h, _, s = ref.jws_sign(header, payload, keys.agent)
    value = f"v={ref.VERSION}; c={credential}; b={h}..{s}"
    signed = ref.fold_header(ref.HEADER, value) + raw
    compact = ref.re.sub(r"[ \t\r\n]+", "", value)
    assert len(compact.encode()) == ref.MAX_HEADER_BYTES, len(compact)
    return Built("cap", recipient, signed, credential, compact, header["nonce"])
