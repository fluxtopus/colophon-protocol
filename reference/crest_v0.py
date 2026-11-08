"""CREST v0 reference sketch: sign and verify a message as the draft specifies.

Not a library. It exists so the draft's examples are real bytes that verify, and so a reader can
check their reading of the spec against running code. It does not check DKIM (the verifier is given
the receiving system's DKIM result, as the spec requires) and it handles ASCII domains only.

Run:  uv run --with cryptography python crest_v0.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HEADER = "Crest-Signature"
VERSION = 0
GRACE = 2 * 3600  # seconds after a credential's exp that it is still accepted on arrival
SKEW = 5 * 60  # clocks may run this fast
MIN_REMAINING = 6 * 3600  # a signer never signs with less credential life left
MAX_LIFETIME = 24 * 3600
MAX_SCOPE_BYTES = 280
MAX_HEADER_BYTES = 2048  # the Crest-Signature value, folding whitespace removed
MAX_CREDENTIAL_BYTES = 1536
MAX_NAME_BYTES = 128
NONCE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
AGENT_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


# ---------------------------------------------------------------- encodings


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jcs(value: object) -> bytes:
    """RFC 8785 for the values CREST uses: objects, arrays, strings, integers, booleans, null.

    Keys are ASCII in CREST, so sorting by code point equals JCS's UTF-16 order."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def strict_json(data: bytes) -> object:
    """I-JSON (RFC 7493): duplicate member names are an error, not a last-one-wins."""

    def pairs(items: list[tuple[str, object]]) -> dict:
        out: dict = {}
        for k, v in items:
            if k in out:
                raise ValueError("duplicate member")
            out[k] = v
        return out

    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs)


def sha256(data: bytes) -> str:
    return b64u(hashlib.sha256(data).digest())


def public_x(key: Ed25519PrivateKey) -> str:
    return b64u(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def jws_sign(header: dict, payload: bytes, key: Ed25519PrivateKey) -> tuple[str, str, str]:
    h = b64u(jcs(header))
    p = b64u(payload)
    s = b64u(key.sign(f"{h}.{p}".encode("ascii")))
    return h, p, s


def jws_check(h: str, p: str, s: str, x: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(unb64u(x)).verify(unb64u(s), f"{h}.{p}".encode("ascii"))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- canonical forms


def canonical_address(addr: str) -> str:
    local, _, domain = addr.strip().rpartition("@")
    if not local or not domain or not domain.isascii():
        raise ValueError(f"not an address this sketch handles: {addr!r}")
    ascii_lower = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
    return f"{local.translate(ascii_lower)}@{domain.lower().rstrip('.')}"


def address_list(msg: Message, name: str) -> list[str]:
    values = msg.get_all(name, [])
    if len(values) > 1:
        raise ValueError(f"more than one {name}")
    out: list[str] = []
    for _, addr in getaddresses([str(v) for v in values]):
        if addr:
            a = canonical_address(addr)
            if a not in out:
                out.append(a)
    return out


def canonical_subject(msg: Message) -> str:
    raw = msg.get_all("Subject", [])
    if len(raw) > 1:
        raise ValueError("more than one Subject")
    if not raw:
        return ""
    text = str(make_header(decode_header(re.sub(r"\r?\n[ \t]", " ", str(raw[0])))))
    return re.sub(r"[ \t\r\n]+", " ", text).strip(" ")


def canonical_text(text: str) -> bytes:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    lines = [line.rstrip(" \t") for line in lines]
    while lines and lines[-1] == "":
        lines.pop()
    return ("".join(line + "\r\n" for line in lines)).encode("utf-8")


# ---------------------------------------------------------------- message layout


def parts(msg: Message) -> tuple[Message, list[Message]]:
    """The body part and the attachments, or ValueError if the layout is not CREST's."""
    if msg.get_content_type() == "text/plain":
        check_charset(msg)
        return msg, []
    if msg.get_content_type() != "multipart/mixed":
        raise ValueError("layout")
    children = list(msg.iter_parts()) if hasattr(msg, "iter_parts") else msg.get_payload()
    if not children or children[0].get_content_type() != "text/plain":
        raise ValueError("layout")
    if children[0].get_content_disposition() == "attachment":
        raise ValueError("layout")
    check_charset(children[0])
    for child in children[1:]:
        if child.is_multipart() or child.get_content_maintype() == "message":
            raise ValueError("layout")  # message/* attachments: allowed by the draft, not by this sketch
        if child.get_content_disposition() != "attachment":
            raise ValueError("layout")
    return children[0], children[1:]


def check_charset(part: Message) -> None:
    if (part.get_content_charset() or "us-ascii").lower() not in ("us-ascii", "utf-8"):
        raise ValueError("layout")


def body_text(part: Message) -> str:
    raw = part.get_payload(decode=True) or b""
    return raw.decode((part.get_content_charset() or "us-ascii").lower())  # bad bytes: malformed


def attachment_entry(part: Message) -> dict:
    return {
        "name": part.get_filename() or "",
        "sha256": sha256(part.get_payload(decode=True) or b""),
        "type": part.get_content_type(),
    }


def signing_input(msg: Message, credential: str) -> dict:
    body, attachments = parts(msg)
    froms = address_list(msg, "From")
    if len(froms) != 1:
        raise ValueError("from")
    return {
        "attachments": [attachment_entry(a) for a in attachments],
        "cc": address_list(msg, "Cc"),
        "credential": sha256(credential.encode("ascii")),
        "from": froms[0],
        "reply_to": address_list(msg, "Reply-To"),
        "subject": canonical_subject(msg),
        "text": sha256(canonical_text(body_text(body))),
        "to": address_list(msg, "To"),
        "v": VERSION,
    }


# ---------------------------------------------------------------- issuing and signing


def dns_record(domain_key: Ed25519PrivateKey) -> str:
    return f"v=CREST0; k=ed25519; p={public_x(domain_key)}"


def issue_credential(
    *,
    domain_key: Ed25519PrivateKey,
    selector: str,
    host: str,
    agent_id: str,
    address: str,
    agent_key: Ed25519PrivateKey,
    principal: dict,
    scope: str | None,
    iat: int,
    exp: int,
) -> str:
    claims = {
        "cnf": {"jwk": {"crv": "Ed25519", "kty": "OKP", "x": public_x(agent_key)}},
        "exp": exp,
        "from": canonical_address(address),
        "iat": iat,
        "iss": host,
        "principal": principal,
        "sub": agent_id,
    }
    if scope is not None:
        claims["scope"] = scope
    h, p, s = jws_sign({"alg": "EdDSA", "kid": selector, "typ": "crest-cred+jwt"}, jcs(claims), domain_key)
    return f"{h}.{p}.{s}"


def fold_header(name: str, value: str) -> bytes:
    """Fold at '; ' and inside long values so no line passes 78 characters. Verifiers remove all
    whitespace before parsing, so where a signer folds does not matter."""
    lines, cur = [], name + ":"
    items = value.split("; ")
    for i, item in enumerate(items):
        piece = item + (";" if i < len(items) - 1 else "")
        if len(cur) + 1 + len(piece) <= 78:
            cur += " " + piece
            continue
        lines.append(cur)
        while len(piece) > 77:
            lines.append(" " + piece[:77])
            piece = piece[77:]
        cur = " " + piece
    lines.append(cur)
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def sign(raw: bytes, credential: str, agent_key: Ed25519PrivateKey, iat: int, nonce: str) -> bytes:
    """Sign the bytes that will be sent, and return them with Crest-Signature prepended."""
    claims = json.loads(unb64u(credential.split(".")[1]))
    if claims["exp"] - iat < MIN_REMAINING:
        raise ValueError("credential too close to expiry to sign with")
    msg = BytesParser(policy=policy.compat32).parsebytes(raw)
    payload = jcs(signing_input(msg, credential))
    h, _, s = jws_sign({"alg": "EdDSA", "iat": iat, "nonce": nonce, "typ": "crest-sig"}, payload, agent_key)
    value = f"v={VERSION}; c={credential}; b={h}..{s}"
    if len(credential) > MAX_CREDENTIAL_BYTES or len(value) > MAX_HEADER_BYTES:
        raise ValueError("Crest-Signature over the size cap")
    return fold_header(HEADER, value) + raw


# ---------------------------------------------------------------- verifying


@dataclass
class Arrival:
    """What the receiving system supplies. The message never supplies these."""

    accepted_at: int  # when the receiver's mail server accepted the message in SMTP
    dkim_pass_domains: set[str]  # d= of every DKIM signature that passed, from the receiver's checks
    envelope_recipient: str  # the RCPT TO this copy was delivered for
    recipient_addresses: set[str]  # every address that mailbox receives at (its own, its forwards)
    dns: dict[str, list[str] | None]  # TXT answers; missing name = NXDOMAIN, None = lookup failed
    seen: set[tuple] = field(default_factory=set)  # replay memory, shared across deliveries


@dataclass
class Verdict:
    verified: bool
    reason: str
    agent: dict | None = None


def tags(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in re.sub(r"[ \t\r\n]+", "", value).split(";"):
        if item:
            k, sep, v = item.partition("=")
            if not sep or not k or k in out:
                raise ValueError("malformed")
            out[k] = v
    return out


def verify(raw: bytes, arrival: Arrival) -> Verdict:
    """Section 7.2 of the draft, step by step. The first failing step gives the reason."""

    def no(reason: str) -> Verdict:
        return Verdict(False, reason)

    msg = BytesParser(policy=policy.compat32).parsebytes(raw)
    t_arr = arrival.accepted_at

    # 1. exactly one Crest-Signature
    headers = msg.get_all(HEADER, [])
    if not headers:
        return no("no_signature")
    if len(headers) > 1:
        return no("multiple_signatures")

    # 2. exactly one From address, and its host
    try:
        froms = address_list(msg, "From")
    except ValueError:
        return no("malformed")
    if len(froms) != 1:
        return no("malformed")
    sender = froms[0]
    host = sender.rpartition("@")[2]

    # 3. aligned DKIM, before any DNS lookup
    if host not in arrival.dkim_pass_domains:
        return no("dkim_unaligned")

    # 4. tags and version
    try:
        t = tags(str(headers[0]))
    except ValueError:
        return no("malformed")
    if len(re.sub(r"[ \t\r\n]+", "", str(headers[0]))) > MAX_HEADER_BYTES:
        return no("malformed")
    if t.get("v") != "0":
        return no("unsupported_version")
    try:
        credential, sig = t["c"], t["b"]
        ch, cp, cs = credential.split(".")
        cred_header, claims = strict_json(unb64u(ch)), strict_json(unb64u(cp))
        sh, sp, ss = sig.split(".")
        sig_header = strict_json(unb64u(sh))
    except (KeyError, ValueError):
        return no("malformed")
    if (
        sp
        or len(credential) > MAX_CREDENTIAL_BYTES
        or not all(isinstance(x, dict) for x in (cred_header, claims, sig_header))
    ):
        return no("malformed")

    # 5. credential header and issuer
    selector = cred_header.get("kid", "")
    if (
        cred_header.get("alg") != "EdDSA"
        or cred_header.get("typ") != "crest-cred+jwt"
        or "crit" in cred_header
        or not isinstance(selector, str)
        or not LABEL.match(selector)
        or claims.get("iss") != host
    ):
        return no("credential_invalid")

    # 6. domain key from DNS
    name = f"{selector}._crest.{host}"
    if name in arrival.dns and arrival.dns[name] is None:
        return no("dns_error")
    try:
        records = [r for r in (tags(a) for a in arrival.dns.get(name) or []) if r.get("v") == "CREST0"]
    except ValueError:
        records = []
    if len(records) != 1 or records[0].get("k") != "ed25519" or "p" not in records[0]:
        return no("key_not_found")
    if records[0]["p"] == "":
        return no("key_revoked")

    # 7. credential signature
    if not jws_check(ch, cp, cs, records[0]["p"]):
        return no("credential_invalid")

    # 8. credential contents and time
    jwk = claims.get("cnf", {}).get("jwk", {}) if isinstance(claims.get("cnf"), dict) else {}
    iat, exp, scope = claims.get("iat"), claims.get("exp"), claims.get("scope", "")
    if (
        not isinstance(iat, int)
        or not isinstance(exp, int)
        or not iat < exp <= iat + MAX_LIFETIME
        or not AGENT_ID.match(str(claims.get("sub", "")))
        or not isinstance(scope, str)
        or len(scope.encode()) > MAX_SCOPE_BYTES
        or any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in scope)
        or not valid_principal(claims.get("principal"))
        or jwk.get("kty") != "OKP"
        or jwk.get("crv") != "Ed25519"
        or not isinstance(jwk.get("x"), str)
    ):
        return no("credential_invalid")
    if not (iat - SKEW <= t_arr <= exp + GRACE):
        return no("credential_expired")
    if claims.get("from") != sender:
        return no("from_mismatch")

    # 9. rebuild the signing input and check the agent signature
    try:
        payload = jcs(signing_input(msg, credential))
    except ValueError as err:
        return no("layout" if str(err) == "layout" else "malformed")
    sig_iat = sig_header.get("iat")
    if (
        sig_header.get("alg") != "EdDSA"
        or sig_header.get("typ") != "crest-sig"
        or not isinstance(sig_iat, int)
        or not iat - SKEW <= sig_iat <= min(exp, t_arr + SKEW)
        or "crit" in sig_header
        or not isinstance(sig_header.get("nonce"), str)
        or not NONCE.match(sig_header["nonce"])
    ):
        return no("signature_invalid")
    if not jws_check(sh, b64u(payload), ss, jwk["x"]):
        return no("signature_invalid")

    # 10. addressed to this recipient
    listed = set(address_list(msg, "To")) | set(address_list(msg, "Cc"))
    if not listed & {canonical_address(a) for a in arrival.recipient_addresses}:
        return no("not_addressed")

    # 11. not seen before by this recipient
    key = (canonical_address(arrival.envelope_recipient), host, claims["sub"], sig_header["nonce"])
    if key in arrival.seen:
        return no("replay")
    arrival.seen.add(key)

    agent = {"iss": host, "sub": claims["sub"], "from": sender, "principal": claims["principal"]}
    if "scope" in claims:
        agent["scope"] = scope
    return Verdict(True, "verified", agent)


def valid_principal(p: object) -> bool:
    if not isinstance(p, dict):
        return False
    if p.get("mode") == "withheld":
        return set(p) == {"mode"}
    if p.get("mode") == "pseudonymous":
        return set(p) == {"mode", "id"} and isinstance(p["id"], str) and bool(AGENT_ID.match(p["id"]))
    if p.get("mode") == "named":
        name = p.get("name")
        return (
            set(p) == {"mode", "name"}
            and isinstance(name, str)
            and 0 < len(name.encode()) <= MAX_NAME_BYTES
            and not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in name)
        )
    return False


# ---------------------------------------------------------------- the draft's example


def test_key(label: str) -> Ed25519PrivateKey:
    """Deterministic test keys: never use these for anything but vectors."""
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(f"crest-v0 test key {label}".encode()).digest()
    )


ISSUED = 1793865600  # 2026-11-05T08:00:00Z


def example() -> tuple[bytes, Arrival, dict]:
    domain_key, agent_key = test_key("domain acme.example s1"), test_key("agent maple-tiger-27")
    credential = issue_credential(
        domain_key=domain_key,
        selector="s1",
        host="acme.example",
        agent_id="ag_7Hq2",
        address="maple-tiger-27@acme.example",
        agent_key=agent_key,
        principal={"mode": "pseudonymous", "id": "p_Xk29"},
        scope="Books restaurant tables for one person, up to $500 per booking.",
        iat=ISSUED,
        exp=ISSUED + MAX_LIFETIME,
    )
    msg = EmailMessage()
    msg["From"] = "Booking agent <Maple-Tiger-27@acme.example>"
    msg["To"] = "Reservations <reservations@bistro.example>"
    msg["Subject"] = "Table for 2, Friday 7 November, 19:30"
    msg["Message-ID"] = "<example-1@acme.example>"
    msg["Date"] = "Thu, 05 Nov 2026 09:15:00 +0000"
    msg.set_content(
        "Hello,\n\nCould you hold a table for 2 this Friday, 7 November, at 19:30?\n"
        "One guest is vegetarian.\n\nThank you\n",
        charset="utf-8",
        cte="quoted-printable",
    )
    msg.add_attachment(
        b"date,time,party\n2026-11-07,19:30,2\n", maintype="text", subtype="csv", filename="booking.csv"
    )
    msg.set_boundary("=_crest_example_1")
    unsigned = msg.as_bytes(policy=policy.SMTP)
    raw = sign(unsigned, credential, agent_key, iat=ISSUED + 4500, nonce="Zm9yLWV4YW1wbGUtb25seQ")
    parsed = BytesParser(policy=policy.compat32).parsebytes(raw)
    info = {
        "dns_name": "s1._crest.acme.example",
        "dns_record": dns_record(domain_key),
        "credential": credential,
        "credential_header": json.loads(unb64u(credential.split(".")[0])),
        "credential_claims": json.loads(unb64u(credential.split(".")[1])),
        "signing_input": jcs(signing_input(parsed, credential)).decode(),
        "header_value": tags(str(parsed[HEADER])),
    }
    arrival = Arrival(
        accepted_at=ISSUED + 4510,
        dkim_pass_domains={"acme.example"},
        envelope_recipient="reservations@bistro.example",
        recipient_addresses={"reservations@bistro.example"},
        dns={info["dns_name"]: [info["dns_record"]]},
    )
    return raw, arrival, info


def vectors(raw: bytes, arrival: Arrival, info: dict) -> list[tuple[str, bytes, Arrival, str]]:
    def at(**changes) -> Arrival:
        return Arrival(**{**arrival.__dict__, "seen": set(), **changes})

    shared = at()
    crlf = b"\r\n"
    return [
        ("as sent", raw, shared, "verified"),
        ("same message again, same mailbox", raw, shared, "replay"),
        (
            "same message, second local recipient",
            raw,
            at(envelope_recipient="tables@bistro.example"),
            "verified",
        ),
        ("header refolded in transit", raw.replace(b";" + crlf + b" b=", b"; b="), at(), "verified"),
        ("display name changed", raw.replace(b"From: Booking agent", b"From: Bank"), at(), "verified"),
        ("trailing spaces added to a body line", raw.replace(b"Thank you", b"Thank you  "), at(), "verified"),
        (
            "subject changed",
            raw.replace(b"Subject: Table for 2", b"Subject: Table for 4"),
            at(),
            "signature_invalid",
        ),
        ("text changed", raw.replace(b"for 2 this", b"for 4 this"), at(), "signature_invalid"),
        (
            "Reply-To added",
            raw.replace(b"Subject:", b"Reply-To: x@evil.example" + crlf + b"Subject:", 1),
            at(),
            "signature_invalid",
        ),
        (
            "Cc added",
            raw.replace(b"Subject:", b"Cc: x@evil.example" + crlf + b"Subject:", 1),
            at(),
            "signature_invalid",
        ),
        (
            "attachment changed",
            raw.replace(
                b"ZGF0ZSx0aW1lLHBhcnR5CjIwMjYtMTEtMDcsMTk6MzAsMgo=",
                b"ZGF0ZSx0aW1lLHBhcnR5CjIwMjYtMTEtMDcsMTk6MzAsOAo=",
            ),
            at(),
            "signature_invalid",
        ),
        ("HTML part added", add_html(raw), at(), "layout"),
        ("body in ISO-8859-1", raw.replace(b'charset="utf-8"', b'charset="iso-8859-1"'), at(), "layout"),
        (
            "second To header",
            raw.replace(b"Subject:", b"To: x@evil.example" + crlf + b"Subject:", 1),
            at(),
            "malformed",
        ),
        (
            "second Crest-Signature",
            raw.replace(b"From:", b"Crest-Signature: v=0" + crlf + b"From:", 1),
            at(),
            "multiple_signatures",
        ),
        ("no Crest-Signature", raw[raw.index(b"From:") :], at(), "no_signature"),
        (
            "DKIM passes only for a parent domain",
            raw,
            at(dkim_pass_domains={"mail.acme.example"}),
            "dkim_unaligned",
        ),
        (
            "unknown version",
            raw.replace(b"Crest-Signature: v=0", b"Crest-Signature: v=1", 1),
            at(),
            "unsupported_version",
        ),
        ("DNS lookup failed", raw, at(dns={info["dns_name"]: None}), "dns_error"),
        ("no key at the selector", raw, at(dns={}), "key_not_found"),
        ("key revoked", raw, at(dns={info["dns_name"]: ["v=CREST0; k=ed25519; p="]}), "key_revoked"),
        (
            "key replaced",
            raw,
            at(dns={info["dns_name"]: [dns_record(test_key("other"))]}),
            "credential_invalid",
        ),
        (
            "arrived after exp + grace",
            raw,
            at(accepted_at=ISSUED + MAX_LIFETIME + GRACE + 1),
            "credential_expired",
        ),
        ("arrived within grace", raw, at(accepted_at=ISSUED + MAX_LIFETIME + GRACE), "verified"),
        (
            "From is another address on the same host",
            raw.replace(b"<Maple-Tiger-27@", b"<oak-fox-11@"),
            at(),
            "from_mismatch",
        ),
        (
            "delivered to a Bcc recipient",
            raw,
            at(envelope_recipient="x@bistro.example", recipient_addresses={"x@bistro.example"}),
            "not_addressed",
        ),
    ]


def add_html(raw: bytes) -> bytes:
    end = b"--=_crest_example_1--"
    html = b"--=_crest_example_1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Table for 8</p>\r\n"
    return raw.replace(end, html + end)


def main() -> int:
    raw, arrival, info = example()
    if "--example" in sys.argv:
        print("## DNS\n")
        print(f'{info["dns_name"]}. TXT "{info["dns_record"]}"\n')
        print("## Credential protected header\n")
        print(json.dumps(info["credential_header"]), "\n")
        print("## Credential claims\n")
        print(json.dumps(info["credential_claims"], indent=2), "\n")
        print("## Credential (compact)\n")
        print(info["credential"], "\n")
        print("## Signing input (JCS, one line)\n")
        print(info["signing_input"], "\n")
        print("## Agent signature (tag b)\n")
        print(info["header_value"]["b"], "\n")
        print("## Message as sent, before the sender's DKIM signature\n")
        print(raw.decode().replace("\r\n", "\n"))
    failed = 0
    for name, data, arr, want in vectors(raw, arrival, info):
        got = verify(data, arr)
        ok = got.reason == want
        failed += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {want:<20} {name}" + ("" if ok else f"  (got {got.reason})"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
