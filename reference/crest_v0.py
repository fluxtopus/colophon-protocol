"""CREST v0 reference sketch: sign and verify a message as the draft specifies.

Not a library. It exists so the draft's examples are real bytes that verify, and so a reader can
check their reading of the spec against running code. It does not check DKIM or query DNS: the
verifier is given the receiving system's DKIM result, DNS answers and mailbox, as §7.1 describes.

Run:  uv run --with cryptography python crest_v0.py [--example | --json]
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HEADER = "Crest-Signature"
VERSION = 0
GRACE = 2 * 3600  # seconds after a credential's exp that it is still accepted on arrival
SKEW = 5 * 60  # clocks may run this fast
MIN_REMAINING = 6 * 3600  # a signer SHOULD NOT sign with less credential life left (not checked)
MAX_LIFETIME = 24 * 3600
MAX_SCOPE_BYTES = 280
MAX_NAME_BYTES = 128
MAX_HEADER_BYTES = 2560  # the Crest-Signature value, whitespace removed
MAX_CREDENTIAL_BYTES = 2048  # the c tag value
MAX_INT = 2**53 - 1

# Every grammar is matched against the whole value (fullmatch), never with match() or a $ anchor.
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
AGENT_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
NONCE = re.compile(r"[A-Za-z0-9_-]{16,64}")
B64URL = re.compile(r"[A-Za-z0-9_-]*")
TAG_NAME = re.compile(r"[a-z][a-z0-9_]*")
ATEXT = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]"
LOCAL_PART = re.compile(rf"(?:{ATEXT}|[^\x00-\x7f])+(?:\.(?:{ATEXT}|[^\x00-\x7f])+)*")
LDH = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
DOMAIN = re.compile(rf"{LDH}(?:\.{LDH})+")
PHRASE = re.compile(rf"(?:{ATEXT}|[ \t.]|[^\x00-\x7f]|\"(?:[^\"\\\r\n]|\\.)*\")*")
ENCODED_WORD = re.compile(r"=\?([^?*\s]+)(\*[^?\s]*)?\?([BbQq])\?([!->@-~]+)\?=")
TOKEN = r"[A-Za-z0-9!#$%&'*+.^_`{|}~-]+"
CONTENT_TYPE = re.compile(rf"\s*{TOKEN}/{TOKEN}\s*(?:;.*)?", re.DOTALL)
TRANSFER_ENCODINGS = {"7bit", "8bit", "binary", "quoted-printable", "base64"}
BASE64 = re.compile(rb"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
# C0, DEL, C1 and the bidirectional controls: not allowed in scope or a named principal (§5.4).
FORBIDDEN_TEXT = re.compile("[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


class Fail(Exception):
    """A step failed: the verdict is not verified, with this reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------- encodings


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: object) -> bytes:
    """Strict base64url (§2): URL-safe alphabet, no padding, no stray bits. ValueError otherwise."""
    if not isinstance(text, str) or not B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("not base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u(data) != text:
        raise ValueError("non-canonical base64url")
    return data


def strict_json(data: bytes) -> object:
    """I-JSON (RFC 7493) as v0 uses it: unique member names, and numbers are integers within
    +/-(2^53 - 1). ValueError otherwise."""

    def pairs(items: list[tuple[str, object]]) -> dict:
        out: dict = {}
        for k, v in items:
            if k in out:
                raise ValueError("duplicate member")
            out[k] = v
        return out

    def not_an_integer(text: str) -> float:
        raise ValueError(f"not an integer: {text}")

    def integer(text: str) -> int:
        value = int(text)
        if abs(value) > MAX_INT:
            raise ValueError("integer out of range")
        return value

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_float=not_an_integer,
            parse_int=integer,
            parse_constant=not_an_integer,
        )
    except RecursionError:
        raise ValueError("nested too deeply") from None


def jcs(value: object) -> bytes:
    """RFC 8785 for the values CREST uses: objects, arrays, strings and integers.

    Keys are ASCII in CREST, so sorting by code point equals JCS's UTF-16 order."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def sha256(data: bytes) -> str:
    return b64u(hashlib.sha256(data).digest())


def public_x(key: Ed25519PrivateKey) -> str:
    return b64u(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def jws_sign(header: dict, payload: bytes, key: Ed25519PrivateKey) -> tuple[str, str, str]:
    h = b64u(jcs(header))
    p = b64u(payload)
    s = b64u(key.sign(f"{h}.{p}".encode("ascii")))
    return h, p, s


def jws_check(h: str, p: str, s: str, public: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(unb64u(s), f"{h}.{p}".encode("ascii"))
        return True
    except (InvalidSignature, ValueError):
        return False


def tags(value: str) -> dict[str, str]:
    """A tag list (§6.2, §4.1): whitespace removed, `name=value` items split at `;`, names in
    lowercase, no duplicates. Fail("malformed") otherwise."""
    out: dict[str, str] = {}
    for item in re.sub(r"[ \t\r\n]+", "", value).split(";"):
        if item:
            k, sep, v = item.partition("=")
            if not sep or not TAG_NAME.fullmatch(k) or k in out:
                raise Fail("malformed")
            out[k] = v
    return out


# ---------------------------------------------------------------- header fields


def raw_values(msg: Message, name: str) -> list[str]:
    """Each instance of a header field, unfolded, as text. Header octets must be UTF-8 (RFC 6532)."""
    out = []
    for key, value in msg.raw_items():
        if key.lower() != name.lower():
            continue
        try:
            text = value.encode("ascii", "surrogateescape").decode("utf-8")
        except UnicodeError:
            raise Fail("malformed") from None
        out.append(re.sub(r"\r?\n(?=[ \t])", "", text))
    return out


def split_address_list(value: str) -> list[str]:
    """Split at top-level commas. Groups, comments, domain literals and routes are malformed."""
    items: list[str] = []
    cur: list[str] = []
    quoted = escaped = angle = False
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
        elif ch == "<":
            if angle:
                raise Fail("malformed")
            angle = True
        elif ch == ">":
            if not angle:
                raise Fail("malformed")
            angle = False
        elif ch in "():;[]\\":
            raise Fail("malformed")
        elif ch == "," and not angle:
            items.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    if quoted or angle:
        raise Fail("malformed")
    items.append("".join(cur))
    return [i.strip(" \t") for i in items]


def canonical_addr_spec(addr: str) -> str:
    """§6.4: a dot-atom local part, and a domain of ASCII labels (A-labels for IDNs)."""
    local, at, domain = addr.rpartition("@")
    if not at or not LOCAL_PART.fullmatch(local) or not DOMAIN.fullmatch(domain):
        raise Fail("malformed")
    ascii_lower = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
    return f"{local.translate(ascii_lower)}@{domain.lower()}"


def canonical_mailbox(item: str) -> str:
    if item.endswith(">"):
        i = item.index("<")
        if not PHRASE.fullmatch(item[:i]):
            raise Fail("malformed")
        return canonical_addr_spec(item[i + 1 : -1])
    return canonical_addr_spec(item)


def address_list(msg: Message, name: str) -> list[str]:
    values = raw_values(msg, name)
    if len(values) > 1:
        raise Fail("malformed")
    if not values:
        return []
    out: list[str] = []
    for item in split_address_list(values[0]):
        addr = canonical_mailbox(item)
        if addr not in out:
            out.append(addr)
    return out


def decode_word(word: re.Match) -> str:
    """One RFC 2047 encoded word, decoded on its own under §6.4's rules."""
    charset, language, encoding, text = word.groups()
    if language or charset.lower() not in ("utf-8", "us-ascii"):
        raise Fail("malformed")
    if encoding in "Bb":
        if not BASE64.fullmatch(text.encode()):
            raise Fail("malformed")
        data = base64.b64decode(text)
    else:
        out, i = bytearray(), 0
        while i < len(text):
            ch = text[i]
            if ch == "=":
                pair = text[i + 1 : i + 3]
                if not re.fullmatch(r"[0-9A-Fa-f]{2}", pair):
                    raise Fail("malformed")
                out.append(int(pair, 16))
                i += 3
            else:
                out.append(0x20 if ch == "_" else ord(ch))
                i += 1
        data = bytes(out)
    try:
        return data.decode(charset.lower())
    except UnicodeError:  # includes a character split across two encoded words
        raise Fail("malformed") from None


def canonical_subject(msg: Message) -> str:
    values = raw_values(msg, "Subject")
    if len(values) > 1:
        raise Fail("malformed")
    if not values:
        return ""
    pieces = re.split(r"([ \t]+)", values[0])  # words at even indexes, whitespace at odd
    words = [ENCODED_WORD.fullmatch(p) if i % 2 == 0 else None for i, p in enumerate(pieces)]
    out = []
    for i, piece in enumerate(pieces):
        if i % 2 == 0:
            out.append(decode_word(words[i]) if words[i] else piece)
        elif not (words[i - 1] and i + 1 < len(pieces) and words[i + 1]):
            out.append(piece)  # whitespace between two encoded words is dropped
    return re.sub(r"[ \t]+", " ", "".join(out)).strip(" ")


def canonical_text(text: str) -> bytes:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    lines = [line.rstrip(" \t") for line in lines]
    while lines and lines[-1] == "":
        lines.pop()
    return ("".join(line + "\r\n" for line in lines)).encode("utf-8")


# ---------------------------------------------------------------- MIME


def check_part_headers(part: Message) -> str:
    """§6.1: Content-* fields appear at most once and parse. Returns the transfer encoding."""
    for name in ("Content-Type", "Content-Transfer-Encoding", "Content-Disposition"):
        if len(part.get_all(name, [])) > 1:
            raise Fail("malformed")
    ctype = part.get("Content-Type")
    if ctype is not None and not CONTENT_TYPE.fullmatch(str(ctype)):
        raise Fail("malformed")
    cte = str(part.get("Content-Transfer-Encoding", "7bit")).strip().lower()
    if cte not in TRANSFER_ENCODINGS:
        raise Fail("layout")
    return cte


def check_body_part(part: Message) -> None:
    check_part_headers(part)
    if part.get_content_type() != "text/plain" or part.get_content_disposition() == "attachment":
        raise Fail("layout")
    if (part.get_content_charset() or "us-ascii") not in ("us-ascii", "utf-8"):
        raise Fail("layout")  # names only: no aliases such as utf8
    if str(part.get_param("format", "fixed")).lower() == "flowed":
        raise Fail("layout")


def parts(msg: Message) -> tuple[Message, list[Message]]:
    """§7.2 step 16: walk the parts from the top; the first failure gives the reason."""
    check_part_headers(msg)
    if msg.get_content_type() == "text/plain":
        check_body_part(msg)
        return msg, []
    if msg.get_content_type() != "multipart/mixed":
        raise Fail("layout")
    children = msg.get_payload()
    if not isinstance(children, list) or not children:
        raise Fail("layout")
    check_body_part(children[0])
    for child in children[1:]:
        check_part_headers(child)
        if child.get_content_maintype() in ("multipart", "message"):
            raise Fail("layout")
        if child.get_content_disposition() != "attachment":
            raise Fail("layout")
    return children[0], children[1:]


def decode_qp(data: bytes) -> bytes:
    """Quoted-printable per RFC 2045 §6.7, strictly: '=' not followed by two hex digits or a line
    end is malformed."""
    out = bytearray()
    lines = re.split(rb"\r\n|\n", data)
    for n, line in enumerate(lines):
        line = line.rstrip(b" \t")  # rule 3: trailing whitespace is not content
        soft = line.endswith(b"=")
        if soft:
            line = line[:-1]
        i = 0
        while i < len(line):
            if line[i : i + 1] == b"=":
                pair = line[i + 1 : i + 3]
                if not re.fullmatch(rb"[0-9A-Fa-f]{2}", pair):
                    raise Fail("malformed")
                out.append(int(pair, 16))
                i += 3
            else:
                out += line[i : i + 1]
                i += 1
        if not soft and n < len(lines) - 1:
            out += b"\r\n"
    return bytes(out)


def decoded(part: Message) -> bytes:
    """A part's body with its transfer encoding removed."""
    raw = part.get_payload(decode=False)
    if not isinstance(raw, str):
        raise Fail("layout")
    data = raw.encode("ascii", "surrogateescape")
    cte = check_part_headers(part)
    if cte == "base64":
        compact = re.sub(rb"[ \t\r\n]+", b"", data)
        if not BASE64.fullmatch(compact):
            raise Fail("malformed")
        return base64.b64decode(compact)
    if cte == "quoted-printable":
        return decode_qp(data)
    return data


def body_text(part: Message) -> str:
    try:
        return decoded(part).decode(part.get_content_charset() or "us-ascii")  # a BOM is content
    except UnicodeError:
        raise Fail("malformed") from None


def signing_input(msg: Message, credential: str) -> dict:
    """§6.3. Layout first (step 16), then the rest (step 17)."""
    body, attachments = parts(msg)
    froms = address_list(msg, "From")
    if len(froms) != 1:
        raise Fail("malformed")
    return {
        "attachments": [{"sha256": sha256(decoded(a)), "type": a.get_content_type()} for a in attachments],
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


def issue_credential(domain_key: Ed25519PrivateKey, selector: str, claims: dict) -> str:
    header = {"alg": "EdDSA", "kid": selector, "typ": "crest-cred+jwt"}
    h, p, s = jws_sign(header, jcs(claims), domain_key)
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


def sign(
    raw: bytes,
    credential: str,
    agent_key: Ed25519PrivateKey,
    iat: int,
    nonce: str,
    strict: bool = True,
) -> bytes:
    """Sign the bytes that will be sent, and return them with Crest-Signature prepended.

    strict=False skips the signer-side rules, so vectors can build messages a signer must not."""
    if strict:
        claims = strict_json(unb64u(credential.split(".")[1]))
        if claims["exp"] - iat < MIN_REMAINING:
            raise ValueError("credential too close to expiry to sign with")
    msg = BytesParser(policy=policy.compat32).parsebytes(raw)
    payload = jcs(signing_input(msg, credential))
    header = {"alg": "EdDSA", "iat": iat, "nonce": nonce, "typ": "crest-sig"}
    h, _, s = jws_sign(header, payload, agent_key)
    value = f"v={VERSION}; c={credential}; b={h}..{s}"
    if strict and (len(credential) > MAX_CREDENTIAL_BYTES or len(value) > MAX_HEADER_BYTES):
        raise ValueError("Crest-Signature over the size cap")
    return fold_header(HEADER, value) + raw


# ---------------------------------------------------------------- verifying


@dataclass
class Arrival:
    """What the receiving system supplies (§7.1). The message never supplies these."""

    accepted_at: int  # when the receiver's mail server accepted the message in SMTP
    dkim_pass_domains: set[str]  # d= of every DKIM signature that passed, from the receiver's checks
    mailbox: str  # the receiver's stable identifier for the mailbox this copy was delivered to
    mailbox_addresses: set[str]  # every address that mailbox receives at: its own and its aliases
    dns: dict[str, list[str] | None]  # TXT answers; a missing name is NXDOMAIN, None a failed lookup
    envelope_recipient: str = ""  # the RCPT TO; the receiver maps it to the mailbox. Not used here.
    seen: set[tuple] = field(default_factory=set)  # the replay store for the mailbox


@dataclass
class Verdict:
    verified: bool
    reason: str
    agent: dict | None = None


def domain_key(answers: list[str]) -> bytes:
    """§7.4: the one CREST record at the name, or Fail."""
    records = []
    for answer in answers:
        try:
            record = tags(answer)
        except Fail:
            continue  # not a tag list, or a duplicate tag: not a CREST record
        if record.get("v") == "CREST0":
            records.append(record)
    if len(records) != 1:
        raise Fail("key_not_found")
    record = records[0]
    if record.get("k") != "ed25519" or "p" not in record:
        raise Fail("key_not_found")
    if record["p"] == "":
        raise Fail("key_revoked")
    try:
        key = unb64u(record["p"])
    except ValueError:
        raise Fail("key_not_found") from None
    if len(key) != 32:
        raise Fail("key_not_found")
    return key


def is_int(value: object) -> bool:
    return type(value) is int  # not bool


def plain_text(value: object, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value.encode()) <= limit and not FORBIDDEN_TEXT.search(value)


def valid_principal(p: object) -> bool:
    if not isinstance(p, dict):
        return False
    mode = p.get("mode")
    if mode == "withheld":
        return set(p) == {"mode"}
    if mode == "pseudonymous":
        pid = p.get("id")
        return set(p) == {"mode", "id"} and isinstance(pid, str) and bool(AGENT_ID.fullmatch(pid))
    if mode == "named":
        return set(p) == {"mode", "name"} and plain_text(p["name"], MAX_NAME_BYTES)
    return False


def agent_key(claims: dict) -> bytes:
    """§7.2 step 13: each claim has its JSON type and matches its grammar in full."""
    iat, exp = claims.get("iat"), claims.get("exp")
    if not (is_int(iat) and is_int(exp) and iat < exp <= iat + MAX_LIFETIME):
        raise Fail("credential_invalid")
    sub, sender = claims.get("sub"), claims.get("from")
    if not isinstance(sub, str) or not AGENT_ID.fullmatch(sub):
        raise Fail("credential_invalid")
    if not isinstance(sender, str):
        raise Fail("credential_invalid")
    try:
        canonical = canonical_addr_spec(sender)
    except Fail:
        raise Fail("credential_invalid") from None
    if canonical != sender:
        raise Fail("credential_invalid")
    if not valid_principal(claims.get("principal")):
        raise Fail("credential_invalid")
    if "scope" in claims and not plain_text(claims["scope"], MAX_SCOPE_BYTES):
        raise Fail("credential_invalid")
    cnf = claims.get("cnf")
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise Fail("credential_invalid")
    try:
        key = unb64u(jwk.get("x"))
    except ValueError:
        raise Fail("credential_invalid") from None
    if len(key) != 32:
        raise Fail("credential_invalid")
    return key


def verify(raw: bytes, arrival: Arrival) -> Verdict:
    try:
        return Verdict(True, "verified", _verify(raw, arrival))
    except Fail as failed:
        return Verdict(False, failed.reason)


def _verify(raw: bytes, arrival: Arrival) -> dict:
    """§7.2, step by step. The first failing step gives the reason."""
    msg = BytesParser(policy=policy.compat32).parsebytes(raw)
    t_arr = arrival.accepted_at

    # 1, 2. exactly one Crest-Signature
    count = sum(1 for key, _ in msg.raw_items() if key.lower() == HEADER.lower())
    if count == 0:
        raise Fail("no_signature")
    if count > 1:
        raise Fail("multiple_signatures")

    # 3. exactly one From address; H is its host
    froms = address_list(msg, "From")
    if len(froms) != 1:
        raise Fail("malformed")
    sender = froms[0]
    host = sender.rpartition("@")[2]

    # 4. aligned DKIM, before any DNS lookup
    if host not in {d.lower() for d in arrival.dkim_pass_domains}:
        raise Fail("dkim_unaligned")

    # 5. the tag list, within its size cap, with a v tag
    value = re.sub(r"[ \t\r\n]+", "", raw_values(msg, HEADER)[0])
    if len(value.encode()) > MAX_HEADER_BYTES:
        raise Fail("malformed")
    t = tags(value)
    if "v" not in t:
        raise Fail("malformed")

    # 6. the version
    if t["v"] != "0":
        raise Fail("unsupported_version")

    # 7. c and b: two compact JWS, b with its payload detached; I-JSON objects
    if "c" not in t or "b" not in t or len(t["c"]) > MAX_CREDENTIAL_BYTES:
        raise Fail("malformed")
    credential, sig = t["c"], t["b"]
    try:
        ch, cp, cs = credential.split(".")
        sh, sp, ss = sig.split(".")
        cred_header, claims = strict_json(unb64u(ch)), strict_json(unb64u(cp))
        sig_header = strict_json(unb64u(sh))
        unb64u(cs), unb64u(ss)
    except ValueError:
        raise Fail("malformed") from None
    if sp != "" or not all(isinstance(x, dict) for x in (cred_header, claims, sig_header)):
        raise Fail("malformed")

    # 8. the credential's header and issuer
    selector = cred_header.get("kid")
    if (
        cred_header.get("alg") != "EdDSA"
        or cred_header.get("typ") != "crest-cred+jwt"
        or "crit" in cred_header
        or not isinstance(selector, str)
        or not LABEL.fullmatch(selector)
        or claims.get("iss") != host
    ):
        raise Fail("credential_invalid")

    # 9 to 11. the domain key (the DNS budget of §7.4 is the receiver's; not modelled here)
    name = f"{selector}._crest.{host}"
    if name in arrival.dns and arrival.dns[name] is None:
        raise Fail("dns_error")
    key = domain_key(arrival.dns.get(name) or [])

    # 12. the credential's signature
    if not jws_check(ch, cp, cs, key):
        raise Fail("credential_invalid")

    # 13 to 15. the claims, the arrival time, the address
    public = agent_key(claims)
    if not claims["iat"] - SKEW <= t_arr <= claims["exp"] + GRACE:
        raise Fail("credential_expired")
    if claims["from"] != sender:
        raise Fail("from_mismatch")

    # 16, 17. the layout, then the signing input
    payload = jcs(signing_input(msg, credential))

    # 18, 19. the agent signature
    sig_iat, nonce = sig_header.get("iat"), sig_header.get("nonce")
    if (
        sig_header.get("alg") != "EdDSA"
        or sig_header.get("typ") != "crest-sig"
        or "crit" in sig_header
        or not isinstance(nonce, str)
        or not NONCE.fullmatch(nonce)
        or not is_int(sig_iat)
        or sig_iat > min(claims["exp"], t_arr + SKEW)
    ):
        raise Fail("signature_invalid")
    if not jws_check(sh, b64u(payload), ss, public):
        raise Fail("signature_invalid")

    # 20. addressed to this mailbox
    listed = set(address_list(msg, "To")) | set(address_list(msg, "Cc"))
    if not listed & {canonical_addr_spec(a) for a in arrival.mailbox_addresses}:
        raise Fail("not_addressed")

    # 21. not verified before for this mailbox
    seen_key = (arrival.mailbox, host, claims["sub"], nonce)
    if seen_key in arrival.seen:
        raise Fail("replay")
    arrival.seen.add(seen_key)

    agent = {"iss": host, "sub": claims["sub"], "from": sender, "principal": claims["principal"]}
    if "scope" in claims:
        agent["scope"] = claims["scope"]
    return agent


# ---------------------------------------------------------------- the draft's example


def test_key(label: str) -> Ed25519PrivateKey:
    """Deterministic test keys: never use these for anything but vectors."""
    seed = hashlib.sha256(f"crest-v0 test key {label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


ISSUED = 1793865600  # 2026-11-05T08:00:00Z
SIGNED = ISSUED + 4500  # 2026-11-05T09:15:00Z
ARRIVED = ISSUED + 4510  # 2026-11-05T09:15:10Z
EXAMPLE_NONCE = "Zm9yLWV4YW1wbGUtb25seQ"
DOMAIN_KEY = test_key("domain acme.example s1")
AGENT_KEY = test_key("agent maple-tiger-27")
DNS_NAME = "s1._crest.acme.example"
BOUNDARY = "=_crest_example_1"


def example_claims(**patch: object) -> dict:
    """The example's claims. A patch value of None removes the claim."""
    claims = {
        "cnf": {"jwk": {"crv": "Ed25519", "kty": "OKP", "x": public_x(AGENT_KEY)}},
        "exp": ISSUED + MAX_LIFETIME,
        "from": "maple-tiger-27@acme.example",
        "iat": ISSUED,
        "iss": "acme.example",
        "principal": {"id": "p_Xk29", "mode": "pseudonymous"},
        "scope": "Books restaurant tables for one person, up to $500 per booking.",
        "sub": "ag_7Hq2",
    }
    for k, v in patch.items():
        if v is None:
            claims.pop(k, None)
        else:
            claims[k] = v
    return claims


def example_unsigned(subject: str = "Table for 2, Friday 7 November, 19:30") -> bytes:
    msg = EmailMessage()
    msg["From"] = "Booking agent <Maple-Tiger-27@acme.example>"
    msg["To"] = "Reservations <reservations@bistro.example>"
    msg["Subject"] = subject
    msg["Message-ID"] = "<example-1@acme.example>"
    msg["Date"] = "Thu, 05 Nov 2026 09:15:00 +0000"
    msg.set_content(
        "Hello,\n\nCould you hold a table for 2 this Friday, 7 November, at 19:30?\n"
        "One guest is vegetarian.\n\nThank you\n",
        charset="utf-8",
        cte="quoted-printable",
    )
    msg.add_attachment(
        b"date,time,party\n2026-11-07,19:30,2\n",
        maintype="text",
        subtype="csv",
        filename="booking.csv",
    )
    msg.set_boundary(BOUNDARY)
    return msg.as_bytes(policy=policy.SMTP)


def signed(
    claims: dict | None = None,
    unsigned: bytes | None = None,
    iat: int = SIGNED,
    credential: str | None = None,
) -> bytes:
    if credential is None:
        credential = issue_credential(DOMAIN_KEY, "s1", claims or example_claims())
    raw = unsigned or example_unsigned()
    return sign(raw, credential, AGENT_KEY, iat=iat, nonce=EXAMPLE_NONCE, strict=False)


def credential_with_payload(payload: bytes) -> str:
    """A credential over exact payload bytes, for vectors whose JSON JCS cannot produce."""
    h, p, s = jws_sign({"alg": "EdDSA", "kid": "s1", "typ": "crest-cred+jwt"}, payload, DOMAIN_KEY)
    return f"{h}.{p}.{s}"


MAILBOX = {
    "mailbox": "mbx-reservations",
    "mailbox_addresses": {"reservations@bistro.example", "reservations+web@bistro.example"},
}


def arrival(seen: set, **changes: object) -> Arrival:
    base: dict = {
        "accepted_at": ARRIVED,
        "dkim_pass_domains": {"acme.example"},
        **MAILBOX,
        "dns": {DNS_NAME: [dns_record(DOMAIN_KEY)]},
        "envelope_recipient": "reservations@bistro.example",
    }
    return Arrival(**{**base, **changes}, seen=seen)


Step = tuple[dict, str]  # arrival changes, expected reason
Case = tuple[str, bytes, list[Step]]


def vectors() -> list[Case]:
    raw = signed()
    crlf = b"\r\n"
    record = dns_record(DOMAIN_KEY)

    def edit(old: bytes, new: bytes, data: bytes = raw) -> bytes:
        assert old in data, old
        return data.replace(old, new, 1)

    def before(field_name: bytes, line: bytes) -> bytes:
        return edit(field_name, line + crlf + field_name)

    def set_header(name: bytes, value: bytes, data: bytes = raw) -> bytes:
        start = data.index(name + b": ")
        end = data.index(crlf, start)
        return data[:start] + name + b": " + value + data[end:]

    def one(name: str, data: bytes, want: str, **changes: object) -> Case:
        return (name, data, [(changes, want)])

    def claims(name: str, want: str, **patch: object) -> Case:
        return one(name, signed(example_claims(**patch)), want)

    def dns(name: str, answers: list[str] | None, want: str) -> Case:
        return one(name, raw, want, dns={DNS_NAME: answers})

    payload = jcs(example_claims())
    attachment_part = b'Content-Type: text/csv\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="booking.csv"'
    rfc822_part = b"Content-Type: message/rfc822\r\nContent-Disposition: attachment"
    forwarded = b"From: a@partner.example\r\nSubject: hi\r\n\r\nhello\r\n"
    rfc822 = edit(
        b"ZGF0ZSx0aW1lLHBhcnR5CjIwMjYtMTEtMDcsMTk6MzAsMgo=",
        forwarded.rstrip(),
        edit(attachment_part, rfc822_part),
    )
    other_mailbox = {
        "mailbox": "mbx-tables",
        "mailbox_addresses": {"tables@bistro.example", "reservations@bistro.example"},
    }
    return [
        (
            "replay: one mailbox, its alias, and a second mailbox",
            raw,
            [
                ({}, "verified"),
                ({}, "replay"),
                ({"envelope_recipient": "reservations+web@bistro.example"}, "replay"),
                ({**other_mailbox, "envelope_recipient": "tables@bistro.example"}, "verified"),
            ],
        ),
        # what does not change the verdict
        one("Crest-Signature refolded in transit", edit(b";" + crlf + b" b=", b"; b="), "verified"),
        one("display name changed", edit(b"From: Booking agent", b"From: Bank"), "verified"),
        one("trailing spaces on a body line", edit(b"Thank you", b"Thank you  "), "verified"),
        one("charset name in capitals", edit(b'charset="utf-8"', b'charset="UTF-8"'), "verified"),
        one("attachment renamed (names are not signed)", edit(b"booking.csv", b"invoice.csv"), "verified"),
        one(
            "subject sent as an encoded word",
            set_header(b"Subject", b"=?UTF-8?Q?Table_for_2=2C_Friday_7_November=2C_19=3A30?="),
            "verified",
        ),
        one(
            "non-ASCII subject, as the signer encoded it",
            signed(unsigned=example_unsigned("Réservation pour 2, vendredi")),
            "verified",
        ),
        one("unrelated TXT beside the record", raw, "verified", dns={DNS_NAME: ["hello world", record]}),
        one(
            "a CREST record with a duplicate tag beside the record",
            raw,
            "verified",
            dns={DNS_NAME: ["v=CREST0; v=CREST0; k=ed25519; p=", record]},
        ),
        one("arrived exactly at exp + grace", raw, "verified", accepted_at=ISSUED + MAX_LIFETIME + GRACE),
        one("signed 1 hour before the credential's iat", signed(iat=ISSUED - 3600), "verified"),
        # covered content changed
        one("subject changed", edit(b"Subject: Table for 2", b"Subject: Table for 4"), "signature_invalid"),
        one(
            "an encoded word inside a longer word is literal text",
            set_header(b"Subject", b"Table=?utf-8?q?_for_?=2, Friday 7 November, 19:30"),
            "signature_invalid",
        ),
        one("text changed", edit(b"for 2 this", b"for 4 this"), "signature_invalid"),
        one("Reply-To added", before(b"Subject:", b"Reply-To: x@evil.example"), "signature_invalid"),
        one("Cc added", before(b"Subject:", b"Cc: x@evil.example"), "signature_invalid"),
        one(
            "attachment changed",
            edit(b"MTk6MzAsMgo=", b"MTk6MzAsOAo="),
            "signature_invalid",
        ),
        one(
            "body starts with a BOM (a BOM is content)",
            edit(b"Hello,", b"=EF=BB=BFHello,"),
            "signature_invalid",
        ),
        # layout
        one("HTML part added", add_html(raw), "layout"),
        one("body in ISO-8859-1", edit(b'charset="utf-8"', b'charset="iso-8859-1"'), "layout"),
        one("charset alias utf8", edit(b'charset="utf-8"', b'charset="utf8"'), "layout"),
        one(
            "body marked format=flowed", edit(b'charset="utf-8"', b'charset="utf-8"; format=flowed'), "layout"
        ),
        one("unknown transfer encoding", edit(b"quoted-printable", b"x-uuencode"), "layout"),
        one("message/rfc822 attachment", rfc822, "layout"),
        # malformed
        one("second To field", before(b"Subject:", b"To: x@evil.example"), "malformed"),
        one("second Subject field", before(b"Message-ID:", b"Subject: Table for 8"), "malformed"),
        one(
            "second Content-Type in the body part",
            edit(
                b"Content-Transfer-Encoding: quoted-printable",
                b"Content-Type: text/plain; format=flowed\r\nContent-Transfer-Encoding: quoted-printable",
            ),
            "malformed",
        ),
        one("quoted local part in Cc", before(b"Subject:", b'Cc: "a b"@partner.example'), "malformed"),
        one("quoted local part in From", edit(b"<Maple-Tiger-27@", b'<"Maple-Tiger-27"@'), "malformed"),
        one("group in To", set_header(b"To", b"Team: reservations@bistro.example;"), "malformed"),
        one("domain literal in Cc", before(b"Subject:", b"Cc: bob@[192.0.2.1]"), "malformed"),
        one("non-ASCII domain in Cc", before(b"Subject:", "Cc: bob@café.example".encode()), "malformed"),
        one("comment in To", set_header(b"To", b"reservations@bistro.example (front desk)"), "malformed"),
        one(
            "unquoted @ in a display name",
            set_header(b"To", b"reservations@bistro.example <reservations@bistro.example>"),
            "malformed",
        ),
        one(
            "empty member in To",
            set_header(b"To", b"reservations@bistro.example, , x@bistro.example"),
            "malformed",
        ),
        one(
            "a character split across two encoded words",
            set_header(b"Subject", b"=?utf-8?q?caf=C3?= =?utf-8?q?=A9?="),
            "malformed",
        ),
        one("encoded word with a language tag", set_header(b"Subject", b"=?utf-8*en?q?Table?="), "malformed"),
        one(
            "encoded word in another charset", set_header(b"Subject", b"=?iso-8859-1?q?caf=E9?="), "malformed"
        ),
        one("bad quoted-printable in the body", edit(b"Hello,", b"Hello=ZZ,"), "malformed"),
        one("bad base64 in the attachment", edit(b"MTk6MzAsMgo=", b"MTk6MzAs*go="), "malformed"),
        one("missing v tag", edit(b"Crest-Signature: v=0;", b"Crest-Signature:"), "malformed"),
        one("tag name in capitals", edit(b"Crest-Signature: v=0", b"Crest-Signature: V=0"), "malformed"),
        one("padded base64url in c", edit(b"9mcKLCQ;", b"9mcKLCQ==;"), "malformed"),
        one(
            "a fraction in exp",
            signed(
                credential=credential_with_payload(
                    payload.replace(b'"exp":1793952000', b'"exp":1793952000.0')
                )
            ),
            "malformed",
        ),
        one(
            "a duplicate claim",
            signed(credential=credential_with_payload(payload.replace(b'"sub":', b'"sub":"x","sub":'))),
            "malformed",
        ),
        one(
            "credential over 2,048 octets",
            signed(example_claims(**{"example.com:pad": "x" * 1200})),
            "malformed",
        ),
        # count, DKIM, version
        one("second Crest-Signature", before(b"From:", b"Crest-Signature: v=0"), "multiple_signatures"),
        one("no Crest-Signature", raw[raw.index(b"From:") :], "no_signature"),
        one(
            "DKIM passes only for mail.acme.example",
            raw,
            "dkim_unaligned",
            dkim_pass_domains={"mail.acme.example"},
        ),
        one("v=1", edit(b"Crest-Signature: v=0", b"Crest-Signature: v=1"), "unsupported_version"),
        # DNS
        dns("DNS lookup failed", None, "dns_error"),
        one("no record at the selector", raw, "key_not_found", dns={}),
        dns("two CREST records", [record, dns_record(test_key("other"))], "key_not_found"),
        dns("a k=rsa CREST record beside the record", [record, "v=CREST0; k=rsa; p=AAAA"], "key_not_found"),
        dns("record without p", ["v=CREST0; k=ed25519"], "key_not_found"),
        dns("key of the wrong length", ["v=CREST0; k=ed25519; p=AAAA"], "key_not_found"),
        dns("key in padded base64", [record + "="], "key_not_found"),
        dns("record with empty p=", ["v=CREST0; k=ed25519; p="], "key_revoked"),
        dns("record holds a different key", [dns_record(test_key("other"))], "credential_invalid"),
        # credential contents
        claims("sub with a trailing newline", "credential_invalid", sub="ag_7Hq2\n"),
        claims("sub as a number", "credential_invalid", sub=12345),
        claims("no from claim", "credential_invalid", **{"from": None}),
        claims(
            "from claim not in canonical form",
            "credential_invalid",
            **{"from": "Maple-Tiger-27@acme.example"},
        ),
        claims("lifetime of 25 hours", "credential_invalid", exp=ISSUED + 25 * 3600),
        claims("bidi control in scope", "credential_invalid", scope="Books tables \u202eFOR FREE"),
        claims(
            "agent key of 31 octets",
            "credential_invalid",
            cnf={"jwk": {"crv": "Ed25519", "kty": "OKP", "x": b64u(b"\x01" * 31)}},
        ),
        # time and address
        one(
            "arrived 1 second after exp + grace",
            raw,
            "credential_expired",
            accepted_at=ISSUED + MAX_LIFETIME + GRACE + 1,
        ),
        one(
            "From is another address on the same host",
            edit(b"<Maple-Tiger-27@", b"<oak-fox-11@"),
            "from_mismatch",
        ),
        one("signature iat 10 minutes after arrival", signed(iat=ARRIVED + 600), "signature_invalid"),
        one(
            "delivered to a mailbox not in To or Cc (Bcc)",
            raw,
            "not_addressed",
            mailbox="mbx-x",
            mailbox_addresses={"x@bistro.example"},
            envelope_recipient="x@bistro.example",
        ),
    ]


def add_html(raw: bytes) -> bytes:
    end = f"--{BOUNDARY}--".encode()
    html = f"--{BOUNDARY}\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Table for 8</p>\r\n"
    return raw.replace(end, html.encode() + end)


def run(cases: list[Case]) -> list[tuple[str, int, str, str]]:
    """Run every step of every case. A case's steps share one replay store."""
    results = []
    for name, data, steps in cases:
        seen: set = set()
        for n, (changes, want) in enumerate(steps):
            got = verify(data, arrival(seen, **changes)).reason
            results.append((name, n, want, got))
    return results


def vector_json(cases: list[Case]) -> list[dict]:
    out = []
    for name, data, steps in cases:
        deliveries = []
        for changes, want in steps:
            a = arrival(set(), **changes)
            deliveries.append(
                {
                    "accepted_at": a.accepted_at,
                    "dkim_pass_domains": sorted(a.dkim_pass_domains),
                    "envelope_recipient": a.envelope_recipient,
                    "mailbox": a.mailbox,
                    "mailbox_addresses": sorted(a.mailbox_addresses),
                    "dns_txt": a.dns,
                    "expected": want,
                }
            )
        out.append({"name": name, "message": base64.b64encode(data).decode(), "deliveries": deliveries})
    return out


def print_example() -> None:
    raw = signed()
    parsed = BytesParser(policy=policy.compat32).parsebytes(raw)
    value = tags(raw_values(parsed, HEADER)[0])
    credential = value["c"]
    print("## DNS\n")
    print(f'{DNS_NAME}. TXT "{dns_record(DOMAIN_KEY)}"\n')
    print("## Credential protected header\n")
    print(unb64u(credential.split(".")[0]).decode(), "\n")
    print("## Credential claims\n")
    print(json.dumps(strict_json(unb64u(credential.split(".")[1])), indent=2), "\n")
    print("## Credential (compact)\n")
    print(credential, "\n")
    print("## Signing input (JCS, one line)\n")
    print(jcs(signing_input(parsed, credential)).decode(), "\n")
    print("## Agent signature (tag b)\n")
    print(value["b"], "\n")
    print("## Message as sent, before the issuer's DKIM signature\n")
    print(raw.decode().replace("\r\n", "\n"))


def main() -> int:
    cases = vectors()
    if "--json" in sys.argv:
        doc = {
            "about": "CREST v0 test vectors. Each message is base64 of the octets as accepted. "
            "Deliveries run in order and share one replay store; a missing DNS name is "
            "NXDOMAIN and null is a failed lookup.",
            "cases": vector_json(cases),
        }
        print(json.dumps(doc, indent=1, ensure_ascii=False))
        return 0
    if "--example" in sys.argv:
        print_example()
    failed = 0
    for name, n, want, got in run(cases):
        ok = got == want
        failed += not ok
        label = name if n == 0 else f"  ... delivery {n + 1}"
        print(f"{'ok  ' if ok else 'FAIL'}  {want:<20} {label}" + ("" if ok else f"  (got {got})"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
