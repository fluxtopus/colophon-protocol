"""Raw-message mode for the reference verifier.

A capture is the message as the receiver stored it. This module derives the verifier's inputs from
it and from the receiver's description (spec section 7.1), runs the sketch's `verify`, and compares
the Colophon-Signature header with the message as sent."""

from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

from . import authres
from .reference import ref

WS = re.compile(r"[ \t\r\n]+")
DNS_BUDGET_SECONDS = 2.0


@dataclass
class ReceiverInputs:
    """What the harness knows about the receiver. Anything left None is derived from the capture."""

    mailbox: str
    addresses: set[str]
    arrival: int | None = None  # else the topmost Received field's date
    dkim_pass_domains: set[str] | None = None  # else the receiver's Authentication-Results
    authserv_ids: list[str] | None = None  # the receiver's own authserv-id(s), if known
    dns: dict[str, list[str] | None] | None = None  # else a live TXT lookup
    envelope_recipient: str = ""


@dataclass
class HeaderDiff:
    """The Colophon-Signature header as captured, against the one sent."""

    status: str  # identical, refolded, missing, duplicated, truncated, altered, or captured-only
    sent_octets: int | None
    captured_octets: int | None
    captured_count: int
    sent_lines: int | None = None
    captured_lines: int | None = None
    detail: str = ""

    @property
    def intact(self) -> bool:
        return self.status in ("identical", "refolded")


@dataclass
class Outcome:
    verified: bool
    reason: str
    agent: dict | None
    header: HeaderDiff
    arrival: int | None
    arrival_source: str
    dkim_pass_domains: list[str]
    authserv_id: str
    dkim_note: str
    dns_name: str | None
    dns_answers: list[str] | None
    dns_source: str
    signed_fields_changed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


def parse_message(raw: bytes) -> Message:
    return BytesParser(policy=policy.compat32).parsebytes(raw)


def header_instances(msg: Message, name: str) -> list[str]:
    """Each instance's value as it is in the message, folding kept."""
    return [str(v) for k, v in msg.raw_items() if k.lower() == name.lower()]


def compact(value: str) -> str:
    return WS.sub("", value)


def header_diff(captured: Message, sent: Message | None) -> HeaderDiff:
    got = header_instances(captured, ref.HEADER)
    got_compact = [compact(v) for v in got]
    if sent is None:
        if not got:
            return HeaderDiff("missing", None, None, 0)
        return HeaderDiff(
            "captured-only",
            None,
            len(got_compact[0].encode()),
            len(got),
            captured_lines=got[0].count("\n") + 1,
            detail="no sent message to compare with",
        )
    want = header_instances(sent, ref.HEADER)
    if len(want) != 1:
        raise ValueError("the sent message must carry exactly one Colophon-Signature")
    want_compact = compact(want[0])
    sent_octets, sent_lines = len(want_compact.encode()), want[0].count("\n") + 1
    if not got:
        return HeaderDiff("missing", sent_octets, None, 0, sent_lines)
    if len(got) > 1:
        return HeaderDiff(
            "duplicated", sent_octets, len(got_compact[0].encode()), len(got), sent_lines
        )
    captured_octets, captured_lines = len(got_compact[0].encode()), got[0].count("\n") + 1
    if got_compact[0] == want_compact:
        status = "identical" if got[0] == want[0] else "refolded"
        return HeaderDiff(status, sent_octets, captured_octets, 1, sent_lines, captured_lines)
    if want_compact.startswith(got_compact[0]):
        detail = f"cut after {captured_octets} of {sent_octets} octets"
        return HeaderDiff(
            "truncated", sent_octets, captured_octets, 1, sent_lines, captured_lines, detail
        )
    prefix = 0
    for a, b in zip(got_compact[0], want_compact):
        if a != b:
            break
        prefix += 1
    detail = f"first difference at octet {prefix}"
    return HeaderDiff(
        "altered", sent_octets, captured_octets, 1, sent_lines, captured_lines, detail
    )


def arrival_time(msg: Message) -> tuple[int | None, str]:
    """The topmost Received field's date: the receiver's boundary server stamps it when it accepts
    the message. Falls back to Date, which is the sender's clock and only a stand-in."""
    received = header_instances(msg, "Received")
    for value in received[:1]:
        _, _, date = value.rpartition(";")
        try:
            return int(parsedate_to_datetime(date.strip()).timestamp()), "topmost Received"
        except (TypeError, ValueError):
            continue
    for value in header_instances(msg, "Date")[:1]:
        try:
            return int(
                parsedate_to_datetime(value.strip()).timestamp()
            ), "Date header (no usable Received)"
        except (TypeError, ValueError):
            continue
    return None, "none found"


def credential_selector_and_host(msg: Message) -> tuple[str, str] | None:
    """`<kid>._colophon.<host>` from the capture, when the header and From allow it."""
    try:
        froms = ref.address_list(msg, "From")
        values = header_instances(msg, ref.HEADER)
        if len(froms) != 1 or len(values) != 1:
            return None
        t = ref.tags(compact(values[0]))
        header = ref.strict_json(ref.unb64u(t["c"].split(".")[0]))
        selector = header.get("kid")
        if not isinstance(selector, str) or not ref.LABEL.fullmatch(selector):
            return None
        return selector, froms[0].rpartition("@")[2]
    except (ref.Fail, ValueError, KeyError, IndexError, AttributeError):
        return None


def lookup_txt(name: str) -> list[str] | None:
    """TXT answers at `name`, each record's strings joined (section 7.4), within the 2-second
    budget. [] for no record; None for a failed lookup."""
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_BUDGET_SECONDS
    try:
        answer = resolver.resolve(name, "TXT", raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.exception.DNSException):
        return None
    out = []
    for rdata in answer.rrset or []:
        out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
    return out


def signed_fields_changed(captured: Message, sent: Message, credential: str) -> list[str]:
    """Members of the signing input that differ between the message as sent and as captured."""
    try:
        before = ref.signing_input(sent, credential)
        after = ref.signing_input(captured, credential)
    except ref.Fail as failed:
        return [f"signing input not buildable: {failed.reason}"]
    return [k for k in before if before[k] != after.get(k)]


def check(captured_raw: bytes, inputs: ReceiverInputs, sent_raw: bytes | None = None) -> Outcome:
    captured = parse_message(captured_raw)
    sent = parse_message(sent_raw) if sent_raw else None
    notes: list[str] = []
    diff = header_diff(captured, sent)

    arrival, arrival_source = inputs.arrival, "given"
    if arrival is None:
        arrival, arrival_source = arrival_time(captured)
    if arrival is None:
        arrival, arrival_source = int(time.time()), "now (no Received or Date)"
        notes.append("arrival time is the time of checking")

    if inputs.dkim_pass_domains is not None:
        dkim, authserv, dkim_note = set(inputs.dkim_pass_domains), "", "given"
    else:
        results = authres.receiver_results(captured, inputs.authserv_ids)
        dkim, authserv, dkim_note = (
            set(results.dkim_pass_domains),
            results.authserv_id,
            results.note,
        )

    dns_name: str | None = None
    answers: list[str] | None = None
    dns_source = "not needed"
    located = credential_selector_and_host(captured)
    if located:
        selector, host = located
        dns_name = f"{selector}._colophon.{host}"
        if inputs.dns is not None:
            answers, dns_source = inputs.dns.get(dns_name, []), "given"
        elif host.lower() in {d.lower() for d in dkim}:
            answers, dns_source = lookup_txt(dns_name), "live lookup"
        else:
            dns_source = "skipped: DKIM not aligned, so no lookup (section 7.4)"
    dns_map = {dns_name: answers} if dns_name and dns_source != "skipped" else {}
    if dns_name and answers is None and dns_source == "live lookup":
        dns_map = {dns_name: None}

    arrival_inputs = ref.Arrival(
        accepted_at=arrival,
        dkim_pass_domains=dkim,
        mailbox=inputs.mailbox,
        mailbox_addresses=set(inputs.addresses),
        dns=dns_map,
        envelope_recipient=inputs.envelope_recipient,
    )
    verdict = ref.verify(captured_raw, arrival_inputs)

    changed: list[str] = []
    if sent is not None and diff.intact:
        try:
            credential = ref.tags(compact(header_instances(sent, ref.HEADER)[0]))["c"]
            changed = signed_fields_changed(captured, sent, credential)
        except (ref.Fail, KeyError):
            changed = ["sent header unreadable"]

    return Outcome(
        verified=verdict.verified,
        reason=verdict.reason,
        agent=verdict.agent,
        header=diff,
        arrival=arrival,
        arrival_source=arrival_source,
        dkim_pass_domains=sorted(dkim),
        authserv_id=authserv,
        dkim_note=dkim_note,
        dns_name=dns_name,
        dns_answers=answers,
        dns_source=dns_source,
        signed_fields_changed=changed,
        notes=notes,
    )
