"""The results table: one row per receiver and message, direct deliveries apart from forwards."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .messages import LABELS

STATUS_WORD = {
    "identical": "intact",
    "refolded": "intact (refolded)",
    "missing": "dropped",
    "truncated": "truncated",
    "altered": "altered",
    "duplicated": "duplicated",
    "captured-only": "seen",
}


@dataclass
class Row:
    receiver: str
    provider: str
    account_type: str
    hops: list[str]
    label: str
    status: str  # header diff status, or "not captured" / "not sent"
    verified: bool | None
    reason: str
    sent_octets: int | None
    captured_octets: int | None
    sent_lines: int | None
    captured_lines: int | None
    dkim_pass_domains: list[str] = field(default_factory=list)
    signed_fields_changed: list[str] = field(default_factory=list)
    arrival_source: str = ""
    dns_source: str = ""
    capture_kind: str = ""
    note: str = ""

    @property
    def direct(self) -> bool:
        return not self.hops


def row_from_outcome(receiver, label: str, outcome: dict, capture_kind: str) -> Row:
    h = outcome["header"]
    return Row(
        receiver=receiver.name,
        provider=receiver.provider,
        account_type=receiver.account_type,
        hops=list(receiver.hops),
        label=label,
        status=h["status"],
        verified=outcome["verified"],
        reason=outcome["reason"],
        sent_octets=h["sent_octets"],
        captured_octets=h["captured_octets"],
        sent_lines=h["sent_lines"],
        captured_lines=h["captured_lines"],
        dkim_pass_domains=outcome["dkim_pass_domains"],
        signed_fields_changed=outcome["signed_fields_changed"],
        arrival_source=outcome["arrival_source"],
        dns_source=outcome["dns_source"],
        capture_kind=capture_kind,
        note=h.get("detail", ""),
    )


def _cell(row: Row) -> str:
    if row.status in ("not captured", "not sent"):
        return row.status
    word = STATUS_WORD.get(row.status, row.status)
    verdict = "verified" if row.verified else f"not verified: {row.reason}"
    extra = ""
    if row.status == "refolded":
        extra = f" {row.sent_lines}->{row.captured_lines} lines"
    if row.note and row.status in ("truncated", "altered"):
        extra = f" ({row.note})"
    return f"{word}{extra}; {verdict}"


def table(rows: list[Row], title: str) -> str:
    if not rows:
        return ""
    by_receiver: dict[str, list[Row]] = {}
    for r in rows:
        by_receiver.setdefault(r.receiver, []).append(r)
    head = ["Receiver", "Provider", "Account", "Capture"] + list(LABELS)
    if any(r.hops for r in rows):
        head.insert(4, "Via")
    lines = [f"### {title}", "", "| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for name, group in by_receiver.items():
        first = group[0]
        cells = [name, first.provider, first.account_type or "-", first.capture_kind or "-"]
        if "Via" in head:
            cells.append(" then ".join(first.hops) or "direct")
        for label in LABELS:
            match = [r for r in group if r.label == label]
            cells.append(_cell(match[0]) if match else "not sent")
        lines.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    return "\n".join(lines) + "\n"


def markdown(rows: list[Row], run_id: str, sent_at: str, sender: str) -> str:
    direct = [r for r in rows if r.direct]
    forwarded = [r for r in rows if not r.direct]
    out = [
        f"# Header survival results: run {run_id}",
        "",
        f"Sent {sent_at} from `{sender}` through Amazon SES. Messages: `minimal` (one short header),",
        "`cap` (the header at exactly 2,560 octets with a 2,048-octet credential), `attachments`",
        "(a CSV and a PDF attached). Each cell: what the receiver did to the header, then the",
        "reference verifier's verdict on the stored message with the receiver's own inputs.",
        "",
        "`intact` means the whitespace-removed value is what was sent; `refolded` means the same",
        "value on different line breaks, which the spec allows (section 6.2).",
        "",
    ]
    out.append(table(direct, "Direct deliveries"))
    if forwarded:
        out.append(
            table(forwarded, "Recorded forwards (behaviour of the whole path, not one provider)")
        )
    changed = [r for r in rows if r.signed_fields_changed]
    if changed:
        out += ["### Signed fields that changed in transit", ""]
        for r in changed:
            out.append(f"- {r.receiver} / {r.label}: {', '.join(r.signed_fields_changed)}")
        out.append("")
    out += ["### Inputs used", ""]
    for r in rows:
        if r.status in ("not captured", "not sent"):
            continue
        dk = ", ".join(r.dkim_pass_domains) or "none"
        out.append(
            f"- {r.receiver} / {r.label}: DKIM pass for {dk}; arrival from {r.arrival_source}; DNS {r.dns_source}"
        )
    return "\n".join(out) + "\n"


def redact(rows: list[Row], private_domains: dict[str, str]) -> list[Row]:
    """The rows with the operator's own domains replaced by their neutral labels wherever a
    receiver reported them as DKIM signers. The sender's domain and public infrastructure
    (amazonses.com, cloudflare-email.net) stay: they are the evidence."""
    if not private_domains:
        return rows
    out = []
    for r in rows:
        d = dict(r.__dict__)
        seen: list[str] = []
        for dom in r.dkim_pass_domains:
            label = private_domains.get(dom.lower(), dom)
            if label not in seen:
                seen.append(label)
        d["dkim_pass_domains"] = seen
        out.append(Row(**d))
    return out


def redact_text(text: str, private_domains: dict[str, str]) -> str:
    for dom, label in private_domains.items():
        text = re.sub(re.escape(dom), label, text, flags=re.IGNORECASE)
    return text


def write(
    out_dir: Path, rows: list[Row], run_id: str, sent_at: str, sender: str
) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / "results.md"
    js = out_dir / "results.json"
    md.write_text(markdown(rows, run_id, sent_at, sender), encoding="utf-8")
    js.write_text(
        json.dumps([r.__dict__ for r in rows], indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return md, js


HEADER_FIELD = re.compile(rb"(?im)^Colophon-Signature:[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*")


def header_fields(raw: bytes) -> list[str]:
    """Every `Colophon-Signature` field in a message's header block, folded as stored."""
    head = raw.split(b"\r\n\r\n", 1)[0]
    return [m.group(0).decode("utf-8", "replace") for m in HEADER_FIELD.finditer(head)]


def headers_markdown(copies: list[tuple[str, str, bytes, bytes | None]], run_id: str) -> str:
    """The header as sent and as stored for each captured copy: the one piece of a stored
    message that is publishable, since it holds no address, host or storage key. `copies` is
    (receiver, label, sent raw, captured raw or None)."""
    out = [
        f"# Colophon-Signature as sent and as stored: run {run_id}",
        "",
        "Each block is the exact field from the message's header block, with its line breaks.",
        "Only this header is reproduced; the rest of each stored message stays private.",
        "",
    ]
    for receiver, label, sent, captured in copies:
        out += [f"## {receiver} / {label}", "", "As sent:", "", "```"]
        out += header_fields(sent) or ["(none)"]
        out += ["```", "", "As stored:", "", "```"]
        if captured is None:
            out.append("(not captured)")
        else:
            out += header_fields(captured) or ["(none)"]
        out += ["```", ""]
    return "\n".join(out)
