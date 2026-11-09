"""The results table: one row per receiver and message, direct deliveries apart from forwards."""

from __future__ import annotations

import json
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
        "value on different line breaks, which the spec allows (section 3.1).",
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


def write(
    run_dir: Path, rows: list[Row], run_id: str, sent_at: str, sender: str
) -> tuple[Path, Path]:
    md = run_dir / "results.md"
    js = run_dir / "results.json"
    md.write_text(markdown(rows, run_id, sent_at, sender), encoding="utf-8")
    js.write_text(
        json.dumps([r.__dict__ for r in rows], indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return md, js
