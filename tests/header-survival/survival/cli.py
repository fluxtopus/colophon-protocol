"""Command line for the header-survival test.

    keys      generate the private keys (outside the repository) and print the DNS record
    build     build the three messages for every receiver into runs/<run-id>/sent/
    send      send them through SES
    capture   fetch what arrived into runs/<run-id>/captured/
    check     one raw message against one sent message (or alone)
    report    results.md and results.json for a run

A run directory holds everything about one run: the messages as sent, the captures, and the
results. Runs worth keeping are copied under results/ by hand."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import secrets
import sys
import time
from pathlib import Path

from . import capture as cap_mod
from . import check as check_mod
from . import keys as keys_mod
from . import messages, report, sender
from .receivers import Receiver, load

HERE = Path(__file__).resolve().parents[1]
RUNS = HERE / "runs"
EXPORTS = RUNS / "exports"


def export_dir(receiver_name: str) -> Path:
    return EXPORTS / receiver_name


def run_dir(run_id: str) -> Path:
    return RUNS / run_id


def new_run_id() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(2)


def load_keys(args) -> keys_mod.Keys:
    if args.test_keys:
        return keys_mod.test_keys()
    if args.key_dir:
        d = Path(args.key_dir)
        return keys_mod.from_files(d / "domain.key", d / "agent.key")
    return keys_mod.from_environment()


def meta_path(rd: Path, receiver: str, label: str) -> Path:
    return rd / "sent" / receiver / f"{label}.json"


def sent_path(rd: Path, receiver: str, label: str) -> Path:
    return rd / "sent" / receiver / f"{label}.eml"


def captured_path(rd: Path, receiver: str, label: str) -> Path:
    return rd / "captured" / receiver / f"{label}.eml"


# ---------------------------------------------------------------- commands


def cmd_keys(args) -> int:
    k = keys_mod.generate(Path(args.key_dir))
    print(f"wrote domain.key and agent.key under {args.key_dir} (mode 0600)")
    print(f"domain public key: {k.domain_public}")
    print(f"agent public key:  {k.agent_public}")
    print(f'TXT record for {messages.SELECTOR}._colophon.<sender host>: "{k.dns_record()}"')
    return 0


def cmd_build(args) -> int:
    plan = load(Path(args.receivers))
    k = load_keys(args)
    run_id = args.run_id or new_run_id()
    rd = run_dir(run_id)
    now = int(time.time())
    for receiver in plan.receivers:
        if receiver.capture.kind == "file":
            export_dir(receiver.name).mkdir(parents=True, exist_ok=True)
            print(f"{receiver.name}: export the stored messages into {export_dir(receiver.name)}")
        for label in args.labels:
            built = messages.build(
                label,
                keys=k,
                sender=plan.sender,
                recipient=receiver.address,
                run_id=run_id,
                now=now,
                display=plan.display,
            )
            p = sent_path(rd, receiver.name, label)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(built.raw)
            meta_path(rd, receiver.name, label).write_text(
                json.dumps(
                    {
                        "label": label,
                        "receiver": receiver.name,
                        "recipient": receiver.address,
                        "token": f"{run_id}/{label}",
                        "header_octets": built.header_octets,
                        "credential_octets": built.credential_octets,
                        "nonce": built.nonce,
                        "built_at": now,
                        "keys": k.source,
                    },
                    indent=1,
                )
                + "\n",
                encoding="utf-8",
            )
            print(
                f"built {receiver.name}/{label}: header {built.header_octets} octets, credential {built.credential_octets}"
            )
    (rd / "run.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "sender": plan.sender,
                "region": plan.region,
                "built_at": now,
                "dns_record": k.dns_record(),
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"run {run_id} in {rd}")
    return 0


def cmd_send(args) -> int:
    plan = load(Path(args.receivers))
    rd = run_dir(args.run_id)
    info = json.loads((rd / "run.json").read_text(encoding="utf-8"))
    ses = sender.client(plan.region, args.profile)
    state = sender.account_state(ses)
    print(
        f"SES account: production access {state['production_access']}, sending {state['sending_enabled']}, quota {state['sent_last_day']}/{state['max_per_day']} per day"
    )
    if not state["production_access"] and not args.allow_sandbox:
        print(
            "account is in the SES sandbox: only verified recipients receive mail; pass --allow-sandbox to send anyway",
            file=sys.stderr,
        )
        return 2
    receivers = [plan.receiver(n) for n in args.only] if args.only else plan.receivers
    sent_at = int(time.time())
    for receiver in receivers:
        for label in args.labels:
            meta_file = meta_path(rd, receiver.name, label)
            if not meta_file.exists():
                print(f"skip {receiver.name}/{label}: not built", file=sys.stderr)
                continue
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            if "ses_message_id" in meta and not args.again:
                print(f"skip {receiver.name}/{label}: already sent as {meta['ses_message_id']}")
                continue
            if args.dry_run:
                print(f"would send {receiver.name}/{label} to {receiver.address}")
                continue
            result = sender.send_raw(
                ses, sent_path(rd, receiver.name, label).read_bytes(), plan.sender, receiver.address
            )
            meta.update(ses_message_id=result.ses_message_id, sent_at=sent_at)
            meta_file.write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
            print(f"sent {receiver.name}/{label} to {receiver.address}: {result.ses_message_id}")
    info.setdefault("sent_at", sent_at)
    (rd / "run.json").write_text(json.dumps(info, indent=1) + "\n", encoding="utf-8")
    return 0


def cmd_capture(args) -> int:
    plan = load(Path(args.receivers))
    rd = run_dir(args.run_id)
    info = json.loads((rd / "run.json").read_text(encoding="utf-8"))
    since = float(info.get("sent_at", info["built_at"]))
    receivers = [plan.receiver(n) for n in args.only] if args.only else plan.receivers
    failures = 0
    for receiver in receivers:
        for label in args.labels:
            out = captured_path(rd, receiver.name, label)
            if out.exists() and not args.again:
                print(f"have {receiver.name}/{label}")
                continue
            token = f"{args.run_id}/{label}"
            try:
                got = cap_mod.wait_for(
                    receiver.capture,
                    token,
                    since=since,
                    state_dir=HERE,
                    export_dir=export_dir(receiver.name),
                    timeout=0 if receiver.capture.kind == "file" else args.timeout,
                    recipient=receiver.address,
                )
            except cap_mod.NotFound as missing:
                print(f"missing {receiver.name}/{label}: {missing}", file=sys.stderr)
                failures += 1
                continue
            except (ValueError, OSError, cap_mod.Unavailable) as unavailable:
                # A credential not there yet or a mailbox that cannot be reached: report the
                # receiver and go on to the next one, so one gap does not block the others.
                print(f"unavailable {receiver.name}: {unavailable}", file=sys.stderr)
                failures += 1
                break
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(got.raw)
            out.with_suffix(".json").write_text(
                json.dumps(
                    {"where": got.where, "kind": got.kind, "captured_at": int(time.time())},
                    indent=1,
                )
                + "\n",
                encoding="utf-8",
            )
            print(f"captured {receiver.name}/{label} from {got.where}")
    return 1 if failures else 0


def inputs_for(receiver: Receiver, args) -> check_mod.ReceiverInputs:
    dns = None
    if args.dns_record:
        name, _, value = args.dns_record.partition("=")
        dns = {name.strip(): [value.strip()]}
    return check_mod.ReceiverInputs(
        mailbox=receiver.mailbox,
        addresses=set(receiver.addresses),
        authserv_ids=list(receiver.authserv_ids) or None,
        dns=dns,
    )


def cmd_check(args) -> int:
    captured = Path(args.captured).read_bytes()
    sent = Path(args.sent).read_bytes() if args.sent else None
    dns = None
    if args.dns_record:
        name, _, value = args.dns_record.partition("=")
        dns = {name.strip(): [value.strip()]}
    inputs = check_mod.ReceiverInputs(
        mailbox=args.mailbox,
        addresses=set(args.address or [args.mailbox]),
        arrival=args.arrival,
        dkim_pass_domains=set(args.dkim_pass) if args.dkim_pass else None,
        authserv_ids=args.authserv or None,
        dns=dns,
    )
    outcome = check_mod.check(captured, inputs, sent)
    print(json.dumps(outcome.as_dict(), indent=1, ensure_ascii=False))
    return 0 if outcome.verified else 1


def cmd_report(args) -> int:
    plan = load(Path(args.receivers))
    rd = run_dir(args.run_id)
    info = json.loads((rd / "run.json").read_text(encoding="utf-8"))
    rows: list[report.Row] = []
    copies: list[tuple[str, str, bytes, bytes | None]] = []
    for receiver in plan.receivers:
        for label in messages.LABELS:
            sp, cp = sent_path(rd, receiver.name, label), captured_path(rd, receiver.name, label)
            meta = (
                json.loads(meta_path(rd, receiver.name, label).read_text()) if sp.exists() else {}
            )
            if "ses_message_id" not in meta and not args.unsent:
                rows.append(
                    report.Row(
                        receiver.name,
                        receiver.provider,
                        receiver.account_type,
                        list(receiver.hops),
                        label,
                        "not sent",
                        None,
                        "",
                        None,
                        None,
                        None,
                        None,
                    )
                )
                continue
            copies.append(
                (receiver.name, label, sp.read_bytes(), cp.read_bytes() if cp.exists() else None)
            )
            if not cp.exists():
                rows.append(
                    report.Row(
                        receiver.name,
                        receiver.provider,
                        receiver.account_type,
                        list(receiver.hops),
                        label,
                        "not captured",
                        None,
                        "",
                        None,
                        None,
                        None,
                        None,
                    )
                )
                continue
            kind = (
                json.loads(cp.with_suffix(".json").read_text()).get("kind", "")
                if cp.with_suffix(".json").exists()
                else ""
            )
            outcome = check_mod.check(
                cp.read_bytes(), inputs_for(receiver, args), sp.read_bytes()
            ).as_dict()
            (rd / "captured" / receiver.name / f"{label}.outcome.json").write_text(
                json.dumps(outcome, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            rows.append(report.row_from_outcome(receiver, label, outcome, kind))
    sent_at = dt.datetime.fromtimestamp(
        info.get("sent_at", info["built_at"]), dt.timezone.utc
    ).strftime("%Y-%m-%d %H:%M UTC")
    out_dir = Path(args.out) if args.out else rd
    rows = report.redact(rows, plan.private_domains)
    md, js = report.write(out_dir, rows, args.run_id, sent_at, info["sender"])
    hd = out_dir / "headers.md"
    headers = report.redact_text(report.headers_markdown(copies, args.run_id), plan.private_domains)
    hd.write_text(headers, encoding="utf-8")
    print(md.read_text(encoding="utf-8"))
    print(f"wrote {md}, {js} and {hd}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- parser


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m survival",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp, receivers=True, run=True, labels=True, keys=False):
        if receivers:
            sp.add_argument("--receivers", default=str(HERE / "receivers.json"))
        if run:
            sp.add_argument("--run-id", required=True)
        if labels:
            sp.add_argument(
                "--labels", nargs="+", default=list(messages.LABELS), choices=messages.LABELS
            )
        if keys:
            g = sp.add_mutually_exclusive_group()
            g.add_argument("--key-dir", help="directory with domain.key and agent.key")
            g.add_argument(
                "--test-keys", action="store_true", help="the deterministic keys (dry runs only)"
            )

    k = sub.add_parser("keys", help="generate private keys outside the repository")
    k.add_argument("key_dir")
    k.set_defaults(func=cmd_keys)

    b = sub.add_parser("build", help="build the messages for a run")
    common(b, run=False, keys=True)
    b.add_argument("--run-id")
    b.set_defaults(func=cmd_build)

    s = sub.add_parser("send", help="send a built run through SES")
    common(s)
    s.add_argument("--profile", help="AWS profile")
    s.add_argument("--only", nargs="*", help="receiver names")
    s.add_argument("--allow-sandbox", action="store_true")
    s.add_argument("--again", action="store_true", help="send even if already sent")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_send)

    c = sub.add_parser("capture", help="fetch what arrived")
    common(c)
    c.add_argument("--only", nargs="*")
    c.add_argument("--timeout", type=float, default=300)
    c.add_argument("--again", action="store_true")
    c.set_defaults(func=cmd_capture)

    ch = sub.add_parser("check", help="verify one raw message with receiver inputs")
    ch.add_argument("captured")
    ch.add_argument("--sent", help="the message as sent, for the header diff")
    ch.add_argument("--mailbox", required=True)
    ch.add_argument("--address", action="append", help="an address of the mailbox (repeatable)")
    ch.add_argument(
        "--arrival", type=int, help="acceptance time (epoch seconds); else from Received"
    )
    ch.add_argument(
        "--dkim-pass", nargs="*", help="DKIM pass domains; else from Authentication-Results"
    )
    ch.add_argument("--authserv", action="append", help="the receiver's authserv-id (repeatable)")
    ch.add_argument("--dns-record", help="NAME=VALUE to use instead of a live TXT lookup")
    ch.set_defaults(func=cmd_check)

    r = sub.add_parser("report", help="write results.md and results.json")
    common(r, labels=False)
    r.add_argument("--dns-record", help="NAME=VALUE to use instead of a live TXT lookup")
    r.add_argument(
        "--unsent",
        action="store_true",
        help="report captures of messages this tool did not send (dry runs, hand delivery)",
    )
    r.add_argument(
        "--out",
        help="directory for results.md, results.json and headers.md (default: the run directory;"
        " results/<run-id> is what a run publishes)",
    )
    r.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return args.func(args)
