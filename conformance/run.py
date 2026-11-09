#!/usr/bin/env python3
"""Run the Colophon v0 test vectors against any implementation, in any language.

    python conformance/run.py [--vectors reference/vectors.json] -- <command> [args...]

For each vector the runner starts <command> once, writes the vector to its stdin as one JSON
object, closes stdin, and reads one JSON object from its stdout. The contract is in
conformance/README.md. The runner uses only the standard library.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

CONTRACT = "colophon-conformance/1"
REASONS = frozenset(
    {
        "no_signature", "multiple_signatures", "malformed", "dkim_unaligned",
        "unsupported_version", "credential_invalid", "dns_error", "dns_limited", "key_not_found",
        "key_revoked", "credential_expired", "from_mismatch", "layout", "signature_invalid",
        "not_addressed", "replay",
    }
)  # fmt: skip
INPUT_FIELDS = (
    "accepted_at",
    "dkim_pass_domains",
    "envelope_recipient",
    "mailbox",
    "mailbox_addresses",
    "dns_txt",
)
DEFAULT_VECTORS = Path(__file__).resolve().parent.parent / "reference" / "vectors.json"


def vector_input(case: dict[str, Any]) -> dict[str, Any]:
    """What the implementation sees: the vector without its expected outcomes."""
    return {
        "contract": CONTRACT,
        "name": case["name"],
        "message": case["message"],
        "deliveries": [{k: d[k] for k in INPUT_FIELDS} for d in case["deliveries"]],
    }


def outcome(item: object) -> str:
    """One delivery's result as the vectors write it: "verified" or the reason code."""
    if not isinstance(item, dict):
        return "<not an object>"
    if item.get("verdict") == "verified":
        return "verified"
    if item.get("verdict") == "not_verified" and item.get("reason") in REASONS:
        return str(item["reason"])
    return f"<invalid: {json.dumps(item)[:80]}>"


def run_case(command: list[str], case: dict[str, Any], timeout: float) -> list[str]:
    want = len(case["deliveries"])
    try:
        done = subprocess.run(  # noqa: S603 - the command is the caller's own implementation
            command,
            input=json.dumps(vector_input(case)).encode(),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [f"<timeout after {timeout:g} s>"] * want
    if done.returncode != 0:
        tail = done.stderr.decode(errors="replace").strip().splitlines()[-1:] or [""]
        return [f"<exit {done.returncode}: {tail[0][:120]}>"] * want
    try:
        result = json.loads(done.stdout)
        items = result["deliveries"]
    except (ValueError, KeyError, TypeError):
        return ["<stdout is not a result object>"] * want
    if not isinstance(items, list) or len(items) != want:
        return [f"<{want} deliveries expected>"] * want
    return [outcome(item) for item in items]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTORS)
    parser.add_argument("--timeout", type=float, default=20.0, help="seconds per vector")
    parser.add_argument("--only", metavar="NAME", help="run the vectors whose name contains NAME")
    parser.add_argument("--quiet", action="store_true", help="print failures and the score only")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- then the command to run")
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("give the command to run after --")

    cases = json.loads(args.vectors.read_text(encoding="utf-8"))["cases"]
    if args.only:
        cases = [c for c in cases if args.only in c["name"]]
    passed = total = 0
    for case in cases:
        got = run_case(command, case, args.timeout)
        for n, (delivery, outcome_) in enumerate(zip(case["deliveries"], got, strict=True)):
            total += 1
            ok = outcome_ == delivery["expected"]
            passed += ok
            label = case["name"]
            if len(got) > 1:
                label += f" [delivery {n + 1}]"
            if not ok:
                print(f"FAIL  {delivery['expected']:<20} {label}  (got {outcome_})")
            elif not args.quiet:
                print(f"ok    {delivery['expected']:<20} {label}")
    print(f"{passed}/{total} deliveries pass ({len(cases)} vectors)")
    return 0 if total and passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
