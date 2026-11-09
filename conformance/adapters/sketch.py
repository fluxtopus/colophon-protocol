#!/usr/bin/env python3
"""Conformance adapter for the reference sketch (reference/colophon_v0.py).

Reads one vector on stdin and writes the verdicts on stdout (conformance/README.md). The sketch
is found in COLOPHON_SPEC_DIR, or in the repository this file sits in. Needs ``cryptography``.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
from pathlib import Path

SPEC_DIR = Path(os.environ.get("COLOPHON_SPEC_DIR", Path(__file__).resolve().parents[2]))


def load_sketch():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(
        "colophon_v0", SPEC_DIR / "reference" / "colophon_v0.py"
    )
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load reference/colophon_v0.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["colophon_v0"] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    sketch = load_sketch()
    vector = json.load(sys.stdin)
    if vector.get("contract") != "colophon-conformance/1":
        raise SystemExit("unknown contract")
    message = base64.b64decode(vector["message"], validate=True)
    seen: set[tuple[str, ...]] = set()  # one replay store for the vector's deliveries
    out = []
    for d in vector["deliveries"]:
        arrival = sketch.Arrival(
            accepted_at=d["accepted_at"],
            dkim_pass_domains=set(d["dkim_pass_domains"]),
            mailbox=d["mailbox"],
            mailbox_addresses=set(d["mailbox_addresses"]),
            dns=d["dns_txt"],
            envelope_recipient=d["envelope_recipient"],
            seen=seen,
        )
        verdict = sketch.verify(message, arrival)
        if verdict.verified:
            out.append({"verdict": "verified", "agent": verdict.agent})
        else:
            out.append({"verdict": "not_verified", "reason": verdict.reason})
    json.dump({"deliveries": out}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
