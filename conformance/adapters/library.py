#!/usr/bin/env python3
"""Conformance adapter for the Python library (python/, import name ``colophon_protocol``).

Reads one vector on stdin and writes the verdicts on stdout (conformance/README.md). Run it
where the library is installed, for example ``uv run --project python python <this file>``.
"""

from __future__ import annotations

import base64
import json
import sys

from colophon_protocol import NotVerified, Receipt, verify
from colophon_protocol.authres import colophon_resinfo
from colophon_protocol.dns import StaticResolver
from colophon_protocol.replay import MemoryReplayStore


def main() -> int:
    vector = json.load(sys.stdin)
    if vector.get("contract") != "colophon-conformance/1":
        raise SystemExit("unknown contract")
    message = base64.b64decode(vector["message"], validate=True)
    # One store for the vector's deliveries. Its clock never purges: vectors are not real time.
    store = MemoryReplayStore(clock=lambda: 0.0)
    out: list[dict[str, object]] = []
    for d in vector["deliveries"]:
        receipt = Receipt(
            arrival=d["accepted_at"],
            dkim_pass_domains=d["dkim_pass_domains"],
            mailbox=d["mailbox"],
            mailbox_addresses=d["mailbox_addresses"],
        )
        verdict = verify(
            message, receipt, resolver=StaticResolver(d["dns_txt"]), replay_store=store
        )
        result: dict[str, object]
        if isinstance(verdict, NotVerified):
            result = {"verdict": "not_verified", "reason": verdict.reason.value}
        else:
            result = {"verdict": "verified", "agent": verdict.agent.to_json()}
        result["authentication_results"] = colophon_resinfo(verdict)
        out.append(result)
    json.dump({"deliveries": out}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
