#!/usr/bin/env python3
"""Conformance adapter for the Python library (python/, import name ``colophon_protocol``).

Reads one vector on stdin and writes the verdicts on stdout (conformance/README.md). Run it
where the library is installed, for example ``uv run --project python python <this file>``.
"""

from __future__ import annotations

import base64
import json
import sys

from colophon_protocol import KeyQuery, NotVerified, Receipt, ReplayKey, TxtAnswer, verify
from colophon_protocol.authres import colophon_resinfo
from colophon_protocol.dns import GuardedResolver, StaticResolver
from colophon_protocol.errors import DnsLimited
from colophon_protocol.replay import MemoryReplayStore


class AfterMisses:
    """The library's §7.4 guard, with ``misses`` NXDOMAIN lookups for the queried host already
    counted this hour. The host is known only once the verifier asks, so the misses are made
    then, at names that are not in ``dns_txt``."""

    def __init__(self, dns_txt: dict[str, list[str] | None], misses: int) -> None:
        self._guard = GuardedResolver(StaticResolver(dns_txt), clock=lambda: 0.0)
        self._misses = misses

    def resolve_txt(self, query: KeyQuery) -> TxtAnswer:
        for i in range(self._misses):
            try:
                self._guard.resolve_txt(KeyQuery(f"-miss-{i}", query.host))
            except DnsLimited:
                break
        self._misses = 0
        return self._guard.resolve_txt(query)


class Unavailable:
    """A replay store that cannot be read or written."""

    def claim(self, key: ReplayKey, expires_at: int) -> bool:
        raise ConnectionError("replay store unavailable")


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
        available = d.get("replay_store_available", True)
        verdict = verify(
            message,
            receipt,
            resolver=AfterMisses(d["dns_txt"], d.get("dns_misses", 0)),
            replay_store=store if available else Unavailable(),
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
