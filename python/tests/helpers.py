"""The draft's example (Appendix A), built with the library and the sketch's test keys."""

from __future__ import annotations

import hashlib

from colophon_protocol import AgentKey, DomainKey, Issuer, Pseudonymous, Receipt
from colophon_protocol.dns import StaticResolver

ISSUED = 1793865600
SIGNED = ISSUED + 4500
ARRIVED = ISSUED + 4510
NONCE = "Zm9yLWV4YW1wbGUtb25seQ"
SCOPE = "Books restaurant tables for one person, up to $500 per booking."


def seed_for(label: str) -> bytes:
    return hashlib.sha256(f"colophon-v0 test key {label}".encode()).digest()


DOMAIN_KEY = DomainKey.from_seed(seed_for("domain acme.example s1"))
AGENT_KEY = AgentKey.from_seed(seed_for("agent maple-tiger-27"))
ISSUER = Issuer("acme.example", "s1", DOMAIN_KEY)


def credential(**changes: object) -> str:
    args: dict[str, object] = {
        "sub": "ag_7Hq2",
        "address": "maple-tiger-27@acme.example",
        "agent_key": AGENT_KEY,
        "issued_at": ISSUED,
        "principal": Pseudonymous("p_Xk29"),
        "scope": SCOPE,
        **changes,
    }
    return ISSUER.issue(**args).token  # type: ignore[arg-type]


def resolver() -> StaticResolver:
    return StaticResolver({ISSUER.dns_name: [ISSUER.dns_record]})


def receipt(**changes: object) -> Receipt:
    args: dict[str, object] = {
        "arrival": ARRIVED,
        "dkim_pass_domains": {"acme.example"},
        "mailbox": "mbx-reservations",
        "mailbox_addresses": {"reservations@bistro.example", "reservations+web@bistro.example"},
        **changes,
    }
    return Receipt(**args)  # type: ignore[arg-type]
