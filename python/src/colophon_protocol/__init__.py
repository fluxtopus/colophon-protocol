"""Colophon v0: agent signatures for email. A draft implementation, not for production.

Receiving::

    from colophon_protocol import Receipt, verify
    verdict = verify(message, receipt, resolver=..., replay_store=...)
    if verdict.verified:
        verdict.agent.iss, verdict.agent.sub, verdict.agent.principal, verdict.agent.scope
    else:
        verdict.reason  # a Reason, §7.2

``colophon_protocol.aio.verify`` is the same, awaited. ``colophon_protocol.sansio`` is the pure
core both drive.
"""

from __future__ import annotations

from colophon_protocol.blocking import ReplayStore, TxtResolver, verify
from colophon_protocol.errors import ColophonError, DnsError, DnsLimited, IssueError, SigningError
from colophon_protocol.model import (
    Agent,
    DnsFailure,
    KeyQuery,
    Named,
    NotVerified,
    Principal,
    Pseudonymous,
    Reason,
    Receipt,
    ReplayKey,
    TxtAnswer,
    Verdict,
    Verified,
    Withheld,
)

__version__ = "0.0.1.dev0"
SPEC_VERSION = "v0-04"
"""The draft of the specification this release implements."""

__all__ = [
    "SPEC_VERSION",
    "Agent",
    "ColophonError",
    "DnsError",
    "DnsFailure",
    "DnsLimited",
    "IssueError",
    "KeyQuery",
    "Named",
    "NotVerified",
    "Principal",
    "Pseudonymous",
    "Reason",
    "Receipt",
    "ReplayKey",
    "ReplayStore",
    "SigningError",
    "TxtAnswer",
    "TxtResolver",
    "Verdict",
    "Verified",
    "Withheld",
    "__version__",
    "verify",
]
