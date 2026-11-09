"""Exceptions a caller's resolver raises, and the one the sender side raises."""

from __future__ import annotations

__all__ = ["ColophonError", "DnsError", "DnsLimited", "IssueError", "SigningError"]


class ColophonError(Exception):
    """Base class for this package's exceptions."""


class DnsError(ColophonError):
    """A resolver raises this for a timeout or a server failure (§7.4): ``dns_error``.

    The adapters treat any other exception from a resolver the same way.
    """


class DnsLimited(ColophonError):
    """A resolver raises this when the miss limit refuses a lookup (§7.4): ``dns_limited``."""


class IssueError(ColophonError, ValueError):
    """The issuer was asked for a credential v0 does not allow."""


class SigningError(ColophonError, ValueError):
    """The message cannot be signed as given. ``reason`` is what a verifier would say."""

    def __init__(self, message: str, reason: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason
