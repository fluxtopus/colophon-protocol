"""The one internal failure signal. It never leaves the package: the core makes it a verdict."""

from __future__ import annotations

from colophon_protocol.model import Reason


class Fail(Exception):
    """A §7.2 step failed with this reason."""

    def __init__(self, reason: Reason, detail: str = "") -> None:
        super().__init__(detail or reason.value)
        self.reason = reason
        self.detail = detail
