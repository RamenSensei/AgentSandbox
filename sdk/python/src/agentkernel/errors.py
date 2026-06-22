"""Exceptions raised by the AgentKernel client."""

from __future__ import annotations

from typing import List, Optional

from .types import Denial, RequestableScope


class KernelError(Exception):
    """Any error envelope returned by the kernel API."""

    def __init__(self, code: str, message: str, status: int = 0) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status


class DenialError(KernelError):
    """A policy denial (HTTP 403) carrying the full structured Denial.

    Invariant: no denial without a machine-readable explanation — the
    kernel always includes the denial object, and this exception exposes
    it for programmatic recovery.
    """

    def __init__(self, denial: Denial, message: str = "", status: int = 403) -> None:
        super().__init__("DENIED", message or denial.reason, status)
        self.denial = denial

    @property
    def denial_code(self) -> str:
        return self.denial.code

    @property
    def safe_alternatives(self) -> List[str]:
        """Operations the principal is already allowed to use instead."""
        return self.denial.safe_alternatives

    @property
    def requestable_scopes(self) -> List[RequestableScope]:
        """Narrow scopes the principal could request to unblock itself."""
        return self.denial.requestable_scopes

    @property
    def escalation_allowed(self) -> bool:
        return self.denial.escalation_allowed
