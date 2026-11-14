"""Approval interface (Phase 3 hook). NOT an approval system.

What exists today: the shape of a request, the point in the call path where an
approver is consulted, and a default approver that refuses everything. A tool
whose policy effect is `approval_required` therefore never runs.

What does not exist yet, and is required before any approver may say yes:
a pending-request store, an out-of-band human channel (the planned one is a
passkey prompt, as in compose-cd-engine), single-use grants, and expiry
enforcement. Until then there is deliberately no configuration switch that
selects another approver.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Protocol


def arguments_digest(arguments: dict[str, Any]) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApprovalRequest:
    """One specific call awaiting a human decision.

    `arguments_sha256` covers the exact arguments that would be sent upstream,
    pins included. An approval is for this digest only: the gateway computes it
    itself right before the call, so an agent cannot get one set of arguments
    approved and another executed.
    """

    principal: str
    client_id: str
    tool: str
    connection: str
    service: str
    account: str
    upstream_tool: str
    arguments_sha256: str
    id: str = field(default_factory=lambda: secrets.token_urlsafe(16))
    created_at: float = field(default_factory=time.time)
    ttl_seconds: int = 300

    @property
    def expires_at(self) -> float:
        return self.created_at + self.ttl_seconds


@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    reason: str


class Approver(Protocol):
    async def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        """Return approved=True only for a human decision bound to `request`."""
        ...


class DenyAllApprover:
    async def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(approved=False, reason="no_approval_channel")
