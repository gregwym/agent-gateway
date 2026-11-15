"""Bind a human approval to one exact upstream call.

The built-in Passkey approver queues the call for dispatch after approval. The
Gateway rechecks the current authorization when dispatching the saved call.

Two approvers exist. `DenyAllApprover` is the default and refuses everything.
`passkey.PasskeyApprover` is used when the config has an `approvals:` section.
There is no setting that selects an approver which says yes on its own.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

NOT_EXECUTED = "This action needs human approval and was not executed."


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def arguments_digest(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(arguments)).hexdigest()


@dataclass(frozen=True)
class ApprovalRequest:
    """One specific call awaiting a human decision.

    `arguments` are the exact arguments that would be sent upstream, pins
    included, and `arguments_sha256` is their digest. The gateway builds this
    itself right before the call, from the token's identity and the validated
    arguments, so an agent cannot get one call approved and another executed.
    """

    principal: str
    client_id: str
    tool: str
    connection: str
    service: str
    account: str
    upstream_tool: str
    arguments_sha256: str
    # Shown to the person deciding. Never logged.
    arguments: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)
    owner: str = ""
    # The people allowed to decide, resolved from the connection's approval setting.
    approvers: tuple[str, ...] = ()
    configuration_revision: str = ""
    client_token_sha256: str = field(default="", repr=False)
    target_sha256: str = ""
    id: str = field(default_factory=lambda: secrets.token_urlsafe(16))
    created_at: float = field(default_factory=time.time)
    ttl_seconds: int = 300

    @property
    def expires_at(self) -> float:
        return self.created_at + self.ttl_seconds

    @property
    def binding(self) -> str:
        """What a decision is bound to: who asked, which account and tool, and the exact arguments."""
        return hashlib.sha256(
            canonical(
                {
                    "client": self.client_id,
                    "principal": self.principal,
                    "tool": self.tool,
                    "connection": self.connection,
                    "service": self.service,
                    "account": self.account,
                    "upstream_tool": self.upstream_tool,
                    "arguments_sha256": self.arguments_sha256,
                    **({"target_sha256": self.target_sha256} if self.target_sha256 else {}),
                    **({"client_token_sha256": self.client_token_sha256} if self.client_token_sha256 else {}),
                    **({"configuration_revision": self.configuration_revision} if self.configuration_revision else {}),
                }
            )
        ).hexdigest()


@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    reason: str  # a short code for the audit log
    # Text for the agent when the call does not run (for example where the request waits).
    message: str | None = None
    # The approver's own id for the request this decision belongs to.
    approval_id: str | None = None


class Approver(Protocol):
    async def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        """Return approved=True only for a human decision bound to `request`, and only once per decision."""
        ...

    async def finished(self, approval_id: str, outcome: str) -> None:
        """Called after an approved call was attempted, with a short outcome code."""
        ...


class DenyAllApprover:
    async def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(approved=False, reason="no_approval_channel")

    async def finished(self, approval_id: str, outcome: str) -> None:
        return None
