"""Policy: (principal, exposed tool) -> allow | deny | approval_required.

An exposed tool already fixes the service, the account, the upstream tool and
any pinned resource, so this pair covers the whole tuple. Anything without a
matching rule is denied. When several rules match, the most restrictive wins.
"""

from __future__ import annotations

from .config import Config, Effect

_STRICTNESS: dict[Effect, int] = {"allow": 0, "approval_required": 1, "deny": 2}


class Policy:
    def __init__(self, cfg: Config) -> None:
        table: dict[tuple[str, str], Effect] = {}
        for rule in cfg.policy:
            for principal in rule.principals:
                for tool in rule.tools:
                    key = (principal, tool)
                    current = table.get(key)
                    if current is None or _STRICTNESS[rule.effect] > _STRICTNESS[current]:
                        table[key] = rule.effect
        self._table = table

    def effect(self, principal: str, tool: str) -> Effect:
        return self._table.get((principal, tool), "deny")
