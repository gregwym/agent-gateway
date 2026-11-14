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
        agents: dict[tuple[str, str], Effect] = {}
        for rule in cfg.policy:
            selected = agents if rule.clients else table
            for principal in rule.clients or rule.principals:
                for tool in rule.tools:
                    key = (principal, tool)
                    current = selected.get(key)
                    if current is None or _STRICTNESS[rule.effect] > _STRICTNESS[current]:
                        selected[key] = rule.effect
        self._table = table
        self._agents = agents

    def effect(self, principal: str, tool: str, client_id: str | None = None) -> Effect:
        effects = [value for value in (self._table.get((principal, tool)), self._agents.get((client_id, tool))) if value is not None]
        return max(effects, key=_STRICTNESS.__getitem__) if effects else "deny"
