"""Policy: (principal, exposed tool) -> allow | deny | approval_required.

An exposed tool already fixes the service, the account, the upstream tool and
any pinned resource, so this pair covers the whole tuple. Anything without a
matching rule is denied. When several rules match, the most restrictive wins.
"""

from __future__ import annotations

from .config import Config, Effect, is_mail_send
from .web_profiles import WEB_TOOLS, is_website

_STRICTNESS: dict[Effect, int] = {"allow": 0, "approval_required": 1, "deny": 2}


class Policy:
    def __init__(self, cfg: Config) -> None:
        table = {}
        agents = {}
        self._web_tools = {t.name for c in cfg.connections if is_website(c) for t in c.tools if t.upstream in WEB_TOOLS}
        send_tools = {t.name for c in cfg.connections for t in c.tools if is_mail_send(c, t)}
        for rule in cfg.policy:
            selected = agents if rule.clients else table
            for principal in rule.clients or rule.principals:
                for tool in rule.tools:
                    key = (principal, tool, rule.operation)
                    effect = rule.effect
                    if effect == "allow" and tool in send_tools and not rule.mail_send_direct:
                        effect = "approval_required"
                    current = selected.get(key)
                    if current is None or _STRICTNESS[effect] > _STRICTNESS[current]:
                        selected[key] = effect
        self._table = table
        self._agents = agents

    def effect(self, principal: str, tool: str, client_id: str | None = None, *, operation=None) -> Effect:
        if operation is None and tool in self._web_tools:
            # Visibility only: any usable operation makes the shared tool discoverable.
            return min((self.effect(principal, tool, client_id, operation=kind) for kind in ("read", "write")),
                       key=_STRICTNESS.__getitem__)
        effects = [value for value in (self._table.get((principal, tool, operation)),
                                       self._agents.get((client_id, tool, operation))) if value is not None]
        return max(effects, key=_STRICTNESS.__getitem__) if effects else "deny"
