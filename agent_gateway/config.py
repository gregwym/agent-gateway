"""Configuration: the single place where clients, connections and policy are declared.

Everything here is static. There is no admin API and no hot reload: the file is
read once at startup, and a change needs a restart by whoever controls the host.
Unknown keys are rejected so a typo cannot silently widen or drop a rule.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

NAME = r"^[a-z][a-z0-9_-]{0,47}$"
# Deliberately narrower than what MCP allows: no dots, so names survive every client.
TOOL_NAME = r"^[A-Za-z][A-Za-z0-9_-]{0,63}$"
ENV_NAME = r"^[A-Za-z_][A-Za-z0-9_]*$"

Effect = Literal["allow", "deny", "approval_required"]


class ConfigError(Exception):
    """The configuration is invalid. The message never contains secret values."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ServerCfg(_Model):
    host: str = "127.0.0.1"
    port: int = Field(8080, ge=1, le=65535)
    # Accepted Host header values ("gateway.example.ts.net:8080"). Empty disables the check.
    allowed_hosts: list[str] = []
    max_result_bytes: int = Field(1_000_000, ge=1_000)


class AuditCfg(_Model):
    path: Path
    retention_days: int = Field(90, ge=1, le=3650)


class SecretsCfg(_Model):
    path: Path
    key_file: Path


class ClientCfg(_Model):
    """One credential. A client is bound to exactly one principal, forever."""

    id: str = Field(pattern=NAME)
    principal: str
    token_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ToolCfg(_Model):
    """One upstream tool, exposed under one name, optionally narrowed.

    The same upstream tool may be listed twice under different names with
    different pins, which is how a resource-level restriction is expressed
    (for example a "family calendar only" variant of ``list_events``).
    """

    upstream: str = Field(min_length=1, max_length=128)
    name: str = Field(pattern=TOOL_NAME)
    description: str | None = None
    # Arguments the gateway always sets. They disappear from the schema the agent sees.
    pin: dict[str, Any] = {}
    # Arguments the agent must supply, restricted to these values.
    allow_values: dict[str, list[Any]] = {}

    @model_validator(mode="after")
    def _check(self) -> ToolCfg:
        both = set(self.pin) & set(self.allow_values)
        if both:
            raise ValueError(f"tool {self.name}: {sorted(both)} is in both pin and allow_values")
        for key, values in self.allow_values.items():
            if not values:
                raise ValueError(f"tool {self.name}: allow_values.{key} is empty")
        return self


class ConnectionCfg(_Model):
    """One upstream MCP server bound to one account of one service."""

    id: str = Field(pattern=NAME)
    service: str = Field(pattern=NAME)
    account: str = Field(pattern=NAME)
    owner: str
    transport: Literal["stdio", "http"]

    # stdio
    command: list[str] = []
    env: dict[str, str] = {}
    secret_env: dict[str, str] = {}  # ENV_VAR -> secret name

    # http
    url: str | None = None
    allow_plain_http: bool = False
    bearer_secret: str | None = None  # secret name, sent as "Authorization: Bearer <value>"
    secret_headers: dict[str, str] = {}  # Header-Name -> secret name

    timeout_seconds: float = Field(30, gt=0, le=600)
    max_concurrency: int = Field(4, ge=1, le=64)
    verify_interval_seconds: float = Field(300, gt=0)
    tools: list[ToolCfg]

    @model_validator(mode="after")
    def _check(self) -> ConnectionCfg:
        where = f"connection {self.id}"
        if self.transport == "stdio":
            if not self.command:
                raise ValueError(f"{where}: stdio transport needs a command")
            if self.url or self.bearer_secret or self.secret_headers:
                raise ValueError(f"{where}: url/bearer_secret/secret_headers are http-only")
            for name in list(self.env) + list(self.secret_env):
                if not _matches(ENV_NAME, name):
                    raise ValueError(f"{where}: invalid environment variable name")
            if set(self.env) & set(self.secret_env):
                raise ValueError(f"{where}: a variable is in both env and secret_env")
        else:
            if self.command or self.env or self.secret_env:
                raise ValueError(f"{where}: command/env/secret_env are stdio-only")
            _check_url(where, self.url, self.allow_plain_http)
            if self.bearer_secret and any(h.lower() == "authorization" for h in self.secret_headers):
                raise ValueError(f"{where}: bearer_secret and an Authorization secret header conflict")
        return self

    def secret_names(self) -> set[str]:
        names = set(self.secret_env.values()) | set(self.secret_headers.values())
        if self.bearer_secret:
            names.add(self.bearer_secret)
        return names


class RuleCfg(_Model):
    principals: list[str] = Field(min_length=1)
    connection: str
    tools: list[str] = Field(min_length=1)  # exposed names; no wildcards
    effect: Effect
    # Must be set to grant a principal access to an account it does not own
    # (unless the owner is listed under `shared`). Guards against copy-paste grants.
    cross_account: bool = False


class Config(_Model):
    server: ServerCfg = ServerCfg()
    audit: AuditCfg
    secrets: SecretsCfg | None = None
    lock_file: Path = Path("tools.lock.json")
    principals: list[str] = Field(min_length=1)
    # Principals whose accounts are meant to be shared, e.g. `household`.
    shared: list[str] = []
    clients: list[ClientCfg]
    connections: list[ConnectionCfg]
    policy: list[RuleCfg] = []

    @model_validator(mode="after")
    def _check(self) -> Config:
        for principal in self.principals:
            if not _matches(NAME, principal):
                raise ValueError(f"invalid principal name {principal!r}")
        _unique("principal", self.principals)
        known = set(self.principals)
        for name in self.shared:
            if name not in known:
                raise ValueError(f"shared: unknown principal {name!r}")

        _unique("client id", [c.id for c in self.clients])
        _unique("client token", [c.token_sha256 for c in self.clients], show=False)
        for client in self.clients:
            if client.principal not in known:
                raise ValueError(f"client {client.id}: unknown principal {client.principal!r}")

        _unique("connection id", [c.id for c in self.connections])
        _unique("(service, account)", [f"{c.service}/{c.account}" for c in self.connections])
        # Exposed names are unique across the whole gateway, not per principal, so a
        # name always means the same account and the same upstream tool for everyone.
        _unique("exposed tool name", [t.name for c in self.connections for t in c.tools])
        for conn in self.connections:
            if conn.owner not in known:
                raise ValueError(f"connection {conn.id}: unknown owner {conn.owner!r}")
            if conn.secret_names() and self.secrets is None:
                raise ValueError(f"connection {conn.id} references secrets but no `secrets:` store is configured")

        by_id = {c.id: c for c in self.connections}
        for i, rule in enumerate(self.policy):
            where = f"policy[{i}]"
            conn = by_id.get(rule.connection)
            if conn is None:
                raise ValueError(f"{where}: unknown connection {rule.connection!r}")
            exposed = {t.name for t in conn.tools}
            for tool in rule.tools:
                if tool not in exposed:
                    raise ValueError(f"{where}: {tool!r} is not a tool of connection {conn.id}")
            for principal in rule.principals:
                if principal not in known:
                    raise ValueError(f"{where}: unknown principal {principal!r}")
                crosses = principal != conn.owner and conn.owner not in self.shared
                if crosses and rule.effect != "deny" and not rule.cross_account:
                    raise ValueError(
                        f"{where}: grants {principal!r} access to an account owned by {conn.owner!r}; "
                        "set cross_account: true if that is intended"
                    )
        return self

    def connection(self, conn_id: str) -> ConnectionCfg:
        return next(c for c in self.connections if c.id == conn_id)


def _matches(pattern: str, value: str) -> bool:
    return re.fullmatch(pattern, value) is not None


def _unique(what: str, values: list[str], *, show: bool = True) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise ValueError(f"duplicate {what}" + (f": {value}" if show else ""))
        seen.add(value)


def _check_url(where: str, url: str | None, allow_plain_http: bool) -> None:
    """Upstream URLs come only from this file; agents can never supply one."""
    if not url:
        raise ValueError(f"{where}: http transport needs a url")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"{where}: url must be http(s)")
    if parts.username or parts.password:
        raise ValueError(f"{where}: put credentials in the secret store, not in the url")
    if parts.query or parts.fragment:
        raise ValueError(f"{where}: url must not carry a query string or fragment")
    if parts.scheme == "http" and not allow_plain_http and not _is_loopback(parts.hostname):
        raise ValueError(f"{where}: plain http to a non-loopback host needs allow_plain_http: true")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def load_config(path: str | Path) -> Config:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config file: {exc.strerror}") from None
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file is not valid YAML: {exc}") from None
    if not isinstance(raw, dict):
        raise ConfigError("config file must be a YAML mapping")
    try:
        cfg = Config.model_validate(raw)
    except ValidationError as exc:
        # `input` is left out on purpose: echoing config values back is how secrets end up in logs.
        lines = [f"  {'.'.join(str(p) for p in e['loc']) or '<root>'}: {e['msg']}" for e in exc.errors()]
        raise ConfigError("invalid configuration:\n" + "\n".join(lines)) from None
    # Relative paths are relative to the config file, not to the working directory.
    base = path.resolve().parent

    def located(value: Path) -> Path:
        return Path(os.path.normpath(base / value))

    updates: dict[str, Any] = {"lock_file": located(cfg.lock_file)}
    updates["audit"] = cfg.audit.model_copy(update={"path": located(cfg.audit.path)})
    if cfg.secrets:
        updates["secrets"] = cfg.secrets.model_copy(
            update={"path": located(cfg.secrets.path), "key_file": located(cfg.secrets.key_file)}
        )
    return cfg.model_copy(update=updates)
