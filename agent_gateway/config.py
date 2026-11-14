"""Configuration: the single place where clients, connections and policy are declared.

The host file is read at startup. Optional web administration stores encrypted
overrides for account/client/policy sections; host settings remain immutable.
Unknown keys are rejected so a typo cannot silently widen or drop a rule.
"""

from __future__ import annotations

import ipaddress
import os
import re
import unicodedata
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

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


class ApprovalsCfg(_Model):
    """The passkey approval page. Without this section an `approval_required` tool never runs.

    There is nothing here that approves on its own: the section only says where
    people decide and how long a request and a decision stay valid.
    """

    # What a person types into the browser, e.g. https://gateway.example.ts.net. Passkeys are
    # bound to this hostname by the browser, so changing it later means enrolling again.
    origin: str
    store: Path
    request_ttl_seconds: int = Field(600, ge=60, le=86_400)  # how long a request waits for a decision
    grant_ttl_seconds: int = Field(600, ge=30, le=3_600)  # how long an approved call may be used, once

    @model_validator(mode="after")
    def _check(self) -> ApprovalsCfg:
        parts = urlsplit(self.origin)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise ValueError("approvals.origin must look like https://host[:port]")
        if parts.path or parts.query or parts.fragment:
            raise ValueError("approvals.origin must not have a path, query string or fragment")
        # Browsers only offer passkeys on https, with localhost as the one exception.
        if parts.scheme == "http" and parts.hostname != "localhost":
            raise ValueError("approvals.origin must be https (http is accepted for localhost only)")
        return self

    @property
    def rp_id(self) -> str:
        return urlsplit(self.origin).hostname or ""


class ClientCfg(_Model):
    """One Agent credential, with its own grants and a household membership."""

    id: str = Field(pattern=NAME)
    principal: str | None = None  # legacy audit/binding identity; never a grant in the household model
    household: str | None = None
    token_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def subject(self) -> str:
        return self.principal or self.household or ""


def validate_name(value: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value.strip()) <= 80 or
            any(unicodedata.category(c) in ("Cc", "Cs") or unicodedata.bidirectional(c) in
                ("LRE", "RLE", "LRO", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI") for c in value)):
        raise ValueError("name must contain 1 to 80 characters without control characters")
    return value.strip()


class HouseholdCfg(_Model):
    id: str = Field(pattern=NAME)
    name: str
    _name = field_validator("name", mode="before")(validate_name)


class MemberCfg(_Model):
    id: str = Field(pattern=NAME)  # immutable credential/ownership key, not a second name
    name: str
    household: str
    _name = field_validator("name", mode="before")(validate_name)


class AdminCfg(_Model):
    """Opt-in web administration; the host assigns the administrator identity."""

    owner: str = Field(pattern=NAME)
    state: Path
    session_seconds: int = Field(1800, ge=60, le=3600)


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
    principals: list[str] = []  # legacy host configuration only
    clients: list[str] = []
    connection: str
    tools: list[str] = Field(min_length=1)  # exposed names; no wildcards
    effect: Effect
    # Must be set to grant a principal access to an account it does not own
    # (unless the owner is listed under `shared`). Guards against copy-paste grants.
    cross_account: bool = False

    @model_validator(mode="after")
    def _subjects(self):
        if bool(self.principals) == bool(self.clients):
            raise ValueError("a rule must select either Agents or legacy principals")
        return self


class Config(_Model):
    server: ServerCfg = ServerCfg()
    audit: AuditCfg
    secrets: SecretsCfg | None = None
    approvals: ApprovalsCfg | None = None
    admin: AdminCfg | None = None
    lock_file: Path = Path("tools.lock.json")
    principals: list[str] = Field(default_factory=list, min_length=1)
    # Principals whose accounts are meant to be shared, e.g. `household`.
    shared: list[str] = []
    households: list[HouseholdCfg] = []
    members: list[MemberCfg] = []
    clients: list[ClientCfg]
    connections: list[ConnectionCfg]
    policy: list[RuleCfg] = []

    @model_validator(mode="before")
    @classmethod
    def _identity_keys(cls, raw):
        if isinstance(raw, dict) and raw.get("households"):
            raw = dict(raw)
            key = lambda item: item.id if isinstance(item, _Model) else item["id"]
            raw.setdefault("principals", [key(m) for m in raw.get("members", [])] + [key(h) for h in raw["households"]])
            raw.setdefault("shared", [key(h) for h in raw["households"]])
        return raw

    @model_validator(mode="after")
    def _check(self) -> Config:
        for principal in self.principals:
            if not _matches(NAME, principal):
                raise ValueError(f"invalid principal name {principal!r}")
        _unique("principal", self.principals)
        known = set(self.principals)
        homes = {h.id for h in self.households}
        if homes:
            _unique("household", [h.id for h in self.households])
            _unique("member", [m.id for m in self.members])
            _unique("member name", [m.name.casefold() for m in self.members])
            _unique("household name", [h.name.casefold() for h in self.households])
            if homes & {m.id for m in self.members} or known != homes | {m.id for m in self.members} or set(self.shared) != homes:
                raise ValueError("identity keys must match members and households")
            if any(m.household not in homes for m in self.members):
                raise ValueError("member belongs to an unknown household")
        elif self.members:
            raise ValueError("members need a household")
        if self.admin:
            if not self.approvals or not self.secrets:
                raise ValueError("admin requires approvals and an encrypted secrets store")
            if self.admin.owner not in known or self.admin.owner in self.shared:
                raise ValueError("admin.owner must name a non-shared principal")
        for name in self.shared:
            if name not in known:
                raise ValueError(f"shared: unknown principal {name!r}")

        _unique("client id", [c.id for c in self.clients])
        _unique("client token", [c.token_sha256 for c in self.clients], show=False)
        for client in self.clients:
            if homes and client.household not in homes:
                raise ValueError(f"client {client.id}: unknown household")
            if client.subject not in known:
                raise ValueError(f"client {client.id}: unknown principal {client.principal!r}")
            if homes and self.household_of(client.subject) != client.household:
                raise ValueError(f"client {client.id}: identity is outside its household")

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
            if homes and rule.principals:
                raise ValueError(f"{where}: household configuration requires per-Agent grants")
            for client_id in rule.clients:
                client = next((c for c in self.clients if c.id == client_id), None)
                if client is None:
                    raise ValueError(f"{where}: unknown Agent {client_id!r}")
                if homes and client.household != self.household_of(conn.owner) and rule.effect != "deny":
                    raise ValueError(f"{where}: cannot grant access outside the Agent's household")
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

    def approvers_of(self, conn: ConnectionCfg) -> tuple[str, ...]:
        """Whose decision counts for a call on this account: its owner, or every person if it is shared."""
        if conn.owner in self.shared:
            if self.households:
                return tuple(m.id for m in self.members if m.household == conn.owner)
            return tuple(p for p in self.principals if p not in self.shared)
        return (conn.owner,)

    def household_of(self, owner: str) -> str | None:
        if any(h.id == owner for h in self.households):
            return owner
        return next((m.household for m in self.members if m.id == owner), None)

    def name_of(self, identity: str) -> str:
        return next((item.name for item in [*self.members, *self.households] if item.id == identity), identity)


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
    if cfg.approvals:
        updates["approvals"] = cfg.approvals.model_copy(update={"store": located(cfg.approvals.store)})
    if cfg.admin:
        updates["admin"] = cfg.admin.model_copy(update={"state": located(cfg.admin.state)})
    return cfg.model_copy(update=updates)
