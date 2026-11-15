"""Encrypted web-managed overrides, and a bounded catalog of connector templates.

The immutable host configuration owns paths, origin, administrator, and server
settings. Web administration cannot install code or choose subprocess commands.
"""
import copy
import json
import re
import secrets
import sys
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .config import Config, ConnectionCfg, validate_name
from .credentials import EncryptedFileStore
from .lock import Lock, digest_of
from .passkey import Refused

SECTIONS = ("principals", "shared", "households", "members", "clients", "connections", "policy")
CONNECTION_ACCESS = {
    "none": {"read": "deny", "write": "deny"},
    "read": {"read": "allow", "write": "deny"},
    "read_approval": {"read": "approval_required", "write": "deny"},
    "read_write": {"read": "allow", "write": "approval_required"},
    "read_write_direct": {"read": "allow", "write": "allow"},
    "read_write_approval": {"read": "approval_required", "write": "approval_required"},
    "read_approval_write_direct": {"read": "approval_required", "write": "allow"},
}
CATALOG = {
    "demo": {"label": "Demo notes / 模拟笔记", "fields": [], "secrets": [],
             "tools": [("list_notes", "list"), ("get_note", "get"), ("add_note", "add")],
             "probe": ("list_notes", {"folder": "inbox"})},
    "imap": {"label": "Mail / 邮箱 (iCloud, IMAP + SMTP)",
             "fields": ["username", "host", "port", "smtp_host", "smtp_port", "smtp_security", "smtp_username", "smtp_sender"], "secrets": ["password"],
             "tools": [("list_mailboxes", "mailboxes"), ("search_messages", "search"), ("get_message", "get"), ("get_attachment", "attachment"),
                       ("list_messages", "list"), ("get_messages", "get_batch"), ("set_message_state", "set_state"),
                       ("move_messages", "move"), ("archive_messages", "archive"), ("trash_messages", "trash"), ("send_message", "send")],
             "writes": {"set_message_state", "move_messages", "archive_messages", "trash_messages", "send_message"},
             "probe": ("list_mailboxes", {})},
    "caldav": {"label": "iCloud Calendar / CalDAV", "fields": ["username", "url", "timezone"], "secrets": ["password"],
               "tools": [("list_calendars", "calendars"), ("list_events", "events"), ("get_event", "event"), ("check_conflicts", "conflicts")],
               "probe": ("list_calendars", {})},
    "gmail": {"label": "Gmail", "fields": ["client_id"], "secrets": ["client_secret", "refresh_token"],
              "tools": [("search_messages", "search"), ("get_message", "get"), ("get_attachment", "attachment")],
              "probe": ("search_messages", {"query": "in:inbox", "limit": 1})},
    "reminders": {"label": "Reminders Mac helper / 提醒事项 Mac 辅助服务", "fields": ["url"], "secrets": ["token"],
                  "tools": [("reminders_lists", "lists"), ("reminders_list", "list"), ("reminders_get", "get")],
                  "probe": ("reminders_lists", {})},
}


def member_name(value):
    try:
        return validate_name(value)
    except ValueError:
        raise Refused("invalid_member_name", 400) from None


class ManagedStore:
    def __init__(self, gateway):
        self.base = gateway.cfg
        self.base_secrets = dict(gateway.secrets)
        self.base_lock = gateway.lock
        self.file = EncryptedFileStore(self.base.admin.state, self.base.secrets.key_file)
        self.state = {"revision": 0, "config": {}, "secrets": {}, "locks": {}}
        if "state" in self.file.names():
            self.state = json.loads(self.file.get("state"))
        # Fail closed on a malformed/corrupt state file, including tool locks.
        self.effective(self.state)
        self.state = self.upgrade(self.state)

    def upgrade(self, state):
        """Normalize legacy web state without changing any existing Agent's grants.

        No disk write at startup: the next administrator edit persists this format.
        Credential IDs, client subjects, token hashes and approval revisions survive.
        """
        cfg, _, _ = self.effective(state)
        if cfg.households:
            result = copy.deepcopy(state)
            result.update(schema=2, config={key: cfg.model_dump(mode="json")[key] for key in SECTIONS})
            result.pop("display_names", None)
            return result
        if len(cfg.shared) > 1:
            raise ValueError("legacy shared identities need an explicit household membership migration")
        from .policy import Policy
        policy = Policy(cfg)
        result = copy.deepcopy(state)
        raw = {key: cfg.model_dump(mode="json")[key] for key in SECTIONS}
        home = cfg.shared[0] if cfg.shared else "household"
        suffix = 0
        while home in cfg.principals and home not in cfg.shared:
            suffix += 1
            home = f"home_{suffix}"
        names = result.pop("display_names", {})
        raw["households"] = [{"id": home, "name": names.get(home, "Home")}]
        raw["members"] = [{"id": p, "name": names.get(p, p), "household": home}
                          for p in cfg.principals if p not in cfg.shared]
        raw["principals"] = [m["id"] for m in raw["members"]] + [home]
        raw["shared"] = [home]
        for client in raw["clients"]:
            client["household"] = home
        raw["policy"] = [{"clients": [c.id], "connection": conn.id, "tools": [tool.name], "effect": effect}
                         for c in cfg.clients for conn in cfg.connections for tool in conn.tools
                         if (effect := policy.effect(c.subject, tool.name, c.id)) != "deny"]
        result.update(schema=2, config=raw)
        normalized, _, _ = self.effective(result)
        result["config"] = {key: normalized.model_dump(mode="json")[key] for key in SECTIONS}
        return result

    def effective(self, state):
        raw = self.base.model_dump(mode="json")
        if set(state["config"]) - set(SECTIONS):
            raise ValueError("managed state contains host-only settings")
        raw.update(state["config"])
        cfg = Config.model_validate(raw)
        names = state.get("display_names", {})  # read-only upgrade input from releases before 0.3
        if not isinstance(names, dict) or set(names) - set(cfg.principals):
            raise ValueError("names must belong to existing members")
        for value in names.values():
            if member_name(value) != value:
                raise ValueError("names must be trimmed")
        entries = copy.deepcopy(self.base_lock.entries)
        for connection, definitions in state["locks"].items():
            for entry in definitions.values():
                if digest_of(entry["definition"]) != entry["sha256"]:
                    raise ValueError("managed tool definition digest mismatch")
            entries[connection] = definitions
        values = {**self.base_secrets, **state["secrets"]}
        for conn in cfg.connections:
            if conn.secret_names() - values.keys():
                raise ValueError("managed configuration references missing credentials")
        return cfg, Lock(entries), values

    def candidate(self):
        state = copy.deepcopy(self.state)
        cfg, _, _ = self.effective(state)
        state["config"] = {key: cfg.model_dump(mode="json")[key] for key in SECTIONS}
        return state

    def save(self, state):
        self.file.set("state", json.dumps(state, ensure_ascii=False))
        self.state = state

    def name_of(self, principal):
        raw = self.state["config"]
        return next((m["name"] for key in ("members", "households") for m in raw.get(key, []) if m["id"] == principal), principal)

    def rename(self, principal, value):
        cfg, _, _ = self.effective(self.state)
        if principal not in cfg.principals:
            raise Refused("unknown_member", 400)
        state = copy.deepcopy(self.state)
        name = member_name(value)
        kind = "members" if principal not in cfg.shared else "households"
        if any(m["id"] != principal and m["name"].casefold() == name.casefold() for m in state["config"][kind]):
            raise Refused("duplicate_member" if kind == "members" else "duplicate_household", 400)
        next(m for m in state["config"][kind] if m["id"] == principal)["name"] = name
        self.save(state)


def kind_of(conn):
    if conn.transport == "http" and conn.service == "reminders":
        return "reminders"
    command = " ".join(conn.command)
    for needle, kind in (("demo_connector.py", "demo"), ("agent_gateway.demo_connector", "demo"), ("connectors.imap_mail", "imap"),
                         ("connectors.caldav_calendar", "caldav"), ("connectors.gmail", "gmail")):
        if needle in command:
            return kind
    return None


def settings_of(conn):
    names = {"IMAP_USERNAME": "username", "IMAP_HOST": "host", "IMAP_PORT": "port",
             "SMTP_HOST": "smtp_host", "SMTP_PORT": "smtp_port", "SMTP_SECURITY": "smtp_security",
             "SMTP_USERNAME": "smtp_username", "SMTP_SENDER": "smtp_sender",
             "CALDAV_USERNAME": "username", "CALDAV_URL": "url", "CALDAV_TIMEZONE": "timezone",
             "GMAIL_CLIENT_ID": "client_id"}
    result = {names[key]: value for key, value in conn.env.items() if key in names}
    if conn.transport == "http":
        result["url"] = conn.url
    return result


def tool_access(conn, tool):
    """Only the reviewed host classification or our fixed catalog can label a read.

    Do not trust upstream MCP readOnlyHint annotations to grant unapproved access.
    """
    if tool.access:
        return tool.access
    kind = kind_of(conn)
    if kind in CATALOG and tool.upstream in {name for name, _ in CATALOG[kind]["tools"]}:
        return "write" if ((kind == "demo" and tool.upstream == "add_note") or
                           tool.upstream in CATALOG[kind].get("writes", ())) else "read"
    return "write"


def connection_access(policy, client, conn):
    effects = [(tool_access(conn, t), policy.effect(client.subject, t.name, client.id)) for t in conn.tools]
    for name, settings in CONNECTION_ACCESS.items():
        if all(effect == settings[access] for access, effect in effects):
            return name
    return "custom"


def make_connection(body, cfg, values):
    if set(body) - {"kind", "id", "owner", "settings", "credentials", "revision"}:
        raise Refused("invalid_connector", 400)
    kind, name, owner = body.get("kind"), body.get("id"), body.get("owner")
    if kind not in CATALOG:
        raise Refused("invalid_connector", 400)
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name):
        raise Refused("invalid_connector_name", 400)
    if owner not in cfg.principals:
        raise Refused("unknown_member", 400)
    settings, provided = body.get("settings", {}), body.get("credentials", {})
    if (not isinstance(settings, dict) or not isinstance(provided, dict)
            or set(settings) - set(CATALOG[kind]["fields"]) or set(provided) - set(CATALOG[kind]["secrets"])
            or any(not isinstance(v, str) or len(v) > 16000 for v in [*settings.values(), *provided.values()])):
        raise Refused("invalid_connector", 400)
    previous = next((c for c in cfg.connections if c.id == name), None)
    if previous and (kind_of(previous) != kind or previous.owner != owner):
        raise Refused("connector_identity_is_fixed", 409)
    fresh = {}

    def field(key, default=""):
        value = settings.get(key, default).strip()
        if not value:
            raise Refused("missing_" + key, 400)
        return value

    def secret(key, env_name):
        old_name = (previous.secret_env.get(env_name) or previous.bearer_secret) if previous else None
        value = provided.get(key) or values.get(old_name)
        if not value:
            raise Refused("missing_" + key, 400)
        secret_name = "web_" + name + "_" + key
        fresh[secret_name] = value
        return secret_name

    service = {"demo": "notes", "imap": "imap-mail", "caldav": "caldav-calendar"}.get(kind, kind)
    # Multiple accounts of one service can belong to a person; account identity is
    # the connector id. Ownership and approval authority are separate.
    raw = {"id": name, "service": previous.service if previous else service,
           "account": previous.account if previous else name, "owner": owner,
           "approver": previous.approver if previous else None,
           "transport": "stdio", "timeout_seconds": 60,
           "command": [sys.executable, "-m", "agent_gateway.connectors." + {"imap": "imap_mail", "caldav": "caldav_calendar"}.get(kind, kind)],
           "env": {}, "secret_env": {}}
    if kind == "demo":
        raw["command"] = [sys.executable, "-m", "agent_gateway.demo_connector"]
        raw["env"] = {"DEMO_ACCOUNT": owner}
        key = "web_" + name + "_demo"
        fresh[key] = values.get(key, "demo-only-" + secrets.token_urlsafe(24))
        raw["secret_env"] = {"DEMO_API_KEY": key}
    elif kind == "imap":
        port = field("port", "993")
        host = field("host", "imap.mail.me.com")
        if not port.isdecimal() or not 1 <= int(port) <= 65535 or any(c in host for c in "/@?#"):
            raise Refused("invalid_imap_server", 400)
        raw["env"] = {"IMAP_USERNAME": field("username"), "IMAP_HOST": host, "IMAP_PORT": port}
        raw["secret_env"] = {"IMAP_PASSWORD": secret("password", "IMAP_PASSWORD")}
        smtp_host = settings.get("smtp_host", "smtp.mail.me.com" if host.lower() == "imap.mail.me.com" else "").strip()
        smtp_port = settings.get("smtp_port", "587").strip() or "587"
        security = settings.get("smtp_security", "starttls").strip() or "starttls"
        if any(c in smtp_host for c in "/@?# \t\r\n") or not smtp_port.isdecimal() or not 1 <= int(smtp_port) <= 65535:
            raise Refused("invalid_smtp_server", 400)
        if security not in ("starttls", "tls"):
            raise Refused("smtp_invalid_security", 400)
        raw["env"].update(SMTP_HOST=smtp_host, SMTP_PORT=smtp_port, SMTP_SECURITY=security,
                          SMTP_USERNAME=settings.get("smtp_username", "").strip(), SMTP_SENDER=settings.get("smtp_sender", "").strip())
        if raw["env"]["SMTP_SENDER"]:
            from .connectors._smtp import address
            from .connectors._base import ConnectorError
            try:
                address(raw["env"]["SMTP_SENDER"])
            except ConnectorError:
                raise Refused("smtp_invalid_address", 400) from None
    elif kind == "caldav":
        url = field("url", "https://caldav.icloud.com")
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment or parts.query:
            raise Refused("https_url_required", 400)
        zone = field("timezone", "UTC")
        try:
            ZoneInfo(zone)
        except (ValueError, ZoneInfoNotFoundError):
            raise Refused("invalid_timezone", 400) from None
        raw["env"] = {"CALDAV_USERNAME": field("username"), "CALDAV_URL": url, "CALDAV_TIMEZONE": zone}
        raw["secret_env"] = {"CALDAV_PASSWORD": secret("password", "CALDAV_PASSWORD")}
    elif kind == "gmail":
        raw["env"] = {"GMAIL_CLIENT_ID": field("client_id")}
        raw["secret_env"] = {"GMAIL_CLIENT_SECRET": secret("client_secret", "GMAIL_CLIENT_SECRET"),
                             "GMAIL_REFRESH_TOKEN": secret("refresh_token", "GMAIL_REFRESH_TOKEN")}
    else:
        raw.update(transport="http", url=field("url"), command=[], bearer_secret=secret("token", ""))
        parts = urlsplit(raw["url"])
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment or parts.query:
            raise Refused("https_url_required", 400)
        # Plain HTTP helpers must be exposed through an HTTPS reverse proxy. The
        # existing YAML-only escape hatch remains unavailable to web input.
    # Keep reviewed restrictions and names, and present newly bundled tools for
    # explicit review. No policy rule is added, so additions start denied.
    raw["tools"] = [t.model_dump(mode="json") for t in previous.tools] if previous else []
    existing = {t["upstream"] for t in raw["tools"]}
    raw["tools"] += [{"upstream": upstream, "name": name.replace("-", "_") + "_" + suffix}
                     for upstream, suffix in CATALOG[kind]["tools"] if upstream not in existing]
    return ConnectionCfg.model_validate(raw), fresh
