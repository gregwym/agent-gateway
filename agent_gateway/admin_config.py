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

from .config import Config, ConnectionCfg, allocate_tool_name, is_mail_send, validate_name
from .credentials import EncryptedFileStore
from .gmail_scopes import ORGANIZE_TOOLS, SCOPES, tool_enabled
from .lock import Lock, digest_of
from .mail_address import email_address
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
CONNECTOR_NAME = r"[a-z][a-z0-9_-]{0,31}"
from .admin_remote import SPEC, make_remote
from .plugins import SPEC as LOCAL_SPEC, Plugin
from .web_profiles import (
    CUSTOM_PROFILE, PROFILE_ENV, SESSION_ENV, WEB_TOOLS, WebProfile, connection_origins, is_website, website_origin,
)

CATALOG = {
    "remote": SPEC,
    "web": {**LOCAL_SPEC, "label": "Website / 网站", "fields": ["plugin", "origin"], "probe": ("http_request", {"method": "HEAD", "path": "/"})},
    "imap": {"label": "Mail / 邮箱 (IMAP + SMTP)",
             "fields": ["username", "host", "port", "smtp_host", "smtp_port", "smtp_security", "smtp_username", "smtp_sender",
                        "mailbox_email", "mailbox_aliases"], "secrets": ["password"],
             "tools": [("list_mailboxes", "mailboxes"), ("search_messages", "search"), ("get_message", "get"), ("get_attachment", "attachment"),
                       ("list_messages", "list"), ("get_messages", "get_batch"), ("set_message_state", "set_state"),
                       ("move_messages", "move"), ("archive_messages", "archive"), ("trash_messages", "trash"), ("send_message", "send")],
             "writes": {"set_message_state", "move_messages", "archive_messages", "trash_messages", "send_message"},
             "probe": ("list_mailboxes", {})},
    "caldav": {"label": "iCloud Calendar / CalDAV", "fields": ["username", "url", "timezone"], "secrets": ["password"],
               "tools": [("list_calendars", "calendars"), ("list_events", "events"), ("get_event", "event"), ("check_conflicts", "conflicts")],
               "probe": ("list_calendars", {})},
    "gmail": {"label": "Gmail (Google OAuth)", "fields": ["client_id", "gmail_access"], "secrets": ["client_secret", "refresh_token"],
              "tools": [("search_messages", "search"), ("get_message", "get"), ("get_attachment", "attachment"), ("list_labels", "labels"),
                        ("send_message", "send"), *ORGANIZE_TOOLS],
              "writes": {"send_message", *(name for name, _ in ORGANIZE_TOOLS)},
              "probe": ("search_messages", {"query": "in:inbox", "limit": 1})},
    "reminders": {"label": "Reminders Mac helper / 提醒事项 Mac 辅助服务", "fields": ["url"], "secrets": ["token"],
                  "tools": [("reminders_lists", "lists"), ("reminders_list", "list"), ("reminders_get", "get")],
                  "probe": ("reminders_lists", {})},
    "local": LOCAL_SPEC,
    "gateway_config": {"label": "Gateway configuration / 网关配置", "fields": [], "secrets": [],
                       "tools": [("read", "read"), ("provision", "provision")],
                       "writes": {"provision"}, "probe": (None, {})},
    "demo": {"label": "Demo notes / 模拟笔记", "fields": [], "secrets": [],
             "tools": [("list_notes", "list"), ("get_note", "get"), ("add_note", "add")],
             "probe": ("list_notes", {"folder": "inbox"})},
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
        self.state, self.catalog_updates = self.reconcile(self.upgrade(self.state))
        if self.state.get("gmail_client"):
            from .admin_oauth import store_gmail_client
            store_gmail_client(self.state, self.state["gmail_client"])

    def reconcile(self, state):
        from .catalog_sync import sync_catalog
        cfg, lock, values = self.effective(state)
        if not any(kind_of(conn) == "gateway_config" for conn in cfg.connections):
            name, suffix = "gateway_config", 1
            occupied = {conn.id for conn in cfg.connections}
            while name in occupied:
                name = f"gateway_config-{suffix}"
                suffix += 1
            conn, _ = make_connection({"id": name, "kind": "gateway_config", "owner": cfg.admin.owner},
                                      cfg, values)
            cfg = cfg.model_copy(update={"connections": [*cfg.connections, conn]})
        cfg, lock, metadata, reports = sync_catalog(cfg, lock, state.get("bundled_catalog", {}))
        result = copy.deepcopy(state)
        result["config"] = {key: cfg.model_dump(mode="json")[key] for key in SECTIONS}
        for conn_id, report in reports.items():
            if report["automatic"]:
                result["locks"][conn_id] = lock.entries.get(conn_id, {})
        result["bundled_catalog"] = metadata
        return result, reports

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
        raw["policy"] = [{"clients": [c.id], "connection": conn.id, "tools": [tool.name], "effect": effect,
                          "operation": operation, "mail_send_direct": effect == "allow" and is_mail_send(conn, tool)}
                         for c in cfg.clients for conn in cfg.connections for tool in conn.tools
                         for operation in (("read", "write") if is_website(conn) and tool.upstream in WEB_TOOLS else (None,))
                         if (effect := policy.effect(c.subject, tool.name, c.id, operation=operation)) != "deny"]
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
    if conn.plugin:
        return "web" if is_website(conn) else "local"
    if conn.transport == "http" and conn.service == "reminders":
        return "reminders"
    if conn.transport == "http":
        return "remote"
    command = " ".join(conn.command)
    for needle, kind in (("demo_connector.py", "demo"), ("agent_gateway.demo_connector", "demo"), ("connectors.imap_mail", "imap"),
                         ("connectors.caldav_calendar", "caldav"), ("connectors.gmail", "gmail"),
                         ("connectors.gateway_config", "gateway_config")):
        if needle in command:
            return kind
    return None


def settings_of(conn):
    names = {"IMAP_USERNAME": "username", "IMAP_HOST": "host", "IMAP_PORT": "port",
             "SMTP_HOST": "smtp_host", "SMTP_PORT": "smtp_port", "SMTP_SECURITY": "smtp_security",
             "SMTP_USERNAME": "smtp_username", "SMTP_SENDER": "smtp_sender",
             "CALDAV_USERNAME": "username", "CALDAV_URL": "url", "CALDAV_TIMEZONE": "timezone",
             "GMAIL_CLIENT_ID": "client_id", "GMAIL_ACCESS": "gmail_access"}
    result = {names[key]: value for key, value in conn.env.items() if key in names}
    if conn.plugin:
        return {"plugin": conn.plugin}
    if kind_of(conn) == "imap":
        result.update(mailbox_email=conn.mailbox_email or "", mailbox_aliases="\n".join(conn.mailbox_aliases))
    if conn.transport == "http":
        result["url"] = conn.url
        if kind_of(conn) == "remote":
            result.update(service=conn.service, auth="oauth" if conn.oauth_ref else "bearer" if conn.bearer_secret else "header" if conn.secret_headers else "none",
                          header=next(iter(conn.secret_headers), ""))
    return result


def mailbox_metadata(conn):
    kind = kind_of(conn)
    if kind not in ("imap", "gmail"):
        return {}
    primary = conn.mailbox_email
    result = {}
    if kind == "imap":
        username = conn.env.get("IMAP_USERNAME", "")
        icloud = conn.env.get("IMAP_HOST", "imap.mail.me.com").lower() == "imap.mail.me.com"
        default_address = username + "@icloud.com" if icloud and username and "@" not in username else username
        primary = primary or email_address(default_address)
        sender = email_address(conn.env.get("SMTP_SENDER"))
        if sender and sender != primary:
            result["sender_email"] = sender
    seen = {primary.casefold()} if primary else set()
    aliases = []
    for alias in conn.mailbox_aliases:
        if alias.casefold() not in seen:
            aliases.append(alias)
            seen.add(alias.casefold())
    if primary:
        result["email"] = primary
    if aliases:
        result["aliases"] = aliases
    return result


def tool_access(conn, tool):
    """Only the reviewed host classification or our fixed catalog can label a read.

    Do not trust upstream MCP readOnlyHint annotations to grant unapproved access.
    """
    if is_website(conn) and tool.upstream in WEB_TOOLS:
        return "dynamic"
    if tool.access:
        return tool.access
    kind = kind_of(conn)
    if kind in CATALOG and tool.upstream in {name for name, _ in CATALOG[kind]["tools"]}:
        return "write" if ((kind == "demo" and tool.upstream == "add_note") or
                           tool.upstream in CATALOG[kind].get("writes", ())) else "read"
    return "write"


def catalog_tools(conn):
    kind = kind_of(conn)
    tools = CATALOG.get(kind, {}).get("tools", ())
    if kind == "gmail":
        return [tool for tool in tools if tool_enabled(tool[0], conn.env.get("GMAIL_ACCESS", "read"))]
    return tools


def catalog_additions(conn, cfg):
    registered = {tool.upstream for tool in conn.tools}
    occupied = {tool.name for c in cfg.connections for tool in c.tools}
    return [{"upstream": upstream, "name": allocate_tool_name(conn.id, upstream, suffix, occupied)}
            for upstream, suffix in catalog_tools(conn) if upstream not in registered]


def extend_catalog_tools(conn, cfg):
    raw = conn.model_dump(mode="json")
    raw["tools"] += catalog_additions(conn, cfg)
    return ConnectionCfg.model_validate(raw)


def connection_access(policy, client, conn):
    effects = [(operation or access, policy.effect(client.subject, t.name, client.id, operation=operation))
               for t in conn.tools if not is_mail_send(conn, t)
               for access in (tool_access(conn, t),)
               for operation in (("read", "write") if access == "dynamic" else (None,))]
    has_send = any(policy.effect(client.subject, t.name, client.id) != "deny"
                   for t in conn.tools if is_mail_send(conn, t))
    for name, settings in CONNECTION_ACCESS.items():
        if has_send and settings["write"] == "deny":
            continue
        if all(effect == settings[access] for access, effect in effects):
            return name
    return "custom"


def make_connection(body, cfg, values, *, gmail_email=None, plugins=None):
    if set(body) - {"kind", "id", "owner", "settings", "credentials", "revision"}:
        raise Refused("invalid_connector", 400)
    kind, name, owner = body.get("kind"), body.get("id"), body.get("owner")
    if kind not in CATALOG:
        raise Refused("invalid_connector", 400)
    if not isinstance(name, str) or not re.fullmatch(CONNECTOR_NAME, name):
        raise Refused("invalid_connector_name", 400)
    if owner not in cfg.principals:
        raise Refused("unknown_member", 400)
    settings, provided = body.get("settings", {}), body.get("credentials", {})
    previous = next((c for c in cfg.connections if c.id == name), None)
    if previous and (kind_of(previous) != kind or previous.owner != owner):
        raise Refused("connector_identity_is_fixed", 409)
    plugin = None
    allowed_secrets = CATALOG[kind]["secrets"]
    if kind in ("local", "web"):
        plugin_id = settings.get("plugin") if isinstance(settings, dict) else None
        if not isinstance(plugin_id, str):
            raise Refused("local_plugin_unavailable", 400)
        if previous:
            if previous.plugin != plugin_id:
                raise Refused("connector_identity_is_fixed", 409)
            allowed_secrets = previous.secret_env
        else:
            if kind == "web" and plugin_id == CUSTOM_PROFILE:
                try:
                    profile = WebProfile(origin=website_origin(settings.get("origin")))
                except ValueError:
                    raise Refused("website_origin_invalid", 400) from None
                plugin = Plugin(id=CUSTOM_PROFILE, label="Website", kind="web", web=profile.model_dump())
            else:
                plugin = (plugins or {}).get(plugin_id)
            if plugin is None or (kind == "web") != (plugin.kind == "web"):
                raise Refused("local_plugin_unavailable", 400)
            allowed_secrets = plugin.credential_slots()
    if (not isinstance(settings, dict) or not isinstance(provided, dict)
            or set(settings) - set(CATALOG[kind]["fields"]) or set(provided) - set(allowed_secrets)
            or any(not isinstance(v, str) or len(v) > 16000 for v in settings.values())
            or any(not isinstance(v, str) or len(v) > (60_000 if kind == "web" and k == SESSION_ENV else 16000)
                   for k, v in provided.items())):
        raise Refused("invalid_connector", 400)
    # The public ID can change. Keep the account and credentials bound to the
    # original connector, even if the old ID is used to create another one.
    accounts = {c.account for c in cfg.connections}
    account = previous.account if previous else name
    if not previous:
        while account in accounts:
            account = f"{name[:31]}-{secrets.token_hex(8)}"
    other_refs = {ref for c in cfg.connections if c.id != name for ref in c.secret_names()}

    def credential_ref(key, old_ref=None):
        preferred = f"web_{account}_{key}"
        if old_ref and old_ref.startswith(preferred + "_") and old_ref not in other_refs:
            return old_ref
        if preferred not in values or (preferred == old_ref and preferred not in other_refs):
            return preferred
        while (ref := f"{preferred}_{secrets.token_hex(8)}") in values:
            pass
        return ref

    if kind == "remote":
        return make_remote(name, owner, account, settings, provided, previous, values, credential_ref)
    if kind == "gateway_config" and (not cfg.admin or owner != cfg.admin.owner or any(
            conn.id != name and kind_of(conn) == kind for conn in cfg.connections)):
        raise Refused("invalid_configuration_connector", 400)
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
        if old_name and not provided.get(key):
            return old_name
        secret_name = credential_ref(key, old_name)
        fresh[secret_name] = value
        return secret_name

    if kind in ("local", "web"):
        if kind == "web" and provided.get(SESSION_ENV):
            from .connectors.web import import_session
            profile = (WebProfile.saved(previous.env[PROFILE_ENV]) if previous
                       else WebProfile.model_validate(plugin.web))
            try:
                provided = {SESSION_ENV: import_session(provided[SESSION_ENV], profile, connection_origins(previous)[1:] if previous else ())}
            except (ValueError, RecursionError):
                raise Refused("web_session_invalid", 400) from None
        refs = {}
        for env_name in allowed_secrets:
            if not provided.get(env_name) and (not previous or not values.get(previous.secret_env.get(env_name))):
                raise Refused("local_plugin_credential_required", 400)
            refs[env_name] = secret(env_name, env_name)
        if previous:
            return previous.model_copy(update={"secret_env": refs}), fresh
        command, env = plugin.connection()
        return ConnectionCfg(id=name, service=plugin.id, account=account, owner=owner, plugin=plugin.id,
                             transport="stdio", command=command, env=env, secret_env=refs, socket=plugin.socket,
                             max_concurrency=1, timeout_seconds=60, tools=[]), fresh

    service = {"demo": "notes", "imap": "imap-mail", "caldav": "caldav-calendar"}.get(kind, kind)
    raw = {"id": name, "service": previous.service if previous else service,
           "account": account, "owner": owner,
           "approver": previous.approver if previous else None,
           "transport": "stdio", "timeout_seconds": 60,
           "command": [sys.executable, "-m", "agent_gateway.connectors." + {"imap": "imap_mail", "caldav": "caldav_calendar"}.get(kind, kind)],
           "env": {}, "secret_env": {}}
    if kind == "demo":
        raw["command"] = [sys.executable, "-m", "agent_gateway.demo_connector"]
        raw["env"] = {"DEMO_ACCOUNT": owner}
        old_ref = previous.secret_env.get("DEMO_API_KEY") if previous else None
        key = credential_ref("demo", old_ref)
        fresh[key] = values.get(old_ref) or "demo-only-" + secrets.token_urlsafe(24)
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
        raw["mailbox_email"] = settings.get("mailbox_email", previous.mailbox_email if previous else "") or None
        if raw["mailbox_email"]:
            raw["mailbox_email"] = raw["mailbox_email"].strip() or None
        raw["mailbox_aliases"] = ([line.strip() for line in settings["mailbox_aliases"].splitlines() if line.strip()]
                                  if "mailbox_aliases" in settings else previous.mailbox_aliases if previous else [])
        if raw["mailbox_email"] and not email_address(raw["mailbox_email"]):
            raise Refused("invalid_mailbox_email", 400)
        if len(raw["mailbox_aliases"]) > 50 or any(not email_address(alias) for alias in raw["mailbox_aliases"]):
            raise Refused("invalid_mailbox_aliases", 400)
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
        old_access = previous.env.get("GMAIL_ACCESS", "read") if previous else "read"
        access = settings.get("gmail_access", old_access)
        if access not in SCOPES:
            raise Refused("gmail_access_invalid", 400)
        client_id = field("client_id")
        if previous and ((access != old_access and not provided.get("refresh_token")) or
                         (client_id != previous.env.get("GMAIL_CLIENT_ID") and
                          not (provided.get("client_secret") and provided.get("refresh_token")))):
            raise Refused("gmail_reauthorize_required", 400)
        raw["env"] = {"GMAIL_CLIENT_ID": client_id, "GMAIL_ACCESS": access}
        raw["secret_env"] = {"GMAIL_CLIENT_SECRET": secret("client_secret", "GMAIL_CLIENT_SECRET"),
                             "GMAIL_REFRESH_TOKEN": secret("refresh_token", "GMAIL_REFRESH_TOKEN")}
        if gmail_email:
            raw["mailbox_email"] = gmail_email
        elif previous and previous.env.get("GMAIL_CLIENT_ID") == raw["env"]["GMAIL_CLIENT_ID"] and all(
                fresh.get(ref, values.get(ref)) == values.get(previous.secret_env.get(key)) for key, ref in raw["secret_env"].items()):
            raw["mailbox_email"] = previous.mailbox_email
            raw["mailbox_aliases"] = previous.mailbox_aliases
    elif kind == "reminders":
        raw.update(transport="http", url=field("url"), command=[], bearer_secret=secret("token", ""))
        parts = urlsplit(raw["url"])
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment or parts.query:
            raise Refused("https_url_required", 400)
        # Plain HTTP helpers must be exposed through an HTTPS reverse proxy. The
        # existing YAML-only escape hatch remains unavailable to web input.
    # Keep reviewed restrictions and names, and present newly bundled tools for
    # explicit review. No policy rule is added, so additions start denied.
    raw["tools"] = [t.model_dump(mode="json") for t in previous.tools
                    if kind != "gmail" or tool_enabled(t.upstream, raw["env"]["GMAIL_ACCESS"])] if previous else []
    return extend_catalog_tools(ConnectionCfg.model_validate(raw), cfg), fresh
