"""Encrypted web-managed overrides, and a bounded catalog of connector templates.

The immutable host configuration owns paths, origin, administrator, and server
settings. Web administration cannot install code or choose subprocess commands.
"""
import copy
import json
import re
import secrets
import sys
import unicodedata
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .config import Config, ConnectionCfg
from .credentials import EncryptedFileStore
from .lock import Lock, digest_of
from .passkey import Refused

SECTIONS = ("principals", "shared", "clients", "connections", "policy")
CATALOG = {
    "demo": {"label": "Demo notes / 模拟笔记", "fields": [], "secrets": [],
             "tools": [("list_notes", "list"), ("get_note", "get"), ("add_note", "add")],
             "probe": ("list_notes", {"folder": "inbox"})},
    "imap": {"label": "iCloud Mail / IMAP", "fields": ["username", "host", "port"], "secrets": ["password"],
             "tools": [("list_mailboxes", "mailboxes"), ("search_messages", "search"), ("get_message", "get"), ("get_attachment", "attachment")],
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


def display_name(value):
    if not isinstance(value, str):
        raise Refused("invalid_display_name", 400)
    value = value.strip()
    if not 1 <= len(value) <= 80 or any(unicodedata.category(c) in ("Cc", "Cs") or
            unicodedata.bidirectional(c) in ("LRE", "RLE", "LRO", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI") for c in value):
        raise Refused("invalid_display_name", 400)
    return value


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

    def effective(self, state):
        raw = self.base.model_dump(mode="json")
        if set(state["config"]) - set(SECTIONS):
            raise ValueError("managed state contains host-only settings")
        raw.update(state["config"])
        cfg = Config.model_validate(raw)
        names = state.get("display_names", {})
        if not isinstance(names, dict) or set(names) - set(cfg.principals):
            raise ValueError("display names must belong to existing members")
        for value in names.values():
            if display_name(value) != value:
                raise ValueError("display names must be trimmed")
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
        return self.state.get("display_names", {}).get(principal, principal)

    def rename(self, principal, value):
        cfg, _, _ = self.effective(self.state)
        if principal not in cfg.principals:
            raise Refused("unknown_member", 400)
        state = copy.deepcopy(self.state)
        state.setdefault("display_names", {})[principal] = display_name(value)
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
             "CALDAV_USERNAME": "username", "CALDAV_URL": "url", "CALDAV_TIMEZONE": "timezone",
             "GMAIL_CLIENT_ID": "client_id"}
    result = {names[key]: value for key, value in conn.env.items() if key in names}
    if conn.transport == "http":
        result["url"] = conn.url
    return result


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
    # the connector id, while owner is the person who can approve access.
    raw = {"id": name, "service": previous.service if previous else service,
           "account": previous.account if previous else name, "owner": owner,
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
    raw["tools"] = ([t.model_dump(mode="json") for t in previous.tools] if previous else
                    [{"upstream": upstream, "name": name.replace("-", "_") + "_" + suffix}
                     for upstream, suffix in CATALOG[kind]["tools"]])
    return ConnectionCfg.model_validate(raw), fresh
