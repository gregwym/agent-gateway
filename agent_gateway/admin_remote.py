"""Web-managed remote MCP connections: bounded settings and explicit tool review."""
import re

from .config import ConnectionCfg, NAME, ToolCfg, allocate_tool_name
from .oauth import https_url
from .passkey import Refused

FIELDS = ["url", "service", "auth", "header", "issuer", "client_id", "auth_method", "scope", "client_metadata_url", "oauth_client"]
SPEC = {"label": "Remote MCP / 远程 MCP", "fields": FIELDS, "secrets": ["token", "client_secret"], "tools": [], "probe": (None, {})}


def make_remote(name, owner, account, settings, provided, previous, values, credential_ref):
    url = https_url(settings.get("url", ""))
    service = settings.get("service") or "remote-mcp"
    auth = settings.get("auth", "none")
    if not re.fullmatch(NAME, service) or auth not in ("none", "bearer", "header", "oauth"):
        raise Refused("invalid_remote_settings", 400)
    if settings.get("oauth_client") and auth != "oauth":
        raise Refused("oauth_client_settings_invalid", 400)
    if previous and previous.service != service:
        raise Refused("connector_identity_is_fixed", 409)
    raw = {"id": name, "owner": owner, "service": service, "account": account,
           "transport": "http", "url": url, "tools": [t.model_dump(mode="json") for t in previous.tools] if previous else [],
           "approver": previous.approver if previous else None}
    fresh = {}
    if auth in ("bearer", "header"):
        old = None
        if previous and previous.url == url:
            old = previous.bearer_secret if auth == "bearer" else previous.secret_headers.get(settings.get("header"))
        token = provided.get("token") or values.get(old)
        if not token:
            raise Refused("missing_token", 400)
        if any(ord(c) < 32 or ord(c) == 127 for c in token):
            raise Refused("invalid_remote_token", 400)
        key = old if old and not provided.get("token") else credential_ref("token", old)
        if provided.get("token"):
            fresh[key] = token
        if auth == "bearer":
            raw["bearer_secret"] = key
        else:
            header = settings.get("header", "")
            # Routing, framing and protocol headers cannot be credentials.
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", header) or header.lower() in {
                "host", "content-length", "content-type", "accept", "connection", "transfer-encoding", "cookie", "origin",
                "referer", "mcp-session-id", "mcp-protocol-version", "proxy-authorization", "upgrade", "te", "trailer"
            } or header.lower().startswith(("sec-", "x-forwarded-")):
                raise Refused("invalid_credential_header", 400)
            raw["secret_headers"] = {header: key}
    if auth == "oauth" and previous and previous.url == url:
        raw["oauth_ref"] = previous.oauth_ref
    return ConnectionCfg.model_validate(raw), fresh


_READ_ACTIONS = frozenset({"get", "list", "search", "query", "read", "fetch", "find", "count", "describe", "lookup"})
_WRITE_ACTIONS = frozenset({
    "add", "archive", "cancel", "close", "complete", "create", "delete", "exec", "execute",
    "insert", "move", "publish", "remove", "replace", "run", "save", "send", "set",
    "submit", "update", "upload", "upsert", "write",
})


def suggested_access(name, definition):
    """Suggest a category for admin review using the name and conflicting hints."""
    annotations = definition.get("annotations") or {}
    if annotations.get("readOnlyHint") is False or annotations.get("destructiveHint") is True:
        return "write"
    separated = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", separated)
    words = re.findall(r"[a-z0-9]+", separated.casefold())
    if not words or words[0] not in _READ_ACTIONS or _WRITE_ACTIONS.intersection(words[1:]):
        return "write"
    if words[0] == "query":
        properties = definition.get("inputSchema", {}).get("properties") or {}
        if {"sql", "cypher", "sparql", "statement"}.intersection([*words[1:], *properties]):
            return "write"
    return "read"


def remote_tools(conn, definitions, cfg):
    previous = {t.upstream: t for t in conn.tools}
    occupied = {t.name for c in cfg.connections for t in c.tools} | {t.name for t in conn.tools}
    result = []
    for upstream in definitions:
        if upstream in previous:
            tool = previous[upstream]
        else:
            suffix = re.sub(r"[^A-Za-z0-9_-]", "_", upstream)
            name = allocate_tool_name(conn.id, upstream, suffix, occupied)
            tool = ToolCfg(upstream=upstream, name=name, access=suggested_access(upstream, definitions[upstream]))
        result.append(tool)
    return conn.model_copy(update={"tools": result})


def apply_selection(draft, body):
    selection = body.get("tools")
    if not isinstance(selection, list) or not selection or len(selection) > 1000:
        raise Refused("remote_tool_selection_required", 400)
    raw = draft["state"]["config"]
    conn = next(c for c in raw["connections"] if c["id"] == draft["connection"])
    from .plugins import MANIFEST_ENV
    fixed = MANIFEST_ENV in conn.get("env", {}) and conn.get("plugin")
    available = {t["upstream"]: t for t in conn["tools"]}
    chosen, names, revoke = [], set(), set()
    for item in selection:
        if not isinstance(item, dict) or set(item) != {"upstream", "access"} or not isinstance(item.get("upstream"), str):
            raise Refused("invalid_remote_tool_selection", 400)
        tool = available.get(item["upstream"])
        if tool is None or item["upstream"] in names or item["access"] not in ("read", "write") or (fixed and item["access"] != tool["access"]):
            raise Refused("invalid_remote_tool_selection", 400)
        names.add(item["upstream"])
        if tool.get("access") == "read" and item["access"] == "write":
            revoke.add(tool["name"])
        chosen.append({**tool, "access": item["access"]})
    allowed = {t["name"] for t in chosen} - revoke
    raw["policy"] = [{**r, "tools": [t for t in r["tools"] if t in allowed]} if r["connection"] == conn["id"] else r
                     for r in raw["policy"] if r["connection"] != conn["id"] or any(t in allowed for t in r["tools"])]
    conn["tools"] = chosen
    draft["state"]["locks"][conn["id"]] = {k: v for k, v in draft["state"]["locks"][conn["id"]].items() if k in names}
