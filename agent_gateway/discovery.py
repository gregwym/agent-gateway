"""A fixed MCP surface for permission-filtered, on-demand tool discovery."""
from __future__ import annotations

import hashlib
import re

import mcp_types as types

from .admin_config import kind_of, mailbox_metadata
from .approval_dispatch import KEY_PROPERTY, WAIT_PROPERTY
from .web_catalog import DESCRIPTIONS
from .web_profiles import connection_origins

SEARCH_TOOLS = "gateway_search_tools"
SEARCH_CONNECTIONS = "gateway_search_connections"
CALL_TOOL = "gateway_call_tool"
DISCOVERY_INSTRUCTIONS = (
    "Start with gateway_search_connections to select an authorized account or website. "
    "Then call gateway_search_tools with that connection ID and a focused query; "
    "this returns only the relevant tool schemas. Use gateway_call_tool with the selected connection and tool. "
    "Search tools across all connections only when the target connection is unknown."
)


def schema(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


def text(description, maximum=200):
    return {"type": "string", "maxLength": maximum, "description": description}


PAGING = {"query": text("Optional search words; empty finds all permitted matches."),
          "offset": {"type": "integer", "minimum": 0, "maximum": 100000, "default": 0},
          "limit": {"type": "integer", "minimum": 1, "maximum": 25, "default": 10}}
TOOLS = [
    types.Tool(name=SEARCH_CONNECTIONS, description=(
        "Start here to find an authorized connection by account, website, service, or owner. "
        "Mail addresses and their aliases share a connection ID. Pass the selected ID to gateway_search_tools "
        "so you only receive schemas for that connection. If you already know a tool, pass it here to inspect "
        "its connection-specific variants and approval requirements."
    ), input_schema=schema({**PAGING, "tool": text("Optional known shared tool name.", 128)}),
        annotations=types.ToolAnnotations(read_only_hint=True)),
    types.Tool(name=SEARCH_TOOLS, description=(
        "Find permitted tools and their parameter schemas. First use gateway_search_connections to pick a connection, "
        "then pass its ID as connection and use a focused query. Omit the connection only to search across accounts. "
        "Results reflect current permissions; run a selected tool with gateway_call_tool."
    ), input_schema=schema({**PAGING, "connection": text("Connection ID from gateway_search_connections. Omit only to search across all permitted connections.", 48)}),
        annotations=types.ToolAnnotations(read_only_hint=True)),
    types.Tool(
        name=CALL_TOOL,
        description="Execute a permitted tool: generate a new idempotency_key for each intended operation and pass "
                    "tool, connection and arguments. Reuse the same key if a response is lost. "
                    "Set background=true to return immediately. Share any approval_url with the approver; "
                    "the Gateway runs the action after Passkey approval. To get status and results, call this "
                    "same tool with only the original idempotency_key and optional wait_seconds.",
        input_schema={
            **schema({"tool": text("Shared tool name from gateway_search_tools.", 128),
                      "connection": text("Connection ID from gateway_search_connections.", 48),
                      "arguments": {"type": "object", "description": "Parameters for the selected tool and connection."},
                      "background": {"type": "boolean", "default": False, "description": "Queue the call. Approval requirements still apply."},
                      "variant": text("Optional variant ID from gateway_search_connections.", 64),
                      "idempotency_key": KEY_PROPERTY,
                      "wait_seconds": WAIT_PROPERTY}, ("idempotency_key",)),
            "oneOf": [
                {"required": ["tool", "connection", "arguments"], "not": {"required": ["wait_seconds"]}},
                {"not": {"anyOf": [{"required": [key]} for key in ("tool", "connection", "arguments", "background", "variant")]}},
            ],
        },
        annotations=types.ToolAnnotations(read_only_hint=False),
    ),
]
BY_NAME = {tool.name: tool for tool in TOOLS}


def shared_name(route):
    kind = kind_of(route.conn)
    namespace = {"imap": "mail", "caldav": "calendar", "gmail": "gmail", "demo": "notes", "reminders": "reminders", "web": "web"}.get(kind)
    raw = f"{namespace or 'service_' + route.conn.service}_{route.tool.upstream}"
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", raw)
    if cleaned != raw or len(cleaned) > 64:
        cleaned = cleaned[:55] + "_" + hashlib.sha256(raw.encode()).hexdigest()[:8]
    return cleaned


def permitted(gateway, who):
    return [route for route in gateway.routes.values() if route.exposed is not None and gateway.problem(route) is None
            and gateway.policy.effect(who.principal, route.tool.name, who.client_id) != "deny"]


def matches(query, *values):
    haystack = " ".join(values).casefold()
    return all(word in haystack for word in query.casefold().split())


def page(items, args, key):
    offset, limit = args.get("offset", 0), args.get("limit", 10)
    return {key: items[offset:offset + limit], "total": len(items),
            "next_offset": offset + limit if offset + limit < len(items) else None}


def search_tools(gateway, who, args):
    grouped = {}
    for route in permitted(gateway, who):
        if args.get("connection") and args["connection"] != route.conn.id:
            continue
        name = shared_name(route)
        definition = gateway.lock.get(route.conn.id, route.tool.upstream)["definition"]
        if not matches(args.get("query", ""), name, route.exposed.description or "", definition.get("description", ""), route.conn.service):
            continue
        grouped.setdefault(name, []).append(route)
    items = []
    for name, routes in sorted(grouped.items()):
        definition = gateway.lock.get(routes[0].conn.id, routes[0].tool.upstream)["definition"]
        items.append({"name": name, "description": routes[0].exposed.description or definition.get("description", ""),
                      "inputSchema": routes[0].exposed.input_schema, "connection_count": len({r.conn.id for r in routes}),
                      "note": "Connection restrictions can differ. Search connections for this tool to get its exact permitted parameters."})
    catalog = gateway.website_catalogs
    # Description maintenance is on demand. It does not clutter the ordinary
    # tool list but is discoverable by name and from website connections.
    if catalog and args.get("query"):
        client = next(c for c in gateway.cfg.clients if c.id == who.client_id)
        for name, (description, schema) in DESCRIPTIONS.items():
            if not matches(args["query"], name, description, "catalog OpenAPI GraphQL"):
                continue
            conns = [conn for conn in gateway.cfg.connections
                     if (not args.get("connection") or args["connection"] == conn.id)
                     and catalog.connection(gateway, client, conn.id, name)]
            if conns:
                items.append({"name": name, "description": description, "inputSchema": schema, "connection_count": len(conns)})
    return page(items, args, "tools")


def search_connections(gateway, who, args):
    grouped = {}
    catalog_tool = args.get("tool") in DESCRIPTIONS
    for route in permitted(gateway, who):
        if args.get("tool") and not catalog_tool and args["tool"] != shared_name(route):
            continue
        grouped.setdefault(route.conn.id, []).append(route)
    items = []
    for name, routes in sorted(grouped.items()):
        conn = routes[0].conn
        owner = gateway.cfg.name_of(conn.owner)
        mailbox = mailbox_metadata(conn)
        origins = connection_origins(conn) if kind_of(conn) == "web" else []
        origin = origins[0] if origins else None
        if catalog_tool:
            client = next(c for c in gateway.cfg.clients if c.id == who.client_id)
            if not gateway.website_catalogs or not gateway.website_catalogs.connection(gateway, client, conn.id, args["tool"]):
                continue
        if not matches(args.get("query", ""), name, conn.service, owner, *origins, mailbox.get("email", ""),
                       mailbox.get("sender_email", ""), *mailbox.get("aliases", ())):
            continue
        item = {"connection": name, "service": conn.service, "owner": owner,
                "tool_count": len({shared_name(r) for r in routes}), **mailbox}
        if origin:
            item["origin"] = origin
            item["api_origins"] = origins[1:]
            if gateway.website_catalogs:
                item["api_catalog"] = gateway.website_catalogs.metadata(conn, who.client_id)
        if who.client_id in conn.mailbox_access:
            item["mailbox_paths_restricted"] = True
        if args.get("tool") and not catalog_tool:
            item["variants"] = []
            for route in sorted(routes, key=lambda r: r.tool.name):
                tool = route.tool.name
                variant = {"id": tool, "description": route.exposed.description or "", "inputSchema": route.exposed.input_schema}
                if origin:
                    variant["access"] = {kind: gateway.policy.effect(who.principal, tool, who.client_id, operation=kind)
                                         for kind in ("read", "write")}
                else:
                    variant["approval_required"] = gateway.policy.effect(who.principal, tool, who.client_id) == "approval_required"
                item["variants"].append(variant)
        items.append(item)
    return page(items, args, "connections")


def candidates(gateway, who, args):
    return [r for r in permitted(gateway, who) if shared_name(r) == args["tool"] and r.conn.id == args["connection"]
            and (not args.get("variant") or args["variant"] == r.tool.name)]
