"""A fixed MCP surface for permission-filtered, on-demand tool discovery."""
from __future__ import annotations

import hashlib
import re

import mcp_types as types

from .admin_config import kind_of, mailbox_metadata
from .approval_dispatch import KEY_PROPERTY, WAIT_PROPERTY

SEARCH_TOOLS = "gateway_search_tools"
SEARCH_CONNECTIONS = "gateway_search_connections"
CALL_TOOL = "gateway_call_tool"


def schema(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


def text(description, maximum=200):
    return {"type": "string", "maxLength": maximum, "description": description}


PAGING = {"query": text("Optional search words; empty finds all permitted matches."),
          "offset": {"type": "integer", "minimum": 0, "maximum": 100000, "default": 0},
          "limit": {"type": "integer", "minimum": 1, "maximum": 25, "default": 10}}
TOOLS = [
    types.Tool(name=SEARCH_TOOLS, description="Search the tools this Agent may use. Tools are shared across connections. Returns names, parameter schemas and connection counts. Use gateway_search_connections to inspect connection-specific restrictions, then gateway_call_tool to execute. Results reflect current permissions, without reloading the MCP tool list.",
               input_schema=schema({**PAGING, "connection": text("Optional connection ID to search within.", 48)}), annotations=types.ToolAnnotations(read_only_hint=True)),
    types.Tool(name=SEARCH_CONNECTIONS, description="Search connections this Agent may access by name, service, owner, or known mailbox address and aliases. Mail aliases share the same connection ID. Optionally specify a tool from gateway_search_tools to see its permitted parameter variants and approval requirements on each connection. Hidden or denied connections are never returned.",
               input_schema=schema({**PAGING, "tool": text("Optional shared tool name from gateway_search_tools.", 128)}), annotations=types.ToolAnnotations(read_only_hint=True)),
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
    namespace = {"imap": "mail", "caldav": "calendar", "gmail": "gmail", "demo": "notes", "reminders": "reminders"}.get(kind)
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
    return page(items, args, "tools")


def search_connections(gateway, who, args):
    grouped = {}
    for route in permitted(gateway, who):
        if args.get("tool") and args["tool"] != shared_name(route):
            continue
        grouped.setdefault(route.conn.id, []).append(route)
    items = []
    for name, routes in sorted(grouped.items()):
        conn = routes[0].conn
        owner = gateway.cfg.name_of(conn.owner)
        mailbox = mailbox_metadata(conn)
        if not matches(args.get("query", ""), name, conn.service, owner, mailbox.get("email", ""),
                       mailbox.get("sender_email", ""), *mailbox.get("aliases", ())):
            continue
        item = {"connection": name, "service": conn.service, "owner": owner,
                "tool_count": len({shared_name(r) for r in routes}), **mailbox}
        if who.client_id in conn.mailbox_access:
            item["mailbox_paths_restricted"] = True
        if args.get("tool"):
            item["variants"] = [{"id": r.tool.name, "description": r.exposed.description or "", "inputSchema": r.exposed.input_schema,
                                 "approval_required": gateway.policy.effect(who.principal, r.tool.name, who.client_id) == "approval_required"}
                                for r in sorted(routes, key=lambda r: r.tool.name)]
        items.append(item)
    return page(items, args, "connections")


def candidates(gateway, who, args):
    return [r for r in permitted(gateway, who) if shared_name(r) == args["tool"] and r.conn.id == args["connection"]
            and (not args.get("variant") or args["variant"] == r.tool.name)]
