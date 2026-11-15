"""Reconcile installed, bundled capabilities without contacting account services.

The installed package is the authority for bundled tool definitions. Remote MCP
servers and arbitrary launch commands retain the existing review/lock workflow.
"""
from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from .config import Config, ToolCfg, allocate_tool_name
from .lock import Lock, definition_of, digest_of

MODULES = {
    "agent_gateway.connectors.imap_mail": "imap",
    "agent_gateway.connectors.caldav_calendar": "caldav",
    "agent_gateway.connectors.gmail": "gmail",
    "agent_gateway.demo_connector": "demo",
}


def bundled_kind(conn):
    if conn.transport != "stdio" or len(conn.command) != 3 or conn.command[1] != "-m":
        return None
    executable = Path(conn.command[0]).name
    if executable not in ("python", "python3") and not executable.startswith("python3."):
        return None
    if any(key in conn.env or key in conn.secret_env for key in ("PYTHONPATH", "PYTHONHOME")):
        return None
    kind = MODULES.get(conn.command[2])
    if kind == "demo" and (conn.env.get("DEMO_VARIANT", "1") != "1" or conn.env.get("DEMO_VARIANT_FILE")):
        return None
    return kind


def bundled_manifest(conn):
    """Pure schema factories; no credentials, process launches, or network access."""
    from .admin_config import CATALOG, catalog_tools

    kind = bundled_kind(conn)
    if kind is None:
        return None
    if kind == "imap":
        from .connectors.imap_mail import build_tools
        tools = [t.as_mcp() for t in build_tools(None, 40_000_000, 5_000_000)]
    elif kind == "gmail":
        from .connectors.gmail import build_tools
        tools = [t.as_mcp() for t in build_tools(None, 40_000_000, 5_000_000,
                                                 can_send=conn.env.get("GMAIL_ACCESS") == "read_send")]
    elif kind == "caldav":
        from .connectors.caldav_calendar import build_tools
        tools = [t.as_mcp() for t in build_tools(SimpleNamespace(zone=ZoneInfo(conn.env.get("CALDAV_TIMEZONE", "UTC"))))]
    else:
        from .demo_connector import tool_definitions
        tools = tool_definitions()
    definitions = {t.name: definition_of(t) for t in tools}
    writes = CATALOG[kind].get("writes", {"add_note"} if kind == "demo" else set())
    return {name: {"definition": definitions[name], "suffix": suffix, "access": "write" if name in writes else "read"}
            for name, suffix in catalog_tools(conn)}


def sync_catalog(cfg, lock, previous=None):
    """Return an idempotent configuration overlay; never write host/state files.

Only additions are auto-exposed in configuration, not to Agents. Ordinary
definition updates preserve rules. A read-to-write change revokes its grants.
Incompatible restrictions remain intact and produce a visible, disabled tool.
"""
    from .server import build_route

    previous = previous or {}
    raw = cfg.model_dump(mode="json")
    entries, metadata, reports = copy.deepcopy(lock.entries), {}, {}
    occupied = {tool.name for conn in cfg.connections for tool in conn.tools}
    revoke = set()
    for conn, updated in zip(cfg.connections, raw["connections"]):
        try:
            manifest = bundled_manifest(conn)
        except (ImportError, KeyError, ValueError):
            reports[conn.id] = {"automatic": False, "issues": [{"reason": "bundle_unavailable"}]}
            continue
        if manifest is None:
            continue
        report = {"automatic": True, "added": [], "updated": [], "revoked": [], "issues": []}
        reports[conn.id] = report
        old_metadata = previous.get(conn.id, {})
        metadata[conn.id] = copy.deepcopy(old_metadata)
        registered = {tool.upstream for tool in conn.tools}
        for upstream, spec in manifest.items():
            if upstream not in registered:
                name = allocate_tool_name(conn.id, upstream, spec["suffix"], occupied)
                updated["tools"].append(ToolCfg(upstream=upstream, name=name).model_dump(mode="json"))
                report["added"].append(name)
        incompatible = set()
        for tool_raw in updated["tools"]:
            tool = ToolCfg.model_validate(tool_raw)
            if spec := manifest.get(tool.upstream):
                definition = spec["definition"]
                route = build_route(conn, tool, {"definition": definition, "sha256": digest_of(definition)})
                if route.problem:
                    incompatible.add(tool.upstream)
                    report["issues"].append({"tool": tool.name, "reason": route.problem})
        for tool_raw in updated["tools"]:
            tool = ToolCfg.model_validate(tool_raw)
            spec = manifest.get(tool.upstream)
            if spec is None:
                if tool.upstream in old_metadata:
                    report["issues"].append({"tool": tool.name, "reason": "tool_removed"})
                    revoke.add(tool.name)
                continue  # retain aliases/custom tools and their reviewed locks
            old_entry = lock.get(conn.id, tool.upstream)
            old_access = old_metadata.get(tool.upstream, {}).get("access")
            if old_access is None:
                old_access = tool.access or ("read" if old_entry and old_entry["definition"].get("annotations", {}).get("readOnlyHint") else "write")
            if old_access == "read" and spec["access"] == "write":
                tool_raw["access"] = "write"
                revoke.add(tool.name)
                report["revoked"].append(tool.name)
            definition = spec["definition"]
            entry = {"definition": definition, "sha256": digest_of(definition)}
            # A lock belongs to the upstream tool, shared by all its aliases.
            # Update it only when every alias can retain its restrictions.
            if tool.upstream in incompatible:
                continue
            entries.setdefault(conn.id, {})[tool.upstream] = entry
            if old_entry and old_entry["sha256"] != entry["sha256"]:
                report["updated"].append(tool.name)
            metadata[conn.id][tool.upstream] = {"sha256": entry["sha256"], "access": spec["access"]}
        # A safe reclassification must remain visible on subsequent restarts.
        # Existing explicit write overrides are intentionally never loosened.
    if revoke:
        raw["policy"] = [{**rule, "tools": [name for name in rule["tools"] if name not in revoke]}
                         for rule in raw["policy"] if any(name not in revoke for name in rule["tools"])]
    return Config.model_validate(raw), Lock(entries), metadata, reports


def catalog_revision(cfg, lock):
    """Bind pending approvals to the installed bundled definitions as well."""
    values = [(conn.id, tool.name, tool.access, lock.get(conn.id, tool.upstream))
              for conn in cfg.connections if bundled_kind(conn)
              for tool in conn.tools]
    return digest_of({"bundled_tools": values})
