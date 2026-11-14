"""Tool lock file: the tool definitions an admin has reviewed.

A tool's description and schema are text the model reads, so an upstream that
can change them at will can steer the model ("tool poisoning", "rug pull").
The gateway therefore serves agents the definition recorded here, never the
live one, and refuses to call a tool whose live definition no longer matches.
`agw lock` is the only thing that writes this file.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import mcp_types as types

# Everything a model or client reads about a tool. Icons and _meta are left out.
_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


class LockError(Exception):
    pass


def definition_of(tool: types.Tool) -> dict[str, Any]:
    dumped = tool.model_dump(mode="json", by_alias=True, exclude_none=True)
    return {field: dumped[field] for field in _FIELDS if field in dumped}


def digest_of(definition: dict[str, Any]) -> str:
    canonical = json.dumps(definition, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class Lock:
    def __init__(self, entries: dict[str, dict[str, dict[str, Any]]] | None = None) -> None:
        # connection id -> upstream tool name -> {"sha256": ..., "definition": ...}
        self.entries = entries or {}

    @classmethod
    def load(cls, path: Path) -> Lock:
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        except (OSError, ValueError):
            raise LockError("the tool lock file is unreadable or not valid JSON") from None
        entries = raw.get("connections") if isinstance(raw, dict) else None
        if not isinstance(entries, dict):
            raise LockError("the tool lock file has an unexpected shape")
        for conn_id, tools in entries.items():
            for name, entry in tools.items():
                # A hand-edited definition without a matching digest is rejected rather than trusted.
                if digest_of(entry.get("definition", {})) != entry.get("sha256"):
                    raise LockError(f"lock entry {conn_id}/{name} does not match its digest; re-run `agw lock`")
        return cls(entries)

    def save(self, path: Path) -> None:
        path = Path(path)
        tmp = path.with_name(path.name + ".tmp")
        body = json.dumps({"version": 1, "connections": self.entries}, indent=2, sort_keys=True, ensure_ascii=False)
        tmp.write_text(body + "\n", encoding="utf-8")
        os.replace(tmp, path)

    def get(self, conn_id: str, upstream_tool: str) -> dict[str, Any] | None:
        return self.entries.get(conn_id, {}).get(upstream_tool)

    def put(self, conn_id: str, definition: dict[str, Any]) -> None:
        self.entries.setdefault(conn_id, {})[definition["name"]] = {
            "sha256": digest_of(definition),
            "definition": definition,
        }
