"""Test rig: a real gateway on a real localhost port, in front of real connector processes.

Nothing is mocked. Each test gets its own config directory, secret store and
audit log; the gateway runs under uvicorn exactly as `agw serve` runs it, and
upstreams are `examples/demo_connector.py` subprocesses (one per account).
"""

from __future__ import annotations

import copy
import json
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
import httpx2
import uvicorn
import yaml
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from agent_gateway.audit import Audit
from agent_gateway.auth import hash_token
from agent_gateway.cli import _lock, resolve_secrets
from agent_gateway.config import Config, load_config
from agent_gateway.credentials import EncryptedFileStore
from agent_gateway.lock import Lock
from agent_gateway.server import SERVE_OPTIONS, Gateway, build_app

ROOT = Path(__file__).resolve().parent.parent
CONNECTOR = str(ROOT / "examples" / "demo_connector.py")

TOKEN_A = "agw_test-token-for-person-a-000000000000000000"
TOKEN_B = "agw_test-token-for-person-b-111111111111111111"
TOKEN_HOUSE = "agw_test-token-for-household-2222222222222222"
SECRETS = {
    "notes_key_a": "upstream-key-AAAA-1234567890",
    "notes_key_b": "upstream-key-BBBB-1234567890",
    "notes_key_house": "upstream-key-HHHH-1234567890",
}


def notes_connection(conn_id: str, owner: str, secret: str, tools: list[dict[str, Any]], **env: str) -> dict[str, Any]:
    return {
        "id": conn_id,
        "service": "notes",
        "account": owner,
        "owner": owner,
        "transport": "stdio",
        "command": [sys.executable, CONNECTOR],
        "env": {"DEMO_ACCOUNT": owner, **env},
        "secret_env": {"DEMO_API_KEY": secret},
        "timeout_seconds": 10,
        "tools": tools,
    }


def base_config() -> dict[str, Any]:
    """Two people and a household account; one notes connector per account."""
    return {
        "audit": {"path": "audit/audit.jsonl", "retention_days": 30},
        "secrets": {"path": "secrets.enc", "key_file": "master.key"},
        "principals": ["person_a", "person_b", "household"],
        "shared": ["household"],
        "clients": [
            {"id": "agent-a", "principal": "person_a", "token_sha256": hash_token(TOKEN_A)},
            {"id": "agent-b", "principal": "person_b", "token_sha256": hash_token(TOKEN_B)},
            {"id": "shared-agent", "principal": "household", "token_sha256": hash_token(TOKEN_HOUSE)},
        ],
        "connections": [
            notes_connection(
                "notes-a",
                "person_a",
                "notes_key_a",
                [
                    {"upstream": "list_notes", "name": "a_list_notes"},
                    {"upstream": "get_note", "name": "a_get_note"},
                    {"upstream": "add_note", "name": "a_add_note"},
                    {"upstream": "whoami", "name": "a_whoami"},
                    {"upstream": "debug_dump", "name": "a_debug_dump"},
                    {"upstream": "injection", "name": "a_injection"},
                    {"upstream": "crash", "name": "a_crash"},
                    {"upstream": "slow", "name": "a_slow"},
                    # Resource-level restriction: the same upstream tool, locked to one folder.
                    {"upstream": "list_notes", "name": "a_family_notes", "pin": {"folder": "family"}},
                ],
            ),
            notes_connection(
                "notes-b",
                "person_b",
                "notes_key_b",
                [{"upstream": "list_notes", "name": "b_list_notes"}, {"upstream": "whoami", "name": "b_whoami"}],
            ),
            notes_connection(
                "notes-house",
                "household",
                "notes_key_house",
                [
                    {"upstream": "list_notes", "name": "house_list_notes", "allow_values": {"folder": ["family"]}},
                    {"upstream": "whoami", "name": "house_whoami"},
                ],
            ),
        ],
        "policy": [
            {
                "principals": ["person_a"],
                "connection": "notes-a",
                "tools": ["a_list_notes", "a_get_note", "a_whoami", "a_debug_dump", "a_injection", "a_crash", "a_slow"],
                "effect": "allow",
            },
            {"principals": ["person_a"], "connection": "notes-a", "tools": ["a_add_note"], "effect": "approval_required"},
            {"principals": ["person_b"], "connection": "notes-b", "tools": ["b_list_notes", "b_whoami"], "effect": "allow"},
            {
                "principals": ["household"],
                "connection": "notes-a",
                "tools": ["a_family_notes"],
                "effect": "allow",
                "cross_account": True,
            },
            {
                "principals": ["person_a", "person_b", "household"],
                "connection": "notes-house",
                "tools": ["house_list_notes", "house_whoami"],
                "effect": "allow",
            },
        ],
    }


def write_config(directory: Path, raw: dict[str, Any], secrets: dict[str, str] | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "gateway.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    key_file = directory / "master.key"
    if not key_file.exists():
        EncryptedFileStore.create_key(key_file)
    store = EncryptedFileStore(directory / "secrets.enc", key_file)
    for name, value in (SECRETS if secrets is None else secrets).items():
        store.set(name, value)
    return path


async def write_lock(config_path: Path) -> None:
    """Accept the upstreams' current tool definitions, as `agw lock --write` does."""
    await _lock(load_config(config_path), True, None)


_LOCKS: dict[str, str] = {}


async def prepare(directory: Path, raw: dict[str, Any] | None = None, *, lock: bool = True) -> Path:
    """Write config + secrets (+ lock file) for a test.

    A lock file depends only on the connections, so it is computed once per
    distinct set of connections and reused for the rest of the run.
    """
    raw = raw if raw is not None else base_config()
    path = write_config(directory, raw)
    if not lock:
        return path
    key = json.dumps(raw["connections"], sort_keys=True)
    if key not in _LOCKS:
        await write_lock(path)
        _LOCKS[key] = (directory / "tools.lock.json").read_text(encoding="utf-8")
    else:
        (directory / "tools.lock.json").write_text(_LOCKS[key], encoding="utf-8")
    return path


@dataclass
class Running:
    url: str
    base: str
    gateway: Gateway
    cfg: Config

    def audit(self) -> list[dict[str, Any]]:
        path = self.cfg.audit.path
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    def audit_text(self) -> str:
        return self.cfg.audit.path.read_text(encoding="utf-8") if self.cfg.audit.path.exists() else ""

    async def connected(self, conn_id: str, timeout: float = 15) -> None:
        with anyio.fail_after(timeout):
            while self.gateway.upstreams[conn_id]._client is None:
                await anyio.sleep(0.02)


@asynccontextmanager
async def running_gateway(config_path: Path, approver: Any = None) -> AsyncIterator[Running]:
    cfg = load_config(config_path)
    audit = Audit(cfg.audit.path, cfg.audit.retention_days)
    gateway = Gateway(cfg, Lock.load(cfg.lock_file), resolve_secrets(cfg), audit, approver=approver)
    server = uvicorn.Server(
        uvicorn.Config(build_app(gateway), host="127.0.0.1", port=0, log_level="error", **SERVE_OPTIONS)
    )
    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve)
        with anyio.fail_after(15):
            while not server.started:
                await anyio.sleep(0.01)
        port = server.servers[0].sockets[0].getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        try:
            yield Running(url=f"{base}/mcp", base=base, gateway=gateway, cfg=cfg)
        finally:
            server.should_exit = True
            audit.close()


@asynccontextmanager
async def agent(url: str, token: str | None, **headers: str) -> AsyncIterator[Client]:
    """An MCP client, as an agent would configure it: a URL and a bearer token."""
    all_headers = dict(headers)
    if token is not None:
        all_headers["Authorization"] = f"Bearer {token}"
    async with httpx2.AsyncClient(headers=all_headers, timeout=30) as http:
        async with Client(streamable_http_client(url, http_client=http), cache=None) as client:
            yield client


async def tool_names(client: Client) -> set[str]:
    return {tool.name for tool in (await client.list_tools()).tools}


def text_of(result: Any) -> str:
    return "\n".join(block.text for block in result.content if getattr(block, "type", "") == "text")


def variant(raw: dict[str, Any], **changes: Any) -> dict[str, Any]:
    out = copy.deepcopy(raw)
    out.update(changes)
    return out
