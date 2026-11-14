"""Upstream behaviour: crashes, timeouts, HTTP upstreams, redirects (SSRF)."""

from __future__ import annotations

import json
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import pytest
import uvicorn
from helpers import (
    ROOT,
    SECRETS,
    TOKEN_A,
    TOKEN_B,
    agent,
    base_config,
    prepare,
    running_gateway,
    text_of,
    tool_names,
    write_config,
)
from mcp import MCPError

from agent_gateway.config import ConfigError, load_config
from agent_gateway.lock import Lock

sys.path.insert(0, str(ROOT / "examples"))
from demo_connector import build_server  # noqa: E402

pytestmark = pytest.mark.anyio


async def test_upstream_crash_is_reported_then_recovered_without_replay(tmp_path):
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with agent(gw.url, TOKEN_A) as a, agent(gw.url, TOKEN_B) as b:
            crashed = await a.call_tool("a_crash", {})
            assert crashed.is_error and text_of(crashed) == "The upstream service is currently unavailable."
            # Another account's upstream is a different process and is unaffected.
            assert "account=person_b" in text_of(await b.call_tool("b_whoami", {}))
            # The gateway reconnects on its own; the failed call is not replayed.
            with anyio.fail_after(20):
                while (await a.call_tool("a_whoami", {})).is_error:
                    await anyio.sleep(0.2)
        crashes = [e for e in gw.audit() if e.get("tool") == "a_crash"]
        assert len(crashes) == 1 and crashes[0]["reason"] == "upstream_unavailable"


async def test_slow_upstream_times_out(tmp_path):
    raw = base_config()
    raw["connections"][0]["timeout_seconds"] = 1
    async with running_gateway(await prepare(tmp_path, raw)) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            await gw.connected("notes-a")
            started = time.monotonic()
            result = await a.call_tool("a_slow", {"seconds": 30})
            assert result.is_error and "did not answer in time" in text_of(result)
            assert time.monotonic() - started < 8
            assert not (await a.call_tool("a_whoami", {})).is_error


# -- HTTP upstreams -------------------------------------------------------------------


class Recorder:
    """Wraps an ASGI app and remembers the headers of every request it receives."""

    def __init__(self, app: Any = None, *, redirect_to: str | None = None, require_bearer: str | None = None) -> None:
        self.app = app
        self.redirect_to = redirect_to
        self.require_bearer = require_bearer
        self.requests: list[dict[str, str]] = []

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.decode().lower(): value.decode() for key, value in scope["headers"]}
        self.requests.append(headers)
        if self.redirect_to is not None:
            await send({"type": "http.response.start", "status": 307, "headers": [(b"location", self.redirect_to.encode())]})
            await send({"type": "http.response.body", "body": b""})
        elif self.require_bearer and headers.get("authorization") != f"Bearer {self.require_bearer}":
            await send({"type": "http.response.start", "status": 401, "headers": []})
            await send({"type": "http.response.body", "body": b""})
        else:
            await self.app(scope, receive, send)


@asynccontextmanager
async def serving(app: Any) -> AsyncIterator[int]:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error"))
    async with anyio.create_task_group() as tg:
        tg.start_soon(server.serve)
        with anyio.fail_after(10):
            while not server.started:
                await anyio.sleep(0.01)
        try:
            yield server.servers[0].sockets[0].getsockname()[1]
        finally:
            server.should_exit = True


def http_connection(url: str) -> dict[str, Any]:
    return {
        "id": "notes-a",
        "service": "notes",
        "account": "person_a",
        "owner": "person_a",
        "transport": "http",
        "url": url,
        "bearer_secret": "notes_key_a",
        "timeout_seconds": 5,
        "tools": [{"upstream": "whoami", "name": "a_whoami"}],
    }


def http_config(url: str) -> dict[str, Any]:
    raw = base_config()
    raw["connections"][0] = http_connection(url)
    raw["policy"] = [{"principals": ["person_a"], "connection": "notes-a", "tools": ["a_whoami"], "effect": "allow"}]
    return raw


async def test_http_upstream_gets_its_own_credential_and_never_the_callers_token(tmp_path):
    upstream_app = build_server("person_a", SECRETS["notes_key_a"]).streamable_http_app(
        stateless_http=True, json_response=True
    )
    recorder = Recorder(upstream_app, require_bearer=SECRETS["notes_key_a"])
    async with serving(_with_lifespan(recorder, upstream_app)) as port:
        raw = http_config(f"http://127.0.0.1:{port}/mcp")
        async with running_gateway(await prepare(tmp_path, raw)) as gw:
            async with agent(gw.url, TOKEN_A) as a:
                result = await a.call_tool("a_whoami", {})
                assert "account=person_a authenticated=yes" in text_of(result)
    assert recorder.requests
    seen = json.dumps(recorder.requests)
    assert {r.get("authorization") for r in recorder.requests} == {f"Bearer {SECRETS['notes_key_a']}"}
    assert TOKEN_A not in seen


async def test_a_gateway_can_be_the_upstream_of_another_gateway(tmp_path):
    """The arrangement for a helper on another machine: it serves one account to one client, the main gateway."""
    async with running_gateway(await prepare(tmp_path / "helper")) as helper:
        raw = base_config()
        raw["connections"][1] = {
            "id": "notes-b", "service": "notes", "account": "person_b", "owner": "person_b", "transport": "http",
            "url": helper.url, "bearer_secret": "helper_token", "timeout_seconds": 10,
            "tools": [{"upstream": "b_whoami", "name": "b_whoami"}, {"upstream": "b_list_notes", "name": "b_list_notes"}],
        }  # fmt: skip
        secrets = {**SECRETS, "helper_token": TOKEN_B}  # the helper knows the main gateway as its client `agent-b`
        async with running_gateway(await prepare(tmp_path / "main", raw, secrets=secrets)) as main:
            async with agent(main.url, TOKEN_B) as b, agent(main.url, TOKEN_A) as a:
                assert "account=person_b authenticated=yes" in text_of(await b.call_tool("b_whoami", {}))
                assert "b_whoami" not in await tool_names(a)
                with pytest.raises(MCPError):
                    await a.call_tool("b_whoami", {})
        assert [r["client"] for r in helper.audit() if r["event"] == "tool_call"] == ["agent-b"]
        assert TOKEN_B not in main.audit_text() + helper.audit_text()


def _with_lifespan(recorder: Recorder, inner: Any) -> Any:
    """Route lifespan events to the SDK app and HTTP through the recorder."""

    async def app(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await inner(scope, receive, send)
        else:
            await recorder(scope, receive, send)

    return app


async def test_a_redirecting_upstream_cannot_send_the_gateway_or_its_credential_elsewhere(tmp_path):
    canary = Recorder(redirect_to=None)

    async def canary_app(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        canary.requests.append({k.decode().lower(): v.decode() for k, v in scope["headers"]})
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b"{}"})

    async with serving(canary_app) as canary_port:
        redirector = Recorder(redirect_to=f"http://127.0.0.1:{canary_port}/steal")

        async def redirector_app(scope: Any, receive: Any, send: Any) -> None:
            if scope["type"] == "http":
                await redirector(scope, receive, send)

        async with serving(redirector_app) as port:
            raw = http_config(f"http://127.0.0.1:{port}/mcp")
            path = write_config(tmp_path, raw)
            # This upstream never answers MCP, so write the lock entry it would have had by hand.
            lock = Lock()
            lock.put("notes-a", {"name": "whoami", "description": "x", "inputSchema": {"type": "object", "properties": {}}})
            lock.save(load_config(path).lock_file)
            async with running_gateway(path) as gw:
                async with agent(gw.url, TOKEN_A) as a:
                    result = await a.call_tool("a_whoami", {})
                    assert result.is_error and text_of(result) == "The upstream service is currently unavailable."
                    assert str(canary_port) not in text_of(result)
            assert redirector.requests, "the gateway should have tried the configured upstream"
    assert canary.requests == [], "the redirect target must never be contacted"


def test_upstream_urls_are_restricted_to_what_the_admin_wrote(tmp_path):
    bad = [
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/x",
        "ftp://example.com/mcp",
        "https://user:password@example.com/mcp",
        "https://example.com/mcp?token=abc",
        "http://example.com/mcp",  # plain http off-host needs an explicit opt-in
        "http://169.254.169.254/latest",
        "//example.com/mcp",
        "",
    ]
    for index, url in enumerate(bad):
        with pytest.raises(ConfigError):
            load_config(write_config(Path(tmp_path) / str(index), http_config(url)))
    load_config(write_config(tmp_path / "ok1", http_config("https://example.com/mcp")))
    load_config(write_config(tmp_path / "ok2", http_config("http://127.0.0.1:9000/mcp")))
    opted_in = http_config("http://offbook.internal:8080/mcp")
    opted_in["connections"][0]["allow_plain_http"] = True
    load_config(write_config(tmp_path / "ok3", opted_in))
