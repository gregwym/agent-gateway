"""What the gateway exposes at all: two HTTP paths and two MCP methods."""

from __future__ import annotations

import subprocess
import sys

import httpx2
import pytest
from helpers import CONNECTOR, TOKEN_A, agent, base_config, prepare, running_gateway, text_of, tool_names
from mcp import MCPError

pytestmark = pytest.mark.anyio

RPC_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2025-06-18",
    "Authorization": f"Bearer {TOKEN_A}",
}


def rpc(method: str, params: dict | None = None) -> dict:
    body: dict = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return body


async def test_only_mcp_and_healthz_exist(tmp_path):
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with httpx2.AsyncClient(base_url=gw.base) as http:
            for path in (
                "/", "/admin", "/config", "/gateway.yaml", "/metrics", "/docs", "/openapi.json", "/audit",
                "/tools", "/secrets", "/proxy", "/fetch", "/sse", "/.well-known/oauth-protected-resource",
                "/.well-known/oauth-authorization-server", "/register", "/token", "/authorize",
            ):  # fmt: skip
                for headers in ({}, {"Authorization": f"Bearer {TOKEN_A}"}):
                    assert (await http.get(path, headers=headers)).status_code == 404, path
                    assert (await http.post(path, headers=headers, json={})).status_code == 404, path

            health = await http.get("/healthz")
            assert (health.status_code, health.text) == (200, "ok")  # nothing about config, tools or upstreams
            assert (await http.post("/healthz")).status_code == 405
            assert "server" not in health.headers  # no software banner


async def test_only_tools_are_served_over_mcp(tmp_path):
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with httpx2.AsyncClient(headers=RPC_HEADERS) as http:
            init = await http.post(
                gw.url,
                json=rpc(
                    "initialize",
                    {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}},
                ),
            )
            capabilities = init.json()["result"]["capabilities"]
            assert "tools" in capabilities
            assert not {"resources", "prompts", "completions", "logging"} & set(capabilities)

            # Upstream resources and prompts are not proxied, whatever the upstream offers.
            for method, params in (
                ("resources/list", None),
                ("resources/read", {"uri": "file:///etc/passwd"}),
                ("resources/templates/list", None),
                ("prompts/list", None),
                ("prompts/get", {"name": "x"}),
                ("completion/complete", {"ref": {"type": "ref/prompt", "name": "x"}, "argument": {"name": "a", "value": ""}}),
            ):
                answer = (await http.post(gw.url, json=rpc(method, params))).json()
                assert "result" not in answer and "error" in answer, method


async def test_injected_instructions_in_a_tool_result_change_nothing_at_the_gateway(tmp_path):
    """Untrusted content (a mail body, a note) can carry instructions for the model.

    What the gateway guarantees: the text comes back as plain tool output, and whatever
    the model then tries is still bounded by the caller's token. What it cannot do is
    stop the model from believing the text; there is no content filter here, on purpose.
    """
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            before = await tool_names(a)
            poisoned = await a.call_tool("a_injection", {})
            assert not poisoned.is_error and "ignore all previous instructions" in text_of(poisoned)
            assert [block.type for block in poisoned.content] == ["text"]

            # A model that obeys the note and "acts for person_b":
            with pytest.raises(MCPError):
                await a.call_tool("b_list_notes", {"folder": "inbox"})
            obeyed = await a.call_tool("a_list_notes", {"folder": "inbox", "user_id": "person_b"})
            assert obeyed.is_error
            write = await a.call_tool("a_add_note", {"folder": "inbox", "text": "exfiltrated"})
            assert write.is_error  # approval_required: never runs
            assert await tool_names(a) == before
        assert {e["principal"] for e in gw.audit() if e["event"] == "tool_call"} == {"person_a"}
        assert "ignore all previous" not in gw.audit_text()


async def test_host_header_check_when_configured(tmp_path):
    raw = base_config()
    raw["server"] = {"allowed_hosts": ["gateway.tailnet.example:8080"]}
    async with running_gateway(await prepare(tmp_path, raw)) as gw:
        async with httpx2.AsyncClient(headers=RPC_HEADERS) as http:
            direct = await http.post(gw.url, json=rpc("tools/list"))  # Host: 127.0.0.1:<port>
            assert direct.status_code in (400, 403, 421) and "a_list_notes" not in direct.text
            named = await http.post(gw.url, json=rpc("tools/list"), headers={"Host": "gateway.tailnet.example:8080"})
            assert named.status_code == 200 and "a_list_notes" in named.text
            # A browser page on another origin (DNS rebinding) is refused even with the right Host.
            browser = await http.post(
                gw.url,
                json=rpc("tools/list"),
                headers={"Host": "gateway.tailnet.example:8080", "Origin": "https://evil.example"},
            )
            assert browser.status_code in (400, 403) and "a_list_notes" not in browser.text


def test_a_connector_started_without_the_gateway_has_no_credential():
    """Bypassing the gateway only helps an agent that can also read the gateway's secrets.

    Keeping those out of reach is a deployment property (see docs/deployment.md); this
    only checks the connector contract: no credential from the gateway, no service.
    """
    done = subprocess.run(
        [sys.executable, CONNECTOR],
        env={"PATH": "/usr/bin:/bin", "DEMO_ACCOUNT": "person_a"},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert done.returncode != 0 and b"DEMO_API_KEY is not set" in done.stderr
