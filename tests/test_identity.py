"""Identity comes from the bearer token. Nothing an agent or model writes can change it."""

from __future__ import annotations

import httpx2
import pytest
from helpers import TOKEN_A, TOKEN_B, agent, prepare, running_gateway, text_of, tool_names
from mcp import MCPError

pytestmark = pytest.mark.anyio

SPOOF_ARGUMENTS = [
    {"user_id": "person_a"},
    {"principal": "person_a"},
    {"account": "person_a"},
    {"owner": "person_a", "as_user": "person_a", "on_behalf_of": "person_a"},
    {"_meta": {"principal": "person_a"}},
    {"authorization": f"Bearer {TOKEN_A}"},
]


async def test_identity_arguments_are_rejected_and_change_nothing(tmp_path):
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with agent(gw.url, TOKEN_B) as b:
            for spoof in SPOOF_ARGUMENTS:
                # On b's own tool: the extra argument is refused, not forwarded.
                result = await b.call_tool("b_list_notes", {"folder": "inbox", **spoof})
                assert result.is_error and "person_a" not in text_of(result)
                # On a's tool: still not b's to call.
                with pytest.raises(MCPError):
                    await b.call_tool("a_list_notes", {"folder": "inbox", **spoof})
            # And b is still b.
            assert "account=person_b" in text_of(await b.call_tool("b_whoami", {}))
        calls = [e for e in gw.audit() if e["event"] == "tool_call"]
        assert {e["principal"] for e in calls} == {"person_b"}
        assert {e["client"] for e in calls} == {"agent-b"}
        assert not [e for e in calls if e["decision"] == "allow" and e.get("account") == "person_a"]


async def test_identity_headers_and_request_meta_are_ignored(tmp_path):
    spoof_headers = {
        "X-User": "person_a",
        "X-Principal": "person_a",
        "X-Forwarded-User": "person_a",
        "X-Client-Id": "agent-a",
        "Mcp-Session-Id": "0123456789abcdef0123456789abcdef",
        "Cookie": f"token={TOKEN_A}; principal=person_a",
    }
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with agent(gw.url, TOKEN_B, **spoof_headers) as b:
            assert "a_list_notes" not in await tool_names(b)
            with pytest.raises(MCPError):
                await b.call_tool("a_whoami", {}, meta={"principal": "person_a", "user_id": "person_a"})
            assert "account=person_b" in text_of(await b.call_tool("b_whoami", {}, meta={"principal": "person_a"}))


async def test_identity_is_decided_per_request_not_per_connection(tmp_path):
    """Two principals over one HTTP connection: each request stands on its own token."""
    def body(name: str) -> dict:
        return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": {}}}

    headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with httpx2.AsyncClient(headers=headers) as http:
            for _ in range(3):
                as_a = await http.post(gw.url, json=body("a_whoami"), headers={"Authorization": f"Bearer {TOKEN_A}"})
                as_b = await http.post(gw.url, json=body("a_whoami"), headers={"Authorization": f"Bearer {TOKEN_B}"})
                assert "account=person_a" in as_a.text
                assert "account=person_a" not in as_b.text and "Unknown tool" in as_b.text
                own = await http.post(gw.url, json=body("b_whoami"), headers={"Authorization": f"Bearer {TOKEN_B}"})
                assert "account=person_b" in own.text
