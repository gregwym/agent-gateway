"""Phase 1 acceptance: two people, one gateway, no way across."""

from __future__ import annotations

import httpx2
import pytest
from helpers import TOKEN_A, TOKEN_B, TOKEN_HOUSE, agent, prepare, running_gateway, text_of, tool_names
from mcp import MCPError

pytestmark = pytest.mark.anyio

A_TOOLS = {"a_list_notes", "a_get_note", "a_add_note", "a_whoami", "a_debug_dump", "a_injection", "a_crash", "a_slow"}
HOUSE_TOOLS = {"house_list_notes", "house_whoami"}


async def test_each_person_sees_and_reaches_only_their_own_account(tmp_path):
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with agent(gw.url, TOKEN_A) as a, agent(gw.url, TOKEN_B) as b:
            assert await tool_names(a) == A_TOOLS | HOUSE_TOOLS
            assert await tool_names(b) == {"b_list_notes", "b_whoami"} | HOUSE_TOOLS

            assert "account=person_a" in text_of(await a.call_tool("a_whoami", {}))
            assert "account=person_b" in text_of(await b.call_tool("b_whoami", {}))
            assert "private inbox note of person_a" in text_of(await a.call_tool("a_list_notes", {"folder": "inbox"}))
            assert "private inbox note of person_b" in text_of(await b.call_tool("b_list_notes", {"folder": "inbox"}))


async def test_other_persons_tools_are_not_callable(tmp_path):
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with agent(gw.url, TOKEN_B) as b:
            for name in sorted(A_TOOLS | {"a_family_notes"}):
                with pytest.raises(MCPError) as denied:
                    await b.call_tool(name, {"folder": "inbox"})
                assert denied.value.error.message == "Unknown tool"
        denials = [e for e in gw.audit() if e["event"] == "tool_call"]
        assert {e["decision"] for e in denials} == {"deny"}
        assert {e["reason"] for e in denials} == {"policy_deny"}
        assert {e["principal"] for e in denials} == {"person_b"}


async def test_denied_and_nonexistent_tools_are_indistinguishable(tmp_path):
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with agent(gw.url, TOKEN_B) as b:
            with pytest.raises(MCPError) as exists_but_denied:
                await b.call_tool("a_list_notes", {"folder": "inbox"})
            with pytest.raises(MCPError) as does_not_exist:
                await b.call_tool("no_such_tool_anywhere", {"folder": "inbox"})
        assert exists_but_denied.value.error.code == does_not_exist.value.error.code
        assert exists_but_denied.value.error.message == does_not_exist.value.error.message


async def test_tools_outside_the_allowlist_are_invisible_and_uncallable(tmp_path):
    # The connector offers more than the config lists; none of it leaks through.
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with agent(gw.url, TOKEN_B) as b:
            names = await tool_names(b)
            # person_b's connector has add_note, crash, debug_dump, ... upstream; only two are configured.
            assert names == {"b_list_notes", "b_whoami"} | HOUSE_TOOLS
            for guess in ("add_note", "b_add_note", "notes-b_add_note", "notes-b.add_note", "list_notes", "debug_dump"):
                with pytest.raises(MCPError):
                    await b.call_tool(guess, {"folder": "inbox", "text": "x"})


async def test_shared_client_is_limited_to_household_scope(tmp_path):
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with agent(gw.url, TOKEN_HOUSE) as shared:
            assert await tool_names(shared) == {"a_family_notes"} | HOUSE_TOOLS
            assert "account=household" in text_of(await shared.call_tool("house_whoami", {}))
            for name in ("a_list_notes", "a_whoami", "b_list_notes", "b_whoami"):
                with pytest.raises(MCPError):
                    await shared.call_tool(name, {"folder": "inbox"})


async def test_a_client_without_any_rule_gets_nothing(tmp_path):
    from helpers import base_config

    raw = base_config()
    raw["policy"] = []
    async with running_gateway(await prepare(tmp_path, raw)) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            assert await tool_names(a) == set()
            with pytest.raises(MCPError):
                await a.call_tool("a_whoami", {})


async def test_no_token_or_wrong_token_is_rejected_before_mcp(tmp_path):
    async with running_gateway(await prepare(tmp_path)) as gw:
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        headers = {"Accept": "application/json, text/event-stream"}
        async with httpx2.AsyncClient() as http:
            for auth in (
                {},
                {"Authorization": "Bearer agw_not-a-real-token"},
                {"Authorization": "Bearer " + TOKEN_A[:-1]},  # one character short
                {"Authorization": "Bearer " + TOKEN_A + "x"},
                {"Authorization": TOKEN_A},  # right token, no Bearer scheme
                {"Authorization": f"Basic {TOKEN_A}"},
                {"X-Api-Key": TOKEN_A},
            ):
                for method in ("POST", "GET", "DELETE"):
                    response = await http.request(method, gw.url, json=body, headers={**headers, **auth})
                    assert response.status_code == 401, (auth, method)
                    assert "tools" not in response.text
            # A token in the URL is not a credential.
            response = await http.post(f"{gw.url}?token={TOKEN_A}&access_token={TOKEN_A}", json=body, headers=headers)
            assert response.status_code == 401
        failures = [e for e in gw.audit() if e["event"] == "auth_failed"]
        assert {e["reason"] for e in failures} == {"no_token", "invalid_token"}
        assert TOKEN_A not in gw.audit_text()
