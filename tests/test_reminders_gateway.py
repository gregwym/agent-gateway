"""Two simulated Mac helpers reached through the household gateway over HTTP.

The real Reminders connector runs in subprocesses. Only the EventKit module is a
test fixture, so its authorization checks, predicates and callbacks are exercised.
"""

import json
import os
import sys
from pathlib import Path

import pytest
from helpers import TOKEN_A, TOKEN_B, TOKEN_HOUSE, agent, base_config, prepare, running_gateway, text_of, tool_names
from mcp import MCPError

pytestmark = pytest.mark.anyio
TOOLS = {"list_lists": "lists", "list_reminders": "reminders", "get_reminder": "reminder"}


def helper_config(person):
    raw = base_config()
    raw["principals"] = [person]
    raw["shared"] = []
    raw["clients"] = [client for client in raw["clients"] if client["principal"] == person]
    tests = Path(__file__).resolve().parent
    raw["connections"] = [{
        "id": "reminders", "service": "reminders", "account": person, "owner": person,
        "transport": "stdio", "command": [sys.executable, "-m", "agent_gateway.connectors.reminders_eventkit"],
        "env": {"AGW_TEST_REMINDERS_ACCOUNT": person,
                "PYTHONPATH": os.pathsep.join([str(tests / "fixtures" / "eventkit"), str(tests)])},
        "tools": [{"upstream": name, "name": exposed} for name, exposed in TOOLS.items()],
    }]
    raw["policy"] = [{"principals": [person], "connection": "reminders", "tools": list(TOOLS.values()), "effect": "allow"}]
    raw.pop("secrets")
    return raw


async def read(client, tool, **arguments):
    result = await client.call_tool(tool, arguments)
    assert not result.is_error, text_of(result)
    return json.loads(text_of(result))


async def test_two_reminders_helpers_are_isolated_and_serve_real_connector_calls(tmp_path):
    async with running_gateway(await prepare(tmp_path / "a", helper_config("person_a"))) as helper_a:
        async with running_gateway(await prepare(tmp_path / "b", helper_config("person_b"))) as helper_b:
            raw = base_config()
            raw["connections"], raw["policy"] = [], []
            for prefix, helper in (("a", helper_a), ("b", helper_b)):
                person, conn = f"person_{prefix}", f"reminders-{prefix}"
                tools = [{"upstream": name, "name": f"{prefix}_{name}"} for name in TOOLS.values()]
                raw["connections"].append({
                    "id": conn, "service": "reminders", "account": person, "owner": person,
                    "transport": "http", "url": helper.url, "bearer_secret": f"helper_{prefix}", "tools": tools,
                })
                raw["policy"].append({"principals": [person], "connection": conn,
                                      "tools": [tool["name"] for tool in tools], "effect": "allow"})
            path = await prepare(tmp_path / "main", raw, secrets={"helper_a": TOKEN_A, "helper_b": TOKEN_B})
            async with running_gateway(path) as main:
                async with agent(main.url, TOKEN_A) as a, agent(main.url, TOKEN_B) as b, agent(main.url, TOKEN_HOUSE) as shared:
                    assert await tool_names(a) == {"a_lists", "a_reminders", "a_reminder"}
                    assert await tool_names(b) == {"b_lists", "b_reminders", "b_reminder"}
                    assert await tool_names(shared) == set()
                    assert await read(a, "a_lists") == [{"list": "person_a-list", "name": "person_a private list"}]
                    found = await read(a, "a_reminders", list="person_a-list")
                    assert found["found"] == 1 and found["reminders"][0]["id"] == "person_a-open"
                    done = await read(a, "a_reminders", completed=True)
                    assert done["reminders"][0]["id"] == "person_a-done"
                    assert (await read(a, "a_reminder", id="person_a-open"))["notes"] == "person_a private notes"
                    assert (await read(b, "b_reminder", id="person_b-open"))["notes"] == "person_b private notes"
                    for tool, args in (("a_reminder", {"id": "person_b-open"}), ("a_reminders", {"list": "person_b-list"})):
                        assert (await a.call_tool(tool, args)).is_error
                    with pytest.raises(MCPError):
                        await b.call_tool("a_reminders", {})
                    with pytest.raises(MCPError):
                        await shared.call_tool("a_reminders", {})
                audit = main.audit_text() + helper_a.audit_text() + helper_b.audit_text()
                assert TOKEN_A not in audit and TOKEN_B not in audit
                assert "private notes" not in audit and "private task" not in audit
