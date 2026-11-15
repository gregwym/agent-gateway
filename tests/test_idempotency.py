"""The caller can recover a lost response using the key it already knows."""
import anyio
import pytest
from mcp import MCPError

from helpers import TOKEN_A, TOKEN_B, agent, base_config, prepare, running_gateway, text_of
from passkey_helpers import approval_config, Page

pytestmark = pytest.mark.anyio
BROKER = "gateway_call_tool"
WRITE = {"tool": "notes_add_note", "connection": "notes-a",
         "arguments": {"folder": "family", "text": "one intended note"}}


async def test_same_key_executes_once_and_survives_restart_without_passkeys(tmp_path):
    cfg = base_config()
    cfg["server"]["tool_discovery"] = "search"
    cfg["policy"][1]["effect"] = "allow"
    path = await prepare(tmp_path, cfg)
    submit = {**WRITE, "idempotency_key": "first-write"}
    query = {"idempotency_key": submit["idempotency_key"], "wait_seconds": 0}
    async with running_gateway(path) as gw, agent(gw.url, TOKEN_A) as client, agent(gw.url, TOKEN_B) as other:
        with pytest.raises(MCPError, match="Unknown idempotency_key"):
            await client.call_tool(BROKER, query)
        results = []

        async def write():
            results.append(await client.call_tool(BROKER, submit))

        async with anyio.create_task_group() as tasks:
            for _ in range(5):
                tasks.start_soon(write)
        assert [text_of(r) for r in results] == ["added"] * 5
        notes = await client.call_tool("a_list_notes", {"folder": "family"})
        assert text_of(notes).count("one intended note") == 1

        same = await client.call_tool(BROKER, query)
        assert same.structured_content == {"idempotency_key": "first-write", "status": "succeeded", "outcome": "ok"}
        assert same.content[1].text == "added"
        with pytest.raises(MCPError, match="already bound"):
            await client.call_tool(BROKER, {**submit, "arguments": {**WRITE["arguments"], "text": "different"}})
        with pytest.raises(MCPError, match="Unknown idempotency_key"):
            await other.call_tool(BROKER, query)

    async with running_gateway(path) as gw, agent(gw.url, TOKEN_A) as client:
        for args in (query, submit):
            same = await client.call_tool(BROKER, args)
            assert same.structured_content["status"] == "succeeded"
            assert "original output is no longer available" in text_of(same)
        notes = await client.call_tool("a_list_notes", {"folder": "family"})
        # The example connector resets its notes on restart. A key retry did not send another write.
        assert "one intended note" not in text_of(notes)
        assert text_of(await client.call_tool(BROKER, {**submit, "idempotency_key": "another-intended-write"})) == "added"
        notes = await client.call_tool("a_list_notes", {"folder": "family"})
        assert text_of(notes).count("one intended note") == 1


async def test_key_recovers_same_approval_and_new_key_is_a_separate_operation(tmp_path):
    raw = approval_config()
    raw["server"]["tool_discovery"] = "search"
    async with running_gateway(await prepare(tmp_path, raw)) as gw, agent(gw.url, TOKEN_A) as client:
        page = Page(gw.base)
        passkey = await page.enroll(gw.gateway, "person_a")
        submit = {**WRITE, "idempotency_key": "approval-once"}
        pending = (await client.call_tool(BROKER, submit)).structured_content
        check = {"idempotency_key": submit["idempotency_key"], "wait_seconds": 0}
        assert (await client.call_tool(BROKER, check)).structured_content == pending
        assert (await client.call_tool(BROKER, submit)).structured_content == pending
        assert pending["status"] == "pending" and "request_id" not in pending

        different = {**submit, "idempotency_key": "second-approval"}
        second = (await client.call_tool(BROKER, different)).structured_content
        assert second["approval_url"] != pending["approval_url"]
        assert (await page.decide("approve", pending["approval_url"].rsplit("/", 1)[1], passkey))[0] == 200
        finished = await client.call_tool(BROKER, {"idempotency_key": submit["idempotency_key"]})
        assert finished.structured_content["status"] == "succeeded" and finished.content[1].text == "added"
        assert (await client.call_tool(BROKER, submit)).structured_content == finished.structured_content
        assert (await client.call_tool(BROKER, {"idempotency_key": different["idempotency_key"],
                                                "wait_seconds": 0})).structured_content["status"] == "pending"
