"""Exercise MCP Tasks over authenticated Streamable HTTP with a simulated Passkey."""
import anyio
import httpx2
import pytest

from agent_gateway.mcp_tasks import EXTENSION, PROTOCOL
from helpers import TOKEN_A, prepare, running_gateway
from passkey_helpers import ORIGIN, TOKEN_A2, Page, approval_config

pytestmark = pytest.mark.anyio
TASKS = {"extensions": {EXTENSION: {}}}
CAPS = {**TASKS, "elicitation": {"url": {}}}
BROKER = "gateway_call_tool"


async def rpc(http, method, params=None, *, caps=CAPS, token=TOKEN_A, header_name=None):
    params = dict(params or {})
    name = header_name or params.get("name") or params.get("taskId")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream",
               "Mcp-Protocol-Version": PROTOCOL, "Mcp-Method": method}
    if name:
        headers["Mcp-Name"] = name
    params["_meta"] = {"io.modelcontextprotocol/protocolVersion": PROTOCOL,
                       "io.modelcontextprotocol/clientCapabilities": caps}
    response = await http.post("/mcp", headers=headers,
                               json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    return response.json()


async def call(http, name, arguments, **opts):
    return (await rpc(http, "tools/call", {"name": name, "arguments": arguments}, **opts))["result"]


async def get_task(http, task_id):
    return (await rpc(http, "tasks/get", {"taskId": task_id}))["result"]


async def completed(http, task_id):
    with anyio.fail_after(10):
        while True:
            task = await get_task(http, task_id)
            if task["status"] not in ("working", "input_required"):
                return task
            await anyio.sleep(.1)


async def test_native_approval_signals_input_and_returns_the_original_tool_result(tmp_path):
    async with running_gateway(await prepare(tmp_path, approval_config())) as gw:
        page = Page(gw.base)
        key = await page.enroll(gw.gateway, "person_a")
        async with httpx2.AsyncClient(base_url=gw.base) as http:
            discovery = (await rpc(http, "server/discover"))["result"]
            assert discovery["capabilities"]["extensions"][EXTENSION] == {}
            tools = (await rpc(http, "tools/list"))["result"]["tools"]
            assert "gateway_watch" not in {t["name"] for t in tools}
            assert BROKER in {t["name"] for t in tools}

            note = {"folder": "family", "text": "native task: one approved write"}
            task = await call(http, "a_add_note", note)
            assert task["resultType"] == "task" and task["status"] == "working"
            task_id = task["taskId"]
            params = {"taskId": task_id}
            pending = await get_task(http, task_id)
            assert pending["resultType"] == "complete" and pending["status"] == "input_required"
            assert pending["createdAt"] == task["createdAt"]
            assert pending["inputRequests"]["approval"]["params"]["url"] == f"{ORIGIN}/approvals/r/{task_id}"
            reply = {**params, "inputResponses": {"approval": {"action": "accept"}}}
            for method, arguments in [("tasks/get", params), ("tasks/update", reply), ("tasks/cancel", params)]:
                assert (await rpc(http, method, arguments, token=TOKEN_A2))["error"]["code"] == -32602
            assert (await rpc(http, "tasks/get", params, caps={}))["error"]["code"] == -32021
            assert (await rpc(http, "tasks/get", params, header_name="incorrect"))["error"]
            assert (await rpc(http, "tasks/update", reply))["result"]["resultType"] == "complete"
            waiting = await get_task(http, task_id)
            assert waiting["status"] == "working" and "inputRequests" not in waiting
            assert (await page.view(task_id))[1]["status"] == "pending"
            assert note["text"] not in str(await call(http, "a_list_notes", {"folder": "family"}))

            assert (await page.decide("approve", task_id, key))[0] == 200
            result = await completed(http, task_id)
            assert result["status"] == "completed" and not result["result"]["isError"]
            assert result["result"]["content"] == [{"type": "text", "text": "added"}]
            assert (await call(http, "a_add_note", note))["taskId"] == task_id
            assert str(await call(http, "a_list_notes", {"folder": "family"})).count(note["text"]) == 1


async def test_native_cancel_and_compatibility_use_the_same_saved_requests(tmp_path):
    raw = approval_config()
    raw["server"]["tool_discovery"] = "search"
    async with running_gateway(await prepare(tmp_path, raw)) as gw:
        page = Page(gw.base)
        key = await page.enroll(gw.gateway, "person_a")
        async with httpx2.AsyncClient(base_url=gw.base) as http:
            names = {t["name"] for t in (await rpc(http, "tools/list", caps={}))["result"]["tools"]}
            assert names == {"gateway_search_tools", "gateway_search_connections", BROKER}
            args = {"tool": "notes_add_note", "connection": "notes-a",
                    "arguments": {"folder": "family", "text": "must not execute"}}
            for ending in ("cancel", "decline"):
                args["idempotency_key"] = ending
                task_id = (await call(http, BROKER, args))["taskId"]
                params = {"taskId": task_id}
                if ending == "cancel":
                    reply = await rpc(http, "tasks/cancel", params)
                else:
                    reply = await rpc(http, "tasks/update", {**params, "inputResponses": {"approval": {"action": ending}}})
                assert reply["result"]["resultType"] == "complete"
                assert (await get_task(http, task_id))["status"] == "cancelled"
                assert (await page.decide("approve", task_id, key))[0] != 200
                args["arguments"]["text"] += " again"

            # Tasks without URL elicitation, and clients without Tasks, get a normal result and a link.
            for index, caps in enumerate((TASKS, {})):
                args["idempotency_key"] = f"fallback-{index}"
                pending = await call(http, BROKER, args, caps=caps)
                assert pending["resultType"] == "complete"
                request = pending["structuredContent"]
                assert request["idempotency_key"] == args["idempotency_key"]
                check = {"idempotency_key": args["idempotency_key"], "wait_seconds": 0}
                found = (await call(http, BROKER, check, caps=caps))["structuredContent"]
                assert found == request and found["status"] == "pending" and "request_id" not in found
                for name, params in ((BROKER, {"request_id": request["approval_url"].rsplit("/", 1)[-1]}),
                                     ("gateway_watch", check)):
                    assert (await rpc(http, "tools/call", {"name": name, "arguments": params},
                                      caps=caps))["error"]["code"] == -32602
                args["arguments"]["text"] += " again"

            background = await call(http, BROKER, {"idempotency_key": "bg-list", "tool": "notes_list_notes", "connection": "notes-a",
                                                  "arguments": {"folder": "family"}, "background": True}, caps=TASKS)
            assert background["resultType"] == "task"
            result = await completed(http, background["taskId"])
            assert result["status"] == "completed"
            assert "must not execute" not in str(result["result"])


            # A connector crash can leave the side effect unknown. Preserve its original error and explain the ambiguity.
            crashed = await call(http, BROKER, {"idempotency_key": "crash", "tool": "notes_crash", "connection": "notes-a",
                                               "arguments": {}, "background": True})
            result = await completed(http, crashed["taskId"])
            assert result["status"] == "completed" and result["result"]["isError"]
            assert "may already have run" in result["statusMessage"]
