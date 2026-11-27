"""Use the normal management and MCP routes to provision disposable resources."""
import json
import sqlite3
from urllib.parse import parse_qs, urlsplit

import pytest

from helpers import TOKEN_A, TOKEN_HOUSE, prepare
from passkey_helpers import Page, approval_config, request_id_in
from service_helpers import free_port

from agent_gateway.request_store import RequestStore
from test_admin import change, rpc, setup, state, web_gateway
from test_admin_remote import ISSUER, Remote, URL, apply, consent_complete

pytestmark = pytest.mark.anyio


async def test_config_permission_and_two_stage_provision(tmp_path, monkeypatch):
    port = free_port()
    raw = approval_config(origin=f"http://localhost:{port}")
    raw["admin"] = {"owner": "person_a", "state": "admin.enc"}
    raw["server"]["tool_discovery"] = "search"
    config_path = await prepare(tmp_path, raw)
    upstream = Remote(monkeypatch, mode="none")
    async with web_gateway(tmp_path, path=config_path, port=port) as (gw, http, origin, path):
        await setup(http, origin, path)
        reply = await change(http, "connections/save", kind="gateway_config", id="config", owner="person_a")
        assert reply.status_code == 200, reply.text

        async def search(token, query):
            data = (await rpc(origin, token, "tools/call", {"name": "gateway_search_tools",
                        "arguments": {"connection": "config", "query": query}})).json()
            return {item["name"] for item in json.loads(data["result"]["content"][0]["text"])["tools"]}

        async def invoke(token, tool, key, arguments):
            return (await rpc(origin, token, "tools/call", {"name": "gateway_call_tool", "arguments": {
                "connection": "config", "tool": tool, "idempotency_key": key, "arguments": arguments,
            }})).json()

        read, propose = "gateway_config_read", "gateway_config_provision"
        assert await search(TOKEN_HOUSE, "configuration") == set()
        assert (await change(http, "permissions/connection", client="shared-agent", connection="config",
                             access="read_write_direct")).status_code == 200
        assert (await change(http, "permissions/connection", client="agent-a", connection="config",
                             access="read")).status_code == 200
        assert await search(TOKEN_HOUSE, "configuration") == {read, propose}
        assert await search(TOKEN_A, "configuration") == {read}
        oauth = {"kind": "oauth_client", "id": "shared-oauth", "issuer": ISSUER}
        denied = await invoke(TOKEN_A, propose, "denied", oauth)
        assert denied["error"]["message"] == "Unknown tool"
        forged = await invoke(TOKEN_HOUSE, propose, "forged", {**oauth, "_calling_agent": "agent-a"})
        assert forged["result"]["isError"]
        assert not upstream.requests

        first = await invoke(TOKEN_HOUSE, propose, "first", oauth)
        proposal = json.loads(first["result"]["content"][0]["text"])
        assert proposal["status"] == "pending"
        assert proposal["client"] == "shared-agent"
        again = await invoke(TOKEN_HOUSE, propose, "second", oauth)
        assert json.loads(again["result"]["content"][0]["text"])["id"] == proposal["id"]
        other = await invoke(TOKEN_A, read, "other-reads", {})
        assert json.loads(other["result"]["content"][0]["text"])["proposals"] == []
        assert not upstream.requests

        credentials = {"id": oauth["id"], "issuer": oauth["issuer"], "client_id": "registered-client",
                       "client_secret": "synthetic-registered-secret", "proposal": proposal["id"]}
        unapproved = await http.post("/admin/api/oauth-clients/save", json={
            **credentials, "revision": (await state(http))["revision"],
        })
        assert unapproved.status_code == 403
        assert (await change(http, "oauth-clients/save",
                             **{**credentials, "issuer": "https://changed.example.test"})).status_code == 409
        assert (await change(http, "oauth-clients/save", **credentials)).status_code == 200
        response = await invoke(TOKEN_HOUSE, read, "read-after", {})
        info = json.loads(response["result"]["content"][0]["text"])
        assert info["oauth_clients"][0]["id"] == oauth["id"]
        assert info["proposals"][0]["status"] == "applied"
        assert credentials["client_secret"] not in json.dumps(response)
        assert not upstream.requests

        endpoint = {"kind": "http_mcp", "id": "requested", "url": URL, "auth": "none"}
        result = await invoke(TOKEN_HOUSE, propose, "endpoint", endpoint)
        proposed = json.loads(result["result"]["content"][0]["text"])
        assert proposed["status"] == "pending"
        assert not upstream.requests
        form = {"kind": "remote", "id": endpoint["id"], "owner": "person_a", "proposal": proposed["id"],
                "settings": {"url": URL, "auth": "none", "service": "remote-mcp"}}
        assert (await change(http, "connections/preview",
                             **{**form, "settings": {**form["settings"], "url": "https://changed.example.test"}})).status_code == 409
        assert not upstream.requests
        preview = await change(http, "connections/preview", **form)
        assert preview.status_code == 200, preview.text
        assert upstream.requests and not upstream.calls
        assert (await apply(http, preview)).status_code == 200
        created = next(conn for conn in (await state(http))["connections"] if conn["id"] == endpoint["id"])
        assert created["access"]["shared-agent"] == "none"
        info = (await state(http))["config_proposals"]
        assert [proposal["status"] for proposal in info] == ["applied", "applied"]

        rejected_call = await invoke(TOKEN_HOUSE, propose, "unwanted", {**endpoint, "id": "unwanted"})
        rejected = json.loads(rejected_call["result"]["content"][0]["text"])
        requests_before = len(upstream.requests)
        assert (await change(http, "proposals/reject", id=rejected["id"])).status_code == 200
        response = await change(http, "connections/preview", **{**form, "id": "unwanted", "proposal": rejected["id"]})
        assert response.status_code == 409 and response.json()["error"] == "proposal_not_pending"
        assert len(upstream.requests) == requests_before

        expiring = await invoke(TOKEN_HOUSE, propose, "expiry", {**endpoint, "id": "expired"})
        expiring_id = json.loads(expiring["result"]["content"][0]["text"])["id"]
        store = gw.app.state.admin.provisioning
        rows = store.rows()
        next(row for row in rows if row["id"] == expiring_id)["expires_at"] = 0
        store.file.set("proposals", json.dumps(rows))
        response = await change(http, "connections/preview", **{**form, "id": "expired", "proposal": expiring_id})
        assert response.status_code == 409 and len(upstream.requests) == requests_before

        upstream.mode, upstream.grant_scope = "oauth", "notes.read"
        configure = {"kind": "http_mcp", "id": "authorized", "auth": "oauth", "url": URL,
                     "oauth_client": oauth["id"], "scope": "notes.read"}
        response = await invoke(TOKEN_HOUSE, propose, "with-oauth", configure)
        oauth_request = json.loads(response["result"]["content"][0]["text"])
        assert oauth_request["status"] == "pending"
        assert not any(r.url.path in ("/register", "/token") for r in upstream.requests)
        parameters = {**form, "id": "authorized", "proposal": oauth_request["id"],
                      "settings": {key: configure[key] for key in ("auth", "url", "oauth_client", "scope")} |
                      {"service": "remote-mcp"}}
        started = await change(http, "oauth/mcp/start", **parameters)
        assert started.status_code == 200, started.text
        upstream.query = parse_qs(urlsplit(started.json()["url"]).query)
        assert upstream.query["client_id"] == ["registered-client"]
        assert not any(row["id"] == "authorized" for row in (await state(http))["connections"])
        assert (await apply(http, await consent_complete(http, upstream))).status_code == 200
        configured = next(row for row in (await state(http))["connections"] if row["id"] == "authorized")
        assert configured["settings"]["oauth_client"] == "shared-oauth"
        assert configured["access"]["shared-agent"] == "none"


        linear = "https://mcp.linear.app/mcp/readonly"
        dynamic = Remote(monkeypatch, url=linear)
        dynamic.grant_scope = "read"
        request = {"kind": "http_mcp", "id": "dynamic-mcp", "auth": "oauth", "url": linear}
        submitted = await invoke(TOKEN_HOUSE, propose, "dynamic-applied", request)
        dynamic_id = json.loads(submitted["result"]["content"][0]["text"])["id"]
        assert dynamic.requests == []
        started = await change(http, "oauth/mcp/start", **{**form, "id": request["id"], "proposal": dynamic_id,
                               "settings": {"url": linear, "auth": "oauth", "service": "remote-mcp"}})
        assert started.status_code == 200, started.text
        dynamic.query = parse_qs(urlsplit(started.json()["url"]).query)
        assert dynamic.query["scope"] == ["read"]
        assert any(call.url.path == "/register" for call in dynamic.requests)
        assert (await apply(http, await consent_complete(http, dynamic))).status_code == 200
        result = await invoke(TOKEN_HOUSE, read, "read-dynamic", {})
        proposals = json.loads(result["result"]["content"][0]["text"])["proposals"]
        assert next(row for row in proposals if row["id"] == dynamic_id)["status"] == "applied"


@pytest.mark.parametrize("needs_approval", [True, False])
async def test_provisioning_queue_protects_arguments(tmp_path, monkeypatch, needs_approval):
    # Hold the dispatcher at the queue boundary so both paths leave a durable request to inspect.
    dispatch_queue = RequestStore.dispatch_queue
    paused = True
    monkeypatch.setattr(RequestStore, "dispatch_queue", lambda store, limit: [] if paused else dispatch_queue(store, limit))
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        assert (await change(http, "connections/save", kind="gateway_config", id="config", owner="person_a")).status_code == 200
        access = "read_write_approval" if needs_approval else "read_write_direct"
        assert (await change(http, "permissions/connection", client="agent-a", connection="config",
                             access=access, approver="person_a")).status_code == 200
        endpoint = "https://synthetic-private.example.test/mcp"
        args = {"kind": "http_mcp", "id": "new-remote", "url": endpoint, "auth": "none"}
        wrapped = {"connection": "config", "tool": "gateway_config_provision", "arguments": args,
                   "idempotency_key": "protected", "background": True}
        response = (await rpc(origin, TOKEN_A, "tools/call", {"name": "gateway_call_tool", "arguments": wrapped})).json()
        result = response["result"]["structuredContent"]
        assert result["status"] == ("pending" if needs_approval else "queued")
        store = gw.app.state.runtime.gateway.approver
        with sqlite3.connect(store.path) as db:
            saved, = db.execute("SELECT arguments FROM requests").fetchone()
        assert endpoint not in saved
        assert endpoint.encode() not in store.path.read_bytes()

        if needs_approval:
            page = Page(origin, origin)
            request_id = request_id_in(result["approval_url"])
            status, details = await page.view(request_id)
            assert status == 200 and details["arguments"] == args
            status, details = await page.decide("approve", request_id, key, origin=origin)
            assert status == 200, details
        paused = False
        watched = (await rpc(origin, TOKEN_A, "tools/call", {"name": "gateway_call_tool",
                             "arguments": {"idempotency_key": "protected", "wait_seconds": 10}})).json()
        assert watched["result"]["structuredContent"]["status"] == "succeeded"
        rows = gw.app.state.admin.provisioning.rows()
        assert len(rows) == 1 and rows[0]["config"]["url"] == endpoint
