"""Use the normal management and MCP routes to provision disposable resources."""
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import anyio
import pytest

from helpers import TOKEN_A, TOKEN_HOUSE, prepare
from passkey_helpers import Page, approval_config, request_id_in
from service_helpers import free_port

from agent_gateway.connectors import gateway_config
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
        connectors = (await state(http))["connections"]
        assert [(c["id"], c["owner"]) for c in connectors if c["kind"] == "gateway_config"] == [
            ("gateway_config", "person_a")]
        refused = await change(http, "connections/remove", id="gateway_config")
        assert refused.status_code == 400

        async def search(token, query):
            data = (await rpc(origin, token, "tools/call", {"name": "gateway_search_tools",
                        "arguments": {"connection": "gateway_config", "query": query}})).json()
            return {item["name"] for item in json.loads(data["result"]["content"][0]["text"])["tools"]}

        async def invoke(token, tool, key, arguments):
            return (await rpc(origin, token, "tools/call", {"name": "gateway_call_tool", "arguments": {
                "connection": "gateway_config", "tool": tool, "idempotency_key": key, "arguments": arguments,
            }})).json()

        read, propose = "gateway_config_read", "gateway_config_provision"
        assert await search(TOKEN_HOUSE, "configuration") == set()
        assert (await change(http, "permissions/connection", client="shared-agent", connection="gateway_config",
                             access="read_write_direct")).status_code == 200
        assert (await change(http, "permissions/connection", client="agent-a", connection="gateway_config",
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
        access = "read_write_approval" if needs_approval else "read_write_direct"
        assert (await change(http, "permissions/connection", client="agent-a", connection="gateway_config",
                             access=access, approver="person_a")).status_code == 200
        endpoint = "https://synthetic-private.example.test/mcp"
        args = {"kind": "http_mcp", "id": "new-remote", "url": endpoint, "auth": "none"}
        wrapped = {"connection": "gateway_config", "tool": "gateway_config_provision", "arguments": args,
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


def upload_token():
    token = "agw_intake_" + secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest()


@pytest.mark.parametrize("intake_method", ["agent-token", "digest"])
async def test_prepared_oauth_uses_staged_credentials_and_applies_exact_agent_grants(tmp_path, monkeypatch, intake_method):
    import httpx2

    port = free_port()
    raw = approval_config(origin=f"http://localhost:{port}")
    raw["admin"] = {"owner": "person_a", "state": "admin.enc"}
    raw["server"]["tool_discovery"] = "search"
    path = await prepare(tmp_path, raw)
    upstream = Remote(monkeypatch, mode="oauth")
    upstream.no_registration = True
    upstream.grant_scope = "notes.read"
    async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, path):
        await setup(http, origin, path)
        assert (await change(http, "permissions/connection", client="shared-agent", connection="gateway_config",
                             access="read_write_direct")).status_code == 200

        async def invoke(tool, key, arguments, *, connection="gateway_config", token=TOKEN_HOUSE):
            return (await rpc(origin, token, "tools/call", {"name": "gateway_call_tool", "arguments": {
                "connection": connection, "tool": tool, "idempotency_key": key, "arguments": arguments,
            }})).json()

        async def propose(key, args):
            result = await invoke("gateway_config_provision", key, {"prepared": True, **args})
            assert not result["result"].get("isError"), result
            return json.loads(result["result"]["content"][0]["text"])

        client_args = {"kind": "oauth_client", "id": "prepared-client", "issuer": ISSUER}
        other_args = client_args | {"id": "other-client"}
        ticket, digest = upload_token()
        other_ticket, other_digest = upload_token()
        use_digest = intake_method == "digest"
        if use_digest:
            malformed = await invoke("gateway_config_provision", "invalid-digest",
                                     client_args | {"prepared": True, "intake_sha256": ticket})
            assert malformed["result"]["isError"]
            assert "invalid_proposal" in json.dumps(malformed) and ticket not in json.dumps(malformed)
            no_auth = await invoke("gateway_config_provision", "no-auth-digest", {
                "kind": "http_mcp", "id": "no-auth", "url": URL, "auth": "none",
                "prepared": True, "intake_sha256": digest,
            })
            assert no_auth["result"]["isError"]
            unprepared = await invoke("gateway_config_provision", "unprepared-digest",
                                      client_args | {"intake_sha256": digest})
            assert unprepared["result"]["isError"]
            denied = await invoke("gateway_config_provision", "denied-intake",
                                  client_args | {"prepared": True, "intake_sha256": digest}, token=TOKEN_A)
            assert denied["error"]["message"] == "Unknown tool"
        oauth = await propose("prepared-client", client_args | ({"intake_sha256": digest} if use_digest else {}))
        other = await propose("other-client", other_args | ({"intake_sha256": other_digest} if use_digest else {}))
        assert not upstream.requests
        credentials = {"client_id": "prepared-client-id", "client_secret": "prepared-private-client-secret"}
        async with httpx2.AsyncClient(trust_env=False) as runner:
            auth = {"Authorization": f"Bearer {TOKEN_HOUSE}"}
            wrong_agent = await runner.post(oauth["intake_url"], headers={"Authorization": f"Bearer {TOKEN_A}"})
            assert wrong_agent.status_code == 404
            assert (await runner.post(oauth["intake_url"], headers=auth | {"Origin": origin})).status_code == 403
            if not use_digest:
                ticket = (await runner.post(oauth["intake_url"], headers=auth)).json()["token"]
            headers = {"Authorization": f"Bearer {ticket}"}
            assert (await runner.get(origin + "/admin/api/state", headers=headers)).status_code == 401
            assert (await rpc(origin, ticket)).status_code == 401
            assert (await runner.put(other["intake_url"], headers=headers, json=credentials)).status_code == 401
            command = [sys.executable, "-m", "agent_gateway.cli", "stage", origin, oauth["id"]]
            env = {key: value for key, value in os.environ.items() if key != "AGW_AGENT_TOKEN"}
            payload = json.dumps(credentials)
            if use_digest:
                digest_auth = {"Authorization": f"Bearer {digest}"}
                assert (await runner.put(oauth["intake_url"], headers=digest_auth, json=credentials)).status_code == 401
                command.append("--intake-token-stdin")
                payload = ticket + "\n" + payload
            else:
                env["AGW_AGENT_TOKEN"] = TOKEN_HOUSE
            cli = await anyio.run_process(command, env=env, input=payload.encode(), check=False)
            assert cli.returncode == 0, cli.stderr.decode()
            receipt = json.loads(cli.stdout)
            assert receipt["proposal"] == oauth["id"]
            version = receipt["version"]
            assert all(value.encode() not in cli.stdout for value in (ticket, TOKEN_HOUSE, credentials["client_secret"]))
            assert not cli.stderr
            if use_digest:
                duplicate = await propose("duplicate-client", client_args | {"intake_sha256": other_digest})
                assert duplicate["id"] == oauth["id"] and duplicate["staged_version"] == version
                new_auth = {"Authorization": f"Bearer {other_ticket}"}
                assert (await runner.put(oauth["intake_url"], headers=new_auth, json=credentials)).status_code == 401
            assert (await runner.put(oauth["intake_url"], headers=headers, json=credentials)).status_code == 401
            assert (await runner.post(oauth["intake_url"], headers=auth)).status_code == 409
            if not use_digest:
                assert (await runner.post(other["intake_url"], headers=auth)).status_code == 200

        assert credentials["client_secret"].encode() not in (tmp_path / "admin.enc.staged").read_bytes()
        data = await state(http)
        review = next(row for row in data["config_proposals"] if row["id"] == oauth["id"])
        assert review["staged_client_id"] == credentials["client_id"]
        assert credentials["client_secret"] not in json.dumps(data)
        approval = {"proposal": oauth["id"], "staged_version": version}
        unapproved = await http.post("/admin/api/oauth-clients/save", json=approval | {"revision": data["revision"]})
        assert unapproved.status_code == 403
        assert (await change(http, "oauth-clients/save", **(approval | {"staged_version": "changed"}))).status_code == 409
        assert (await change(http, "oauth-clients/save", **approval)).status_code == 200
        assert (await change(http, "oauth-clients/save", **approval)).status_code == 409
        assert not upstream.requests
        assert oauth["id"] not in gw.app.state.admin.provisioning.intake.names()
        assert (await change(http, "proposals/reject", id=other["id"])).status_code == 200
        assert other["id"] not in gw.app.state.admin.provisioning.intake.names()
        if use_digest:
            async with httpx2.AsyncClient(trust_env=False) as runner:
                response = await runner.put(other["intake_url"], headers=new_auth, json=credentials)
                assert response.json()["error"] == "proposal_not_pending"

        expiry_args = client_args | {"id": "expired-client"}
        async with httpx2.AsyncClient(trust_env=False) as runner:
            if use_digest:
                expiring_ticket, expiring_digest = upload_token()
                now, elapsed = time.time(), 0
                with monkeypatch.context() as clock:
                    clock.setattr(gateway_config, "time", SimpleNamespace(time=lambda: now + elapsed))
                    expiring_args = expiry_args | {"intake_sha256": expiring_digest}
                    expired = await propose("expired-client", expiring_args)
                    elapsed = 600
                    duplicate = await propose("same-digest", expiring_args)
                    assert duplicate["id"] == expired["id"]
                    elapsed = 901
                    expired_auth = {"Authorization": f"Bearer {expiring_ticket}"}
                    refusal = await runner.put(expired["intake_url"], headers=expired_auth, json=credentials)
                    assert refusal.json()["error"] == "invalid_intake_token"
            else:
                expired = await propose("expired-client", expiry_args)
                expiring_ticket = (await runner.post(expired["intake_url"], headers=auth)).json()["token"]
                stage_auth = {"Authorization": f"Bearer {expiring_ticket}"}
                staged = await runner.put(expired["intake_url"], headers=stage_auth, json=credentials)
                assert staged.status_code == 200
                replay = await runner.put(expired["intake_url"], headers=stage_auth, json=credentials)
                assert replay.status_code == 401
                intake_store = gw.app.state.admin.provisioning.intake
                record = json.loads(intake_store.get(expired["id"]))
                intake_store.set(expired["id"], json.dumps(record | {"expires_at": 0}))
                assert (await change(http, "oauth-clients/save", proposal=expired["id"],
                                     staged_version=staged.json()["version"])).status_code == 409
        assert not upstream.requests
        assert all(client["id"] != "expired-client" for client in (await state(http))["oauth_clients"])

        args = {"kind": "http_mcp", "id": "prepared-remote", "url": URL, "auth": "oauth",
                "oauth_client": "prepared-client", "scope": "notes.read",
                "grants": [{"client": "shared-agent", "tool": "read.note", "access": "read"}]}
        remote = await propose("prepared-remote", args)
        assert not upstream.requests
        started = await change(http, "oauth/mcp/start", proposal=remote["id"])
        assert started.status_code == 200, started.text
        upstream.query = parse_qs(urlsplit(started.json()["url"]).query)
        assert upstream.query["client_id"] == [credentials["client_id"]]
        upstream.fail_token = "invalid_grant"
        failed = await consent_complete(http, upstream)
        assert failed.status_code == 400
        readback = await invoke("gateway_config_read", "failed-readback", {})
        requests = json.loads(readback["result"]["content"][0]["text"])["proposals"]
        failure = next(row for row in requests if row["id"] == remote["id"])
        assert failure["status"] == "pending"
        assert failure["last_error"] == failed.json()["error"] == "oauth_code_rejected"
        upstream.fail_token = None
        restarted = await change(http, "oauth/mcp/start", proposal=remote["id"])
        assert restarted.status_code == 200, restarted.text
        upstream.query = parse_qs(urlsplit(restarted.json()["url"]).query)
        reviewed = await consent_complete(http, upstream)
        draft = reviewed.json()["draft"]
        assert reviewed.json()["proposal_grants"] == args["grants"]
        after_retry = await invoke("gateway_config_read", "successful-retry-readback", {})
        rows = json.loads(after_retry["result"]["content"][0]["text"])["proposals"]
        assert "last_error" not in next(row for row in rows if row["id"] == remote["id"])
        refused = await apply(http, reviewed, [{"upstream": "write.note", "access": "write"}])
        assert refused.status_code == 409
        assert refused.json()["error"] == "proposal_tool_grant_changed"
        after_apply = await invoke("gateway_config_read", "apply-failure-readback", {})
        rows = json.loads(after_apply["result"]["content"][0]["text"])["proposals"]
        failure = next(row for row in rows if row["id"] == remote["id"])
        assert failure["status"] == "pending" and failure["last_error"] == refused.json()["error"]
        assert all(row["id"] != args["id"] for row in (await state(http))["connections"])
        assert (await apply(http, reviewed)).status_code == 200
        assert (await change(http, "connections/apply", draft=draft, reviewed=True, tools=[])).status_code == 409
        data = await state(http)
        connection = next(row for row in data["connections"] if row["id"] == args["id"])
        tools = {row["upstream"]: row for row in connection["tools"]}
        assert tools["read.note"]["permissions"]["shared-agent"] == "allow"
        assert tools["write.note"]["permissions"]["shared-agent"] == "deny"
        result = await invoke("gateway_config_read", "prepared-readback", {})
        for private_value in (ticket, other_ticket, expiring_ticket, credentials["client_secret"]):
            assert all(private_value not in json.dumps(value) for value in (oauth, other, result))
            assert private_value not in gw.audit_text()
        rows = json.loads(result["result"]["content"][0]["text"])["proposals"]
        assert {row["config"]["id"]: row["status"] for row in rows} == {
            "prepared-client": "applied", "other-client": "rejected", "expired-client": "pending", "prepared-remote": "applied",
        }
        assert "last_error" not in next(row for row in rows if row["id"] == remote["id"])

        async def discover(token):
            result = (await rpc(origin, token, "tools/call", {"name": "gateway_search_tools",
                      "arguments": {"connection": args["id"]}})).json()
            return [tool["name"] for tool in json.loads(result["result"]["content"][0]["text"])["tools"]]

        read_tool, = await discover(TOKEN_HOUSE)
        assert await discover(TOKEN_A) == []
        used = await invoke(read_tool, "prepared-call", {}, connection=args["id"])
        assert "result" in used and "simulated result" in used["result"]["content"][0]["text"], used
        denied = await invoke(read_tool, "prepared-denied", {}, connection=args["id"], token=TOKEN_A)
        assert denied["error"]["message"] == "Unknown tool"
        await propose("legacy-pending", {"kind": "http_mcp", "id": "legacy-pending",
                                         "url": URL, "auth": "none", "prepared": False})
        if use_digest:
            revoked_ticket, revoked_digest = upload_token()
            revoked = await propose("revoked", client_args | {"id": "revoked", "intake_sha256": revoked_digest})
            assert (await change(http, "permissions/connection", client="shared-agent", connection="gateway_config",
                                 access="read")).status_code == 200
            async with httpx2.AsyncClient(trust_env=False) as runner:
                revoked_auth = {"Authorization": f"Bearer {revoked_ticket}"}
                refusal = await runner.put(revoked["intake_url"], headers=revoked_auth, json=credentials)
                assert refusal.json()["error"] == "proposal_not_pending"
