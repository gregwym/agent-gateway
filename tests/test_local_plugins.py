"""Install a manifest while a gateway is running and call its reviewed tools."""
import json
import sys

import pytest

from helpers import TOKEN_A
from test_admin import change, rpc, setup, state, web_gateway

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("kind", ["cli", "stdio"])
async def test_host_plugin_install_review_and_account_credentials(tmp_path, kind):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        marker = tmp_path / "cli-called"
        secret = "private-plugin-credential"
        if kind == "cli":
            program = ("import os, pathlib, sys; "
                       f"pathlib.Path({str(marker)!r}).touch(); "
                       "print(sys.argv[1]); print(os.environ['PLUGIN_TEST_KEY'])")
            command = [sys.executable, "-c", program]
            tools = {"get_value": {"description": "Read a fixture", "access": "read",
                                   "options": {"query": {"flag": "--query", "required": True}}}}
        else:
            command = [sys.executable, "-m", "agent_gateway.demo_connector"]
            tools = {}
        slot = "PLUGIN_TEST_KEY" if kind == "cli" else "DEMO_API_KEY"
        name = "fixture-" + kind
        body = {"id": name, "owner": "person_a", "kind": "local",
                "settings": {"plugin": name}, "credentials": {slot: secret}}
        assert not [p for p in (await state(http))["plugins"] if p["kind"] != "web"]
        rejected = await change(http, "connections/preview", **body)
        assert rejected.json()["error"] == "local_plugin_unavailable"
        directory = tmp_path / "plugins"
        directory.mkdir()
        (directory / f"{name}.json").write_text(json.dumps({
            "id": name, "label": "Fixture", "kind": kind, "command": command,
            "tools": tools, "credentials": {slot: "Fixture key"},
        }))
        public = [p for p in (await state(http))["plugins"] if p["kind"] != "web"]
        assert public == [{"id": name, "label": "Fixture", "kind": kind, "credentials": {slot: "Fixture key"}}]
        invalid = await change(http, "connections/preview", **{**body, "settings": {**body["settings"], "command": "/bin/sh"}})
        assert invalid.json()["error"] == "invalid_connector"
        preview = await change(http, "connections/preview", **body)
        assert preview.status_code == 200, preview.text
        review = preview.json()
        assert not marker.exists()
        assert secret not in preview.text
        if kind == "cli":
            assert review["fixed_access"]
            changed = await change(http, "connections/apply", draft=review["draft"], reviewed=True,
                                   tools=[{**review["tools"][0], "access": "write"}])
            assert changed.json()["error"] == "invalid_remote_tool_selection"
        applied = await change(http, "connections/apply", draft=review["draft"], reviewed=True, tools=review["tools"])
        assert applied.status_code == 200, applied.text
        conn = next(c for c in (await state(http))["connections"] if c["id"] == name)
        assert conn["access"]["agent-a"] == "none"
        assert (await change(http, "connections/test", id=name)).status_code == 200
        assert not marker.exists()
        assert (await change(http, "permissions/connection", client="agent-a", connection=name, access="read")).status_code == 200
        tool = next(t for t in conn["tools"] if t["access"] == "read")
        result = (await rpc(origin, TOKEN_A, "tools/call", {"name": tool["name"], "arguments": {"query": "--force; touch pwned"} if kind == "cli" else {"folder": "inbox"}})).json()
        assert not result.get("error") and not result["result"].get("isError"), result
        if kind == "cli":
            assert marker.exists()
            assert "--query=--force; touch pwned" in result["result"]["content"][0]["text"]
            assert "REDACTED" in result["result"]["content"][0]["text"]
        assert secret not in str(result) + gw.audit_text()


async def test_amazon_session_api_rejects_invalid_replacements(tmp_path):
    directory = tmp_path / "plugins"
    directory.mkdir()
    slot = "ORDERS_SESSION_SECRET"
    (directory / "amazon-orders.json").write_text(json.dumps({
        "id": "amazon-orders", "label": "Amazon Orders", "kind": "stdio",
        "command": [sys.executable, "-m", "agent_gateway.demo_connector"],
        "env": {"DEMO_API_KEY": "synthetic-test-credential"},
        "credentials": {slot: "Amazon session file"},
    }))
    login = {"name": "x-main", "value": '"synthetic-amazon-login"', "domain": ".amazon.com", "path": "/"}
    body = {"id": "orders", "owner": "person_a", "kind": "local", "settings": {"plugin": "amazon-orders"}}

    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)

        async def submit(operation, value):
            return await change(http, operation, **body, credentials={slot: value})

        rejected = await submit("connections/preview", json.dumps([{**login, "name": "session-id"}]))
        assert rejected.status_code == 400 and rejected.json() == {"error": "amazon_session_invalid"}
        assert not gw.cfg.admin.state.exists()

        preview = await submit("connections/preview", json.dumps([login]))
        assert preview.status_code == 200, preview.text
        review = preview.json()
        applied = await change(http, "connections/apply", draft=review["draft"], reviewed=True, tools=review["tools"])
        assert applied.status_code == 200, applied.text
        before = gw.cfg.admin.state.read_bytes()
        invalid = ("not JSON", json.dumps({"cookies": [login]}),
                   *(json.dumps([{**login, **changes}]) for changes in (
                       {"expires": 1}, {"domain": ".amazon.co.uk"}, {"path": "/orders"},
                   )))
        for value in invalid:
            rejected = await submit("connections/save", value)
            assert rejected.status_code == 400 and rejected.json() == {"error": "amazon_session_invalid"}
        assert gw.cfg.admin.state.read_bytes() == before
        assert "synthetic-amazon-login" not in preview.text + applied.text + gw.audit_text()
