"""Exercise the shared website tools with simulated HTTPS responses and real approvals."""
import json
import socket
import uuid
from email.message import Message
from io import BytesIO
from urllib.parse import urlencode

import pytest
from mcp import MCPError

from agent_gateway.connectors import web
from agent_gateway.config import Config
from agent_gateway.web_profiles import PROFILE_ENV, SESSION_ENV, bundled_profiles
from agent_gateway.web_sessions import session_ref
from helpers import TOKEN_A, TOKEN_B, agent, prepare, text_of
from passkey_helpers import Page, approval_config, request_id_in
from service_helpers import free_port
from test_admin import change, login, setup, state, web_gateway
from test_discovery import execute, search


def response(receive, body=b'', *, status=200, rotate=None, location=None, content_type="text/html; charset=utf-8"):
    headers = Message()
    headers["Content-Type"] = content_type
    if rotate:
        headers["Set-Cookie"] = f"auth={rotate}; Secure; HttpOnly; Path=/"
    if location:
        headers["Location"] = location
    return receive(status, headers, BytesIO(body))


async def start_site(tmp_path):
    port = free_port()
    origin = f"http://localhost:{port}"
    raw = approval_config(origin=origin)
    raw["server"]["tool_discovery"] = "search"
    raw["admin"] = {"owner": "person_a", "state": "admin.enc"}
    return await prepare(tmp_path, raw), port


async def add_site(http, name, plugin, cookie):
    profile = bundled_profiles()[plugin][1]
    cookies = [{"domain": profile.origin.removeprefix("https://"), "name": "auth", "value": cookie},
               {"domain": "unrelated.example", "name": "auth", "value": "not-our-cookie"}]
    saved = await change(http, "connections/save", id=name, kind="web", owner="person_a",
                         settings={"plugin": plugin}, credentials={SESSION_ENV: json.dumps(cookies)})
    assert saved.status_code == 200, saved.text
    assert cookie not in saved.text


def payload(result):
    assert not result.is_error, text_of(result)
    return json.loads(result.content[-1].text)


@pytest.mark.anyio
async def test_two_shared_tools_account_isolation_read_rules_and_write_approval(tmp_path, monkeypatch):
    requests = []
    private = {"www.amazon.com": "alpha-private-cookie", "www.weee.com": "bravo-private-cookie"}

    def fetch(host, target, method, headers, body, receive):
        assert headers["Cookie"] == f"auth={private[host]}"
        requests.append((host, target, method, body))
        if target == "/redirect":
            return response(receive, status=307, location="https://other.example/steal")
        if target == "/locale":
            return response(receive, status=307, location="/zh/page?language=zh")
        if target == "/api":
            return response(receive, b'{"data":{"result":"simulated"}}', content_type="application/graphql-response+json")
        return response(receive, f"<main>Simulated page {private[host]}</main>".encode())

    monkeypatch.setattr(web, "_fetch", fetch)
    path, port = await start_site(tmp_path)
    async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        await add_site(http, "shop-a", "amazon-us", private["www.amazon.com"])
        await add_site(http, "shop-b", "weee-orders", private["www.weee.com"])
        assert not requests
        config = await state(http)
        for conn in (c for c in config["connections"] if c["kind"] == "web"):
            assert {t["upstream"] for t in conn["tools"]} == {"http_request", "graphql_request"}
            assert conn["access"]["agent-a"] == "none"
        assert all(cookie not in str(config) for cookie in private.values())

        async with agent(origin + "/mcp", TOKEN_A) as allowed, agent(origin + "/mcp", TOKEN_B) as denied:
            assert (await search(allowed, "tools", query="web_http_request"))["total"] == 0
            for name in ("shop-a", "shop-b"):
                grant = await change(http, "permissions/connection", connection=name, client="agent-a", access="read")
                assert grant.status_code == 200, grant.text
            tools = (await search(allowed, "tools", connection="shop-a"))["tools"]
            assert {t["name"] for t in tools} == {"web_http_request", "web_graphql_request"}
            assert (await search(allowed, "tools", query="web_http_request"))["tools"][0]["connection_count"] == 2
            item, = (await search(allowed, "connections", query="weee.com", tool="web_graphql_request"))["connections"]
            assert item["origin"] == "https://www.weee.com"
            assert item["variants"][0]["access"] == {"read": "allow", "write": "deny"}
            assert (await search(denied, "connections", query="weee.com"))["total"] == 0
            assert (await search(allowed, "tools", query="list_orders"))["total"] == 0
            with pytest.raises(MCPError, match="Unknown tool"):
                await execute(allowed, "service_amazon_us_list_orders", "shop-a", {})
            result = await execute(allowed, "web_http_request", "shop-a", {"method": "GET", "path": "/account/items?q=10"})
            assert payload(result)["body"] == "<main>Simulated page [REDACTED]</main>"
            assert requests[-1][:3] == ("www.amazon.com", "/account/items?q=10", "GET")

            document = "query View($q: String) { items(q:$q) } mutation Delete { deleteItem }"
            query = {"path": "/api", "query": document, "operation_name": "View", "variables": {"q": "rice"}}
            assert payload(await execute(allowed, "web_graphql_request", "shop-b", query))["status"] == 200
            assert requests[-1][:3] == ("www.weee.com", "/api", "POST")
            assert json.loads(requests[-1][3]) == {"query": document, "operationName": "View", "variables": {"q": "rice"}}
            mutation = {**query, "operation_name": "Delete"}
            count = len(requests)
            for tool, args in [
                ("graphql", mutation),
                ("graphql", {**query, "operation_name": "NoSuchOperation"}),
                ("graphql", {"path": "/api", "query": "query Same {a} mutation Same {b}", "operation_name": "Same"}),
                ("graphql", {"path": "/api?operationName=Delete", "query": "{ items }"}),
                ("http", {"path": "/account/archive", "method": "POST"}),
                ("http", {"path": "/api?" + urlencode({"query": "# check\nmutation { deleteItem }"}), "method": "GET"}),
                ("http", {"path": "/path?%5fmethod=DELETE", "method": "GET"}),
                ("http", {"path": "//other.example/stolen", "method": "GET"}),
                ("http", {"path": "/page", "method": "GET", "headers": {"Cookie": "fake"}}),
                ("http", {"path": "/page", "method": "GET", "headers": {"X-HTTP-Method-Override": "DELETE"}}),
            ]:
                assert (await execute(allowed, f"web_{tool}_request", "shop-b", args)).is_error
            assert len(requests) == count
            result = payload(await execute(allowed, "web_http_request", "shop-b", {"method": "GET", "path": "/redirect"}))
            assert result["status"] == 307 and result["redirect_blocked"] and "location" not in result
            result = payload(await execute(allowed, "web_http_request", "shop-b", {"method": "GET", "path": "/locale"}))
            assert result["location"] == "/zh/page?language=zh"
            assert len(requests) == count + 2  # neither redirect was followed

            grant = await change(http, "permissions/connection", connection="shop-b", client="agent-a", access="read_write")
            assert grant.status_code == 200, grant.text
            idem = uuid.uuid4().hex
            pending = await execute(allowed, "web_graphql_request", "shop-b", mutation, idempotency_key=idem)
            ident = request_id_in(text_of(pending))
            assert len(requests) == count + 2
            assert (await Page(origin, origin).decide("approve", ident, key, origin=origin))[0] == 200
            resumed = await allowed.call_tool("gateway_call_tool", {"idempotency_key": idem, "wait_seconds": 10})
            assert payload(resumed)["status"] == 200
            assert json.loads(requests[-1][3])["operationName"] == "Delete"
            assert len(requests) == count + 3
        assert all(cookie not in gw.audit_text() for cookie in private.values())


@pytest.mark.anyio
async def test_upgrade_removes_order_tools_and_grants_without_losing_rotated_session(tmp_path, monkeypatch):
    old_cookie, saved_cookie = "initial-private-cookie", "rotated-private-cookie"
    observed = []

    def fetch(host, target, method, headers, body, receive):
        observed.append(headers["Cookie"])
        return response(receive, status=204)

    monkeypatch.setattr(web, "_fetch", fetch)
    path, port = await start_site(tmp_path)
    async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        await add_site(http, "retail", "weee-orders", old_cookie)
        admin = gw.app.state.admin
        legacy = admin.store.candidate()
        conn = next(c for c in legacy["config"]["connections"] if c["id"] == "retail")
        conn["env"][PROFILE_ENV] = json.dumps({"origin": "https://www.weee.com", "probe": "list_orders",
                                               "experimental": True, "actions": {"list_orders": {"path": "/old"}}})
        conn["tools"] = [{"upstream": "list_orders", "name": "retail_list_orders", "access": "read"}]
        legacy["config"]["policy"].append({"clients": ["agent-a"], "connection": "retail", "tools": ["retail_list_orders"], "effect": "allow"})
        legacy["locks"].pop("retail")
        legacy["bundled_catalog"].pop("retail")
        cfg = Config.model_validate({**admin.store.base.model_dump(), **legacy["config"]})
        ref = session_ref(cfg.connection("retail"), legacy["secrets"])
        rotated = [{"name":"auth", "value":saved_cookie, "path":"/", "expires":-1}]
        admin.web_sessions.file.set(ref, json.dumps({"cookies": json.dumps(rotated), "redactions": [old_cookie]}))
        admin.store.save(legacy)
        original_bytes = (tmp_path / "admin.enc.web-sessions").read_bytes()
    async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, _):
        await login(http, key, origin)
        conn = next(c for c in (await state(http))["connections"] if c["id"] == "retail")
        assert conn["access"]["agent-a"] == "none"
        assert "retail_list_orders" in conn["catalog_sync"]["revoked"]
        assert (tmp_path / "admin.enc.web-sessions").read_bytes() == original_bytes
        async with agent(origin + "/mcp", TOKEN_A) as still_denied:
            assert (await search(still_denied, "tools", connection="retail"))["total"] == 0
        assert (await change(http, "permissions/connection", connection="retail", client="agent-a", access="read")).status_code == 200
        async with agent(origin + "/mcp", TOKEN_A) as allowed:
            assert payload(await execute(allowed, "web_http_request", "retail", {"method": "GET", "path": "/new"}))["status"] == 204
        assert observed == ["auth=" + saved_cookie]
        assert saved_cookie.encode() not in original_bytes


@pytest.mark.anyio
async def test_follow_locale_redirects_without_exposing_cookie_values(tmp_path, monkeypatch):
    seen = []
    original, refreshed = "private-session", "private-rotated-session"
    cookies = [{"name": "auth", "value": original, "domain": "www.weee.com"},
               {"name": "site_lang", "value": "zh", "domain": "www.weee.com"}]

    def fetch(host, target, method, headers, body, receive):
        assert host == "www.weee.com" and method in ("GET", "HEAD") and body is None
        seen.append((target, headers["Cookie"]))
        if target == "/":
            return response(receive, status=307, location="/zh/home")
        if target == "/zh/home":
            return response(receive, status=302, location="/home")
        if target == "/home":
            return response(receive, b"<h1>Simulated home</h1>")
        if target == "/account/my_orders":
            return response(receive, status=307, location="/zh/account/my_orders", rotate=refreshed)
        if target == "/zh/account/my_orders":
            return response(receive, f"<p>Simulated orders {refreshed}</p>".encode())
        if target == "/external":
            return response(receive, status=307, location=f"https://other.example/{refreshed}")
        if target == "/override":
            return response(receive, status=307, location="/account?%5fmethod=DELETE")
        if target == "/loop":
            return response(receive, status=307, location="/loop")
        if target.startswith("/step-"):
            return response(receive, status=307, location=f"/step-{int(target[-1]) + 1}")
        pytest.fail(f"Unexpected simulated request: {target}")

    monkeypatch.setattr(web, "_fetch", fetch)
    config, port = await start_site(tmp_path)
    async with web_gateway(tmp_path, path=config, port=port) as (gw, http, origin, config):
        await setup(http, origin, config)
        imported = await change(http, "connections/save", id="retail", kind="web", owner="person_a",
                                settings={"plugin": "weee-orders"}, credentials={SESSION_ENV: json.dumps(cookies)})
        assert imported.status_code == 200, imported.text
        granted = await change(http, "permissions/connection", connection="retail", client="agent-a", access="read_write_direct")
        assert granted.status_code == 200, granted.text
        async with agent(origin + "/mcp", TOKEN_A) as client:
            tools = (await search(client, "tools", query="web_http_request"))["tools"]
            assert tools[0]["inputSchema"]["properties"]["follow_redirects"]["type"] == "boolean"

            async def request(path, *, follow=None, method="GET"):
                args = {"method": method, "path": path}
                if follow is not None:
                    args["follow_redirects"] = follow
                return await execute(client, "web_http_request", "retail", args)

            first = payload(await request("/account/my_orders", follow=False))
            assert first["status"] == 307 and first["location_redacted"] and "location" not in first
            r = payload(await request("/account/my_orders"))
            assert r["status"] == 200 and r["redirects_followed"] == 1
            assert r["body"] == "<p>Simulated orders [REDACTED]</p>"
            assert [p for p, c in seen] == ["/account/my_orders", "/account/my_orders", "/zh/account/my_orders"]
            assert "auth=" + refreshed in seen[-1][1] and "site_lang=zh" in seen[-1][1]
            assert all(token not in str(r) + str(first) + gw.audit_text() for token in (original, refreshed))

            home = payload(await request("/"))
            assert home["status"] == 200 and home["redirects_followed"] == 2
            assert home["body"] == "<h1>Simulated home</h1>"
            head = payload(await request("/", method="HEAD"))
            assert head["status"] == 200 and head["redirects_followed"] == 2 and head["body"] == ""

            external = payload(await request("/external"))
            assert external["status"] == 307 and external["redirect_blocked"] and "location" not in external
            assert seen[-1][0] == "/external"
            assert (await request("/override", follow=True)).is_error and seen[-1][0] == "/override"
            assert (await request("/loop", follow=True)).is_error and seen[-1][0] == "/loop"
            limit = await request("/step-0", follow=True)
            assert limit.is_error and "redirect limit" in text_of(limit)
            assert [p for p, c in seen if p.startswith("/step-")] == [f"/step-{i}" for i in range(5)]
            assert (await request("/account/my_orders", method="POST", follow=True)).is_error
            assert seen[-1][0] == "/step-4"

            conn = next(c for c in (await state(http))["connections"] if c["id"] == "retail")
            name = next(t["name"] for t in conn["tools"] if t["upstream"] == "http_request")
            restricted = await change(http, "tools/restrict", connection="retail", tool=name,
                                      allow_values={"path": ["/account/my_orders"]})
            assert restricted.status_code == 200, restricted.text
            blocked = await request("/account/my_orders", follow=True)
            assert blocked.is_error and "argument restrictions" in text_of(blocked)
            assert seen[-1][0] == "/step-4"
            before = len(seen)
            no_implicit_follow = payload(await request("/account/my_orders"))
            assert no_implicit_follow["status"] == 307 and no_implicit_follow["location_redacted"]
            assert [target for target, cookie in seen[before:]] == ["/account/my_orders"]



def test_non_public_dns_answer_is_refused_before_connect(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))])
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: pytest.fail("attempted a private connection"))
    with pytest.raises(web.ConnectorError) as exc:
        web._public_socket(("www.amazon.com", 443), 1, None)
    assert exc.value.code == "web_unsafe_address"
