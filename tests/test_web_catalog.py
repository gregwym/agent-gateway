"""MCP description maintenance, independent of the website's session and policy."""
import copy
import json

import pytest
from mcp import MCPError

from agent_gateway.connectors import web
from agent_gateway.web_catalog import GET_DESCRIPTION, PUBLISH_DESCRIPTION
from agent_gateway.web_profiles import SESSION_ENV
from helpers import TOKEN_A, TOKEN_B, agent
from passkey_helpers import TOKEN_A2
from test_admin import change, login, setup, state, web_gateway
from test_discovery import execute, search, wait_for_approval
from test_web_connector import payload, response, start_site

pytestmark = pytest.mark.anyio
MAIN = "https://www.example.test"
API = "https://api.example.test"
SECRET = "simulated-host-only-cookie"
SHARED = "simulated-domain-cookie"


def description():
    return {"openapi": "3.1.2", "info": {"title": "Example", "version": "1"},
            "servers": [{"url": API}],
            "paths": {"/orders": {"post": {"summary": "Observe orders",
                                          "responses": {"200": {"description": "Orders"}}}}},
            "components": {"schemas": {"Order": {"type": "object"}}}}


async def setup_site(http, origin, config):
    key, _ = await setup(http, origin, config)
    saved = await change(http, "connections/save", id="shop", kind="web", owner="person_a",
                         settings={"plugin": "custom-website", "origin": MAIN},
                         credentials={SESSION_ENV: json.dumps([
                             {"name": "only", "domain": "www.example.test", "value": SECRET},
                             {"name": "shared", "domain": ".example.test", "value": SHARED}])})
    assert saved.status_code == 200, saved.text
    for client in ("agent-a", "agent-a2"):
        allowed = await change(http, "permissions/connection", connection="shop", client=client, access="read")
        assert allowed.status_code == 200, allowed.text
    return key


async def test_agents_publish_with_version_and_idempotency_without_granting_access(tmp_path, monkeypatch):
    calls = []

    def fetch(host, target, method, headers, body, receive):
        calls.append((host, target, method, headers.get("Cookie")))
        return response(receive, b'{}', content_type="application/json")

    monkeypatch.setattr(web, "_fetch", fetch)
    path, port = await start_site(tmp_path)
    async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, config):
        key = await setup_site(http, origin, config)
        document = description()
        body = {"base_revision": 0, "format": "openapi", "document": document}
        async with (agent(origin + "/mcp", TOKEN_A) as writer, agent(origin + "/mcp", TOKEN_A2) as reader,
                    agent(origin + "/mcp", TOKEN_B) as outsider):
            assert await search(writer, "tools", query=PUBLISH_DESCRIPTION) == {"tools": [], "total": 0, "next_offset": None}
            with pytest.raises(MCPError, match="Unknown tool"):
                await execute(outsider, GET_DESCRIPTION, "shop", {})
            assert (await execute(reader, GET_DESCRIPTION, "shop", {})).structured_content == {
                "revision": 0, "format": None, "document": None}
            with pytest.raises(MCPError, match="Unknown tool"):
                await execute(reader, PUBLISH_DESCRIPTION, "shop", body)
            before = await state(http)
            unconfirmed = await http.post("/admin/api/web-catalog/publisher",
                                          json={"id": "shop", "client": "agent-a", "revision": before["revision"]})
            assert unconfirmed.json()["error"] == "admin_confirmation_required"
            grant = await change(http, "web-catalog/publisher", id="shop", client="agent-a")
            assert grant.status_code == 200, grant.text

            tools = await writer.list_tools()
            assert {t.name for t in tools.tools} == {"gateway_search_tools", "gateway_search_connections", "gateway_call_tool"}
            found = await search(writer, "tools", query="API description", connection="shop")
            assert {t["name"] for t in found["tools"]} == {GET_DESCRIPTION, PUBLISH_DESCRIPTION}
            entries = await search(writer, "connections", query="shop", tool=PUBLISH_DESCRIPTION)
            assert entries["connections"][0]["api_catalog"]["publish_tool"] == PUBLISH_DESCRIPTION

            result = await execute(writer, PUBLISH_DESCRIPTION, "shop", body, background=True, wait_seconds=20,
                                   idempotency_key="publish-one")
            assert result.structured_content["status"] in {"queued", "running", "succeeded"}
            watched = await writer.call_tool("gateway_call_tool", {
                "idempotency_key": "publish-one", "background": False, "wait_seconds": 20})
            assert watched.structured_content["status"] == "succeeded"
            assert watched.structured_content["result"]["revision"] == 1
            retry = await execute(writer, PUBLISH_DESCRIPTION, "shop", body, idempotency_key="publish-one")
            assert retry.structured_content["revision"] == 1
            assert (await state(http))["revision"] == grant.json()["revision"]
            assert (await execute(reader, GET_DESCRIPTION, "shop", {})).structured_content["document"] == document
            assert not calls

            changed = copy.deepcopy(document)
            changed["components"]["schemas"]["Order"]["properties"] = {"id": {"type": "string"}}
            conflict = await execute(writer, PUBLISH_DESCRIPTION, "shop", {**body, "document": changed})
            assert conflict.is_error and conflict.structured_content == {"error": "catalog_revision_conflict", "current_revision": 1}
            update = await execute(writer, PUBLISH_DESCRIPTION, "shop", {**body, "base_revision": 1, "document": changed})
            assert not update.is_error and update.structured_content["changes"]["other"]
            view = (await http.post("/admin/api/web-catalog/view", json={"id": "shop"})).json()
            assert view["current"]["revision"] == 2 and "properties" in view["diff"]
            assert view["api_origins"] == []
            old = await execute(reader, GET_DESCRIPTION, "shop", {"revision": 1})
            assert old.structured_content["document"] == document

            args = {"method": "GET", "path": "/cart", "origin": API}
            forbidden = await execute(writer, "web_http_request", "shop", args)
            assert forbidden.is_error and not calls
            allowed = await change(http, "web-catalog/origins", id="shop", origins=[API])
            assert allowed.status_code == 200, allowed.text
            assert payload(await execute(writer, "web_http_request", "shop", args))["status"] == 200
            assert calls == [("api.example.test", "/cart", "GET", "shared=" + SHARED)]
            denied = await execute(writer, "web_http_request", "shop", {**args, "method": "POST", "path": "/orders"})
            assert denied.is_error and len(calls) == 1

            revoked = await change(http, "web-catalog/publisher", id="shop", client=None)
            assert revoked.status_code == 200, revoked.text
            with pytest.raises(MCPError, match="Unknown tool"):
                await execute(writer, PUBLISH_DESCRIPTION, "shop", {**body, "base_revision": 2})
            assert (await execute(writer, GET_DESCRIPTION, "shop", {})).structured_content["revision"] == 2
        assert SECRET not in gw.audit_text() and "Observe orders" not in gw.audit_text()

    async with web_gateway(tmp_path, path=path, port=port) as (_, http, origin, config):
        await login(http, key, origin)
        async with agent(origin + "/mcp", TOKEN_A2) as client:
            assert (await execute(client, GET_DESCRIPTION, "shop", {"revision": 1})).structured_content["document"] == document


@pytest.mark.browser
async def test_mobile_admin_reviews_catalog_versions_and_approves_origin(tmp_path):
    from test_admin_feedback_browser import admin_page, playwright

    path, port = await start_site(tmp_path)
    async with admin_page(tmp_path, "zh-CN", mobile=True, path=path, port=port) as (page, origin):
        await page.get_by_role("link", name="连接器", exact=True).tap()
        await page.get_by_role("button", name="添加连接器", exact=True).tap()
        await page.get_by_label("服务", exact=True).select_option("web")
        await page.get_by_label("网站", exact=True).select_option("custom-website")
        await page.get_by_label("网站 HTTPS 地址").fill(MAIN)
        await page.get_by_label("连接器名称").fill("shop")
        await page.get_by_text("高级：导入会话文件", exact=True).tap()
        await page.get_by_label("浏览器会话 JSON").set_input_files({
            "name": "session.json", "mimeType": "application/json", "buffer": json.dumps([
                {"name": "auth", "domain": "www.example.test", "value": SECRET},
            ]).encode(),
        })
        await page.get_by_role("button", name="导入会话", exact=True).tap()
        await playwright.expect(page.locator('tr[data-connection="shop"]')).to_be_visible()

        await page.get_by_role("link", name="权限", exact=True).tap()
        await page.get_by_label("Agent", exact=True).select_option("agent-a")
        await page.locator('tr[data-connection="shop"]').get_by_role("button", name="编辑权限").tap()
        await page.get_by_label("连接权限", exact=True).select_option("read")
        await page.get_by_role("button", name="保存连接权限").tap()
        permissions = page.get_by_role("dialog", name="权限：shop")
        await playwright.expect(permissions.get_by_text("连接权限已更新。", exact=True)).to_be_visible()
        await permissions.get_by_role("button", name="关闭", exact=True).tap()

        await page.get_by_role("link", name="连接器", exact=True).tap()
        await page.locator('tr[data-connection="shop"]').get_by_role("button", name="详情").tap()
        await page.get_by_role("button", name="API 描述", exact=True).tap()
        catalog = page.get_by_role("dialog", name="API 描述 · shop", exact=True)
        await catalog.get_by_label("维护者", exact=True).select_option("agent-a")
        await catalog.get_by_role("button", name="保存维护者", exact=True).tap()
        await playwright.expect(catalog.get_by_text("维护者已保存。", exact=True)).to_be_visible()

        async with agent(origin + "/mcp", TOKEN_A) as writer:
            doc = description()
            first = await execute(writer, PUBLISH_DESCRIPTION, "shop",
                                  {"base_revision": 0, "format": "openapi", "document": doc})
            assert first.structured_content["revision"] == 1
            doc["paths"]["/orders"]["post"]["summary"] = "<script>example()</script>"
            second = await execute(writer, PUBLISH_DESCRIPTION, "shop",
                                   {"base_revision": 1, "format": "openapi", "document": doc})
            assert second.structured_content["revision"] == 2
        await catalog.get_by_role("button", name="刷新", exact=True).tap()
        await playwright.expect(catalog.get_by_label("版本", exact=True)).to_have_value("2")
        await catalog.get_by_text("本版改动", exact=True).tap()
        await playwright.expect(catalog.get_by_text('+        "summary": "<script>example()</script>"', exact=False)).to_be_visible()
        assert not await catalog.locator("script").count()
        await catalog.get_by_text("API 域名", exact=True).tap()
        await playwright.expect(catalog.get_by_label(API, exact=True)).not_to_be_checked()
        await catalog.get_by_label(API, exact=True).check()
        await catalog.get_by_role("button", name="保存 API 域名", exact=True).tap()
        await playwright.expect(catalog.get_by_text("API 域名已保存。", exact=True)).to_be_visible()
        async with agent(origin + "/mcp", TOKEN_A) as writer:
            entries = await search(writer, "connections", query="shop")
            assert entries["connections"][0]["api_origins"] == [API]


def test_graphql_description_reports_type_changes_and_rejects_tokens():
    from agent_gateway.passkey import Refused
    from agent_gateway.web_catalog import document_info, summary

    def revision(document):
        operations, origins = document_info("graphql", document)
        assert not origins
        return {"format": "graphql", "document": document, "operations": operations}

    before = revision("type Query { viewer: User }\ntype User { id: ID! }")
    after = revision("type Query { viewer: User }\ntype User { id: ID! name: String }")
    assert summary(before, after)["changed"] == ["User"]
    with pytest.raises(Refused, match="website_catalog_contains_token"):
        document_info("graphql", "# " + "agw_" + "a" * 43 + "\ntype Query { viewer: ID }")
