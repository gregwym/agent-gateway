"""The shipped approval page in Chromium, with a virtual WebAuthn authenticator.

These tests execute approve.js unchanged. They use only disposable demo accounts;
they do not use a person's browser profile, passkeys or real service credentials.
Install with `pip install -e '.[browser-tests]'` and `playwright install chromium`.
"""

from contextlib import asynccontextmanager
import os
from pathlib import Path

import pytest
from helpers import TOKEN_A, agent, prepare, running_gateway, text_of
from passkey_helpers import approval_config, request_id_in, wait_for_approval
from service_helpers import free_port

playwright = pytest.importorskip("playwright.async_api")
pytestmark = [pytest.mark.anyio, pytest.mark.browser]


@asynccontextmanager
async def approval_browser(tmp_path, locale="en-US"):
    port = free_port()
    origin = f"http://localhost:{port}"
    raw = approval_config(origin=origin)
    raw["policy"].append({
        "principals": ["person_a"], "connection": "notes-a", "tools": ["a_crash"],
        "effect": "approval_required",
    })
    async with running_gateway(await prepare(tmp_path, raw), port=port) as gateway:
        async with playwright.async_playwright() as driver:
            browser = await driver.chromium.launch()
            try:
                context = await browser.new_context(locale=locale, viewport={"width": 390, "height": 844})
                page = await context.new_page()
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                cdp = await context.new_cdp_session(page)
                await cdp.send("WebAuthn.enable")
                await cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                    "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                    "hasUserVerification": True, "isUserVerified": True,
                    "automaticPresenceSimulation": True,
                }})
                link = gateway.gateway.approver.new_enrollment("person_a")
                await page.goto(link)
                await page.get_by_role("button", name="注册通行密钥" if locale == "zh-CN" else "Register passkey").click()
                await playwright.expect(page.locator(".notice.ok")).to_contain_text(
                    "已注册" if locale == "zh-CN" else "Passkey registered"
                )
                assert "#" not in page.url
                assert len(gateway.gateway.approver.passkeys()) == 1
                async with agent(gateway.url, TOKEN_A) as client:
                    yield gateway, client, page, origin, link
                assert not errors
            finally:
                await browser.close()


@pytest.mark.parametrize("locale", ["en-US", "zh-CN"])
async def test_browser_enrollment_approval_exact_arguments_and_one_use(tmp_path, locale):
    async with approval_browser(tmp_path, locale) as (gateway, client, page, origin, link):
        note = {"folder": "family", "text": "<img src=x onerror=alert(1)> buy milk"}
        requested = await client.call_tool("a_add_note", note)
        assert requested.is_error
        request_id = request_id_in(text_of(requested))
        await page.goto(f"{origin}/approvals/r/{request_id}")
        await playwright.expect(page.locator("pre")).to_contain_text(note["text"])
        assert await page.locator("#app img").count() == 0
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        if directory := os.environ.get("AGW_TEST_ARTIFACTS"):
            artifacts = Path(directory)
            artifacts.mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=str(artifacts / f"approval-{locale}.png"), full_page=True)
        await page.get_by_role("button", name="用通行密钥批准" if locale == "zh-CN" else "Approve with passkey").click()
        await playwright.expect(page.locator("h1")).to_have_text("已完成" if locale == "zh-CN" else "Completed")

        changed = await client.call_tool("a_add_note", {**note, "text": note["text"] + "!"})
        assert changed.is_error and request_id_in(text_of(changed)) != request_id
        approved = await wait_for_approval(client, request_id)
        assert approved.structured_content["status"] == "succeeded" and approved.content[1].text == "added"
        replay = await client.call_tool("a_add_note", note)
        assert replay.is_error and replay.structured_content["request_id"] == request_id
        assert text_of(await client.call_tool("a_list_notes", {"folder": "family"})).count(note["text"]) == 1
        await page.reload()
        await playwright.expect(page.locator("pre")).to_have_text(
            "（已不再保存）" if locale == "zh-CN" else "(no longer stored)"
        )
        assert gateway.gateway.approver.view(request_id)["outcome"] == "ok"

        # The browser cannot reuse a consumed enrollment link.
        await page.goto(link)
        await page.get_by_role("button", name="注册通行密钥" if locale == "zh-CN" else "Register passkey").click()
        await playwright.expect(page.locator("#status")).to_contain_text(
            "此链接无效" if locale == "zh-CN" else "This link is invalid"
        )
        assert len(gateway.gateway.approver.passkeys()) == 1


async def test_browser_decline_and_withdraw(tmp_path, monkeypatch):
    from test_passkey import defer_dispatch
    start = defer_dispatch(monkeypatch)
    async with approval_browser(tmp_path) as (gateway, client, page, origin, _link):
        denied = {"folder": "family", "text": "do not add this"}
        request_id = request_id_in(text_of(await client.call_tool("a_add_note", denied)))
        await page.goto(f"{origin}/approvals/r/{request_id}")
        await page.get_by_role("button", name="Decline", exact=True).click()
        await playwright.expect(page.locator("h1")).to_have_text("Declined")
        assert "declined" in text_of(await client.call_tool("a_add_note", denied))

        cancelled = {"folder": "family", "text": "withdraw this"}
        request_id = request_id_in(text_of(await client.call_tool("a_add_note", cancelled)))
        await page.goto(f"{origin}/approvals/r/{request_id}")
        await page.get_by_role("button", name="Approve with passkey").click()
        await page.get_by_role("button", name="Withdraw approval").click()
        await playwright.expect(page.locator("h1")).to_have_text("Withdrawn")
        start.set()
        assert gateway.gateway.approver.view(request_id)["status"] == "cancelled"
        assert (await client.call_tool("a_add_note", cancelled)).is_error
        notes = text_of(await client.call_tool("a_list_notes", {"folder": "family"}))
        assert denied["text"] not in notes and cancelled["text"] not in notes


async def test_browser_does_not_claim_execution_when_upstream_failed(tmp_path):
    async with approval_browser(tmp_path) as (gateway, client, page, origin, _link):
        request_id = request_id_in(text_of(await client.call_tool("a_crash", {})))
        await page.goto(f"{origin}/approvals/r/{request_id}")
        await page.get_by_role("button", name="Approve with passkey").click()
        await playwright.expect(page.locator("h1")).to_have_text("Execution outcome unknown")
        assert (await wait_for_approval(client, request_id)).structured_content["status"] == "execution_unknown"
        assert gateway.gateway.approver.view(request_id)["outcome"] != "ok"
        await page.reload()
        await playwright.expect(page.locator("h1")).to_have_text("Execution outcome unknown")
        await playwright.expect(page.locator("pre")).to_have_text("(no longer stored)")


@pytest.mark.parametrize("locale", ["en-US", "zh-CN"])
async def test_admin_copies_new_member_registration_link(tmp_path, locale):
    from test_admin_feedback_browser import admin_page

    def t(en, zh):
        return zh if locale == "zh-CN" else en

    async with admin_page(tmp_path, locale) as (admin, origin):
        await admin.context.grant_permissions(["clipboard-read", "clipboard-write"], origin=origin)
        await admin.get_by_role("link", name=t("Members", "群组成员"), exact=True).click()
        await admin.get_by_role("button", name=t("Add member", "添加成员"), exact=True).click()
        await admin.get_by_label(t("Name", "名字"), exact=True).fill("Alex 林")
        await admin.get_by_role("button", name=t("Add", "添加"), exact=True).click()
        await admin.get_by_role("button", name=t("Create passkey link", "生成通行密钥链接"), exact=True).click()
        link = await admin.get_by_label(t("Registration link", "注册链接"), exact=True).input_value()
        assert link.startswith(origin + "/approvals/enroll#")
        await admin.get_by_role("button", name=t("Copy", "复制"), exact=True).click()
        assert await admin.evaluate("navigator.clipboard.readText()") == link

        member_context = await admin.context.browser.new_context(locale=locale)
        try:
            member = await member_context.new_page()
            cdp = await member_context.new_cdp_session(member)
            await cdp.send("WebAuthn.enable")
            await cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
            assert (await member.request.get(origin + "/admin/api/state")).status == 401
            await member.goto(link)
            await member.get_by_role("button", name=t("Register passkey", "注册通行密钥"), exact=True).click()
            await playwright.expect(member.locator(".notice.ok")).to_contain_text(t("Passkey registered.", "通行密钥已注册"))
            await admin.reload()
            card = admin.locator(".card").filter(has=admin.get_by_role("heading", name="Alex 林", exact=True))
            await playwright.expect(card).to_contain_text(t("1 passkey(s) registered", "已注册 1 个通行密钥"))
        finally:
            await member_context.close()
