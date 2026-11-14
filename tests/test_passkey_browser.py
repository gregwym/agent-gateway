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
from passkey_helpers import approval_config, request_id_in
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
        await playwright.expect(page.locator("h1")).to_have_text("已批准" if locale == "zh-CN" else "Approved")

        changed = await client.call_tool("a_add_note", {**note, "text": note["text"] + "!"})
        assert changed.is_error and request_id_in(text_of(changed)) != request_id
        approved = await client.call_tool("a_add_note", note)
        assert not approved.is_error and text_of(approved) == "added"
        replay = await client.call_tool("a_add_note", note)
        assert replay.is_error and request_id_in(text_of(replay)) != request_id
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


async def test_browser_decline_and_withdraw(tmp_path):
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
        assert gateway.gateway.approver.view(request_id)["status"] == "cancelled"
        assert (await client.call_tool("a_add_note", cancelled)).is_error
        notes = text_of(await client.call_tool("a_list_notes", {"folder": "family"}))
        assert denied["text"] not in notes and cancelled["text"] not in notes


async def test_browser_does_not_claim_execution_when_upstream_failed(tmp_path):
    async with approval_browser(tmp_path) as (gateway, client, page, origin, _link):
        request_id = request_id_in(text_of(await client.call_tool("a_crash", {})))
        await page.goto(f"{origin}/approvals/r/{request_id}")
        await page.get_by_role("button", name="Approve with passkey").click()
        await playwright.expect(page.locator("h1")).to_have_text("Approved")
        assert (await client.call_tool("a_crash", {})).is_error
        assert gateway.gateway.approver.view(request_id)["outcome"] != "ok"
        await page.reload()
        await playwright.expect(page.locator("h1")).to_have_text("Approval used")
        await playwright.expect(page.locator("pre")).to_have_text("(no longer stored)")
