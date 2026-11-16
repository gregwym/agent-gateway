"""A Passkey-bound website login saves the session without contacting the site."""
import asyncio
import base64
import os
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx2
import pytest

from agent_gateway.admin_web_login import WebsiteLogin
from agent_gateway.browser_tunnel import connect
from agent_gateway.connectors import web
from test_admin import change, login, setup, state, web_gateway
from test_web_connector import response

pytestmark = pytest.mark.anyio
SECRET = "private-session-from-browser"



@pytest.fixture
def socket_dir():
    # macOS Unix sockets have a short path limit.
    with TemporaryDirectory(prefix="agwb-", dir="/tmp") as directory:
        yield Path(directory)


def fake_browser(monkeypatch, *, screenshot=None, site="www.amazon.com"):
    backend = {"auth": False, "actions": [], "inputs": [], "taps": [], "swipes": [], "zoom": 100, "cookie_ready": True, "reads": []}

    def fetch(host, target, method, headers, body, receive):
        assert host == site and method == "HEAD" and target == "/" and body is None
        backend["reads"].append(target)
        assert headers.get("Cookie") == "auth=" + SECRET
        return response(receive, status=200 if backend["auth"] else 403)

    async def worker(self, action, data):
        backend["actions"].append(action)
        if action == "text":
            backend["inputs"].append(data["text"])
        if action == "tap":
            backend["taps"].append((data["x"], data["y"]))
        if action == "scroll":
            backend["swipes"].append((data["dx"], data["dy"]))
        if action == "zoom":
            backend["zoom"] = data["percent"]
        if action == "start":
            assert data["url"] == "https://" + site + "/"
        if action == "cookies":
            assert data["origin"] == "https://" + site
            if not backend["cookie_ready"]:
                return {"cookies": []}
            return {"cookies": [{"name": "auth", "domain": site, "value": SECRET},
                                {"name": "auth", "domain": "evil.test", "value": "unrelated-password"}]}
        return {"image": screenshot, "host": "www.amazon.com", "zoom": backend["zoom"]}

    monkeypatch.setattr(web, "_fetch", fetch)
    monkeypatch.setattr(WebsiteLogin, "worker", worker)
    monkeypatch.setattr(WebsiteLogin, "available", lambda _self: True)
    return backend


@pytest.mark.parametrize("plugin", ["amazon-us", "weee-orders"])
async def test_website_session_save_is_private_and_independent_of_read_checks(tmp_path, socket_dir, monkeypatch, plugin):
    monkeypatch.setenv("AGW_BROWSER_SOCKET", str(socket_dir / "control.sock"))
    backend = fake_browser(monkeypatch, site="www.weee.com" if plugin == "weee-orders" else "www.amazon.com")
    async with web_gateway(tmp_path) as (gw, http, origin, config):
        key, _ = await setup(http, origin, config)
        form = {"id": "shop-orders", "owner": "person_a", "plugin": plugin}
        first = await http.post("/admin/api/web-login/start", json={**form, "revision": 0})
        assert first.status_code == 403 and first.json()["error"] == "admin_confirmation_required"
        started = await change(http, "web-login/start", **form)
        assert started.status_code == 200, started.text
        ref = {"id": started.json()["id"]}
        async with httpx2.AsyncClient(base_url=origin, headers={"Origin": origin}, trust_env=False) as other:
            assert (await other.post("/admin/api/web-login/frame", json=ref)).status_code == 401
            await login(other, key, origin)
            assert (await other.post("/admin/api/web-login/frame", json=ref)).json()["error"] == "web_browser_expired"
        bad = await http.post("/admin/api/web-login/tap", json={**ref, "x": 999, "y": 10})
        assert bad.status_code == 400
        typed = "secret-simulated-typed-password"
        assert (await http.post("/admin/api/web-login/text", json={**ref, "text": typed})).status_code == 200
        backend["cookie_ready"] = False
        failure = await http.post("/admin/api/web-login/save", json=ref)
        assert failure.status_code == 422 and failure.json()["error"] == "web_browser_sign_in_required", failure.text
        assert not any(c["id"] == form["id"] for c in (await state(http))["connections"])
        backend["cookie_ready"] = True
        saved = await http.post("/admin/api/web-login/save", json=ref)
        assert saved.status_code == 200, saved.text
        assert not backend["reads"]
        assert backend["actions"][-1] == "close"
        assert (await http.post("/admin/api/web-login/frame", json=ref)).json()["error"] == "web_browser_expired"
        settings = await state(http)
        conn = next(c for c in settings["connections"] if c["id"] == form["id"])
        assert conn["test"] is None and conn["access"]["agent-a"] == "none"
        assert {t["upstream"] for t in conn["tools"]} == {"http_request", "graphql_request"}
        assert SECRET.encode() not in (tmp_path / "admin.enc").read_bytes()
        assert all(s not in str(settings) + gw.audit_text() for s in (SECRET, typed, "unrelated-password"))
        before = (tmp_path / "admin.enc").read_bytes()
        mismatch = await http.post("/admin/api/connections/test", json={"id": conn["id"]})
        assert mismatch.status_code == 422 and mismatch.json()["error"] == "connector_access_denied"
        assert backend["reads"] and (tmp_path / "admin.enc").read_bytes() == before
        backend["auth"] = True
        assert (await http.post("/admin/api/connections/test", json={"id": conn["id"]})).status_code == 200
        refreshed = await change(http, "web-login/start", **form)
        assert refreshed.status_code == 200, refreshed.text
        backend["cookie_ready"] = False
        failure = await http.post("/admin/api/web-login/save", json={"id": refreshed.json()["id"]})
        assert failure.status_code == 422
        assert (tmp_path / "admin.enc").read_bytes() == before
        assert (await http.post("/admin/api/auth/logout", json={})).status_code == 200
        assert not list(socket_dir.glob("*.proxy"))


async def test_proxy_refuses_other_hosts_and_ports(socket_dir, monkeypatch):
    from agent_gateway import browser_tunnel
    attempted = []
    monkeypatch.setattr(browser_tunnel, "_public_socket", lambda address, *_: attempted.append(address))
    async def proxy(rd, wr):
        await connect(rd, wr, ("www.amazon.com",))
    path = socket_dir / "proxy.sock"
    async with await asyncio.start_unix_server(proxy, path):
        for opening in (b"CONNECT www.amazon.com.evil.test:443 HTTP/1.1", b"CONNECT 127.0.0.1:443 HTTP/1.1",
                        b"CONNECT www.amazon.com:8080 HTTP/1.1", b"GET https://www.amazon.com HTTP/1.1"):
            rd, wr = await asyncio.open_unix_connection(path)
            wr.write(opening + b"\r\n\r\n")
            assert (await rd.read()).startswith(b"HTTP/1.1 403")
            wr.close()
            await wr.wait_closed()
    assert attempted == []


@pytest.mark.browser
async def test_mobile_website_enrollment_without_file(tmp_path, socket_dir, monkeypatch):
    from test_admin_feedback_browser import admin_page, playwright

    monkeypatch.setenv("AGW_BROWSER_SOCKET", str(socket_dir / "control.sock"))
    # Real JPEG from the UI browser. The upstream worker is replaced by a
    # deterministic simulated site.
    async with playwright.async_playwright() as driver:
        browser = await driver.chromium.launch()
        page = await browser.new_page(viewport={"width": 420, "height": 620})
        await page.set_content('<main style="background:yellow;height:100vh">Simulated sign-in website</main>')
        jpeg = base64.b64encode(await page.screenshot(type="jpeg")).decode()
        await browser.close()
    backend = fake_browser(monkeypatch, screenshot=jpeg)
    async with admin_page(tmp_path, "zh-CN", mobile=True) as (page, _):
        await page.get_by_role("link", name="连接器", exact=True).click()
        await page.get_by_role("button", name="添加连接器", exact=True).tap()
        await page.get_by_label("服务", exact=True).select_option("web")
        await page.get_by_label("连接器名称", exact=True).fill("amazon-orders")
        await playwright.expect(page.locator('input[type="file"]')).not_to_be_visible()
        await page.get_by_role("button", name="登录网站", exact=True).tap()
        login_box = page.get_by_role("dialog", name="网站登录", exact=True)
        image = login_box.get_by_role("img", name="可操作的网站登录页")
        await playwright.expect(image).to_be_visible()
        await image.evaluate("node => node.decode()")
        assert await login_box.evaluate("""node => {
            const rect = node.getBoundingClientRect(), image = node.querySelector('img').getBoundingClientRect();
            return rect.left === 0 && rect.width === innerWidth && rect.height >= visualViewport.height - 1
                && image.width === innerWidth;
        }""")
        await login_box.get_by_role("button", name="放大网页").tap()
        await playwright.expect(login_box.locator('.login-zoom')).to_have_text("125%")
        smaller = login_box.get_by_role("button", name="缩小网页")
        for _ in range(3):
            await smaller.tap()
        await playwright.expect(login_box.locator('.login-zoom')).to_have_text("67%")
        assert backend["zoom"] == 67

        scroll_started, release = asyncio.Event(), asyncio.Event()

        async def delay_scroll(route):
            scroll_started.set()
            await release.wait()
            await route.continue_()

        await page.route("**/admin/api/web-login/scroll", delay_scroll)
        await image.scroll_into_view_if_needed()
        await image.evaluate("""image => {
            const {left, top} = image.getBoundingClientRect();
            image.setPointerCapture = () => {};
            const point = {pointerId: 1, pointerType: "touch", button: 0, clientY: top + 60};
            image.dispatchEvent(new PointerEvent("pointerdown", {...point, clientX: left + 120}));
            image.dispatchEvent(new PointerEvent("pointerup", {...point, clientX: left + 40}));
        }""")
        try:
            await asyncio.wait_for(scroll_started.wait(), timeout=5)
            await image.tap(position={"x": 40, "y": 60})
            await login_box.get_by_label("输入到选中的框").fill("demo-only-login")
            await login_box.get_by_role("button", name="输入", exact=True).tap()
        finally:
            release.set()
        await playwright.expect(login_box.get_by_label("输入到选中的框")).to_have_value("")
        await playwright.expect(login_box.get_by_role("button", name="输入", exact=True)).to_be_enabled()
        backend["auth"] = True
        await login_box.get_by_role("button", name="保存会话", exact=True).tap()
        row = page.locator('tr[data-connection="amazon-orders"]')
        await playwright.expect(row).to_contain_text("会话已保存")
        assert not backend["reads"]
        assert backend["swipes"] and backend["swipes"][0][0] > 0 and backend["swipes"][0][1] == 0
        assert backend["inputs"] == ["demo-only-login"] and len(backend["taps"]) == 1
        assert (backend["actions"].index("scroll") < backend["actions"].index("tap")
                < backend["actions"].index("text"))
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        if directory := os.environ.get("AGW_TEST_ARTIFACTS"):
            await page.screenshot(path=str(Path(directory) / "mobile-website-connected.png"))


@pytest.mark.browser
async def test_zoom_reflows_the_browser_and_taps_still_hit_the_page(socket_dir):
    from agent_gateway.browser_worker import Browser
    playwright = pytest.importorskip("playwright.async_api")
    async with playwright.async_playwright() as driver:
        chromium = await driver.chromium.launch()
        try:
            view = Browser(socket_dir / "control.sock")
            view.context = await chromium.new_context(viewport={"width": 420, "height": 620})
            view.navigation, view.zoom = ("signin.example",), None
            page = await view.context.new_page()
            await page.route("https://signin.example/**", lambda route: route.fulfill(
                content_type="text/html",
                body='<button style="width:100px">Continue</button><p>Before</p><input type="email">'))
            await page.goto("https://signin.example/")
            await page.get_by_role("button").evaluate(
                "node => node.onclick = () => document.querySelector('p').textContent = 'Clicked'")
            result = await view.use("zoom", {"percent": 150})
            assert result["zoom"] == 150
            rect = await page.get_by_role("button").bounding_box()
            assert rect["width"] == 150
            await view.use("tap", {"x": rect["x"] + 140, "y": rect["y"] + rect["height"] / 2})
            await playwright.expect(page.locator("p")).to_have_text("Clicked")
            # A subsequent navigation (for example password to verification code)
            # maintains zoom in the new page without rewriting the click mapping.
            await page.goto("https://signin.example/next")
            await view.use("frame", {})
            assert (await page.get_by_role("button").bounding_box())["width"] == 150
            result = await view.use("zoom", {"percent": 67})
            assert result["zoom"] == 67
            assert (await page.get_by_role("button").bounding_box())["width"] == 67
            email = page.get_by_role("textbox")
            rect = await email.bounding_box()
            await view.use("tap", {"x": int(rect["x"] + 4), "y": int(rect["y"] + rect["height"] / 2)})
            await view.use("text", {"text": "simulated@example.test"})
            await playwright.expect(email).to_be_focused()
            await playwright.expect(email).to_have_value("simulated@example.test")
        finally:
            await chromium.close()
