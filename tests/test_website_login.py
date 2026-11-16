"""A Passkey-bound website login saves the session without contacting the site."""
import asyncio
import base64
import os
import socket
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx2
import pytest

from agent_gateway.admin_web_login import WebsiteLogin
from agent_gateway.browser_tunnel import connect
from agent_gateway.connectors import web
from agent_gateway.passkey import Refused
from test_admin import admin_post, change, login, setup, state, web_gateway
from test_web_connector import response

pytestmark = pytest.mark.anyio
SECRET = "private-session-from-browser"



@pytest.fixture
def socket_dir():
    # macOS Unix sockets have a short path limit.
    with TemporaryDirectory(prefix="agwb-", dir="/tmp") as directory:
        yield Path(directory)


def fake_browser(monkeypatch, *, screenshot=None, site="www.amazon.com"):
    backend = {"auth": False, "actions": [], "inputs": [], "taps": [], "swipes": [], "zoom": 100, "cookie_ready": True, "reads": [], "active": None}

    def fetch(host, target, method, headers, body, receive):
        assert host == site and method == "HEAD" and target == "/" and body is None
        backend["reads"].append(target)
        assert headers.get("Cookie") == "auth=" + SECRET
        return response(receive, status=200 if backend["auth"] else 403)

    async def worker(self, action, data):
        backend["actions"].append(action)
        if action == "active":
            return {"id": backend["active"]}
        if action == "text":
            backend["inputs"].append(data["text"])
        if action == "tap":
            backend["taps"].append((data["x"], data["y"]))
        if action == "scroll":
            backend["swipes"].append((data["dx"], data["dy"]))
        if action == "zoom":
            backend["zoom"] = data["percent"]
        if action == "start":
            if backend["active"]:
                raise Refused("web_browser_in_use", 409)
            backend["active"] = data["id"]
            assert data["url"] == "https://" + site + "/"
            backend["display"] = {key: data[key] for key in ("user_agent", "viewport", "touch")}
        if action == "close":
            if data["id"] != backend["active"]:
                raise Refused("web_browser_expired", 409)
            backend["active"] = None
        if action == "cookies":
            assert data["origin"] == "https://" + site
            if not backend["cookie_ready"]:
                return {"cookies": []}
            return {"cookies": [{"name": "auth", "domain": site, "value": SECRET},
                                {"name": "auth", "domain": "evil.test", "value": "unrelated-password"}]}
        return {"image": screenshot, "host": "www.amazon.com", "zoom": backend["zoom"],
                "editable": bool(backend["taps"])}

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


async def test_force_close_requires_passkey_and_cannot_close_a_replacement(tmp_path, socket_dir, monkeypatch):
    monkeypatch.setenv("AGW_BROWSER_SOCKET", str(socket_dir / "control.sock"))
    backend = fake_browser(monkeypatch)
    async with web_gateway(tmp_path) as (gw, http, origin, config):
        key, _ = await setup(http, origin, config)
        form = {"id": "shop-orders", "owner": "person_a", "plugin": "amazon-us"}
        first = (await change(http, "web-login/start", **form)).json()
        async with httpx2.AsyncClient(base_url=origin, headers={"Origin": origin}, trust_env=False) as other:
            assert (await other.post("/admin/api/web-login/active", json={})).status_code == 401
            assert (await other.post("/admin/api/web-login/terminate", json={})).status_code == 401
            await login(other, key, origin)
            target = (await other.post("/admin/api/web-login/active", json={})).json()["target"]
            assert target and target != first["id"]
            assert (await other.post("/admin/api/web-login/frame", json={"id": first["id"]})).status_code == 409
            blocked = await other.post("/admin/api/web-login/terminate", json={"target": target})
            assert blocked.status_code == 403 and blocked.json()["error"] == "admin_confirmation_required"
            assert backend["active"] == first["id"]

            await http.post("/admin/api/web-login/cancel", json={"id": first["id"]})
            replacement = (await change(http, "web-login/start", **form)).json()
            challenge = blocked.json()["confirmation"]
            confirmation = {"ceremony_id": challenge["ceremony_id"], "response": key.response(challenge, origin=origin)}
            stale = await other.post("/admin/api/web-login/terminate", json={"target": target, "confirmation": confirmation})
            assert stale.status_code == 409 and stale.json()["error"] == "web_browser_changed"
            assert backend["active"] == replacement["id"]

            current = (await other.post("/admin/api/web-login/active", json={})).json()
            closed = await admin_post(other, "web-login/terminate", json=current)
            assert closed.status_code == 200 and backend["active"] is None
            assert (await http.post("/admin/api/web-login/frame", json={"id": replacement["id"]})).status_code == 409
            assert not list(socket_dir.glob("*.proxy"))
            assert not backend["reads"] and "cookies" not in backend["actions"]
            assert not any(c["id"] == form["id"] for c in (await state(http))["connections"])


async def test_browser_worker_reports_active_id_and_closes_only_that_window(socket_dir, monkeypatch):
    from agent_gateway.browser_worker import Browser, make_app

    async def start(self, _driver, body):
        self.id, self.expires = body["id"], body["expires"]

    monkeypatch.setattr(Browser, "start", start)
    app = make_app(socket_dir / "control.sock")
    app.state.driver = None
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://browser") as client:
        window = "a" * 24
        assert (await client.post("/active", json={})).json() == {"id": None}
        started = await client.post("/start", json={"id": window, "expires": time.time() + 60, "viewport": {}})
        assert started.status_code == 200
        assert (await client.post("/active", json={})).json() == {"id": window}
        assert (await client.post("/close", json={"id": "b" * 24})).status_code == 410
        assert (await client.post("/active", json={})).json() == {"id": window}
        assert (await client.post("/close", json={"id": window})).status_code == 200
        assert (await client.post("/active", json={})).json() == {"id": None}


async def test_proxy_tunnels_public_https_but_rejects_private_addresses(socket_dir, monkeypatch):
    from agent_gateway import browser_tunnel
    resolved = []
    connect_socket, upstream = socket.socketpair()
    resolve = socket.getaddrinfo

    def dns(host, port, *args, **kwargs):
        resolved.append((host, port))
        IPs = {"router.example": ("192.168.2.7",),
               "mixed.example": ("1.1.1.1", "100.64.1.2")}.get(host, (host,))
        return [record for ip in IPs for record in resolve(ip, port, *args, **kwargs)]

    def dial(address, *args):
        if address == ("auth.idp.example", 443):
            return connect_socket
        return web._public_socket(address, *args)

    monkeypatch.setattr(socket, "getaddrinfo", dns)
    monkeypatch.setattr(browser_tunnel, "_public_socket", dial)
    path = socket_dir / "proxy.sock"
    with connect_socket, upstream:
        async with await asyncio.start_unix_server(connect, path):
            reader, writer = await asyncio.open_unix_connection(path)
            writer.write(b"CONNECT auth.idp.example:443 HTTP/1.1\r\n\r\n")
            assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
            upstream.sendall(b"simulated-https-reply")
            assert await reader.readexactly(21) == b"simulated-https-reply"
            writer.close()
            await writer.wait_closed()

            for opening in (b"CONNECT router.example:443 HTTP/1.1", b"CONNECT mixed.example:443 HTTP/1.1",
                            b"CONNECT 127.0.0.1:443 HTTP/1.1", b"CONNECT auth.idp.example:8080 HTTP/1.1",
                            b"GET http://auth.idp.example/ HTTP/1.1"):
                reader, writer = await asyncio.open_unix_connection(path)
                writer.write(opening + b"\r\n\r\n")
                assert (await reader.read()).startswith(b"HTTP/1.1 403")
                writer.close()
                await writer.wait_closed()
    assert resolved == [("router.example", 443), ("mixed.example", 443), ("127.0.0.1", 443)]


@pytest.mark.browser
async def test_mobile_website_enrollment_without_file(tmp_path, socket_dir, monkeypatch):
    from test_admin_feedback_browser import admin_page, playwright

    monkeypatch.setenv("AGW_BROWSER_SOCKET", str(socket_dir / "control.sock"))
    # Real JPEG from the UI browser. The upstream worker is replaced by a
    # deterministic simulated site.
    async with playwright.async_playwright() as driver:
        browser = await driver.chromium.launch()
        page = await browser.new_page(viewport=driver.devices["iPhone 15"]["viewport"])
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
        backend["active"] = "a" * 24  # A worker survived a Gateway restart.
        await page.get_by_role("button", name="登录网站", exact=True).tap()
        conflict = page.get_by_role("dialog", name="已有网站登录窗口", exact=True)
        await conflict.get_by_role("button", name="强制终止", exact=True).tap()
        await playwright.expect(conflict).not_to_be_visible()
        assert backend["active"] is None
        await page.get_by_role("button", name="登录网站", exact=True).tap()
        login_box = page.get_by_role("dialog", name="网站登录", exact=True)
        image = login_box.get_by_role("img", name="可操作的网站登录页")
        await playwright.expect(image).to_be_visible()
        await image.evaluate("node => node.decode()")
        assert backend["display"] == await page.evaluate("""() => ({
            user_agent: navigator.userAgent, viewport: {width: innerWidth, height: innerHeight},
            touch: navigator.maxTouchPoints > 0
        })""")
        assert await login_box.evaluate("""node => {
            const rect = node.getBoundingClientRect(), image = node.querySelector('img').getBoundingClientRect();
            const viewer = node.querySelector('.login-view').getBoundingClientRect();
            return rect.left === 0 && rect.width === innerWidth && rect.height >= visualViewport.height - 1
                && image.width <= viewer.width && image.bottom <= viewer.bottom + 1;
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
        await playwright.expect(login_box.get_by_label("输入到选中的框")).to_have_attribute("placeholder", "已选中网页输入框，在此输入")
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
async def test_zoom_reflows_the_browser_and_taps_still_hit_the_page(socket_dir, monkeypatch):
    from agent_gateway.browser_worker import Browser, NoFocusedInput, WIDTH
    playwright = pytest.importorskip("playwright.async_api")
    async with playwright.async_playwright() as driver:
        chromium = await driver.chromium.launch()
        try:
            view = Browser(socket_dir / "control.sock")
            view.browser = chromium
            viewport = {"width": WIDTH, "height": 750}
            ua = "TestBrowser/1.2 Mobile"
            view.context = await view.new_context(viewport, True, ua)
            view.zoom = None
            page = await view.context.new_page()
            await page.route("https://*.example/**", lambda route: route.fulfill(
                content_type="text/html",
                body=('<button style="width:100px">Continue</button><p>Before</p><input type="email">'
                      if route.request.headers.get("user-agent") == ua else "<p>Other UA</p>")))
            await page.goto("https://signin.example/")
            assert await page.evaluate("() => [innerWidth, innerHeight, navigator.maxTouchPoints > 0, navigator.userAgent]") == [
                WIDTH, viewport["height"], True, ua]

            await page.get_by_role("button").evaluate(
                "node => node.onclick = () => document.querySelector('p').textContent = 'Clicked'")
            result = await view.use("zoom", {"percent": 150})
            assert result["zoom"] == 150
            rect = await page.get_by_role("button").bounding_box()
            assert rect["width"] == 150
            await view.use("tap", {"x": rect["x"] + 140, "y": rect["y"] + rect["height"] / 2})
            await playwright.expect(page.locator("p")).to_have_text("Clicked")
            # Simulate the document being replaced during the snapshot taken
            # after a tap that navigates to a separate identity provider.
            await page.get_by_role("button").evaluate(
                "node => node.onclick = () => location.href = 'https://identity.example/next'")
            evaluate = page.evaluate

            async def context_destroyed(*args, **kwargs):
                monkeypatch.setattr(page, "evaluate", evaluate)
                await page.wait_for_url("https://identity.example/next")
                raise playwright.Error("Execution context was destroyed, most likely because of a navigation")

            monkeypatch.setattr(page, "evaluate", context_destroyed)
            result = await view.use("tap", {"x": int(rect["x"] + 40), "y": int(rect["y"] + rect["height"] / 2)})
            assert result["host"] == "identity.example"
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

            # A site can enable its password field on touch. Mouse input
            # leaves it read-only. Also exercise a separate sign-in frame.
            await page.route("https://credentials.example/password", lambda route: route.fulfill(
                content_type="text/html",
                body='<input aria-label="Password" type="password" readonly '
                     'ontouchstart="this.readOnly=false; this.focus()">'))
            await page.evaluate("""() => {
                const frame = document.createElement('iframe');
                frame.src = 'https://credentials.example/password';
                document.body.replaceChildren(frame);
            }""")
            password = page.frame_locator("iframe").get_by_label("Password")
            bounds = await password.bounding_box()
            x, y = int(bounds["x"] + 5), int(bounds["y"] + bounds["height"] / 2)
            await page.mouse.click(x, y)
            with pytest.raises(NoFocusedInput):
                await view.use("text", {"text": "simulated-secret"})
            selected = await view.use("tap", {"x": x, "y": y})
            assert selected["editable"] is True
            await view.use("text", {"text": "simulated-secret"})
            await playwright.expect(password).to_have_value("simulated-secret")

            await view.context.add_cookies([
                {"name": "account", "value": "keep", "url": "https://signin.example"},
                {"name": "api", "value": "keep", "url": "https://api.signin.example"},
                {"name": "identity", "value": "discard", "url": "https://identity.example"},
            ])
            exported = await view.use("cookies", {"origin": "https://signin.example",
                                                    "api_origins": ["https://api.signin.example"]})
            assert {cookie["name"] for cookie in exported["cookies"]} == {"account", "api"}

            desktop_ua = "TestDesktop/2.0"
            view.zoom = None
            view.context = await view.new_context({"width": 1280, "height": 870}, False, desktop_ua)
            desktop = await view.context.new_page()
            await desktop.route("https://signin.example/", lambda route: route.fulfill(
                content_type="text/html",
                body='<input type="password">' if route.request.headers.get("user-agent") == desktop_ua else "<p>Other UA</p>"))
            await desktop.goto("https://signin.example/")
            assert await desktop.evaluate("() => [innerWidth, navigator.maxTouchPoints, navigator.userAgent]") == [
                1280, 0, desktop_ua]
            bounds = await desktop.locator("input").bounding_box()
            assert (await view.use("tap", {"x": int(bounds["x"] + 5), "y": int(bounds["y"] + 5)}))["editable"]
        finally:
            await chromium.close()
