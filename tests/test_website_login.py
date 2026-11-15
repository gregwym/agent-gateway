"""A Passkey-bound website login saves only credentials proven by the HTTP connector."""
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
PAGE = b'<main id="ordersContainer"><p>Simulated order</p></main>'


@pytest.fixture
def socket_dir():
    # macOS Unix sockets have a short path limit.
    with TemporaryDirectory(prefix="agwb-", dir="/tmp") as directory:
        yield Path(directory)


def fake_browser(monkeypatch, *, screenshot=None):
    backend = {"auth": False, "actions": [], "inputs": [], "swipes": []}

    def fetch(host, target, headers, receive):
        if headers.get("Cookie") != "auth=" + SECRET or not backend["auth"]:
            return response(receive, status=302, location="/ap/signin")
        assert host == "www.amazon.com" and target == "/your-orders/orders"
        return response(receive, PAGE)

    async def worker(self, action, data):
        backend["actions"].append(action)
        if action == "text":
            backend["inputs"].append(data["text"])
        if action == "scroll":
            backend["swipes"].append((data["dx"], data["dy"]))
        if action == "cookies":
            assert data["origin"] == "https://www.amazon.com"
            return {"cookies": [{"name": "auth", "domain": ".amazon.com", "value": SECRET},
                                {"name": "auth", "domain": "evil.test", "value": "unrelated-password"}]}
        return {"image": screenshot, "host": "www.amazon.com"}

    monkeypatch.setattr(web, "_fetch", fetch)
    monkeypatch.setattr(WebsiteLogin, "worker", worker)
    monkeypatch.setattr(WebsiteLogin, "available", lambda _self: True)
    return backend


async def test_verified_website_login_is_private_and_atomic(tmp_path, socket_dir, monkeypatch):
    monkeypatch.setenv("AGW_BROWSER_SOCKET", str(socket_dir / "control.sock"))
    backend = fake_browser(monkeypatch)
    async with web_gateway(tmp_path) as (gw, http, origin, config):
        key, _ = await setup(http, origin, config)
        form = {"id": "amazon-orders", "owner": "person_a", "plugin": "amazon-us"}
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
        failure = await http.post("/admin/api/web-login/save", json=ref)
        assert failure.status_code == 422 and failure.json()["error"] == "web_browser_sign_in_required", failure.text
        assert not any(c["id"] == form["id"] for c in (await state(http))["connections"])
        backend["auth"] = True
        saved = await http.post("/admin/api/web-login/save", json=ref)
        assert saved.status_code == 200, saved.text
        assert backend["actions"][-1] == "close"
        assert (await http.post("/admin/api/web-login/frame", json=ref)).json()["error"] == "web_browser_expired"
        settings = await state(http)
        conn = next(c for c in settings["connections"] if c["id"] == form["id"])
        assert conn["test"]["ok"] and conn["access"]["agent-a"] == "none"
        assert len(conn["tools"]) == 2 and all(t["access"] == "read" for t in conn["tools"])
        assert SECRET.encode() not in (tmp_path / "admin.enc").read_bytes()
        assert all(s not in str(settings) + gw.audit_text() for s in (SECRET, typed, "unrelated-password"))
        refreshed = await change(http, "web-login/start", **form)
        assert refreshed.status_code == 200, refreshed.text
        backend["auth"] = False
        before = (tmp_path / "admin.enc").read_bytes()
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
    # deterministic simulated site and server-side order probe.
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
        await image.scroll_into_view_if_needed()
        await image.evaluate("""image => {
            const {left, top} = image.getBoundingClientRect();
            image.setPointerCapture = () => {};
            const point = {pointerId: 1, pointerType: "touch", button: 0, clientY: top + 60};
            image.dispatchEvent(new PointerEvent("pointerdown", {...point, clientX: left + 120}));
            image.dispatchEvent(new PointerEvent("pointerup", {...point, clientX: left + 40}));
        }""")
        await page.wait_for_function(
            """() => !document.querySelector('.login-keyboard button').disabled""")
        assert backend["swipes"] and backend["swipes"][0][0] > 0 and backend["swipes"][0][1] == 0
        await image.tap(position={"x": 40, "y": 60})
        await login_box.get_by_label("输入到选中的框").fill("demo-only-login")
        await login_box.get_by_role("button", name="输入", exact=True).tap()
        await playwright.expect(login_box.get_by_label("输入到选中的框")).to_have_value("")
        backend["auth"] = True
        await login_box.get_by_role("button", name="保存连接", exact=True).tap()
        row = page.locator('tr[data-connection="amazon-orders"]')
        await playwright.expect(row).to_be_visible()
        assert backend["inputs"] == ["demo-only-login"] and "tap" in backend["actions"]
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        if directory := os.environ.get("AGW_TEST_ARTIFACTS"):
            await page.screenshot(path=str(Path(directory) / "mobile-website-connected.png"))
