"""One transient browser, controlled over a private Unix socket; no access to Gateway state."""
import asyncio
import base64
import os
import re
import sys
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from .browser_tunnel import tunnel

WIDTH, HEIGHT = 420, 620
KEYS = {"Enter", "Tab", "Backspace", "Escape"}
ZOOM_LEVELS = (50, 67, 80, 100, 125, 150, 200)
FLOW = re.compile(r"[0-9a-f]{24}")


class NoFocusedInput(Exception):
    pass


async def has_focused_input(page):
    # Follow the active element into a frame or shadow root, without reading
    # any text, names or values from the form.
    frame = page.main_frame
    while frame is not None:
        focus = await frame.evaluate_handle("""() => {
            let node = document.activeElement;
            while (node?.shadowRoot?.activeElement) node = node.shadowRoot.activeElement;
            return node;
        }""")
        try:
            if await focus.evaluate("""node => !!node && !node.matches(':disabled, [readonly]') &&
                (node.isContentEditable || node.tagName === 'TEXTAREA' ||
                 node.tagName === 'INPUT' && ['text', 'password', 'email', 'tel', 'url', 'search', 'number'].includes(node.type))
            """):
                return True
            element = focus.as_element()
            frame = await element.content_frame() if element else None
        finally:
            await focus.dispose()
    return False


class Browser:
    def __init__(self, path):
        self.path = path
        self.id = None
        self.lock = asyncio.Lock()
        self.relays = set()
        self.browser = self.relay = self.context = None

    async def close(self):
        self.id = None
        if self.relay:
            self.relay.close()
            self.relay = None
        for task in self.relays.copy():
            task.cancel()
        if self.browser:
            browser, self.browser = self.browser, None
            self.context = None
            with suppress(Exception):
                await browser.close()

    async def new_context(self, driver):
        # Request the site's phone layout while keeping screenshot and input coordinates
        # aligned, including on pages without an HTML viewport tag.
        return await self.browser.new_context(
            viewport={"width": WIDTH, "height": HEIGHT},
            user_agent=driver.devices["Pixel 7"]["user_agent"], has_touch=True,
            accept_downloads=False, service_workers="block")

    async def start(self, driver, body):
        self.id, self.expires = body["id"], body["expires"]
        self.zoom = None
        proxy = self.path.parent / f'{self.id}.proxy'

        async def relay(reader, writer):
            task = asyncio.current_task()
            self.relays.add(task)
            peer = None
            try:
                if len(self.relays) <= 48:
                    peer = await asyncio.open_unix_connection(proxy)
                    await tunnel((reader, writer), peer)
            except OSError:
                pass
            finally:
                if peer:
                    peer[1].close()
                writer.close()
                self.relays.discard(task)

        self.relay = await asyncio.start_server(relay, "127.0.0.1", 0)
        port = self.relay.sockets[0].getsockname()[1]
        self.browser = await driver.chromium.launch(
            executable_path=os.environ.get("AGW_CHROMIUM") or None, timeout=12000,
            proxy={"server": f"http://127.0.0.1:{port}", "bypass": "<-loopback>"},
            args=["--disable-quic", "--disable-sync", "--disable-background-networking",
                  "--disable-extensions", "--disable-crash-reporter", "--disable-breakpad",
                  "--disk-cache-size=1048576"])
        self.context = await self.new_context(driver)

        async def guard(route):
            request = route.request
            if request.is_navigation_request() and urlsplit(request.url).scheme != "https":
                await route.abort("accessdenied")
            else:
                await route.continue_()

        await self.context.route("**/*", guard)
        page = await self.context.new_page()
        # Kick off navigation without waiting for every third-party resource.
        with suppress(Exception):
            await page.goto(body["url"], wait_until="commit", timeout=6500)

    async def use(self, op, body):
        if op == "close":
            await self.close()
            return {}
        if op == "cookies":
            hosts = [urlsplit(origin).hostname for origin in (body["origin"], *body.get("api_origins", []))]
            cookies = [cookie for cookie in await self.context.cookies() if any(
                       cookie["domain"] == host or (cookie["domain"].startswith(".")
                                                    and (host == cookie["domain"][1:] or host.endswith(cookie["domain"])))
                       for host in hosts)]
            return {"cookies": cookies}
        page = self.context.pages[-1] if self.context.pages else None
        if page is None:
            raise RuntimeError("browser closed")
        current = urlsplit(page.url)
        if op in {"tap", "text", "key", "scroll"} and current.scheme != "https":
            raise ValueError("sign-in destination not allowed")
        if op == "tap":
            await page.touchscreen.tap(body["x"], body["y"])
        elif op == "text":
            if not await has_focused_input(page):
                raise NoFocusedInput
            await page.keyboard.insert_text(body["text"])
        elif op == "key":
            await page.keyboard.press(body["key"])
        elif op == "scroll":
            await page.mouse.move(body["x"], body["y"])
            await page.mouse.wheel(body["dx"], body["dy"])
        elif op == "zoom":
            self.zoom = body["percent"]
        elif op == "reload":
            with suppress(Exception):
                await page.reload(wait_until="commit", timeout=6500)
        elif op != "frame":
            raise ValueError("invalid action")
        return await self.frame()

    async def frame(self):
        from playwright.async_api import Error

        for attempt in range(3):
            page = self.context.pages[-1]
            url = page.url
            parts = urlsplit(url)
            try:
                if self.zoom is not None and parts.scheme == "https":
                    # Keep zoom and click coordinates aligned across navigation.
                    await page.evaluate("""factor => {
                        const style = document.documentElement?.style;
                        if (!style) return;
                        if (factor === 1) style.removeProperty('zoom');
                        else if (style.zoom !== String(factor)) style.zoom = factor;
                    }""", self.zoom / 100)
                picture = await page.screenshot(type="jpeg", quality=75, timeout=5000)
                editable = parts.scheme == "https" and await has_focused_input(page)
                if self.context.pages[-1:] == [page] and page.url == url:
                    return {"image": base64.b64encode(picture).decode("ascii"),
                            "host": parts.hostname if parts.scheme == "https" else None,
                            "zoom": self.zoom or 100, "editable": editable}
            except Error:
                if attempt == 2:
                    raise
            # A click can destroy the previous page's script context. Retry
            # the snapshot after navigation; do not replay the input.
            await asyncio.sleep(.15)
        raise RuntimeError("browser page changed before capture")


def make_app(path):
    browser = Browser(path)

    @asynccontextmanager
    async def lifespan(app):
        from playwright.async_api import async_playwright
        async with async_playwright() as driver, asyncio.TaskGroup() as group:
            app.state.driver = driver
            async def expire():
                while True:
                    await asyncio.sleep(5)
                    async with browser.lock:
                        if browser.id and browser.expires <= time.time():
                            await browser.close()
            cleanup = group.create_task(expire())
            try:
                yield
            finally:
                cleanup.cancel()
                await browser.close()

    async def api(request):
        op = request.path_params["op"]
        if op == "health":
            return JSONResponse({"ok": True})
        try:
            body = await request.json()
            ident = body["id"]
            if not isinstance(ident, str) or not FLOW.fullmatch(ident):
                return JSONResponse({}, 400)
            async with browser.lock:
                if browser.id and browser.expires <= time.time():
                    await browser.close()
                if op == "start":
                    if browser.id:
                        return JSONResponse({}, 409)
                    try:
                        async with asyncio.timeout(21):
                            await browser.start(request.app.state.driver, body)
                    except BaseException:
                        await browser.close()
                        raise
                    return JSONResponse({"width": WIDTH, "height": HEIGHT})
                if browser.id != ident:
                    return JSONResponse({}, 410)
                async with asyncio.timeout(9):
                    return JSONResponse(await browser.use(op, body))
        except NoFocusedInput:
            return JSONResponse({"error": "web_browser_select_field"}, 422)
        except Exception:
            # Exceptions may contain a page URL or typed text.
            return JSONResponse({}, 422)

    return Starlette(routes=[Route("/{op}", api, methods=["POST"])], lifespan=lifespan)


if __name__ == "__main__":
    import uvicorn

    path = Path(sys.argv[1])
    path.unlink(missing_ok=True)
    os.umask(0o077)
    uvicorn.run(make_app(path), uds=str(path), access_log=False, log_level="warning", server_header=False)
