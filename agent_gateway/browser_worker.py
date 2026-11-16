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

from .browser_tunnel import host_allowed, tunnel

WIDTH, HEIGHT = 420, 620
KEYS = {"Enter", "Tab", "Backspace", "Escape"}
ZOOM_LEVELS = (50, 67, 80, 100, 125, 150, 200)
FLOW = re.compile(r"[0-9a-f]{24}")


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

    async def start(self, driver, body):
        self.id, self.expires = body["id"], body["expires"]
        self.zoom = None
        proxy = self.path.parent / f'{self.id}.proxy'
        allowed = self.navigation = body["navigation"]

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
        self.context = await self.browser.new_context(viewport={"width": WIDTH, "height": HEIGHT},
                                                      accept_downloads=False, service_workers="block")

        async def guard(route):
            request = route.request
            parts = urlsplit(request.url)
            if request.is_navigation_request() and (
                    parts.scheme != "https" or not host_allowed(parts.hostname or "", allowed)):
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
                                                    and host_allowed(host, (cookie["domain"][1:],))) for host in hosts)]
            return {"cookies": cookies}
        page = self.context.pages[-1] if self.context.pages else None
        if page is None:
            raise RuntimeError("browser closed")
        current = urlsplit(page.url)
        if op in {"tap", "text", "key", "scroll"} and (
                current.scheme != "https" or not host_allowed(current.hostname or "", self.navigation)):
            raise ValueError("sign-in destination not allowed")
        if op == "tap":
            await page.mouse.click(body["x"], body["y"])
        elif op == "text":
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
        parts = urlsplit(page.url)
        if self.zoom is not None and parts.scheme == "https" and host_allowed(parts.hostname or "", self.navigation):
            # Apply to the actual page so clickable coordinates stay in the same
            # viewport, and retain the scale when a sign-in step navigates.
            await page.evaluate("""factor => {
                const style = document.documentElement?.style;
                if (!style) return;
                if (factor === 1) style.removeProperty('zoom');
                else if (style.zoom !== String(factor)) style.zoom = factor;
            }""", self.zoom / 100)
        picture = await page.screenshot(type="jpeg", quality=75, timeout=5000)
        return {"image": base64.b64encode(picture).decode("ascii"),
                "host": parts.hostname if parts.scheme == "https" else None, "zoom": self.zoom or 100}


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
