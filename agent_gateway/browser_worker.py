"""One transient browser, controlled over a private Unix socket; no access to Gateway state."""
import asyncio
import base64
import os
import re
import sys
import time
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from weakref import WeakKeyDictionary

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


PASSWORD_FOCUS_ERRORS = {
    "web_browser_password_missing", "web_browser_password_multiple", "web_browser_password_unavailable",
}


class PasswordFocusError(Exception):
    pass


ACTION_ERRORS = {
    "web_browser_closed", "web_browser_still_loading", "web_browser_action_uncertain",
    "web_browser_capture_failed", "web_browser_navigation_failed", "web_browser_navigation_blocked",
    "web_browser_navigation_timeout", "web_browser_no_submit", "web_browser_multiple_submit",
}


class BrowserActionError(Exception):
    pass


@dataclass
class Navigation:
    request: object = None
    started: float = 0
    failure: str | None = None
    status: int | None = None


def is_web_frame(frame):
    return urlsplit(frame.url).scheme == "https" or frame.url in {"about:blank", "about:srcdoc"}


async def focused_input(page, *, kind_only=True):
    # Follow the active element into a frame or shadow root, without reading
    # any text, names or values from the form.
    frame = page.main_frame
    while frame is not None and is_web_frame(frame):
        focus = await frame.evaluate_handle("""() => {
            let node = document.activeElement;
            while (node?.shadowRoot?.activeElement) node = node.shadowRoot.activeElement;
            return node;
        }""")
        try:
            kind = await focus.evaluate("""node => {
                if (!node || node.matches(':disabled, [readonly]') ||
                    !node.checkVisibility({opacityProperty: true, visibilityProperty: true})) return null;
                if (node.tagName === 'INPUT' && node.type === 'password') return 'password';
                if (node.isContentEditable || node.tagName === 'TEXTAREA' ||
                    node.tagName === 'INPUT' && ['text', 'email', 'tel', 'url', 'search', 'number'].includes(node.type))
                    return 'text';
                return null;
            }
            """)
            element = focus.as_element()
            if kind:
                if not kind_only:
                    focus = None
                    return element
                return kind
            frame = await element.content_frame() if element else None
        finally:
            if focus:
                await focus.dispose()
    return None


async def focus_password(page):
    from playwright.async_api import Error

    # The rendered page decides where the password lives. If several fields
    # are visible (such as a change-password form), do not choose one for the user.
    handles = []
    try:
        for frame in page.frames:
            if is_web_frame(frame):
                handles.extend(await frame.locator('input[type="password"]:visible').element_handles())
        # Playwright's :visible also matches fully transparent inputs.
        fields = [field for field in handles if await field.evaluate(
            "node => node.checkVisibility({opacityProperty: true})")]
        if not fields:
            raise PasswordFocusError("web_browser_password_missing")
        if len(fields) != 1:
            raise PasswordFocusError("web_browser_password_multiple")
        field = fields[0]
        await field.focus()
        if (not await field.evaluate("node => node.getRootNode().activeElement === node")
                or await focused_input(page) != "password"):
            raise PasswordFocusError("web_browser_password_unavailable")
    except Error:
        raise PasswordFocusError("web_browser_password_unavailable") from None
    finally:
        for field in handles:
            with suppress(Error):
                await field.dispose()


async def submit_form(page):
    field = await focused_input(page, kind_only=False)
    if not field:
        raise BrowserActionError("web_browser_no_submit")
    try:
        controls = await field.evaluate_handle("""node => Array.from(node.form?.elements || []).filter(el =>
            (el.tagName === 'BUTTON' || el.tagName === 'INPUT') && el.type === 'submit' &&
            !el.matches(':disabled') && el.checkVisibility({opacityProperty: true, visibilityProperty: true}))""")
        try:
            count = await controls.evaluate("items => items.length")
            if count != 1:
                raise BrowserActionError("web_browser_multiple_submit" if count else "web_browser_no_submit")
            control = await controls.evaluate_handle("items => items[0]")
            try:
                # Use native click and form validation, including site click handlers.
                await control.as_element().click(timeout=3000, no_wait_after=True)
            finally:
                await control.dispose()
        finally:
            await controls.dispose()
    finally:
        await field.dispose()


class Browser:
    def __init__(self, path):
        self.path = path
        self.id = None
        self.lock = asyncio.Lock()
        self.relays = set()
        self.browser = self.relay = self.context = None
        self.navigation = WeakKeyDictionary()

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

    async def new_context(self, viewport, touch, user_agent):
        self.touch = touch
        # Use the admin browser's CSS viewport and UA while keeping the
        # screenshot at CSS pixel scale for input mapping.
        context = await self.browser.new_context(
            viewport=viewport, user_agent=user_agent, has_touch=touch,
            accept_downloads=False, service_workers="block")
        context.on("page", self.watch_page)
        return context

    def watch_page(self, page):
        from playwright.async_api import Error

        nav = self.navigation[page] = Navigation()

        def started(request):
            with suppress(Error):
                if request.is_navigation_request() and request.frame == page.main_frame:
                    nav.request, nav.started = request, time.monotonic()
                    nav.failure = nav.status = None

        def response(reply):
            if reply.request == nav.request:
                nav.status = reply.status

        def finished(request, failed=False):
            if request != nav.request:
                return
            nav.request = None
            if failed:
                reason = request.failure
                if reason == "net::ERR_ABORTED":
                    return  # Often a redirect, download, or a superseding navigation.
                nav.failure = {
                    "net::ERR_TIMED_OUT": "web_browser_navigation_timeout",
                    "net::ERR_ACCESS_DENIED": "web_browser_navigation_blocked",
                    "net::ERR_TUNNEL_CONNECTION_FAILED": "web_browser_navigation_blocked",
                }.get(reason, "web_browser_navigation_failed")

        def committed(frame):
            # Some pages keep downloading the document after it is usable.
            if frame == page.main_frame:
                nav.request = None

        page.on("request", started)
        page.on("response", response)
        page.on("requestfinished", finished)
        page.on("requestfailed", lambda request: finished(request, True))
        page.on("framenavigated", committed)

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
        self.context = await self.new_context(body["viewport"], body["touch"], body["user_agent"])

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
        from playwright.async_api import Error

        try:
            return await self._use(op, body)
        except Error:
            # An event might already have been delivered. Do not retry it.
            raise BrowserActionError("web_browser_action_uncertain") from None

    async def _use(self, op, body):
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
            raise BrowserActionError("web_browser_closed")
        if op == "frame":
            return await self.frame()
        current = urlsplit(page.url)
        nav = self.navigation[page]
        if op in {"tap", "text", "focus-password", "submit-form", "key", "scroll"}:
            if nav.failure:
                raise BrowserActionError(nav.failure)
            if nav.request or current.scheme != "https":
                raise BrowserActionError("web_browser_still_loading")
        if op == "tap":
            if self.touch:
                await page.touchscreen.tap(body["x"], body["y"])
            else:
                await page.mouse.click(body["x"], body["y"])
        elif op == "focus-password":
            await focus_password(page)
        elif op == "submit-form":
            await submit_form(page)
        elif op == "text":
            kind = await focused_input(page)
            if body.get("expect_password") and kind != "password":
                raise PasswordFocusError("web_browser_password_unavailable")
            if not kind:
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
            await page.reload(wait_until="commit", timeout=6500)
        else:
            raise ValueError("invalid action")
        return {"ok": True}

    async def frame(self):
        from playwright.async_api import Error, TimeoutError as BrowserTimeout

        for _ in range(2):
            page = self.context.pages[-1]
            url = page.url
            parts = urlsplit(url)
            nav = self.navigation[page]
            if nav.failure:
                raise BrowserActionError(nav.failure)
            if nav.request or url == "about:blank":
                return {"pending": True, "slow": bool(nav.request and time.monotonic() - nav.started > 10)}
            try:
                async with asyncio.timeout(2.5):
                    if self.zoom is not None and parts.scheme == "https":
                        # Keep zoom and click coordinates aligned across navigation.
                        await page.evaluate("""factor => {
                            const style = document.documentElement?.style;
                            if (!style) return;
                            if (factor === 1) style.removeProperty('zoom');
                            else if (style.zoom !== String(factor)) style.zoom = factor;
                        }""", self.zoom / 100)
                    picture = await page.screenshot(type="jpeg", quality=75, timeout=2000)
                    kind = await focused_input(page) if parts.scheme == "https" else None
                    if self.context.pages[-1:] == [page] and page.url == url and not nav.failure and not nav.request:
                        return {"image": base64.b64encode(picture).decode("ascii"),
                                "host": parts.hostname if parts.scheme == "https" else None,
                                "zoom": self.zoom or 100, "editable": kind is not None, "input_kind": kind,
                                "site_status": nav.status if nav.status and nav.status >= 400 else None}
            except (TimeoutError, BrowserTimeout):
                raise BrowserActionError("web_browser_capture_failed") from None
            except Error:
                pass  # A navigation can destroy the old page's script context.
            await asyncio.sleep(.1)
        raise BrowserActionError("web_browser_capture_failed")


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
            async with browser.lock:
                if browser.id and browser.expires <= time.time():
                    await browser.close()
                if op == "active":
                    return JSONResponse({"id": browser.id}) if body == {} else JSONResponse({}, 400)
                ident = body["id"]
                if not isinstance(ident, str) or not FLOW.fullmatch(ident):
                    return JSONResponse({}, 400)
                if op == "start":
                    if browser.id:
                        return JSONResponse({}, 409)
                    try:
                        async with asyncio.timeout(21):
                            await browser.start(request.app.state.driver, body)
                    except BaseException:
                        await browser.close()
                        raise
                    return JSONResponse(body["viewport"])
                if browser.id != ident:
                    return JSONResponse({}, 410)
                async with asyncio.timeout(9):
                    return JSONResponse(await browser.use(op, body))
        except NoFocusedInput:
            return JSONResponse({"error": "web_browser_select_field"}, 422)
        except PasswordFocusError as exc:
            return JSONResponse({"error": str(exc)}, 422)
        except BrowserActionError as exc:
            return JSONResponse({"error": str(exc)}, 422)
        except TimeoutError:
            return JSONResponse({"error": "web_browser_action_uncertain"}, 422)
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
