"""Session-bound Website login. Browser credentials and pixels never enter MCP or the audit."""
import asyncio
import json
import os
import re
import secrets
import stat
import time
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlsplit

import anyio
import httpx2 as httpx

from .admin_config import CONNECTOR_NAME, kind_of, make_connection
from .browser_tunnel import connect
from .browser_worker import HEIGHT, KEYS, WIDTH
from .connectors.web import ConnectorError, SiteSession, import_session
from .lock import definition_of
from .passkey import Refused
from .plugins import connector_plugins
from .upstream import list_all_tools, open_client
from .web_profiles import PROFILE_ENV, SESSION_ENV, WebProfile

# Additional network origins for first-party sign-in and assets. These are never
# accepted as an order endpoint or as a destination supplied by an Agent.
BUNDLED = {
    "www.amazon.com": (("www.amazon.com",), ("media-amazon.com", "ssl-images-amazon.com", "amazon.com")),
    "www.weee.com": (("www.weee.com", "www.sayweee.com", "weee.com", "sayweee.com"), ("static.weeecdn.com",)),
}


class WebsiteLogin:
    def __init__(self, admin):
        self.admin = admin
        self.lock = anyio.Lock()
        self.socket = os.environ.get("AGW_BROWSER_SOCKET")
        self.flow = None

    def available(self):
        try:
            return self.socket is not None and stat.S_ISSOCK(Path(self.socket).stat().st_mode)
        except OSError:
            return False

    async def worker(self, action, data):
        try:
            transport = httpx.AsyncHTTPTransport(uds=self.socket, retries=0)
            async with httpx.AsyncClient(transport=transport, base_url="http://browser", timeout=23,
                                          trust_env=False) as client:
                response = await client.post("/" + action, json=data)
            if response.status_code in (409, 410):
                raise Refused("web_browser_in_use" if response.status_code == 409 else "web_browser_expired", 409)
            response.raise_for_status()
            return response.json()
        except httpx.TimeoutException:
            raise Refused("web_browser_timeout", 422) from None
        except (httpx.HTTPError, ValueError, OSError):
            raise Refused("web_browser_unavailable" if action == "start" else "web_browser_failed", 422) from None

    async def close(self):
        flow, self.flow = self.flow, None
        if flow:
            flow["proxy"].close()
            for task in flow["tunnels"].copy():
                task.cancel()
            flow["path"].unlink(missing_ok=True)
            with anyio.move_on_after(3, shield=True), suppress(Refused):
                await self.worker("close", {"id": flow["id"]})

    async def expire(self, logout=None):
        async with self.lock:
            if self.flow and (self.flow["expires"] <= time.time() or self.flow["session"] == logout):
                await self.close()

    async def start(self, body, session):
        admin = self.admin
        body = dict(body)
        if set(body) != {"revision", "id", "owner", "plugin"}:
            raise Refused("invalid_connector", 400)
        admin._revision(body)
        gateway = admin.runtime.gateway
        name, owner, plugin_id = (body.get(k) for k in ("id", "owner", "plugin"))
        if not isinstance(name, str) or not re.fullmatch(CONNECTOR_NAME, name):
            raise Refused("invalid_connector_name", 400)
        if owner not in gateway.cfg.principals:
            raise Refused("unknown_member", 400)
        previous = next((c for c in gateway.cfg.connections if c.id == name), None)
        if previous:
            if kind_of(previous) != "web" or previous.owner != owner or previous.plugin != plugin_id:
                raise Refused("connector_identity_is_fixed", 409)
            profile = WebProfile.model_validate_json(previous.env[PROFILE_ENV])
        else:
            if len(gateway.cfg.connections) >= 50:
                raise Refused("connector_limit", 400)
            plugins = connector_plugins(admin.store.base.admin.plugins_dir)
            plugin = plugins.get(plugin_id) if isinstance(plugin_id, str) else None
            if not plugin or plugin.kind != "web":
                raise Refused("local_plugin_unavailable", 400)
            profile = WebProfile.model_validate(plugin.web)
        if not self.available():
            raise Refused("web_browser_unavailable", 503)
        host = urlsplit(profile.origin).hostname
        navigation, assets = BUNDLED.get(host, ((host,), ()))
        expires = min(time.time() + 600, session["expires"])
        if expires < time.time() + 15:
            raise Refused("login_required", 401)
        async with self.lock:
            if self.flow:
                if self.flow["expires"] > time.time():
                    raise Refused("web_browser_in_use", 409)
                await self.close()
            ident = secrets.token_hex(12)
            path = Path(self.socket).parent / (ident + ".proxy")
            tunnels = set()

            async def serve(reader, writer):
                task = asyncio.current_task()
                if len(tunnels) >= 48:
                    writer.close()
                    return
                tunnels.add(task)
                try:
                    await connect(reader, writer, navigation + assets)
                finally:
                    tunnels.discard(task)

            try:
                proxy = await asyncio.start_unix_server(serve, path, limit=8192)
                path.chmod(0o600)
            except OSError:
                raise Refused("web_browser_unavailable", 503) from None
            self.flow = {"id": ident, "session": session["id"], "expires": expires, "profile": profile,
                         "path": path, "proxy": proxy, "tunnels": tunnels, "body": body}
            try:
                await self.worker("start", {"id": ident, "expires": expires,
                                           "url": profile.origin + profile.actions[profile.probe].path,
                                           "navigation": navigation})
            except BaseException:
                with anyio.CancelScope(shield=True):
                    await self.close()
                raise
            return {"id": ident, "width": WIDTH, "height": HEIGHT, "host": host}

    async def input(self, operation, body, session, token):
        async with self.lock:
            flow = self.flow
            if not flow or flow["id"] != body.get("id") or flow["session"] != session["id"] or flow["expires"] <= time.time():
                raise Refused("web_browser_expired", 409)
            if operation == "cancel":
                await self.close()
                return {"ok": True}
            if operation == "save":
                return await self.finish(flow, token)
            spec = {
                "frame": (),
                "tap": ("x", "y"),
                "scroll": ("x", "y", "dx", "dy"),
                "text": ("text",),
                "key": ("key",),
                "reload": (),
            }
            if operation not in spec or body.keys() != {"id", *spec[operation]}:
                raise Refused("web_browser_input", 400)
            if ("x" in body and not (type(body["x"]) is type(body["y"]) is int
                    and 0 <= body["x"] < WIDTH and 0 <= body["y"] < HEIGHT)
                    or "dy" in body and not all(type(body[key]) is int and -1200 <= body[key] <= 1200
                                                for key in ("dx", "dy"))
                    or "text" in body and not (isinstance(body["text"], str) and 0 < len(body["text"]) <= 2048
                                               and not any(ord(s) < 32 for s in body["text"]))
                    or "key" in body and not (isinstance(body["key"], str) and body["key"] in KEYS)):
                raise Refused("web_browser_input", 400)
            return await self.worker(operation, body)

    async def finish(self, flow, token):
        admin = self.admin
        profile = flow["profile"]
        cookies = await self.worker("cookies", {"id": flow["id"], "origin": profile.origin})
        try:
            candidate = import_session(json.dumps(cookies), profile)
        except (ValueError, RecursionError):
            raise Refused("web_browser_sign_in_required", 422) from None
        del cookies
        # Read via the actual HTTP connector, using only candidate cookies. An
        # expired, blocked or incompatible page must never replace a good session.
        def verify():
            reader = SiteSession(profile, candidate)
            reader.read(profile.actions[profile.probe], {})
            return json.dumps([{**cookie, "domain": reader.host} for cookie in json.loads(reader._cookies())])

        try:
            with anyio.fail_after(26):
                candidate = await anyio.to_thread.run_sync(verify, abandon_on_cancel=True)
        except TimeoutError:
            raise Refused("connector_timeout", 422) from None
        except ConnectorError as exc:
            raise Refused("web_browser_sign_in_required" if exc.code == "web_login_required" else exc.code, 422) from None
        if candidate == "[]":
            raise Refused("web_browser_sign_in_required", 422)
        form = flow["body"]
        async with admin.editing():
            admin.auth.session(token)
            admin._revision(form)
            state = admin.store.candidate()
            cfg, _, values = admin.store.effective(state)
            plugins = connector_plugins(admin.store.base.admin.plugins_dir)
            payload = {"id": form["id"], "kind": "web", "owner": form["owner"],
                       "settings": {"plugin": form["plugin"]}, "credentials": {SESSION_ENV: candidate}}
            conn, added = make_connection(payload, cfg, values, plugins=plugins)
            # The profile used for the authorization must be the one being saved.
            if WebProfile.model_validate_json(conn.env[PROFILE_ENV]) != profile:
                raise Refused("configuration_changed", 409)
            previous = next((c for c in cfg.connections if c.id == conn.id), None)
            if previous:
                result = await admin.save_connection(state, cfg, conn, added, previous)
            else:
                async with open_client(conn, added) as client:
                    definitions = {t.name: definition_of(t) for t in await list_all_tools(client)}
                admin.stage_website(state, cfg, conn, added, definitions)
                result = await admin._commit(state, "web-login/save")
            admin.tests[conn.id] = {"ok": True, "at": int(time.time()), "reason": "ok", "incident": None}
        await self.close()
        return result
