"""Session-bound browser handoff for the MCP SDK OAuth client."""
import copy
import secrets
import time
from urllib.parse import parse_qs, urlsplit

import anyio
from mcp.shared.auth import AuthorizationCodeResult

from .admin_config import make_connection
from .admin_oauth import ConsentSessions
from .lock import definition_of
from .oauth import https_url, oauth_error
from .passkey import Refused
from .upstream import list_all_tools, open_client
from .web_errors import leaves


class MCPConsent(ConsentSessions):
    def __init__(self, controller):
        self.controller = controller
        self.flows = {}
        self.redirect = controller.store.base.approvals.origin + "/admin/oauth/mcp/callback"

    def sweep(self):
        for key, flow in list(self.flows.items()):
            if flow["expires"] <= time.time():
                if flow.get("cancel"):
                    flow["cancel"].cancel()
                self.controller.oauth.discard(flow["ref"])
                del self.flows[key]

    async def start(self, body, session):
        self.controller._revision(body)
        if body.get("kind") != "remote" or body.get("settings", {}).get("auth") != "oauth":
            raise Refused("invalid_connector", 400)
        body = copy.deepcopy(body)
        gw = self.controller.runtime.gateway
        conn, _ = make_connection(body, gw.cfg, gw.secrets)
        self.sweep()
        if len(self.flows) >= 16:
            raise Refused("too_many_drafts", 429)
        settings = body["settings"]
        client_secret = body.get("credentials", {}).get("client_secret", "")
        if not client_secret and conn.oauth_ref:
            old = self.controller.oauth.get(conn.oauth_ref, conn.url)
            client = old.get("client") or {}
            if settings.get("issuer") == old.get("issuer") and settings.get("client_id") == client.get("client_id"):
                client_secret = client.get("client_secret") or ""
        ref = self.controller.oauth.create(conn.url, self.redirect, settings, client_secret)
        body["credentials"] = {}
        key = secrets.token_urlsafe(32)
        flow = {"session": session["id"], "body": body, "ref": ref, "expires": time.time() + 600,
                "phase": "starting", "started": anyio.Event(), "returned": anyio.Event(), "done": anyio.Event()}
        self.flows[key] = flow
        self.controller.runtime.tasks.start_soon(self._run, key, conn.model_copy(update={"oauth_ref": ref}))
        try:
            with anyio.fail_after(30):
                await flow["started"].wait()
        except TimeoutError:
            flow["expires"] = 0
            self.sweep()
            raise Refused("oauth_timeout", 504) from None
        if flow.get("error"):
            self.controller.oauth.discard(ref)
            del self.flows[key]
            raise Refused(flow["error"], 422, incident=flow.get("incident"))
        return {"url": flow["url"]}

    async def _run(self, key, conn):
        flow = self.flows[key]
        async def redirect(url):
            https_url(url, query=True)
            flow.update(url=url, state=parse_qs(urlsplit(url).query)["state"][0], phase="pending")
            flow["started"].set()
        async def callback():
            await flow["returned"].wait()
            self._active(flow)
            self.controller._revision(flow["body"])
            if flow.get("error"):
                raise Refused(flow["error"], 400)
            return flow["result"]
        try:
            with anyio.fail_after(600) as scope:
                flow["cancel"] = scope
                auth = self.controller.oauth.auth(conn, redirect_handler=redirect, callback_handler=callback)
                async with open_client(conn, {}, auth=auth) as client:
                    flow["definitions"] = {t.name: definition_of(t) for t in await list_all_tools(client)}
                if not self.controller.oauth.get(flow["ref"]).get("tokens"):
                    raise Refused("oauth_not_required", 400)
                flow["phase"] = "ready"
        except Exception as exc:
            reason = oauth_error(exc)
            incident = secrets.token_hex(6)
            self.controller.runtime.gateway.audit.write(
                "admin_oauth_failed", connection=conn.id, reason=reason,
                detail=f"{incident}:{type(leaves(exc)[0]).__name__}",
            )
            flow.update(phase="failed", error=reason, incident=incident)
        finally:
            flow["started"].set()
            flow["done"].set()

    async def callback(self, query):
        state = query.get("state", "")
        match = next(((k, f) for k, f in self.flows.items() if f.get("state") == state), None)
        if match is None:
            raise Refused("oauth_expired", 409)
        key, flow = match
        self._active(flow)
        self.controller._revision(flow["body"])
        if flow["phase"] != "pending":
            raise Refused("oauth_already_used", 409)
        flow["phase"] = "exchanging"
        if query.get("error") or not query.get("code") or len(query["code"]) > 4096:
            flow["error"] = "oauth_declined"
        flow["result"] = AuthorizationCodeResult(code=query.get("code", ""), state=state, iss=query.get("iss"))
        flow["returned"].set()
        with anyio.move_on_after(35):
            await flow["done"].wait()
        return "/admin/?mcp_oauth=" + key

    def complete(self, key, session):
        flow = self.flows.get(key)
        self._active(flow)
        if flow["session"] != session["id"]:
            raise Refused("oauth_wrong_session")
        self.controller._revision(flow["body"])
        if flow.get("error"):
            self.controller.oauth.discard(flow["ref"])
            del self.flows[key]
            raise Refused(flow["error"], 400, incident=flow.get("incident"))
        if flow["phase"] != "ready":
            raise Refused("oauth_not_ready", 409)
        del self.flows[key]
        return flow
