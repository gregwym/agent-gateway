"""Opt-in browser administration. No MCP credential grants access to these routes."""
import copy
import hmac
import json
import re
import secrets
import time
from urllib.parse import urlsplit

import anyio
from pydantic import ValidationError
from starlette.responses import RedirectResponse
from starlette.routing import Route

from .admin_auth import AdminAuth, COOKIE
from .admin_config import CATALOG, ManagedStore, kind_of, make_connection, settings_of
from .auth import hash_token, new_token
from .config import NAME
from .lock import Lock, definition_of, digest_of
from .passkey import Refused, _json, _static, _PAGE_HEADERS
from .upstream import list_all_tools, open_client


class AdminController:
    def __init__(self, runtime):
        self.runtime = runtime
        self.store = ManagedStore(runtime.gateway)
        self.auth = AdminAuth(runtime.gateway.cfg, runtime.gateway.approver)
        self.mutex = anyio.Lock()
        self.drafts = {}
        self.tests = {}
        from .admin_oauth import GoogleConsent
        self.google = GoogleConsent(self)
        runtime.gateway = self._gateway(self.store.state)
        if not self.auth.initialized():
            self.auth.setup_link()

    def _gateway(self, state):
        from .server import Gateway
        cfg, lock, values = self.store.effective(state)
        result = Gateway(cfg, lock, values, self.runtime.gateway.audit, self.runtime.gateway.approver)
        result.configuration_revision = "web:" + str(state["revision"])
        return result

    async def sweep(self):
        while True:
            await anyio.sleep(30)
            now = time.time()
            self.drafts = {k: v for k, v in self.drafts.items() if v["expires"] > now}
            self.google.flows = {k: v for k, v in self.google.flows.items() if v["expires"] > now}

    def _revision(self, body):
        if type(body.get("revision")) is not int or body["revision"] != self.store.state["revision"]:
            raise Refused("configuration_changed", 409)

    async def _commit(self, state, action):
        state["revision"] = self.store.state["revision"] + 1
        gateway = self._gateway(state)
        if any(route.problem for route in gateway.routes.values()):
            raise Refused("invalid_tool_configuration", 400)

        def persist():
            self.store.save(state)
            # Revision-bound approvals are unusable immediately after publication,
            # including a crash between the atomic state write and this cleanup.
            with self.auth.approver._db() as db:
                db.execute("UPDATE requests SET status='cancelled', arguments=NULL WHERE status IN ('pending','approved')")

        try:
            await self.runtime.replace(gateway, persist)
        except TimeoutError:
            raise Refused("active_calls_busy", 409) from None
        self.tests.clear()
        gateway.audit.write("admin_updated", principal=self.auth.owner, detail=action,
                            revision=state["revision"])
        return {"revision": state["revision"]}

    def state(self):
        gw = self.runtime.gateway
        keys = self.auth.approver.passkeys()
        connections = []
        for conn in gw.cfg.connections:
            tools = []
            for tool in conn.tools:
                route = gw.routes[tool.name]
                tools.append({"name": tool.name, "upstream": tool.upstream, "pin": tool.pin,
                              "allow_values": tool.allow_values, "problem": gw.problem(route),
                              "permissions": {p: gw.policy.effect(p, tool.name) for p in gw.cfg.principals}})
            connections.append({"id": conn.id, "kind": kind_of(conn), "owner": conn.owner,
                                "settings": settings_of(conn), "tools": tools,
                                "connected": gw.upstreams[conn.id]._client is not None,
                                "test": self.tests.get(conn.id)})
        return {"revision": self.store.state["revision"], "owner": self.auth.owner,
                "mcp_url": gw.cfg.approvals.origin + "/mcp",
                "members": [{"id": p, "shared": p in gw.cfg.shared,
                             "passkeys": sum(k["principal"] == p for k in keys)} for p in gw.cfg.principals],
                "clients": [{"id": c.id, "principal": c.principal} for c in gw.cfg.clients],
                "connections": connections, "passkeys": keys,
                "catalog": {k: {f: v[f] for f in ("label", "fields", "secrets")} for k, v in CATALOG.items()}}

    async def operate(self, operation, body, session):
        if operation == "oauth/start":
            return self.google.start(body, session)
        if operation == "oauth/complete":
            connector, account = self.google.complete(body.get("id"), session)
            result = await self.operate("connections/preview", connector, session)
            return {**result, "google_account": account}
        if operation == "members/enroll":
            principal = body.get("id")
            if principal not in self.runtime.gateway.cfg.principals or principal in self.runtime.gateway.cfg.shared:
                raise Refused("unknown_member", 400)
            return {"url": self.auth.approver.new_enrollment(principal)}
        if operation == "passkeys/remove":
            key_id = body.get("id")
            keys = self.auth.approver.passkeys()
            key = next((k for k in keys if k["id"] == key_id), None)
            if not key:
                raise Refused("not_found", 404)
            if key["principal"] == self.auth.owner and sum(k["principal"] == self.auth.owner for k in keys) <= 1:
                raise Refused("last_admin_passkey", 409)
            self.auth.approver.forget_passkey(key_id)
            return {"ok": True}
        if operation == "connections/test":
            conn = next((c for c in self.runtime.gateway.cfg.connections if c.id == body.get("id")), None)
            if not conn or kind_of(conn) not in CATALOG:
                raise Refused("unsupported_connector", 400)
            probe, arguments = CATALOG[kind_of(conn)]["probe"]
            values = self.runtime.gateway.secrets
            try:
                with anyio.fail_after(35):
                    async with open_client(conn, {n: values[n] for n in conn.secret_names()}) as client:
                        live = {t.name: definition_of(t) for t in await list_all_tools(client)}
                        if any(self.runtime.gateway.lock.get(conn.id, tool.upstream) is None or
                               digest_of(live.get(tool.upstream, {})) != self.runtime.gateway.lock.get(conn.id, tool.upstream)["sha256"]
                               for tool in conn.tools):
                            raise Refused("tool_definitions_changed", 409)
                        result = await client.call_tool(probe, arguments)
                        if result.is_error:
                            raise Refused("connector_login_or_read_failed", 422)
            except Refused:
                raise
            except Exception:
                raise Refused("connector_unavailable", 422) from None
            self.tests[conn.id] = {"ok": True, "at": int(time.time())}
            self.runtime.gateway.audit.write("admin_connector_test", principal=self.auth.owner, connection=conn.id, reason="ok")
            return {"ok": True, "read_tool": probe}

        self._revision(body)
        state = self.store.candidate()
        raw = state["config"]
        if operation == "members/add":
            name = body.get("id")
            if not isinstance(name, str) or not re.fullmatch(NAME, name) or name in raw["principals"]:
                raise Refused("invalid_or_duplicate_member", 400)
            if len(raw["principals"]) >= 50:
                raise Refused("member_limit", 400)
            raw["principals"].append(name)
            if body.get("shared") is True:
                raw["shared"].append(name)
            return await self._commit(state, operation)
        if operation == "members/remove":
            name = body.get("id")
            if name == self.auth.owner or name not in raw["principals"]:
                raise Refused("cannot_remove_member", 400)
            if (any(c["principal"] == name for c in raw["clients"]) or any(c["owner"] == name for c in raw["connections"])
                    or any(name in p["principals"] for p in raw["policy"])):
                raise Refused("member_in_use", 409)
            raw["principals"].remove(name)
            raw["shared"] = [p for p in raw["shared"] if p != name]
            with self.auth.approver._db() as db:
                db.execute("DELETE FROM credentials WHERE principal=?", (name,))
                db.execute("DELETE FROM enrollments WHERE principal=?", (name,))
            # Delete credentials before publishing the removal, so even a failed
            # persistence attempt cannot leave credentials for a later re-added id.
            return await self._commit(state, operation)
        if operation in ("clients/create", "clients/rotate", "clients/revoke"):
            name = body.get("id")
            client = next((c for c in raw["clients"] if c["id"] == name), None)
            token = None
            if operation == "clients/create":
                if client or len(raw["clients"]) >= 100:
                    raise Refused("duplicate_or_too_many_clients", 400)
                token = new_token()
                raw["clients"].append({"id": name, "principal": body.get("principal"), "token_sha256": hash_token(token)})
            elif not client:
                raise Refused("not_found", 404)
            elif operation == "clients/rotate":
                token = new_token()
                client["token_sha256"] = hash_token(token)
            else:
                raw["clients"].remove(client)
            result = await self._commit(state, operation)
            if token:
                result.update(token=token, mcp_url=self.runtime.gateway.cfg.approvals.origin + "/mcp")
            return result
        if operation == "connections/preview":
            cfg, _, values = self.store.effective(state)
            conn, added = make_connection(body, cfg, values)
            if len(raw["connections"]) >= 50 and not any(c["id"] == conn.id for c in raw["connections"]):
                raise Refused("connector_limit", 400)
            values.update(added)
            try:
                with anyio.fail_after(35):
                    async with open_client(conn, {n: values[n] for n in conn.secret_names()}) as client:
                        definitions = {t.name: definition_of(t) for t in await list_all_tools(client)}
            except Exception:
                raise Refused("connector_unavailable", 422) from None
            if any(tool.upstream not in definitions for tool in conn.tools):
                raise Refused("missing_upstream_tool", 422)
            raw["connections"] = [c for c in raw["connections"] if c["id"] != conn.id] + [conn.model_dump(mode="json")]
            existing = any(c.id == conn.id for c in cfg.connections)
            if not existing:
                for tool in conn.tools:
                    raw["policy"].append({"principals": [conn.owner], "connection": conn.id, "tools": [tool.name],
                                          "effect": "approval_required" if tool.upstream == "add_note" else "allow"})
            state["secrets"].update(added)
            lock = Lock()
            for tool in conn.tools:
                lock.put(conn.id, definitions[tool.upstream])
            state["locks"][conn.id] = lock.entries[conn.id]
            self._gateway(state)  # validate before presenting the review
            self.drafts = {k: v for k, v in self.drafts.items() if v["expires"] > time.time()}
            if len(self.drafts) >= 16:
                raise Refused("too_many_drafts", 429)
            draft = secrets.token_urlsafe(24)
            self.drafts[draft] = {"state": state, "session": session["id"], "expires": time.time() + 600, "connection": conn.id}
            return {"draft": draft, "connection": conn.id, "definitions": list({t.upstream: definitions[t.upstream] for t in conn.tools}.values()),
                    "owner": conn.owner, "existing": existing}
        if operation == "connections/apply":
            draft = self.drafts.get(body.get("draft"))
            if not draft or draft["session"] != session["id"] or draft["expires"] <= time.time():
                raise Refused("draft_expired", 409)
            if draft["state"]["revision"] != self.store.state["revision"]:
                raise Refused("configuration_changed", 409)
            if body.get("reviewed") is not True:
                raise Refused("review_required", 400)
            result = await self._commit(draft["state"], operation)
            self.drafts.pop(body["draft"], None)
            return result
        if operation == "connections/remove":
            name = body.get("id")
            if not any(c["id"] == name for c in raw["connections"]):
                raise Refused("not_found", 404)
            raw["connections"] = [c for c in raw["connections"] if c["id"] != name]
            raw["policy"] = [p for p in raw["policy"] if p["connection"] != name]
            state["locks"].pop(name, None)
            referenced = {n for c in raw["connections"] for n in [*c.get("secret_env", {}).values(),
                          *c.get("secret_headers", {}).values(), c.get("bearer_secret")] if n}
            state["secrets"] = {k: v for k, v in state["secrets"].items() if k in referenced}
            return await self._commit(state, operation)
        if operation == "permissions/save":
            principal, name, tool = body.get("principal"), body.get("connection"), body.get("tool")
            for rule in list(raw["policy"]):
                if rule["connection"] == name and principal in rule["principals"] and tool in rule["tools"]:
                    raw["policy"].remove(rule)
                    other_people = [p for p in rule["principals"] if p != principal]
                    other_tools = [t for t in rule["tools"] if t != tool]
                    if other_people:
                        raw["policy"].append({**rule, "principals": other_people})
                    if other_tools:
                        raw["policy"].append({**rule, "principals": [principal], "tools": other_tools})
            raw["policy"].append({"connection": name, "principals": [principal], "tools": [tool],
                                  "effect": body.get("effect"), "cross_account": body.get("cross_account") is True})
            return await self._commit(state, operation)
        if operation == "tools/restrict":
            conn = next((c for c in raw["connections"] if c["id"] == body.get("connection")), None)
            tool = next((t for t in conn["tools"] if t["name"] == body.get("tool")), None) if conn else None
            if not tool:
                raise Refused("not_found", 404)
            tool.update(pin=body.get("pin", {}), allow_values=body.get("allow_values", {}))
            return await self._commit(state, operation)
        raise Refused("not_found", 404)

    def http_routes(self):
        origin = self.store.base.approvals.origin
        authority = urlsplit(origin).netloc
        secure = origin.startswith("https:")
        cookie_name = "__Host-" + COOKIE if secure else COOKIE
        cookie_path = "/" if secure else "/admin"

        async def page(request):
            if request.headers.get("host") != authority:
                return _json({"error": "wrong_origin"}, 403)
            return _static("admin.html", "text/html; charset=utf-8")

        async def asset(request):
            name = request.path_params["name"]
            if name not in ("admin.js", "admin.css"):
                return _json({"error": "not_found"}, 404)
            return _static(name, "text/javascript" if name.endswith(".js") else "text/css")

        async def api(request):
            try:
                if request.headers.get("host") != authority:
                    raise Refused("wrong_origin")
                token = request.cookies.get(cookie_name, "")
                operation = request.path_params["operation"]
                if request.method == "GET":
                    if operation == "status":
                        try:
                            session = self.auth.session(token)
                            return _json({"initialized": True, "authenticated": True, "csrf": session["csrf"]}, 200)
                        except Refused:
                            return _json({"initialized": self.auth.initialized(), "authenticated": False}, 200)
                    self.auth.session(token)
                    if operation == "state":
                        async with self.mutex:
                            self.auth.session(token)
                            return _json(self.state(), 200)
                    raise Refused("not_found", 404)
                if (request.headers.get("origin") != origin
                        or request.headers.get("content-type", "").split(";")[0].strip() != "application/json"):
                    raise Refused("wrong_origin")
                raw = bytearray()
                async for chunk in request.stream():
                    raw.extend(chunk)
                    if len(raw) > 256000:
                        raise Refused("request_too_large", 413)
                try:
                    body = json.loads(raw)
                    if not isinstance(body, dict):
                        raise ValueError()
                except ValueError:
                    raise Refused("invalid_argument", 400) from None
                if operation == "auth/begin":
                    return _json(self.auth.begin(body.get("action"), body.get("code", "")), 200)
                if operation == "auth/finish":
                    token, csrf = self.auth.finish(str(body.get("ceremony_id")), body.get("response"))
                    response = _json({"csrf": csrf}, 200)
                    response.set_cookie(cookie_name, token, max_age=self.store.base.admin.session_seconds,
                                        httponly=True, secure=secure, samesite="strict", path=cookie_path)
                    return response
                session = self.auth.session(token)
                if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), session["csrf"]):
                    raise Refused("csrf_required")
                if operation == "auth/logout":
                    self.auth.logout(token)
                    response = _json({"ok": True}, 200)
                    response.delete_cookie(cookie_name, path=cookie_path, secure=secure, httponly=True, samesite="strict")
                    return response
                async with self.mutex:
                    self.auth.session(token)  # may have expired while waiting for another change
                    result = await self.operate(operation, body, session)
                return _json(result, 200)
            except Refused as exc:
                return _json({"error": exc.code}, exc.status)
            except (ValidationError, TypeError, ValueError, KeyError):
                return _json({"error": "invalid_configuration"}, 400)
            except Exception as exc:
                self.runtime.gateway.audit.write("admin_error", detail=type(exc).__name__)
                return _json({"error": "operation_failed"}, 500)

        async def google_callback(request):
            # Cross-site Google navigation has no SameSite=Strict cookie. The
            # one-use state is bound to a still-live session; only that session
            # can subsequently review/apply the result via a CSRF-protected POST.
            try:
                if request.headers.get("host") != authority:
                    raise Refused("wrong_origin")
                target = await self.google.callback(request.query_params)
                return RedirectResponse(target, status_code=303, headers=_PAGE_HEADERS)
            except Refused as exc:
                return _json({"error": exc.code}, exc.status)

        return [Route("/", page), Route("/admin", page), Route("/admin/", page),
                Route("/admin/oauth/google/callback", google_callback),
                Route("/admin/assets/{name}", asset),
                Route("/admin/api/{operation:path}", api, methods=["GET", "POST"])]
