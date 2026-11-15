"""Opt-in browser administration. No MCP credential grants access to these routes."""
import copy
import hmac
import html
import json
import re
import secrets
import time
from urllib.parse import urlsplit

import anyio
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

from .admin_auth import AdminAuth, COOKIE
from .admin_config import CATALOG, CONNECTION_ACCESS, ManagedStore, connection_access, kind_of, make_connection, member_name, settings_of, tool_access
from .auth import hash_token, new_token
from .config import NAME
from .lock import Lock, definition_of, digest_of
from .passkey import Refused, _json, _static, _PAGE_HEADERS
from .upstream import list_all_tools, open_client
from .web_errors import connector_failure, failure_response, probe_error


class AdminController:
    def __init__(self, runtime):
        self.runtime = runtime
        self.store = ManagedStore(runtime.gateway)
        self.auth = AdminAuth(runtime.gateway.cfg, runtime.gateway.approver)
        self.auth.approver.name_of = self.store.name_of
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
        # Renames do not restart connectors or invalidate approvals. A draft must
        # keep the latest canonical names without overwriting newly added members.
        for kind in ("members", "households"):
            names = {m["id"]: m["name"] for m in self.store.state["config"][kind]}
            for member in state["config"][kind]:
                member["name"] = names.get(member["id"], member["name"])
        state["revision"] = self.store.state["revision"] + 1
        gateway = self._gateway(state)
        for route in gateway.routes.values():
            if route.problem:
                raise Refused({"pin_unknown_argument": "pin_unknown_argument", "allow_values_unknown_argument": "allow_values_unknown_argument",
                               "not_locked": "missing_tool_lock", "schema_invalid": "invalid_tool_schema",
                               "schema_remote_ref": "remote_tool_schema", "schema_not_object": "invalid_tool_schema"}.get(
                                   route.problem, "invalid_tool_configuration"), 400)

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
                tools.append({"name": tool.name, "upstream": tool.upstream, "access": tool_access(conn, tool), "pin": tool.pin,
                              "allow_values": tool.allow_values, "problem": gw.problem(route),
                              "permissions": {c.id: gw.policy.effect(c.subject, tool.name, c.id) for c in gw.cfg.clients}})
            connections.append({"id": conn.id, "kind": kind_of(conn), "owner": conn.owner,
                                "household": gw.cfg.household_of(conn.owner), "approvers": list(gw.cfg.approvers_of(conn)),
                                "approver": conn.approver or conn.owner,
                                "access": {c.id: connection_access(gw.policy, c, conn) for c in gw.cfg.clients},
                                "settings": settings_of(conn), "tools": tools,
                                "connected": gw.upstreams[conn.id]._client is not None,
                                "test": self.tests.get(conn.id)})
        return {"revision": self.store.state["revision"], "owner": self.auth.owner,
                "mcp_url": gw.cfg.approvals.origin + "/mcp",
                "households": [{"id": h.id, "name": self.store.name_of(h.id)} for h in gw.cfg.households],
                "members": [{"id": m.id, "name": self.store.name_of(m.id), "household": m.household,
                             "passkeys": sum(k["principal"] == m.id for k in keys)} for m in gw.cfg.members],
                "clients": [{"id": c.id, "household": c.household, "fingerprint": c.token_sha256[:12],
                             "tool_count": sum(gw.policy.effect(c.subject, t.name, c.id) != "deny"
                                               for conn in gw.cfg.connections for t in conn.tools)} for c in gw.cfg.clients],
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
            problem = None
            try:
                with anyio.fail_after(35):
                    async with open_client(conn, {n: values[n] for n in conn.secret_names()}) as client:
                        live = {t.name: definition_of(t) for t in await list_all_tools(client)}
                        if any(self.runtime.gateway.lock.get(conn.id, tool.upstream) is None or
                               digest_of(live.get(tool.upstream, {})) != self.runtime.gateway.lock.get(conn.id, tool.upstream)["sha256"]
                               for tool in conn.tools):
                            problem = "tool_definitions_changed"
                        else:
                            result = await client.call_tool(probe, arguments)
                            if result.is_error:
                                problem = probe_error(kind_of(conn), result)
                            elif kind_of(conn) == "imap" and conn.env.get("SMTP_HOST", "smtp.mail.me.com" if conn.env.get("IMAP_HOST", "imap.mail.me.com").lower() == "imap.mail.me.com" else ""):
                                result = await client.call_tool("check_smtp", {})
                                if result.is_error:
                                    problem = probe_error("imap", result)
            except Exception as exc:
                problem = connector_failure(exc, conn.transport)
            # Raise after leaving MCP's task groups. A Refused raised inside the
            # client context becomes an ExceptionGroup and loses its meaning.
            incident = secrets.token_hex(6) if problem else None
            self.tests[conn.id] = {"ok": problem is None, "at": int(time.time()), "reason": problem or "ok", "incident": incident}
            self.runtime.gateway.audit.write("admin_connector_test", principal=self.auth.owner, connection=conn.id, reason=problem or "ok", detail=incident)
            if problem:
                raise Refused(problem, 409 if problem == "tool_definitions_changed" else 422, incident=incident)
            return {"ok": True, "read_tool": probe}

        self._revision(body)
        if operation in ("members/rename", "households/rename"):
            kind = "members" if operation == "members/rename" else "households"
            if not any(m["id"] == body.get("id") for m in self.store.state["config"][kind]):
                raise Refused("unknown_member" if kind == "members" else "unknown_household", 400)
            self.store.rename(body.get("id"), body.get("name"))
            self.runtime.gateway.audit.write("admin_updated", principal=self.auth.owner, detail=operation,
                                             revision=self.store.state["revision"])
            return {"revision": self.store.state["revision"]}
        state = self.store.candidate()
        raw = state["config"]
        if operation == "members/add":
            if body.get("shared") is True:
                raise Refused("shared_identity_removed", 400)
            name = member_name(body.get("name", body.get("id")))
            identity = body.get("id", "member_" + secrets.token_hex(8))
            if not isinstance(identity, str) or not re.fullmatch(NAME, identity):
                raise Refused("invalid_argument", 400)
            if identity in raw["principals"] or any(m["name"].casefold() == name.casefold() for m in raw["members"]):
                raise Refused("duplicate_member", 400)
            home = body.get("household", raw["households"][0]["id"])
            if home not in raw["shared"]:
                raise Refused("unknown_household", 400)
            if len(raw["members"]) >= 50:
                raise Refused("member_limit", 400)
            raw["principals"].append(identity)
            raw["members"].append({"id": identity, "name": name, "household": home})
            return await self._commit(state, operation)
        if operation == "members/remove":
            name = body.get("id")
            if name == self.auth.owner or not any(m["id"] == name for m in raw["members"]):
                raise Refused("cannot_remove_member", 400)
            if any(c.get("approver") == name for c in raw["connections"]):
                raise Refused("member_is_approver", 409)
            if any(c.get("principal") == name for c in raw["clients"]) or any(c["owner"] == name for c in raw["connections"]):
                raise Refused("member_in_use", 409)
            raw["principals"].remove(name)
            raw["members"] = [m for m in raw["members"] if m["id"] != name]
            with self.auth.approver._db() as db:
                db.execute("DELETE FROM credentials WHERE principal=?", (name,))
                db.execute("DELETE FROM enrollments WHERE principal=?", (name,))
            # Delete credentials before publishing the removal, so even a failed
            # persistence attempt cannot leave credentials for a later re-added id.
            return await self._commit(state, operation)
        if operation in ("clients/create", "clients/rename", "clients/rotate", "clients/revoke"):
            name = body.get("id")
            client = next((c for c in raw["clients"] if c["id"] == name), None)
            token = None
            if operation == "clients/create":
                if not isinstance(name, str) or not re.fullmatch(NAME, name):
                    raise Refused("invalid_client_name", 400)
                if client:
                    raise Refused("duplicate_client", 400)
                if len(raw["clients"]) >= 100:
                    raise Refused("client_limit", 400)
                home = body.get("household")
                if home not in raw["shared"]:
                    raise Refused("unknown_household", 400)
                token = new_token()
                raw["clients"].append({"id": name, "household": home, "token_sha256": hash_token(token)})
            elif not client:
                raise Refused("not_found", 404)
            elif operation == "clients/rename":
                renamed = body.get("name")
                if not isinstance(renamed, str) or not re.fullmatch(NAME, renamed):
                    raise Refused("invalid_client_name", 400)
                if renamed == name:
                    return {"revision": self.store.state["revision"], "id": name}
                if any(c["id"] == renamed for c in raw["clients"]):
                    raise Refused("duplicate_client", 400)
                client["id"] = renamed
                for rule in raw["policy"]:
                    rule["clients"] = [renamed if c == name else c for c in rule["clients"]]
            elif operation == "clients/rotate":
                token = new_token()
                client["token_sha256"] = hash_token(token)
            else:
                raw["clients"].remove(client)
                raw["policy"] = [{**r, "clients": [c for c in r["clients"] if c != name]}
                                 for r in raw["policy"] if any(c != name for c in r["clients"])]
            result = await self._commit(state, operation)
            if operation == "clients/rename":
                result["id"] = client["id"]
            if token:
                result.update(token=token, fingerprint=hash_token(token)[:12], mcp_url=self.runtime.gateway.cfg.approvals.origin + "/mcp")
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
            except Exception as exc:
                reason, incident = connector_failure(exc, conn.transport), secrets.token_hex(6)
                self.runtime.gateway.audit.write("admin_connector_preview", reason=reason, detail=f"{incident}:{type(exc).__name__}")
                raise Refused(reason, 422, incident=incident) from None
            if any(tool.upstream not in definitions for tool in conn.tools):
                raise Refused("missing_upstream_tool", 422)
            raw["connections"] = [c for c in raw["connections"] if c["id"] != conn.id] + [conn.model_dump(mode="json")]
            existing = any(c.id == conn.id for c in cfg.connections)
            # Ownership never grants an Agent access. Every new connector starts denied.
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
        if operation == "permissions/connection":
            client_id, name, mode = body.get("client"), body.get("connection"), body.get("access")
            cfg, _, _ = self.store.effective(state)
            client = next((c for c in cfg.clients if c.id == client_id), None)
            conn = next((c for c in cfg.connections if c.id == name), None)
            if not client:
                raise Refused("unknown_agent", 400)
            if not conn:
                raise Refused("not_found", 404)
            if not isinstance(mode, str) or mode not in (*CONNECTION_ACCESS, "custom"):
                raise Refused("invalid_connection_access", 400)
            if client.household != cfg.household_of(conn.owner):
                raise Refused("outside_household", 400)
            if mode != "custom" and CONNECTION_ACCESS[mode]["write"] != "deny" and not any(tool_access(conn, t) == "write" for t in conn.tools):
                raise Refused("connection_readonly", 400)
            if "approver" in body:
                approver = body["approver"]
                if not isinstance(approver, str) or approver not in cfg.principals or cfg.household_of(approver) != client.household:
                    raise Refused("invalid_connection_approver", 400)
                next(c for c in raw["connections"] if c["id"] == name)["approver"] = approver
            if mode == "custom":
                return await self._commit(state, operation)
            # Replace only this Agent's rules on this connection, atomically.
            for rule in list(raw["policy"]):
                if rule["connection"] == name and client_id in rule["clients"]:
                    raw["policy"].remove(rule)
                    other = [c for c in rule["clients"] if c != client_id]
                    if other:
                        raw["policy"].append({**rule, "clients": other})
            for tool in conn.tools:
                effect = CONNECTION_ACCESS[mode][tool_access(conn, tool)]
                raw["policy"].append({"clients": [client_id], "connection": name, "tools": [tool.name], "effect": effect})
            return await self._commit(state, operation)
        if operation == "permissions/save":
            client_id, name, tool = body.get("client"), body.get("connection"), body.get("tool")
            conn = next((c for c in raw["connections"] if c["id"] == name), None)
            client = next((c for c in raw["clients"] if c["id"] == client_id), None)
            if not client:
                raise Refused("unknown_agent", 400)
            if not conn or not any(t["name"] == tool for t in conn["tools"]):
                raise Refused("not_found", 404)
            if body.get("effect") not in ("deny", "allow", "approval_required"):
                raise Refused("invalid_permission_effect", 400)
            cfg, _, _ = self.store.effective(state)
            if client["household"] != cfg.household_of(conn["owner"]) and body["effect"] != "deny":
                raise Refused("outside_household", 400)
            for rule in list(raw["policy"]):
                if rule["connection"] == name and client_id in rule["clients"] and tool in rule["tools"]:
                    raw["policy"].remove(rule)
                    other_agents = [p for p in rule["clients"] if p != client_id]
                    other_tools = [t for t in rule["tools"] if t != tool]
                    if other_agents:
                        raw["policy"].append({**rule, "clients": other_agents})
                    if other_tools:
                        raw["policy"].append({**rule, "clients": [client_id], "tools": other_tools})
            raw["policy"].append({"connection": name, "clients": [client_id], "tools": [tool], "effect": body["effect"]})
            return await self._commit(state, operation)
        if operation == "tools/restrict":
            conn = next((c for c in raw["connections"] if c["id"] == body.get("connection")), None)
            tool = next((t for t in conn["tools"] if t["name"] == body.get("tool")), None) if conn else None
            if not tool:
                raise Refused("not_found", 404)
            pin, allowed = body.get("pin", {}), body.get("allow_values", {})
            if not isinstance(pin, dict) or not isinstance(allowed, dict):
                raise Refused("restrictions_object_required", 400)
            if set(pin) & set(allowed):
                raise Refused("restriction_conflict", 400)
            if any(not isinstance(v, list) or not v for v in allowed.values()):
                raise Refused("allowed_values_required", 400)
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
                return _json({"error": exc.code, **({"incident": exc.incident} if exc.incident else {})}, exc.status)
            except Exception as exc:
                return failure_response(exc, self.runtime.gateway.audit, _PAGE_HEADERS)

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
                error = _json({"error": exc.code}, exc.status)
            except Exception as exc:
                error = failure_response(exc, self.runtime.gateway.audit, _PAGE_HEADERS)
            # Google callbacks are browser navigations, so render the normal UI
            # with the error instead of leaving the person on a JSON document.
            data = {**json.loads(error.body), "status": error.status_code}
            marker = '<meta name="gateway-error" content="' + html.escape(json.dumps(data), quote=True) + '">'
            page = _static("admin.html", "text/html").body.decode().replace("</head>", marker + "</head>")
            return HTMLResponse(page, status_code=error.status_code, headers=_PAGE_HEADERS)

        return [Route("/", page), Route("/admin", page), Route("/admin/", page),
                Route("/admin/oauth/google/callback", google_callback),
                Route("/admin/assets/{name}", asset),
                Route("/admin/api/{operation:path}", api, methods=["GET", "POST"])]
