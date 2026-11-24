"""Opt-in browser administration. No MCP credential grants access to these routes."""
import copy
import hmac
import html
import json
import re
import secrets
import shutil
import time
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import anyio
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

from . import __version__, registry
from .admin_auth import AdminAuth, COOKIE
from .admin_web_login import WebsiteLogin
from .admin_config import (
    CATALOG, CONNECTION_ACCESS, CONNECTOR_NAME, ManagedStore, catalog_additions, connection_access,
    extend_catalog_tools, kind_of, mailbox_metadata, make_connection, member_name, settings_of, tool_access,
)
from .auth import hash_token, new_token
from .catalog_sync import bundled_kind
from .config import NAME, ToolCfg, WebOperationRule, is_mail_send, valid_mailbox_paths
from .lock import Lock, definition_of, digest_of
from .passkey import Refused, _json, _static, _PAGE_HEADERS
from .plugins import MANIFEST_ENV, connector_plugins
from .upstream import list_all_tools, open_client
from .web_errors import connector_failure, failure_response, probe_error
from .web_catalog import PROPOSE_OPERATION_RULES, WebsiteCatalogs
from .web_profiles import ORIGINS_ENV, PROFILE_ENV, WebProfile, api_origins, connection_origins


_ADMIN_PAGE_HEADERS = {**_PAGE_HEADERS, "Content-Security-Policy":
                       _PAGE_HEADERS["Content-Security-Policy"] + "; img-src blob:"}


def admin_page():
    response = _static("admin.html", "text/html; charset=utf-8")
    response.headers.update(_ADMIN_PAGE_HEADERS)
    return response


def needs_admin_confirmation(operation, body):
    if operation == "web-operation-rules/decide":
        return body.get("decision") == "approve"
    if operation == "web-operation-rules/remove":
        return True
    if operation == "permissions/save":
        return body.get("effect") != "deny"
    if operation == "permissions/connection":
        return body.get("access") != "none" or "approver" in body or "mailbox_paths" in body
    # OAuth callbacks can only save drafts started by an authorized, session-bound request.
    return operation in {
        "members/enroll", "passkeys/remove", "clients/create", "clients/rotate", "tools/restrict",
        "connections/preview", "connections/save", "connections/apply", "oauth/start", "oauth/mcp/start",
        "settings/gmail-oauth", "web-login/start", "web-login/terminate",
        "web-catalog/publisher", "web-catalog/origins",
    }


class AdminController:
    def __init__(self, runtime):
        self.runtime = runtime
        self.store = ManagedStore(runtime.gateway)
        self.auth = AdminAuth(runtime.gateway.cfg, runtime.gateway.approver)
        self.auth.approver.name_of = self.store.name_of
        self.mutex = anyio.Lock()
        self.drafts = {}
        self.tests = {}
        from .oauth import OAuthVault
        from .admin_mcp_oauth import MCPConsent
        self.oauth = OAuthVault(self.store.base)
        from .web_sessions import WebSessions
        self.web_sessions = WebSessions(self.store.base)
        self.website_login = WebsiteLogin(self)
        self.website_catalogs = WebsiteCatalogs(self)
        self.mcp_oauth = MCPConsent(self)
        from .admin_oauth import GoogleConsent
        self.google = GoogleConsent(self)
        runtime.gateway = self._gateway(self.store.state)
        if not self.auth.initialized():
            self.auth.setup_link()

    def _gateway(self, state):
        from .server import Gateway
        cfg, lock, values = self.store.effective(state)
        result = Gateway(cfg, lock, values, self.runtime.gateway.audit, self.runtime.gateway.approver, self.oauth, self.web_sessions)
        from .catalog_sync import catalog_revision
        result.website_catalogs = self.website_catalogs
        result.configuration_revision = "web:" + str(state["revision"]) + ":" + catalog_revision(cfg, lock)
        return result

    async def sweep(self):
        while True:
            await anyio.sleep(30)
            await self.website_login.expire()
            async with self.mutex:
                now = time.time()
                self.drafts = {k: v for k, v in self.drafts.items() if v["expires"] > now}
                self.mcp_oauth.sweep()
                try:
                    self.oauth.prune({c.oauth_ref for c in self.runtime.gateway.cfg.connections if c.oauth_ref})
                except Exception:
                    self.runtime.gateway.audit.write("oauth_cleanup_failed", reason="storage_unavailable")
                self.prune_web_sessions(self.runtime.gateway)
                try:
                    self.website_catalogs.prune()
                except OSError:
                    self.runtime.gateway.audit.write("website_catalog_cleanup_failed", reason="storage_unavailable")
                pending = {f["ref"] for f in self.mcp_oauth.flows.values()} | {d.get("oauth_ref") for d in self.drafts.values()}
                for ref, record in list(self.oauth.records.items()):
                    if ref not in self.oauth.persisted and ref not in pending and record["created"] + 600 <= now:
                        self.oauth.discard(ref)
                self.google.flows = {k: v for k, v in self.google.flows.items() if v["expires"] > now}

    def prune_web_sessions(self, gateway):
        try:
            self.web_sessions.prune(gateway.cfg, gateway.secrets)
        except Exception:
            gateway.audit.write("web_session_cleanup_failed", reason="storage_unavailable")

    @asynccontextmanager
    async def editing(self):
        try:
            with anyio.fail_after(5):
                await self.mutex.acquire()
        except TimeoutError:
            raise Refused("admin_busy", 409) from None
        try:
            yield
        finally:
            self.mutex.release()

    def _revision(self, body):
        if type(body.get("revision")) is not int or body["revision"] != self.store.state["revision"]:
            raise Refused("configuration_changed", 409)

    async def _commit(self, state, action):
        # Member and household renames leave the revision unchanged. Keep
        # their latest names when publishing a draft.
        for kind in ("members", "households"):
            names = {m["id"]: m["name"] for m in self.store.state["config"][kind]}
            for member in state["config"][kind]:
                member["name"] = names.get(member["id"], member["name"])
        state["languages"] = self.store.state.get("languages", {}).copy()
        state["revision"] = self.store.state["revision"] + 1
        state, catalog_updates = self.store.reconcile(state)
        gateway = self._gateway(state)
        for route in gateway.routes.values():
            if route.problem:
                raise Refused({"pin_unknown_argument": "pin_unknown_argument", "allow_values_unknown_argument": "allow_values_unknown_argument",
                               "not_locked": "missing_tool_lock", "schema_invalid": "invalid_tool_schema",
                               "schema_remote_ref": "remote_tool_schema", "schema_not_object": "invalid_tool_schema"}.get(
                                   route.problem, "invalid_tool_configuration"), 400)

        def persist():
            refs = {c.oauth_ref for c in gateway.cfg.connections if c.oauth_ref}
            newly_active = refs - self.oauth.persisted
            try:
                self.oauth.activate(refs)
                self.store.save(state)
            except Exception:
                for ref in newly_active & self.oauth.persisted:
                    self.oauth.file.delete(ref)
                    self.oauth.persisted.remove(ref)
                raise
            try:
                self.oauth.prune(refs)
            except Exception:
                # Configuration is already durable. Retry credential cleanup in
                # the sweeper rather than leaving the old gateway running.
                gateway.audit.write("oauth_cleanup_failed", reason="storage_unavailable")
            self.store.catalog_updates = catalog_updates
            # Revision-bound approvals are unusable immediately after publication,
            # including a crash between the atomic state write and this cleanup.
            with self.auth.approver._db() as db:
                db.execute("UPDATE requests SET status='cancelled', outcome='configuration_changed', arguments=NULL, preview=NULL WHERE status IN ('pending','approved','queued')")

        try:
            await self.runtime.replace(gateway, persist)
        except TimeoutError:
            raise Refused("active_calls_busy", 409) from None
        self.prune_web_sessions(gateway)
        self.tests.clear()
        gateway.audit.write("admin_updated", principal=self.auth.owner, detail=action,
                            revision=state["revision"])
        return {"revision": state["revision"]}

    def state(self):
        from .admin_oauth import saved_gmail_client
        gw = self.runtime.gateway
        keys = self.auth.approver.passkeys()
        plugins = connector_plugins(self.store.base.admin.plugins_dir)
        connections = []
        for conn in gw.cfg.connections:
            tools = []
            for tool in conn.tools:
                route = gw.routes[tool.name]
                tools.append({"name": tool.name, "upstream": tool.upstream, "access": tool_access(conn, tool),
                              "mail_send": is_mail_send(conn, tool), "pin": tool.pin,
                              "allow_values": tool.allow_values, "problem": gw.problem(route),
                              "permissions": {c.id: gw.policy.effect(c.subject, tool.name, c.id) for c in gw.cfg.clients}})
            connections.append({"id": conn.id, "kind": kind_of(conn), "owner": conn.owner,
                                "household": gw.cfg.household_of(conn.owner), "approvers": list(gw.cfg.approvers_of(conn)),
                                "approver": conn.approver or conn.owner,
                                "access": {c.id: connection_access(gw.policy, c, conn) for c in gw.cfg.clients},
                                "settings": self.connection_settings(conn), "tools": tools,
                                "website": self.website(conn),
                                "plugin_credentials": {
                                    key: plugins[conn.plugin].credential_slots().get(key, key) if conn.plugin in plugins else key
                                    for key in conn.secret_env
                                } if conn.plugin else {},
                                "mailbox_access": conn.mailbox_access if bundled_kind(conn) in ("imap", "gmail") else None,
                                "mailbox": mailbox_metadata(conn),
                                "oauth": self.oauth.status(conn.oauth_ref) if conn.oauth_ref else None,
                                "catalog_sync": self.store.catalog_updates.get(conn.id),
                                "available_tools": [{**t, "access": tool_access(conn, ToolCfg.model_validate(t))} for t in catalog_additions(conn, gw.cfg)],
                                "connected": gw.upstreams[conn.id]._client is not None,
                                "test": self.tests.get(conn.id)})
        return {"version": __version__, "revision": self.store.state["revision"], "owner": self.auth.owner,
                "mcp_url": gw.cfg.approvals.origin + "/mcp",
                "households": [{"id": h.id, "name": self.store.name_of(h.id)} for h in gw.cfg.households],
                "members": [{"id": m.id, "name": self.store.name_of(m.id), "household": m.household,
                             "passkeys": sum(k["principal"] == m.id for k in keys)} for m in gw.cfg.members],
                "clients": [{"id": c.id, "household": c.household, "fingerprint": c.token_sha256[:12],
                             "tool_count": sum(gw.policy.effect(c.subject, t.name, c.id) != "deny"
                                               for conn in gw.cfg.connections for t in conn.tools)} for c in gw.cfg.clients],
                "connections": connections, "passkeys": keys,
                "language": self.store.state.get("languages", {}).get(self.auth.owner, "auto"),
                "gmail_oauth": {"client_id": self.store.state.get("gmail_client", {}).get("client_id"),
                                "saved_clients": [c.id for c in gw.cfg.connections if saved_gmail_client(c, gw.secrets)]},
                "plugins": [plugin.public() for plugin in plugins.values()],
                "website_login": self.website_login.available(),
                "catalog": {k: {f: v[f] for f in ("label", "fields", "secrets")} for k, v in CATALOG.items()
                            if k != "local" or any(p.kind != "web" for p in plugins.values())
                            or any(kind_of(c) == "local" for c in gw.cfg.connections)}}

    @staticmethod
    def stage_connection(state, cfg, conn, added):
        connections = state["config"]["connections"]
        updated = conn.model_dump(mode="json")
        state["secrets"].update(added)
        for index, previous in enumerate(cfg.connections):
            if previous.id == conn.id:
                connections[index] = updated
                referenced = conn.secret_names() | {key for c in cfg.connections if c.id != conn.id for key in c.secret_names()}
                for key in previous.secret_names() - referenced:
                    state["secrets"].pop(key, None)
                break
        else:
            if len(connections) >= 50:
                raise Refused("connector_limit", 400)
            connections.append(updated)

    async def save_connection(self, state, cfg, conn, added, previous):
        # Keep the approved capabilities and runtime settings on edits. A
        # different HTTP service endpoint must go through the review flow.
        if previous:
            if conn.url != previous.url:
                raise Refused("connector_review_required", 409)
            if conn.transport == "http":
                conn = previous.model_copy(update={
                    "bearer_secret": conn.bearer_secret,
                    "secret_headers": conn.secret_headers,
                    "oauth_ref": conn.oauth_ref,
                })
            elif kind_of(conn) != "demo":
                conn = previous.model_copy(update={
                    "env": previous.env | conn.env,
                    "secret_env": previous.secret_env | conn.secret_env,
                    "mailbox_email": conn.mailbox_email,
                    "mailbox_aliases": conn.mailbox_aliases,
                    **({"tools": conn.tools} if kind_of(conn) == "gmail" else {}),
                })
                if kind_of(conn) == "gmail":
                    removed = {tool.name for tool in previous.tools} - {tool.name for tool in conn.tools}
                    if removed:
                        state["config"]["policy"] = [
                            {**rule, "tools": [name for name in rule["tools"] if name not in removed]}
                            for rule in state["config"]["policy"]
                            if any(name not in removed for name in rule["tools"])
                        ]
                        upstreams = {t.upstream for t in previous.tools} - {t.upstream for t in conn.tools}
                        for name in upstreams:
                            state["locks"].get(conn.id, {}).pop(name, None)
                            state.get("bundled_catalog", {}).get(conn.id, {}).pop(name, None)
            else:
                conn, added = previous, {}
            _, _, values = self.store.effective(state)
            if conn == previous and all(values.get(key) == value for key, value in added.items()):
                return {"saved": True, "revision": state["revision"], "id": conn.id}
        elif bundled_kind(conn) is None:
            raise Refused("connector_review_required", 409)
        self.stage_connection(state, cfg, conn, added)
        result = await self._commit(state, "connections/save")
        return {**result, "saved": True, "id": conn.id}

    def preview_result(self, state, conn, added, definitions, session):
        from .admin_remote import remote_tools
        cfg, _, _ = self.store.effective(state)
        kind = kind_of(conn)
        remote = kind in ("remote", "local")
        cli = kind == "local" and MANIFEST_ENV in conn.env
        if remote:
            conn = remote_tools(conn, definitions, cfg)
            if cli:
                conn = conn.model_copy(update={"tools": [
                    t.model_copy(update={"access": "read" if definitions[t.upstream].get("annotations", {}).get("readOnlyHint") else "write"})
                    for t in conn.tools]})
        elif any(tool.upstream not in definitions for tool in conn.tools):
            raise Refused("missing_upstream_tool", 422)
        if not conn.tools:
            raise Refused("remote_no_tools", 422)
        self.stage_connection(state, cfg, conn, added)
        raw = state["config"]
        # Removed remote tools lose their rules before the candidate is validated.
        names = {t.name for t in conn.tools}
        raw["policy"] = [{**r, "tools": [t for t in r["tools"] if t in names]} if r["connection"] == conn.id else r
                         for r in raw["policy"] if r["connection"] != conn.id or any(t in names for t in r["tools"])]
        lock = Lock()
        for tool in conn.tools:
            lock.put(conn.id, definitions[tool.upstream])
        state["locks"][conn.id] = lock.entries[conn.id]
        self._gateway(state)
        self.drafts = {k: v for k, v in self.drafts.items() if v["expires"] > time.time()}
        if len(self.drafts) >= 16:
            raise Refused("too_many_drafts", 429)
        draft = secrets.token_urlsafe(24)
        self.drafts[draft] = {"state": state, "session": session["id"], "expires": time.time() + 600,
                              "connection": conn.id, "remote": remote, "oauth_ref": conn.oauth_ref}
        # Definitions can echo credentials. Scrub prior to displaying them too.
        scrubber = self._gateway(state).scrubber
        return {"draft": draft, "connection": conn.id, "definitions": scrubber.data(list({t.upstream: definitions[t.upstream] for t in conn.tools}.values())),
                "owner": conn.owner, "existing": any(c.id == conn.id for c in cfg.connections), "remote": remote, "fixed_access": cli,
                "tools": [{"upstream": t.upstream, "access": tool_access(conn, t)} for t in conn.tools],
                "oauth": self.oauth.status(conn.oauth_ref) if conn.oauth_ref else None}

    async def finish_remote_oauth(self, flow, session):
        state = self.store.candidate()
        cfg, _, values = self.store.effective(state)
        conn, added = make_connection(flow["body"], cfg, values)
        previous = next((c for c in cfg.connections if c.id == conn.id), None)
        if len(cfg.connections) >= 50 and previous is None:
            raise Refused("connector_limit", 400)
        conn = conn.model_copy(update={"oauth_ref": flow["ref"]})
        if previous and conn.url == previous.url:
            return await self.save_connection(state, cfg, conn, added, previous)
        return self.preview_result(state, conn, added, flow["definitions"], session)

    def website_connection(self, name):
        conn = next((c for c in self.runtime.gateway.cfg.connections if c.id == name and kind_of(c) == "web"), None)
        if not conn:
            raise Refused("not_found", 404)
        return conn

    @staticmethod
    def website(conn):
        if kind_of(conn) != "web":
            return None
        spec = WebProfile.saved(conn.env[PROFILE_ENV])
        return {"origin": spec.origin, "api_origins": connection_origins(conn)[1:], "experimental": spec.experimental}

    def connection_settings(self, conn):
        settings = settings_of(conn)
        if conn.oauth_ref:
            record = self.oauth.records.get(conn.oauth_ref, {})
            client = record.get("client") or {}
            settings.update(issuer=record.get("issuer") or "", scope=record.get("requested_scope") or "",
                            client_id="" if record.get("client_metadata_url") else client.get("client_id", ""), auth_method=client.get("token_endpoint_auth_method") or "none",
                            client_metadata_url=record.get("client_metadata_url") or "")
        return settings

    async def operate(self, operation, body, session, *, gmail_email=None):
        if operation == "oauth/mcp/start":
            return await self.mcp_oauth.start(body, session)
        if operation == "oauth/mcp/complete":
            key = body.get("id")
            flow = self.mcp_oauth.complete(key, session)
            result = await self.finish_remote_oauth(flow, session)
            del self.mcp_oauth.flows[key]
            return result
        if operation == "oauth/start":
            return self.google.start(body, session)
        if operation == "oauth/complete":
            key = body.get("id")
            connector, account = self.google.complete(key, session)
            result = await self.operate("connections/save", connector, session, gmail_email=account)
            del self.google.flows[key]
            return {**result, "google_account": account}
        if operation == "web-operation-rules/view":
            proposal_id = body.get("proposal")
            if set(body) - {"id", "proposal"} or (proposal_id is not None and
                    (not isinstance(proposal_id, str) or not re.fullmatch(r"[0-9a-f]{32}", proposal_id))):
                raise Refused("invalid_argument", 400)
            conn = self.website_connection(body.get("id"))
            proposal = self.website_catalogs.operation_rule_proposal(conn, proposal_id)
            return {"active": [rule.model_dump() for rule in conn.web_operation_rules], "proposal": proposal,
                    "revision": self.store.state["revision"]}
        if operation == "web-operation-rules/decide":
            self._revision(body)
            proposal_id, decision = body.get("proposal"), body.get("decision")
            if (set(body) != {"id", "proposal", "decision", "revision"} or decision not in ("approve", "reject")
                    or not isinstance(proposal_id, str) or not re.fullmatch(r"[0-9a-f]{32}", proposal_id)):
                raise Refused("invalid_argument", 400)
            conn = self.website_connection(body["id"])
            proposal = self.website_catalogs.operation_rule_proposal(conn, proposal_id)
            if proposal["status"] != "pending_admin_review":
                raise Refused("web_operation_rule_proposal_stale", 409)
            gateway = self.runtime.gateway
            author = next((c for c in gateway.cfg.clients if c.id == proposal["agent"]), None)
            if not author or not self.website_catalogs.connection(gateway, author, conn.id, PROPOSE_OPERATION_RULES):
                raise Refused("web_operation_rule_proposal_stale", 409)
            if decision == "reject":
                self.website_catalogs.save_operation_rule_proposal(conn, {**proposal, "rejected": True})
                gateway.audit.write("website_operation_rules_rejected", connection=conn.id, proposal=proposal_id)
                return {"status": "rejected"}
            state = self.store.candidate()
            raw = next(c for c in state["config"]["connections"] if c["id"] == conn.id)
            rules = {rule.endpoint: rule for rule in conn.web_operation_rules}
            for item in proposal["rules"]:
                rule = WebOperationRule.model_validate(item)
                rules[rule.endpoint] = rule
            raw["web_operation_rules"] = [rule.model_dump() for rule in rules.values()]
            result = await self._commit(state, operation)
            self.runtime.gateway.audit.write("website_operation_rules_approved", connection=conn.id, proposal=proposal_id,
                                             count=len(proposal["rules"]))
            return result
        if operation == "web-operation-rules/remove":
            self._revision(body)
            if set(body) != {"id", "origin", "method", "path", "revision"}:
                raise Refused("invalid_argument", 400)
            conn = self.website_connection(body["id"])
            rules = [rule.model_dump() for rule in conn.web_operation_rules
                     if rule.endpoint != (body["origin"], body["method"], body["path"])]
            if len(rules) == len(conn.web_operation_rules):
                raise Refused("not_found", 404)
            state = self.store.candidate()
            raw = next(c for c in state["config"]["connections"] if c["id"] == conn.id)
            raw["web_operation_rules"] = rules
            return await self._commit(state, operation)
        if operation == "web-catalog/view":
            conn = self.website_connection(body.get("id"))
            version = body.get("catalog_revision")
            if set(body) - {"id", "catalog_revision"} or version is not None and type(version) is not int:
                raise Refused("invalid_argument", 400)
            return {**self.website_catalogs.view(conn, version), **self.website(conn)}
        if operation == "web-catalog/origins":
            self._revision(body)
            if set(body) != {"id", "origins", "revision"}:
                raise Refused("invalid_argument", 400)
            conn = self.website_connection(body["id"])
            current = connection_origins(conn)
            try:
                origins = [o for o in api_origins(json.dumps(body["origins"])) if o != current[0]]
            except ValueError:
                raise Refused("website_origin_invalid", 400) from None
            if origins == current[1:]:
                return {"revision": self.store.state["revision"]}
            state = self.store.candidate()
            raw = next(c for c in state["config"]["connections"] if c["id"] == conn.id)
            raw["env"][ORIGINS_ENV] = json.dumps(origins)
            raw["web_operation_rules"] = [rule.model_dump() for rule in conn.web_operation_rules if rule.origin in [current[0], *origins]]
            return await self._commit(state, operation)
        if operation == "web-catalog/publisher":
            self._revision(body)
            if set(body) != {"id", "client", "revision"}:
                raise Refused("invalid_argument", 400)
            conn = self.website_connection(body["id"])
            gateway = self.runtime.gateway
            writer = body["client"]
            client = next((c for c in gateway.cfg.clients if c.id == writer), None)
            if writer is not None and (not client or not self.website_catalogs.eligible(gateway, client, conn)):
                raise Refused("website_catalog_publisher_needs_access", 400)
            binding = self.website_catalogs.binding(conn.id)
            if writer == (binding or {}).get("writer"):
                return {"revision": self.store.state["revision"]}
            state = self.store.candidate()
            self.website_catalogs.set_writer(state, conn.id, writer)
            return await self._commit(state, operation)
        if operation == "connections/mailboxes":
            if set(body) != {"id"}:
                raise Refused("invalid_argument", 400)
            gw = self.runtime.gateway
            conn = next((c for c in gw.cfg.connections if c.id == body["id"]), None)
            kind = bundled_kind(conn) if conn else None
            if kind not in ("imap", "gmail"):
                raise Refused("unsupported_connector", 400)
            paths, problem = {}, None
            try:
                with anyio.fail_after(26):
                    async with open_client(conn, {n: gw.secrets[n] for n in conn.secret_names()}, self.oauth) as upstream:
                        offset = 0
                        while True:
                            result = await upstream.call_tool("list_labels", {"offset": offset, "limit": 100}) if kind == "gmail" else await upstream.call_tool("list_mailboxes", {})
                            if result.is_error:
                                problem = probe_error(kind, result)
                                break
                            data = json.loads(result.content[0].text)
                            if kind == "imap":
                                for folder in data:
                                    if not any(flag.casefold() == "\\noselect" for flag in folder["flags"]):
                                        paths[folder["name"]] = folder["name"]
                                break
                            for label in data["labels"]:
                                paths[label["id"]] = label["name"]
                            next_offset = data.get("next_offset")
                            if next_offset is None:
                                break
                            if not isinstance(next_offset, int) or not offset < next_offset <= 10000:
                                problem = "mailbox_listing_unavailable"
                                break
                            offset = next_offset
            except Exception as exc:
                problem = connector_failure(exc, conn.transport)
            if problem:
                incident = secrets.token_hex(6)
                gw.audit.write("admin_mailbox_paths", connection=conn.id, reason=problem, detail=incident)
                raise Refused(problem, 422, incident=incident)
            return {"paths": [{"id": path, "name": name} for path, name in paths.items() if valid_mailbox_paths([path])]}
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
                    async with open_client(conn, {n: values[n] for n in conn.secret_names()}, self.oauth,
                                           web_sessions=self.web_sessions if kind_of(conn) == "web" else None) as client:
                        live = {t.name: definition_of(t) for t in await list_all_tools(client)}
                        if any(self.runtime.gateway.lock.get(conn.id, tool.upstream) is None or
                               digest_of(live.get(tool.upstream, {})) != self.runtime.gateway.lock.get(conn.id, tool.upstream)["sha256"]
                               for tool in conn.tools):
                            problem = "tool_definitions_changed"
                        elif probe:
                            result = await client.call_tool(probe, arguments)
                            if result.is_error:
                                problem = probe_error(kind_of(conn), result)
                            elif kind_of(conn) == "web":
                                code = json.loads(result.content[0].text)["status"]
                                if code >= 400:
                                    problem = {401: "connector_auth_rejected", 403: "connector_access_denied",
                                               404: "connector_endpoint_missing", 429: "connector_rate_limited"}.get(code, "connector_http_error")
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
        if operation == "settings/language":
            if set(body) != {"revision", "language"} or body["language"] not in ("auto", "en", "zh-CN"):
                raise Refused("invalid_language", 400)
            state = copy.deepcopy(self.store.state)
            state.setdefault("languages", {})[self.auth.owner] = body["language"]
            self.store.save(state)
            return {"language": body["language"]}
        if operation == "settings/gmail-oauth":
            from .admin_oauth import saved_gmail_client
            state = self.store.candidate()
            if set(body) == {"revision", "connection"} and isinstance(body["connection"], str):
                gw = self.runtime.gateway
                source = next((c for c in gw.cfg.connections if c.id == body["connection"]), None)
                client = saved_gmail_client(source, gw.secrets) if source else None
                if not client:
                    raise Refused("gmail_saved_client_unavailable", 400)
            elif set(body) == {"revision", "client_id", "client_secret"}:
                client = {key: body[key] for key in ("client_id", "client_secret")}
                if not all(isinstance(value, str) and 1 <= len(value.strip()) <= 4096 for value in client.values()):
                    raise Refused("gmail_client_config_invalid", 400)
                client = {key: value.strip() for key, value in client.items()}
            else:
                raise Refused("gmail_client_config_invalid", 400)
            if client == state.get("gmail_client"):
                return {"revision": state["revision"]}
            state["gmail_client"] = client
            return await self._commit(state, operation)
        if operation == "oauth/revoke":
            conn = next((c for c in self.runtime.gateway.cfg.connections if c.id == body.get("id")), None)
            if not conn or not conn.oauth_ref:
                raise Refused("not_found", 404)
            try:
                with anyio.fail_after(30):
                    result = await self.oauth.revoke(conn.oauth_ref)
            except TimeoutError:
                if self.oauth.get(conn.oauth_ref).get("tokens"):
                    raise Refused("oauth_refresh_busy", 409) from None
                result = "failed"
            self.tests.pop(conn.id, None)
            self.runtime.gateway.audit.write("admin_oauth_revoked", connection=conn.id, principal=self.auth.owner, reason=result)
            return {"local_revoked": True, "provider": result}
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
            return {**await self._commit(state, operation), "id": identity}
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
                for binding in state.get("website_catalogs", {}).values():
                    if binding.get("writer") == name:
                        binding["writer"] = renamed
                for rule in raw["policy"]:
                    rule["clients"] = [renamed if c == name else c for c in rule["clients"]]
                for conn in raw["connections"]:
                    scopes = conn["mailbox_access"]
                    if name in scopes:
                        scopes[renamed] = scopes.pop(name)
            elif operation == "clients/rotate":
                token = new_token()
                client["token_sha256"] = hash_token(token)
            else:
                raw["clients"].remove(client)
                for binding in state.get("website_catalogs", {}).values():
                    if binding.get("writer") == name:
                        binding["writer"] = None
                raw["policy"] = [{**r, "clients": [c for c in r["clients"] if c != name]}
                                 for r in raw["policy"] if any(c != name for c in r["clients"])]
                for conn in raw["connections"]:
                    conn["mailbox_access"].pop(name, None)
            result = await self._commit(state, operation)
            if operation == "clients/rename":
                result["id"] = client["id"]
            if token:
                result.update(token=token, fingerprint=hash_token(token)[:12], mcp_url=self.runtime.gateway.cfg.approvals.origin + "/mcp")
            return result
        if operation == "connections/rename":
            name, renamed = body.get("id"), body.get("name")
            conn = next((c for c in raw["connections"] if c["id"] == name), None)
            if conn is None:
                raise Refused("not_found", 404)
            if renamed == name:
                return {"revision": self.store.state["revision"], "id": name}
            if not isinstance(renamed, str) or not re.fullmatch(CONNECTOR_NAME, renamed):
                raise Refused("invalid_connector_name", 400)
            if any(c["id"] == renamed for c in raw["connections"]):
                raise Refused("duplicate_connector", 409)
            if any(event.connection == name for event in self.store.base.mail_events):
                # gateway.yaml names it for new-mail events and the web cannot change that file (docs/deployment.md 5.4).
                raise Refused("mail_events_rename_first", 409)
            _, lock, _ = self.store.effective(state)
            conn["id"] = renamed
            for rule in raw["policy"]:
                if rule["connection"] == name:
                    rule["connection"] = renamed
            state["locks"][renamed] = copy.deepcopy(lock.entries.get(name, {}))
            state["locks"].pop(name, None)
            catalogs = state.get("website_catalogs", {})
            if name in catalogs:
                catalogs[renamed] = catalogs.pop(name)
            metadata = state.get("bundled_catalog", {})
            if name in metadata:
                metadata[renamed] = metadata.pop(name)
            result = await self._commit(state, operation)
            return {**result, "id": renamed}
        if operation in ("connections/save", "connections/preview", "connections/review-tools"):
            cfg, _, values = self.store.effective(state)
            if operation == "connections/review-tools":
                if set(body) - {"id", "revision"}:
                    raise Refused("invalid_connector", 400)
                previous = next((c for c in cfg.connections if c.id == body.get("id")), None)
                if previous is None:
                    raise Refused("not_found", 404)
                if kind_of(previous) not in CATALOG:
                    raise Refused("unsupported_connector", 400)
                conn, added = extend_catalog_tools(previous, cfg), {}
            else:
                plugins = connector_plugins(self.store.base.admin.plugins_dir) if body.get("kind") in ("local", "web") else None
                conn, added = make_connection(body, cfg, values, gmail_email=gmail_email, plugins=plugins)
            if len(raw["connections"]) >= 50 and not any(c["id"] == conn.id for c in raw["connections"]):
                raise Refused("connector_limit", 400)
            if kind_of(conn) == "remote" and body.get("settings", {}).get("auth") == "oauth":
                if not conn.oauth_ref:
                    raise Refused("oauth_reauthorization_required", 400)
                if operation == "connections/save":
                    saved = self.connection_settings(conn)
                    fields = ("issuer", "client_id", "auth_method", "scope", "client_metadata_url")
                    if body.get("credentials", {}).get("client_secret") or any(
                            key in body["settings"] and body["settings"][key] != saved[key] for key in fields):
                        raise Refused("oauth_reauthorization_required", 400)
            if operation == "connections/save":
                previous = next((c for c in cfg.connections if c.id == conn.id), None)
                return await self.save_connection(state, cfg, conn, added, previous)
            if kind_of(conn) == "web":
                raise Refused("unsupported_connector", 400)
            values.update(added)
            try:
                with anyio.fail_after(35):
                    async with open_client(conn, {n: values[n] for n in conn.secret_names()}, self.oauth) as client:
                        definitions = {t.name: definition_of(t) for t in await list_all_tools(client)}
            except Exception as exc:
                reason, incident = connector_failure(exc, conn.transport), secrets.token_hex(6)
                self.runtime.gateway.audit.write("admin_connector_preview", reason=reason, detail=f"{incident}:{type(exc).__name__}")
                raise Refused(reason, 422, incident=incident) from None
            return self.preview_result(state, conn, added, definitions, session)
        if operation == "connections/apply":
            draft = self.drafts.get(body.get("draft"))
            if not draft or draft["session"] != session["id"] or draft["expires"] <= time.time():
                raise Refused("draft_expired", 409)
            if draft["state"]["revision"] != self.store.state["revision"]:
                raise Refused("configuration_changed", 409)
            if body.get("reviewed") is not True:
                raise Refused("review_required", 400)
            draft = copy.deepcopy(draft)
            if draft.get("remote"):
                from .admin_remote import apply_selection
                apply_selection(draft, body)
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
            state.get("website_catalogs", {}).pop(name, None)
            referenced = {n for c in raw["connections"] for n in [*c.get("secret_env", {}).values(),
                          *c.get("secret_headers", {}).values(), c.get("bearer_secret")] if n}
            state["secrets"] = {k: v for k, v in state["secrets"].items() if k in referenced}
            result = await self._commit(state, operation)
            # Messages still waiting for the Sent folder belong to the removed mailbox; a later
            # connection reusing this name must never file them.
            from .server import connector_state_dir
            shutil.rmtree(connector_state_dir(self.runtime.gateway.cfg, name), ignore_errors=True)
            return result
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
            if mode != "custom" and CONNECTION_ACCESS[mode]["write"] != "deny" and not any(tool_access(conn, t) in ("write", "dynamic") for t in conn.tools):
                raise Refused("connection_tools_update_required" if any(tool_access(conn, ToolCfg.model_validate(t)) == "write" for t in catalog_additions(conn, cfg)) else "connection_readonly", 400)
            send_effect = body.get("mail_send")
            if "mail_send" in body and (mode == "custom" or CONNECTION_ACCESS[mode]["write"] == "deny"
                    or send_effect not in ("deny", "approval_required", "allow", "keep")
                    or not any(is_mail_send(conn, tool) for tool in conn.tools)):
                raise Refused("invalid_mail_send_permission", 400)
            if "approver" in body:
                approver = body["approver"]
                if not isinstance(approver, str) or approver not in cfg.principals or cfg.household_of(approver) != client.household:
                    raise Refused("invalid_connection_approver", 400)
                next(c for c in raw["connections"] if c["id"] == name)["approver"] = approver
            if "mailbox_paths" in body:
                paths = body["mailbox_paths"]
                if bundled_kind(conn) not in ("imap", "gmail") or (paths is not None and not valid_mailbox_paths(paths)):
                    raise Refused("invalid_mailbox_paths", 400)
                scopes = next(c for c in raw["connections"] if c["id"] == name)["mailbox_access"]
                if paths is None:
                    scopes.pop(client_id, None)
                else:
                    scopes[client_id] = sorted(paths)
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
                access = tool_access(conn, tool)
                if access == "dynamic":
                    for kind, effect in CONNECTION_ACCESS[mode].items():
                        raw["policy"].append({"clients": [client_id], "connection": name, "tools": [tool.name],
                                              "effect": effect, "operation": kind})
                    continue
                effect = CONNECTION_ACCESS[mode][access]
                send = is_mail_send(conn, tool)
                if send:
                    if CONNECTION_ACCESS[mode]["write"] == "deny":
                        effect = "deny"
                    elif send_effect == "keep":
                        effect = self.runtime.gateway.policy.effect(client.subject, tool.name, client.id)
                    else:
                        effect = send_effect or "approval_required"
                raw["policy"].append({"clients": [client_id], "connection": name, "tools": [tool.name], "effect": effect,
                                      "mail_send_direct": send and effect == "allow"})
            return await self._commit(state, operation)
        if operation == "permissions/save":
            client_id, name, tool = body.get("client"), body.get("connection"), body.get("tool")
            conn = next((c for c in raw["connections"] if c["id"] == name), None)
            client = next((c for c in raw["clients"] if c["id"] == client_id), None)
            if not client:
                raise Refused("unknown_agent", 400)
            if not conn or not any(t["name"] == tool for t in conn["tools"]):
                raise Refused("not_found", 404)
            if PROFILE_ENV in conn.get("env", {}) and conn.get("plugin"):
                raise Refused("unsupported_connector", 400)
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
            current_conn = cfg.connection(name)
            selected = next(t for t in current_conn.tools if t.name == tool)
            raw["policy"].append({"connection": name, "clients": [client_id], "tools": [tool], "effect": body["effect"],
                                  "mail_send_direct": body["effect"] == "allow" and is_mail_send(current_conn, selected)})
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
            return admin_page()

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
                        async with self.editing():
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
                    await self.website_login.expire(logout=session["id"])
                    response = _json({"ok": True}, 200)
                    response.delete_cookie(cookie_name, path=cookie_path, secure=secure, httponly=True, samesite="strict")
                    return response
                if operation == "registry/search":
                    return _json(await registry.search(body), 200)
                browser_control = operation in ("web-login/start", "web-login/terminate")
                if operation.startswith("web-login/") and not browser_control:
                    return _json(await self.website_login.input(operation.split("/", 1)[1], body, session, token), 200)
                async with self.editing():
                    session = self.auth.session(token)  # may have expired while waiting
                    if needs_admin_confirmation(operation, body):
                        revision = self.store.state["revision"]
                        if "confirmation" not in body:
                            ceremony = self.auth.begin_confirmation(session, operation, body, revision)
                            return _json({"error": "admin_confirmation_required", "confirmation": ceremony}, 403)
                        proof = body.pop("confirmation")
                        self.auth.confirm(session, operation, body, revision, proof)
                    if not browser_control:
                        return _json(await self.operate(operation, body, session), 200)
                # Browser calls may save the session under the admin mutex.
                # Do not hold that mutex while acquiring the browser lock.
                if operation == "web-login/terminate":
                    return _json(await self.website_login.terminate(body, token), 200)
                result = await self.website_login.start(body, session, request.headers.get("user-agent"))
                return _json(result, 200)
            except Refused as exc:
                return _json({"error": exc.code, **({"incident": exc.incident} if exc.incident else {})}, exc.status)
            except Exception as exc:
                return failure_response(exc, self.runtime.gateway.audit, _PAGE_HEADERS)

        async def oauth_callback(request):
            # Cross-site provider navigation has no SameSite=Strict cookie. The
            # one-use state is bound to a still-live session; only that session
            # can subsequently review/apply the result via a CSRF-protected POST.
            try:
                if request.headers.get("host") != authority:
                    raise Refused("wrong_origin")
                target = await (self.mcp_oauth if request.url.path.endswith("/mcp/callback") else self.google).callback(request.query_params)
                return RedirectResponse(target, status_code=303, headers=_PAGE_HEADERS)
            except Refused as exc:
                error = _json({"error": exc.code}, exc.status)
            except Exception as exc:
                error = failure_response(exc, self.runtime.gateway.audit, _PAGE_HEADERS)
            # OAuth callbacks are browser navigations, so render the normal UI
            # with the error instead of leaving the person on a JSON document.
            data = {**json.loads(error.body), "status": error.status_code}
            marker = '<meta name="gateway-error" content="' + html.escape(json.dumps(data), quote=True) + '">'
            page = _static("admin.html", "text/html").body.decode().replace("</head>", marker + "</head>")
            return HTMLResponse(page, status_code=error.status_code, headers=_ADMIN_PAGE_HEADERS)

        return [Route("/", page), Route("/admin", page), Route("/admin/", page),
                *(Route(f"/admin/{section}", page) for section in ("members", "agents", "connections", "permissions", "settings")),
                Route("/admin/oauth/google/callback", oauth_callback),
                Route("/admin/oauth/mcp/callback", oauth_callback),
                Route("/admin/assets/{name}", asset),
                Route("/admin/api/{operation:path}", api, methods=["GET", "POST"])]
