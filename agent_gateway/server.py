"""The gateway: an MCP server whose two handlers enforce the whole policy.

`tools/list` and `tools/call` are the only MCP methods implemented. Resources,
prompts, sampling and elicitation are not proxied, so an upstream has exactly
one way to reach an agent: the result of a tool that agent was allowed to call.

Order of checks in a call, each one failing closed:
  1. identity      from the HTTP request's bearer token, never from arguments
  2. routing       the exposed name must exist
  3. policy        (principal, tool) must not be `deny`; default is deny
  4. definition    the tool must be locked and unchanged upstream
  5. arguments     validated against the schema the agent was shown; pins applied
  6. approval      `approval_required` asks the approver; without a human decision
                   bound to this exact call, nothing runs
  7. upstream call with that account's credentials, a timeout, a size limit
  8. scrub         known secret values are removed from whatever comes back
"""

from __future__ import annotations

import copy
import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import anyio
import mcp_types as types
from jsonschema import exceptions as jsonschema_exceptions
from jsonschema.validators import Draft202012Validator, validator_for
from mcp import MCPError
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, RequireAuthMiddleware
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from referencing import Registry
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import __version__
from .approval import NOT_EXECUTED, ApprovalRequest, Approver, DenyAllApprover, arguments_digest
from .audit import Audit
from .auth import StaticTokenVerifier, caller_of
from .config import Config, ConnectionCfg, ToolCfg, is_mail_send
from .credentials import Scrubber
from .lock import Lock
from .policy import Policy
from .upstream import Upstream, UpstreamError

logger = logging.getLogger("agent_gateway")

# uvicorn settings, shared by `agw serve` and the test rig so both run the same server.
SERVE_OPTIONS: dict[str, Any] = {
    "access_log": False,  # the audit log is the record of who called what
    "proxy_headers": False,  # the audit log records the real peer, not a header's claim
    "server_header": False,
}

# Identical for "no such tool" and "not yours", so a caller cannot probe for names.
_UNKNOWN_TOOL = "Unknown tool"


class ToolUnusable(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class ToolRoute:
    conn: ConnectionCfg
    tool: ToolCfg
    exposed: types.Tool | None = None
    validator: Any = None
    problem: str | None = None  # why the tool can never be served with the current lock/config


def _reject_remote_refs(node: Any) -> None:
    """A schema may only reference itself. Anything else would be a fetch the upstream chose."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("$ref", "$dynamicRef", "$recursiveRef") and not (isinstance(value, str) and value.startswith("#")):
                raise ToolUnusable("schema_remote_ref")
            _reject_remote_refs(value)
    elif isinstance(node, list):
        for item in node:
            _reject_remote_refs(item)


def exposed_schema(tool: ToolCfg, locked_schema: Any) -> dict[str, Any]:
    """The input schema an agent sees: the reviewed one, minus pins, plus restrictions."""
    schema = copy.deepcopy(locked_schema)
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise ToolUnusable("schema_not_object")
    _reject_remote_refs(schema)
    properties = schema.setdefault("properties", {})
    if not isinstance(properties, dict):
        raise ToolUnusable("schema_not_object")
    required = [name for name in schema.get("required", []) if isinstance(name, str)]
    for key in tool.pin:
        if key not in properties:
            raise ToolUnusable("pin_unknown_argument")
        del properties[key]
        required = [name for name in required if name != key]
    for key, values in tool.allow_values.items():
        if key not in properties:
            raise ToolUnusable("allow_values_unknown_argument")
        spec = dict(properties[key]) if isinstance(properties[key], dict) else {}
        spec["enum"] = list(values)
        properties[key] = spec
        if key not in required:
            required.append(key)
    schema["required"] = required
    # Only arguments that were reviewed in the lock file are accepted.
    schema["additionalProperties"] = False
    return schema


def build_route(conn: ConnectionCfg, tool: ToolCfg, locked: dict[str, Any] | None) -> ToolRoute:
    route = ToolRoute(conn=conn, tool=tool)
    if locked is None:
        route.problem = "not_locked"
        return route
    definition = locked["definition"]
    try:
        schema = exposed_schema(tool, definition.get("inputSchema"))
        validator_cls = validator_for(schema, default=Draft202012Validator)
        validator_cls.check_schema(schema)
        # An empty registry: `$ref`s resolve inside the schema or not at all (no network).
        route.validator = validator_cls(schema, registry=Registry())
        route.exposed = types.Tool(
            name=tool.name,
            title=definition.get("title"),
            description=tool.description or definition.get("description"),
            input_schema=schema,
            output_schema=definition.get("outputSchema"),
            annotations=definition.get("annotations"),
        )
    except ToolUnusable as exc:
        route.problem = exc.reason
    except (jsonschema_exceptions.SchemaError, ValueError):
        route.problem = "schema_invalid"
    return route


def _error(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)


def make_approver(cfg: Config, audit: Audit) -> Approver:
    """The config decides only whether a place to ask people exists; never who says yes."""
    if cfg.approvals is None:
        return DenyAllApprover()
    from .passkey import PasskeyApprover  # imported only when used, so the core does not need WebAuthn

    approver = PasskeyApprover(cfg.approvals, audit, retention_days=cfg.audit.retention_days)
    approver.name_of = cfg.name_of
    return approver


class Gateway:
    def __init__(
        self,
        cfg: Config,
        lock: Lock,
        secrets: dict[str, str],
        audit: Audit,
        approver: Approver | None = None,
        oauth=None,
        web_sessions=None,
    ) -> None:
        self.cfg = cfg
        self.lock = lock
        self.secrets = dict(secrets)
        self.configuration_revision = ""
        self.audit = audit
        self.policy = Policy(cfg)
        self.approver: Approver = approver or make_approver(cfg, audit)
        self.oauth = oauth
        self.scrubber = Scrubber(list(secrets.values()), (lambda: oauth.sensitive) if oauth else None)
        self.upstreams: dict[str, Upstream] = {}
        self.routes: dict[str, ToolRoute] = {}
        for conn in cfg.connections:
            own = {name: secrets[name] for name in conn.secret_names()}
            self.upstreams[conn.id] = Upstream(conn, own, lock, audit, oauth, web_sessions)
            for tool in conn.tools:
                self.routes[tool.name] = build_route(conn, tool, lock.get(conn.id, tool.upstream))

    def problem(self, route: ToolRoute) -> str | None:
        return route.problem or self.upstreams[route.conn.id].blocked.get(route.tool.upstream)

    # -- MCP handlers ---------------------------------------------------------

    async def list_tools(self, ctx: Any, params: Any) -> types.ListToolsResult:
        who = caller_of(ctx.request, self.cfg.clients)
        if who is None:
            raise MCPError(types.INVALID_REQUEST, "Not authenticated")
        if self.cfg.server.tool_discovery == "search":
            from .discovery import TOOLS
            return types.ListToolsResult(tools=TOOLS)
        tools = [
            route.exposed
            for name, route in self.routes.items()
            if route.exposed is not None
            and self.policy.effect(who.principal, name, who.client_id) != "deny"
            and self.problem(route) is None
        ]
        return types.ListToolsResult(tools=tools)

    async def call_tool(self, ctx: Any, params: types.CallToolRequestParams, dispatcher):
        started = time.monotonic()
        who = caller_of(ctx.request, self.cfg.clients)
        if who is None:
            raise MCPError(types.INVALID_REQUEST, "Not authenticated")
        name = params.name
        route = self.routes.get(name)
        arguments = params.arguments or {}
        background = False
        from . import discovery
        from .request_store import IdempotencyConflict, SubmissionKey

        key = None
        key_value = None
        if name in discovery.BY_NAME and (self.cfg.server.tool_discovery == "search" or name == discovery.CALL_TOOL):
            def discovery_audit(decision, reason):
                self.audit.write("tool_call", client=who.client_id, principal=who.principal, tool=name,
                                 remote=ctx.request.client.host if ctx.request.client else None,
                                 decision=decision, reason=reason, arg_keys=sorted(arguments),
                                 duration_ms=int((time.monotonic() - started) * 1000))

            validator = Draft202012Validator(discovery.BY_NAME[name].input_schema)
            failure = jsonschema_exceptions.best_match(validator.iter_errors(arguments))
            if failure is not None:
                discovery_audit("deny", "invalid_arguments")
                return _error("Invalid discovery arguments: " + failure.message[:300])
            if name != discovery.CALL_TOOL:
                data = (discovery.search_tools if name == discovery.SEARCH_TOOLS else discovery.search_connections)(self, who, arguments)
                payload = json.dumps(self.scrubber.data(data), ensure_ascii=False)
                if len(payload.encode()) > self.cfg.server.max_result_bytes // 2:
                    discovery_audit("deny", "result_too_large")
                    return _error("Discovery result is too large. Narrow the query or use a smaller limit.")
                discovery_audit("allow", "discovery")
                return types.CallToolResult(content=[types.TextContent(type="text", text=payload)])
            key_value = arguments["idempotency_key"]
            key = SubmissionKey.from_call(arguments)
            background = arguments.get("background", False)
            if existing := dispatcher.existing_key(ctx.request, key):
                return dispatcher.submission(ctx, existing, key_value, background=background)
            choices = discovery.candidates(self, who, arguments)
            if not choices:
                discovery_audit("deny", "unknown_tool")
                raise MCPError(types.INVALID_PARAMS, _UNKNOWN_TOOL)
            if len(choices) > 1:
                valid = []
                for candidate in choices:
                    try:
                        if not set(arguments["arguments"]) & candidate.tool.pin.keys() and candidate.validator.is_valid(arguments["arguments"]):
                            valid.append(candidate)
                    except Exception:  # an unresolved local schema reference cannot select a route
                        continue
                if len(valid) != 1:
                    discovery_audit("deny", "ambiguous_variant")
                    return _error("This connection has multiple permitted parameter variants. Select a variant from gateway_search_connections.")
                choices = valid
            route, arguments = choices[0], arguments["arguments"]
            name = route.tool.name
        peer = ctx.request.client
        record: dict[str, Any] = {
            "client": who.client_id,
            "principal": who.principal,
            # Where the call came from: shows a token being used from an unexpected machine.
            "remote": peer.host if peer else None,
            # A name that matched nothing is caller-chosen text; keep the log line bounded.
            "tool": name if route else str(name)[:64],
            "arg_keys": sorted(str(key)[:64] for key in arguments)[:32],
        }
        if route is not None:
            record.update(
                connection=route.conn.id,
                service=route.conn.service,
                account=route.conn.account,
                upstream_tool=route.tool.upstream,
            )

        def done(decision: str, reason: str, **extra: Any) -> None:
            duration = int((time.monotonic() - started) * 1000)
            self.audit.write("tool_call", decision=decision, reason=reason, duration_ms=duration, **record, **extra)

        effect = self.policy.effect(who.principal, name, who.client_id) if route is not None else "deny"
        if route is None or effect == "deny":
            done("deny", "unknown_tool" if route is None else "policy_deny")
            raise MCPError(types.INVALID_PARAMS, _UNKNOWN_TOOL)

        try:
            return await self._call(ctx, dispatcher, who, route, effect, arguments, done,
                                    background=background, key=key, key_value=key_value)
        except IdempotencyConflict:
            raise MCPError(types.INVALID_PARAMS, "This idempotency_key is already bound to another operation.") from None
        except MCPError:
            raise
        except Exception as exc:  # never let an internal error message reach an agent
            logger.exception("internal error in tool call")
            done("error", "internal_error", detail=type(exc).__name__)
            return _error("The gateway failed to process this call.")

    def _prepare_call(self, client_id, route, arguments, done):
        problem = self.problem(route)
        if problem is not None or route.exposed is None:
            done("deny", problem or "not_locked")
            return _error("This tool is disabled until an administrator reviews its definition.")

        pinned = sorted(key for key in arguments if key in route.tool.pin)
        if pinned:
            done("deny", "pinned_argument_supplied")
            return _error(f"Invalid arguments: {', '.join(pinned)} cannot be set for this tool.")
        try:
            failure = jsonschema_exceptions.best_match(route.validator.iter_errors(arguments))
        except Exception:  # e.g. a `$ref` that does not resolve inside the schema
            done("deny", "schema_unusable")
            return _error("This tool is disabled until an administrator reviews its definition.")
        if failure is not None:
            done("deny", "invalid_arguments")
            # The message quotes the caller's own input back to the caller; it is not logged.
            return _error(f"Invalid arguments: {failure.message[:300]}")

        final_arguments = {**arguments, **route.tool.pin}
        scope = route.conn.mailbox_access.get(client_id)
        upstream_arguments = final_arguments
        if scope is not None and not is_mail_send(route.conn, route.tool):
            from .catalog_sync import bundled_kind
            from .connectors._mail_scope import ARGUMENT, TOOLS, in_folder
            kind = bundled_kind(route.conn)
            if (route.tool.upstream not in TOOLS.get(kind, ()) or
                    (kind == "imap" and route.tool.upstream != "list_mailboxes" and
                     (not in_folder(final_arguments.get("mailbox", "INBOX"), scope) or
                      ("destination" in final_arguments and not in_folder(final_arguments["destination"], scope))))):
                done("deny", "mail_scope_denied")
                return _error("This action is outside the Agent's allowed mailbox folders or labels.")
            upstream_arguments = {**final_arguments, ARGUMENT: scope}

        return final_arguments, upstream_arguments

    def _approval_request(self, client, route, final_arguments, *, requires_approval=True):
        return ApprovalRequest(
            principal=client.subject, client_id=client.id, tool=route.tool.name, connection=route.conn.id,
            service=route.conn.service, account=route.conn.account, upstream_tool=route.tool.upstream,
            arguments_sha256=arguments_digest(final_arguments), arguments=final_arguments, owner=route.conn.owner,
            approvers=self.cfg.approvers_of(route.conn) if requires_approval else (), configuration_revision=self.configuration_revision,
            client_token_sha256=client.token_sha256, background=not requires_approval,
            target_sha256=arguments_digest({
                "connection": route.conn.model_dump(mode="json", exclude={"tools", "mailbox_email", "mailbox_aliases"}),
                "tool": route.tool.model_dump(mode="json"),
                "definition": self.lock.get(route.conn.id, route.tool.upstream),
            }),
        )

    async def _call(self, ctx, dispatcher, who, route, effect, arguments, done, *, background=False, key=None, key_value=None):
        prepared = self._prepare_call(who.client_id, route, arguments, done)
        if isinstance(prepared, types.CallToolResult):
            return prepared
        final_arguments, upstream_arguments = prepared
        if effect != "approval_required" and key is None:
            return await self._run(route, upstream_arguments, done, "ok")

        from .passkey import PasskeyApprover
        from .request_store import QueueFull

        client = next(c for c in self.cfg.clients if c.id == who.client_id)
        if effect != "approval_required":
            request = self._approval_request(client, route, final_arguments, requires_approval=False)
            try:
                job = dispatcher.store.enqueue(request, key)
            except QueueFull:
                done("deny", "too_many_queued")
                return _error("Too many queued operations. Check existing keys before starting more.")
            dispatcher.notify()
            done("queued", "submission", request_id=job)
            return dispatcher.submission(ctx, job, key_value, background=background)

        request = self._approval_request(client, route, final_arguments)
        if isinstance(self.approver, PasskeyApprover):
            decision = await self.approver.authorize(request, key=key)
        elif key is not None:
            done("deny", "approval:unavailable")
            return _error(NOT_EXECUTED)
        else:
            decision = await self.approver.authorize(request)
        approval = decision.approval_id
        if not decision.approved:
            done("deny", f"approval:{decision.reason}", approval=approval)
            if approval and isinstance(self.approver, PasskeyApprover):
                return dispatcher.submission(ctx, approval, key_value or approval, message=decision.message)
            return _error(decision.message or NOT_EXECUTED)
        # From here the approval is spent, whatever happens. Tell the approver how it ended.
        outcome = "internal_error"

        def approved_done(decision_: str, reason: str, **extra: Any) -> None:
            nonlocal outcome
            outcome = reason if decision_ == "error" else ("tool_error" if extra.get("is_error") else "ok")
            done(decision_, reason, approval=approval, **extra)

        try:
            return await self._run(route, upstream_arguments, approved_done, "approved")
        finally:
            if approval is not None:
                with anyio.CancelScope(shield=True):
                    await self.approver.finished(approval, outcome)

    async def run_dispatched(self, row):
        """Recheck the saved call against the leased, current policy before sending it."""
        client = next((c for c in self.cfg.clients if c.id == row["client"] and c.token_sha256 == row["client_token_sha256"]), None)
        route = self.routes.get(row["tool"])
        started = time.monotonic()
        outcome = "configuration_changed"
        approval_required = row["status"] == "approved"

        def done(decision, reason, **extra):
            nonlocal outcome
            if decision == "allow":
                outcome = "tool_error" if extra.get("is_error") else "ok"
            elif decision == "error":
                outcome = ("execution_unknown" if extra.get("execution_uncertain") or
                           reason in ("upstream_timeout", "upstream_invalid_reply", "result_too_large") else reason)
            self.audit.write("tool_call", client=row["client"], principal=row["principal"], tool=row["tool"],
                             connection=row["connection"], service=row["service"], account=row["account"],
                             upstream_tool=row["upstream_tool"], **({"approval": row["id"]} if approval_required else {"request_id": row["id"]}), decision=decision,
                             reason=reason, duration_ms=int((time.monotonic() - started) * 1000), **extra)

        if (not client or client.subject != row["principal"] or not route
                or row["revision"] != self.configuration_revision
                or self.policy.effect(client.subject, route.tool.name, client.id) != ("approval_required" if approval_required else "allow")
                or (approval_required and set(self.cfg.approvers_of(route.conn)) != set(json.loads(row["approvers"])))):
            done("deny", "configuration_changed")
            return None, outcome
        arguments = json.loads(row["arguments"])
        prepared = self._prepare_call(client.id, route, {key: v for key, v in arguments.items() if key not in route.tool.pin}, done)
        if isinstance(prepared, types.CallToolResult):
            return None, outcome
        final_arguments, upstream_arguments = prepared
        if self._approval_request(client, route, final_arguments, requires_approval=approval_required).binding != row["binding"]:
            done("deny", "configuration_changed")
            return None, outcome
        result = await self._run(route, upstream_arguments, done, "approved" if approval_required else "background_completed")
        return result, outcome

    async def _run(self, route: ToolRoute, final_arguments: dict[str, Any], done: Any, ok_reason: str) -> types.CallToolResult:
        try:
            result = await self.upstreams[route.conn.id].call(route.tool.upstream, final_arguments)
        except UpstreamError as exc:
            done("error", exc.reason, **({"execution_uncertain": True} if exc.execution_uncertain else {}))
            return _error(exc.public)

        payload = result.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("_meta", None)
        payload = self.scrubber.data(payload)
        size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        if size > self.cfg.server.max_result_bytes:
            done("error", "result_too_large", result_bytes=size)
            return _error("The result is too large to return. Narrow the request.")
        clean = types.CallToolResult.model_validate(payload)
        done("allow", ok_reason, result_bytes=size, is_error=bool(clean.is_error))
        return clean


class _AuditAuthFailures:
    """Records every 401 so probing with missing or wrong tokens is visible."""

    def __init__(self, app: ASGIApp, audit: Audit) -> None:
        self.app = app
        self.audit = audit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def watch(message: Message) -> None:
            if message["type"] == "http.response.start" and message["status"] == 401:
                peer = scope.get("client")
                presented = any(key == b"authorization" for key, _ in scope["headers"])
                self.audit.write(
                    "auth_failed",
                    remote=peer[0] if peer else None,
                    reason="invalid_token" if presented else "no_token",
                )
            await send(message)

        await self.app(scope, receive, watch)


def build_app(gateway: Gateway) -> Starlette:
    from .runtime import Runtime

    runtime = Runtime(gateway)
    admin = None
    if gateway.cfg.admin:
        from .admin import AdminController
        admin = AdminController(runtime)
    else:
        from .catalog_sync import catalog_revision, sync_catalog
        synced, lock, _, _ = sync_catalog(gateway.cfg, gateway.lock)
        if synced != gateway.cfg or lock.entries != gateway.lock.entries:
            runtime.gateway = Gateway(synced, lock, gateway.secrets, gateway.audit, gateway.approver)
        runtime.gateway.configuration_revision = catalog_revision(synced, lock)
    gateway = runtime.gateway
    cfg = gateway.cfg
    from . import discovery, mcp_tasks
    from .approval_dispatch import ApprovalDispatcher, SUBMIT_FIELDS, WaitForResult
    from .passkey import PasskeyApprover
    from .request_store import RequestStore

    passkeys = isinstance(gateway.approver, PasskeyApprover)
    store = gateway.approver if passkeys else RequestStore(
        cfg.audit.path.with_suffix(".requests.sqlite"), gateway.audit, cfg.audit.retention_days)
    dispatcher = ApprovalDispatcher(runtime, store)

    async def list_tools(ctx, params):
        async with runtime.lease() as current:
            result = await current.list_tools(ctx, params)
            if passkeys and current.cfg.server.tool_discovery == "all":
                return types.ListToolsResult(tools=[*result.tools, discovery.BY_NAME[discovery.CALL_TOOL]])
            return result

    async def call_tool(ctx, params):
        args = params.arguments or {}
        if params.name == discovery.CALL_TOOL and not SUBMIT_FIELDS.intersection(args):
            return await dispatcher.watch(ctx.request, args)
        async with runtime.lease() as current:
            result = await current.call_tool(ctx, params, dispatcher)
        if isinstance(result, WaitForResult):
            return await dispatcher.watch(ctx.request, {"idempotency_key": result.key}, raw=True)
        return result
    server: Server[Any] = Server(
        "agent-gateway",
        version=__version__,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
        # Called before the caller is known, so it must not reveal anything: no schema, no validation.
        get_tool_input_schema=lambda name: None,
    )
    mcp_tasks.register(server, dispatcher)
    server.middleware.clear()  # the SDK's default is a telemetry hook; the gateway emits none

    hosts = list(cfg.server.allowed_hosts)
    if admin and not hosts:
        from urllib.parse import urlsplit
        hosts = [urlsplit(cfg.approvals.origin).netloc]
    manager = StreamableHTTPSessionManager(
        app=server,
        # Stateless: every request is authenticated and authorised on its own, and
        # no session exists that could outlive or be shared between credentials.
        stateless=True,
        json_response=True,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=bool(hosts), allowed_hosts=hosts, allowed_origins=[]
        ),
    )
    # The SDK's bearer backend + guard: no valid token, no MCP.
    class Verifier:
        async def verify_token(self, token):
            return await StaticTokenVerifier(list(runtime.gateway.cfg.clients)).verify_token(token)

    authenticated = AuthenticationMiddleware(
        RequireAuthMiddleware(StreamableHTTPASGIApp(manager), required_scopes=[]),
        backend=BearerAuthBackend(Verifier()),
    )

    class MCPEndpoint:
        async def __call__(self, scope, receive, send):
            await authenticated(scope, receive, send)

    mcp_endpoint = MCPEndpoint()

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with manager.run(), runtime.run():
            runtime.tasks.start_soon(dispatcher.run)
            if admin:
                runtime.tasks.start_soon(admin.sweep)
            yield

    async def healthz(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    # The approval page, if there is one. It is reached by people, not by agents: it takes no
    # bearer token, and nothing on it changes anything without a passkey.
    approval_routes = gateway.approver.http_routes(dispatcher.notify) if passkeys else []

    app = Starlette(
        routes=[
            Route("/mcp", endpoint=mcp_endpoint),
            Route("/healthz", endpoint=healthz, methods=["GET"]),
            *approval_routes,
            *(admin.http_routes() if admin else []),
        ],
        middleware=[
            Middleware(_AuditAuthFailures, audit=gateway.audit),
        ],
        lifespan=lifespan,
    )
    app.state.runtime = runtime
    app.state.admin = admin
    return app
