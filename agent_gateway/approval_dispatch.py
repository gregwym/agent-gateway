"""Durable one-use dispatch and a bounded result inbox for the requesting Agent."""
from collections import OrderedDict
import json
import time

import anyio
import mcp_types as types
from jsonschema import Draft202012Validator
from mcp import MCPError

from .auth import caller_of
from .passkey import ENROLL_TOOL, Refused

WAIT_TOOL = "gateway_wait_for_approval"
REGISTER_TOOL = "gateway_request_passkey"
WAIT = types.Tool(
    name=WAIT_TOOL,
    description="Wait for a Gateway approval and its automatic execution; does not submit or run an action. Pass the request_id returned by the original tool. Pending, approved or running means call this wait tool again with the same request_id. Success returns the original tool output. Declined, cancelled, expired, failed or execution_unknown are final. Do not retry the original action to get its result, even after a client timeout.",
    input_schema={"type": "object", "properties": {
        "request_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{32}$", "description": "Approval request ID, not its URL."},
        "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 25, "default": 20,
                         "description": "Maximum time to wait in this call. Use 0 to check immediately."},
    }, "required": ["request_id"], "additionalProperties": False},
    annotations=types.ToolAnnotations(read_only_hint=True),
)
REGISTER = types.Tool(
    name=REGISTER_TOOL,
    description="Request a passkey registration link for an existing non-admin member of this Agent's group. Use the member's exact name or ID. Give the returned link privately to that person to register on their device. Their passkey is inactive until the administrator approves the review shown after registration. This does not grant Agent access or sign the member into administration.",
    input_schema={"type": "object", "properties": {"member": {"type": "string", "minLength": 1, "maxLength": 80}},
                  "required": ["member"], "additionalProperties": False},
    annotations=types.ToolAnnotations(read_only_hint=False),
)
RESULT_TTL = 600
RESULT_LIMIT = 16 * 1024 * 1024


def response(data, message, result=None, *, error=False):
    content = [types.TextContent(type="text", text=message)]
    if result:
        content += result.content
        if result.structured_content is not None:
            data = {**data, "result": result.structured_content}
    return types.CallToolResult(content=content, structured_content=data, is_error=error)


def member_allowed(cfg, principal, client_id, token_hash, admin):
    if not cfg.admin or admin != cfg.admin.owner or principal == admin:
        return False
    client = next((c for c in cfg.clients if c.id == client_id and c.token_sha256 == token_hash), None)
    return client is not None and client.household is not None and cfg.household_of(principal) == client.household and any(
        m.id == principal for m in cfg.members)


class ApprovalDispatcher:
    def __init__(self, runtime):
        self.runtime = runtime
        self.approver = runtime.gateway.approver
        self.approver.member_allowed = lambda *args: member_allowed(self.runtime.gateway.cfg, *args)
        self.results = OrderedDict()
        self.result_bytes = 0
        self.wakeup = anyio.Event()
        self.inflight = set()

    def notify(self):
        self.wakeup.set()

    def tools(self, caller):
        cfg = self.runtime.gateway.cfg
        client = next(c for c in cfg.clients if c.id == caller.client_id)
        return [WAIT, REGISTER] if cfg.admin and any(member_allowed(cfg, m.id, client.id, client.token_sha256, cfg.admin.owner)
                                                    for m in cfg.members) else [WAIT]

    def _remember(self, request_id, result):
        self._trim()
        size = len(result.model_dump_json().encode())
        if size > RESULT_LIMIT:
            return
        while self.results and self.result_bytes + size > RESULT_LIMIT:
            self.result_bytes -= self.results.popitem(last=False)[1][1]
        self.results[request_id] = time.monotonic() + RESULT_TTL, size, result
        self.result_bytes += size

    def _trim(self):
        while self.results and next(iter(self.results.values()))[0] <= time.monotonic():
            self.result_bytes -= self.results.popitem(last=False)[1][1]

    async def run(self):
        self.approver.recover_dispatch()
        async with anyio.create_task_group() as tasks:
            while True:
                wakeup = self.wakeup
                try:
                    self._trim()
                    for request_id in self.approver.dispatch_queue(16):
                        if len(self.inflight) >= 8:
                            break
                        if request_id not in self.inflight:
                            self.inflight.add(request_id)
                            tasks.start_soon(self._execute, request_id)
                except Exception:
                    self.runtime.gateway.audit.write("approval_queue_error", reason="storage_unavailable")
                with anyio.move_on_after(1):
                    await wakeup.wait()
                if self.wakeup is wakeup:
                    self.wakeup = anyio.Event()

    async def _execute(self, request_id):
        row = None
        try:
            async with self.runtime.lease() as gw:
                row = self.approver.claim_dispatch(request_id)
                if row is None:
                    return
                if row["tool"] == ENROLL_TOOL:
                    self.approver.activate_member_passkey(row)
                else:
                    result, outcome = await gw.run_approved(row)
                    if result is not None:
                        self._remember(request_id, result)
                    await self.approver.finished(request_id, outcome)
        except BaseException as exc:
            if isinstance(exc, Exception):
                self.runtime.gateway.audit.write("approval_dispatch_error", approval=request_id, reason=type(exc).__name__)
            if row is not None:
                with anyio.CancelScope(shield=True):
                    try:
                        await self.approver.finished(request_id, "execution_unknown")
                    except Exception:
                        self.runtime.gateway.audit.write("approval_dispatch_error", approval=request_id, reason="storage_unavailable")
            if not isinstance(exc, Exception):
                raise
        finally:
            self.inflight.discard(request_id)
            self.notify()

    async def call(self, request, tool, args):
        cfg = self.runtime.gateway.cfg
        caller = caller_of(request, cfg.clients)
        if not caller:
            raise MCPError(types.INVALID_REQUEST, "Not authenticated")
        spec = next((item for item in self.tools(caller) if item.name == tool), None)
        if spec is None:
            raise MCPError(types.INVALID_PARAMS, "Unknown tool")
        if not Draft202012Validator(spec.input_schema).is_valid(args):
            raise MCPError(types.INVALID_PARAMS, "Invalid Gateway tool arguments")
        if tool == REGISTER_TOOL:
            client = next(c for c in cfg.clients if c.id == caller.client_id)
            member_input = args["member"].strip()
            candidates = [m.id for m in cfg.members if member_allowed(cfg, m.id, client.id, client.token_sha256, cfg.admin.owner)]
            principal = next((p for p in candidates if p == member_input), None) or next(
                (p for p in candidates if self.approver.name_of(p).casefold() == member_input.casefold()), None)
            if not principal:
                return response({"error": "enrollment_member_unavailable"}, "Select an existing non-admin member of this Agent's group. Ask the administrator to add the member first if needed.", error=True)
            try:
                info = self.approver.request_member_enrollment(principal, client, cfg.admin.owner)
            except Refused as exc:
                message = {"administrator_passkey_required": "The administrator must register their own passkey before reviewing member requests.",
                           "rate_limited": "This Agent already has five unfinished passkey requests."}
                return response({"error": exc.code}, message.get(exc.code, "This member is no longer eligible for registration."), error=True)
            return response(info, "Give this private link to " + self.approver.name_of(principal) + ": " + info["enrollment_url"] +
                            " . After registering on their device, they should send the review link shown on the page to the administrator.")
        deadline = time.monotonic() + args.get("wait_seconds", 20)
        request_id = args["request_id"]
        while True:
            gw = self.runtime.gateway
            caller = caller_of(request, gw.cfg.clients)
            if not caller:
                raise MCPError(types.INVALID_REQUEST, "Not authenticated")
            client = next(c for c in gw.cfg.clients if c.id == caller.client_id)
            row = self.approver.dispatch_status(request_id)
            if not row or row["client"] != client.id or row["client_token_sha256"] != client.token_sha256:
                raise MCPError(types.INVALID_PARAMS, "Unknown approval request")
            status, outcome = row["status"], row["outcome"]
            if status == "used":
                status = ("running" if outcome is None else "succeeded" if outcome == "ok" else
                          "execution_unknown" if outcome == "execution_unknown" else
                          "cancelled" if outcome == "configuration_changed" else "failed")
            if status not in ("pending", "approved", "running") or time.monotonic() >= deadline:
                data = {"request_id": request_id, "status": status, **({"outcome": outcome} if outcome else {})}
                message = f"Approval {request_id}: {status}."
                if status in ("pending", "approved", "running"):
                    return response(data, message + " Call gateway_wait_for_approval again with this request_id.")
                if status == "execution_unknown":
                    message += " The operation may already have run. Verify the upstream state before taking any further action."
                self._trim()
                result = self.results.get(request_id) if row["revision"] == gw.configuration_revision else None
                if result is None and row["tool"] != ENROLL_TOOL and status in ("succeeded", "failed"):
                    message += " The original output is no longer available."
                return response(data, message, result[2] if result else None)
            await anyio.sleep(min(.25, max(0, deadline - time.monotonic())))
