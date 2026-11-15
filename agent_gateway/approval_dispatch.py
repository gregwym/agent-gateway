"""Dispatch saved calls once; let the requesting Agent watch their results."""
from collections import OrderedDict
import json
import time

import anyio
import mcp_types as types
from jsonschema import Draft202012Validator
from mcp import MCPError

from .auth import caller_of

WATCH_TOOL = "gateway_watch"
WATCH = types.Tool(
    name=WATCH_TOOL,
    description="Watch an existing Gateway request until it finishes. Use the request_id returned by a tool call. If queued, pending, approved or running, watch again with the same ID. Completion returns the original tool output if available. This never submits, replays or cancels a request.",
    input_schema={"type": "object", "properties": {
        "request_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{32}$", "description": "Request ID returned by the original tool call."},
        "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 25, "default": 20,
                         "description": "Maximum time to watch in this call. Use 0 to check immediately."},
    }, "required": ["request_id"], "additionalProperties": False},
    annotations=types.ToolAnnotations(read_only_hint=True),
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


class ApprovalDispatcher:
    def __init__(self, runtime):
        self.runtime = runtime
        self.approver = runtime.gateway.approver
        self.results = OrderedDict()
        self.result_bytes = 0
        self.wakeup = anyio.Event()
        self.inflight = set()

    def notify(self):
        self.wakeup.set()

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
                result, outcome = await gw.run_dispatched(row)
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

    async def watch(self, request, args):
        if not Draft202012Validator(WATCH.input_schema).is_valid(args):
            raise MCPError(types.INVALID_PARAMS, "Invalid watch arguments")
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
                raise MCPError(types.INVALID_PARAMS, "Unknown request ID")
            status, outcome = row["status"], row["outcome"]
            if status == "used":
                status = ("running" if outcome is None else "succeeded" if outcome == "ok" else
                          "execution_unknown" if outcome == "execution_unknown" else
                          "cancelled" if outcome == "configuration_changed" else "failed")
            if status not in ("queued", "pending", "approved", "running") or time.monotonic() >= deadline:
                data = {"request_id": request_id, "status": status, **({"outcome": outcome} if outcome else {})}
                message = f"Request {request_id}: {status}."
                if status in ("queued", "pending", "approved", "running"):
                    return response(data, message + " Call gateway_watch again with this request_id.")
                if status == "execution_unknown":
                    message += " The operation may already have run. Verify the upstream state before taking any further action."
                self._trim()
                result = self.results.get(request_id) if row["revision"] == gw.configuration_revision else None
                if result is None and status in ("succeeded", "failed"):
                    message += " The original output is no longer available."
                return response(data, message, result[2] if result else None)
            await anyio.sleep(min(.25, max(0, deadline - time.monotonic())))
