"""Dispatch saved calls once; let the requesting Agent watch their results."""
from collections import OrderedDict
import json
import time
from dataclasses import dataclass

import anyio
import mcp_types as types
from jsonschema import Draft202012Validator
from mcp import MCPError

from .auth import caller_of

KEY_PROPERTY = {"type": "string", "pattern": r"^[A-Za-z0-9._~-]{1,128}$",
                "description": "Use a new UUID for each operation. Reuse it on retries and when checking the result."}
WAIT_PROPERTY = {"type": "integer", "minimum": 0, "maximum": 25, "default": 20,
                 "description": "Maximum time to wait for an existing operation. Use 0 to check immediately."}
WATCH_VALIDATOR = Draft202012Validator({
    "type": "object", "properties": {"idempotency_key": KEY_PROPERTY, "wait_seconds": WAIT_PROPERTY},
    "required": ["idempotency_key"], "additionalProperties": False,
})
SUBMIT_FIELDS = {"tool", "connection", "arguments", "variant", "background"}
ACTIVE = {"queued", "pending", "approved", "running"}
RESULT_TTL = 600
RESULT_LIMIT = 16 * 1024 * 1024


def response(data, message, result=None, *, error=False):
    content = [types.TextContent(type="text", text=message)]
    if result:
        content += result.content
        if result.structured_content is not None:
            data = {**data, "result": result.structured_content}
    return types.CallToolResult(content=content, structured_content=data, is_error=error)


@dataclass(frozen=True)
class WaitForResult:
    key: str


class ApprovalDispatcher:
    def __init__(self, runtime, store):
        self.runtime = runtime
        self.store = store
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
        self.store.recover_dispatch()
        async with anyio.create_task_group() as tasks:
            while True:
                wakeup = self.wakeup
                try:
                    self._trim()
                    for request_id in self.store.dispatch_queue(16):
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
                row = self.store.claim_dispatch(request_id)
                if row is None:
                    return
                result, outcome = await gw.run_dispatched(row)
                if result is not None:
                    self._remember(request_id, result)
                await self.store.finished(request_id, outcome)
        except BaseException as exc:
            if isinstance(exc, Exception):
                self.runtime.gateway.audit.write("approval_dispatch_error", approval=request_id, reason=type(exc).__name__)
            if row is not None:
                with anyio.CancelScope(shield=True):
                    try:
                        await self.store.finished(request_id, "execution_unknown")
                    except Exception:
                        self.runtime.gateway.audit.write("approval_dispatch_error", approval=request_id, reason="storage_unavailable")
            if not isinstance(exc, Exception):
                raise
        finally:
            self.inflight.discard(request_id)
            self.notify()

    def _caller(self, request):
        gw = self.runtime.gateway
        caller = caller_of(request, gw.cfg.clients)
        if not caller:
            raise MCPError(types.INVALID_REQUEST, "Not authenticated")
        return gw, next(c for c in gw.cfg.clients if c.id == caller.client_id)

    def lookup(self, request, request_id):
        gw, client = self._caller(request)
        row = self.store.dispatch_status(request_id)
        if not row or row["client"] != client.id or row["client_token_sha256"] != client.token_sha256:
            raise MCPError(types.INVALID_PARAMS, "Unknown task")
        return gw, row

    def existing_key(self, request, key):
        from .request_store import IdempotencyConflict

        _, client = self._caller(request)
        try:
            return self.store.existing_key(client.id, client.token_sha256, key)
        except IdempotencyConflict:
            raise MCPError(types.INVALID_PARAMS, "This idempotency_key is already bound to another operation.") from None

    def submission(self, ctx, request_id, key, *, background=False, message=None):
        from . import mcp_tasks

        gw, row = self.lookup(ctx.request, request_id)
        needs_approval = row["approvers"] != "[]"
        if not needs_approval and not background:
            return WaitForResult(key)
        if mcp_tasks.enabled(ctx) and (not needs_approval or mcp_tasks.url_enabled(ctx)):
            return mcp_tasks.created(self.store, request_id)
        return self._status(gw, request_id, row, key, message=message)

    def result_for(self, gw, request_id, row):
        self._trim()
        result = self.results.get(request_id) if row["revision"] == gw.configuration_revision else None
        return result[2] if result else None

    @staticmethod
    def _phase(row):
        status, outcome = row["status"], row["outcome"]
        if status == "used":
            return ("running" if outcome is None else "succeeded" if outcome == "ok" else
                    "execution_unknown" if outcome == "execution_unknown" else
                    "cancelled" if outcome == "configuration_changed" else "failed")
        return status

    def _status(self, gw, request_id, row, key, *, message=None, raw=False):
        status, outcome = self._phase(row), row["outcome"]
        result = self.result_for(gw, request_id, row)
        if raw and result is not None and status in ("succeeded", "failed"):
            return result
        data = {"idempotency_key": key, "status": status, **({"outcome": outcome} if outcome else {})}
        message = message or f"Operation: {status}."
        if status == "pending":
            data["approval_url"] = self.store._url(request_id)
            if data["approval_url"] not in message:
                message += f" Share {data['approval_url']} with the approver. The Gateway runs it after Passkey approval."
        if status in ACTIVE:
            message += " Call gateway_call_tool with only the same idempotency_key to get the result."
        if status == "execution_unknown":
            message += " The operation may already have run. Verify the upstream state before taking any further action."
        if result is None and status in ("succeeded", "failed"):
            message += " The original output is no longer available."
        return response(data, message, result, error=status in ("denied", "failed", "execution_unknown")
                        or (status in ACTIVE and row["approvers"] != "[]" and not raw))

    async def watch(self, request, args, *, raw=False):
        if not WATCH_VALIDATOR.is_valid(args):
            raise MCPError(types.INVALID_PARAMS, "To check an operation, pass only idempotency_key and optional wait_seconds")
        deadline = time.monotonic() + args.get("wait_seconds", 20)
        key = args["idempotency_key"]
        while True:
            gw, client = self._caller(request)
            request_id = self.store.request_for_key(client.id, client.token_sha256, key)
            row = self.store.dispatch_status(request_id) if request_id else None
            if not row:
                raise MCPError(types.INVALID_PARAMS, "Unknown idempotency_key")
            if self._phase(row) not in ACTIVE or time.monotonic() >= deadline:
                return self._status(gw, request_id, row, key, raw=raw)
            await anyio.sleep(min(.1, max(0, deadline - time.monotonic())))
