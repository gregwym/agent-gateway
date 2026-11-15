"""Expose the approval dispatcher through the MCP Tasks polling protocol."""
from datetime import datetime, timezone
from typing import Annotated

import mcp_types as types
from mcp import MCPError
from pydantic import Field

EXTENSION = "io.modelcontextprotocol/tasks"
PROTOCOL = "2026-07-28"
APPROVAL_INPUT = "approval"


class TaskParams(types.RequestParams):
    task_id: Annotated[str, Field(alias="taskId", pattern=r"^[A-Za-z0-9_-]{32}$")]


class UpdateParams(TaskParams):
    input_responses: Annotated[dict[str, object], Field(alias="inputResponses")]


def enabled(ctx):
    caps = ctx.session.client_capabilities
    return ctx.protocol_version == PROTOCOL and caps is not None and EXTENSION in (caps.extensions or {})


def url_enabled(ctx):
    caps = ctx.session.client_capabilities
    return caps is not None and caps.elicitation is not None and caps.elicitation.url is not None


def _timestamp(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace("+00:00", "Z")


def _summary(approver, request_id, row):
    timestamps = [row[key] for key in ("created", "decided", "used", "link_accepted", "finished") if row[key] is not None]
    if row["status"] == "expired":
        timestamps.append(row["expires"])
    return {
        "taskId": request_id,
        "createdAt": _timestamp(row["created"]),
        "lastUpdatedAt": _timestamp(max(timestamps)),
        "ttlMs": approver.task_retention_ms,
        "pollIntervalMs": 1000,
    }


def created(approver, request_id):
    row = approver.dispatch_status(request_id)
    if row is not None:
        return {**_summary(approver, request_id, row), "resultType": "task", "status": "working"}
    return None


def _require(ctx, params, dispatcher):
    if ctx.protocol_version != PROTOCOL:
        raise MCPError(types.METHOD_NOT_FOUND, "MCP Tasks requires protocol " + PROTOCOL)
    if not enabled(ctx):
        raise MCPError(types.MISSING_REQUIRED_CLIENT_CAPABILITY, "MCP Tasks capability required",
                       data={"requiredCapabilities": {"extensions": {EXTENSION: {}}}})
    if ctx.request.headers.get("Mcp-Name") != params.task_id:
        raise MCPError(types.HEADER_MISMATCH, "Mcp-Name must match taskId")
    return dispatcher.lookup(ctx.request, params.task_id)


def _missing_result(message):
    return types.CallToolResult(content=[types.TextContent(type="text", text=message)], is_error=True)


def register(server, dispatcher):
    server.extensions[EXTENSION] = {}
    approver = dispatcher.store

    async def get(ctx, params):
        gw, row = _require(ctx, params, dispatcher)
        task = _summary(approver, params.task_id, row)
        status, outcome = row["status"], row["outcome"]
        if status == "pending":
            if row["link_accepted"] is not None:
                return {**task, "status": "working", "statusMessage": "Waiting for Passkey approval in the browser."}
            if not url_enabled(ctx):
                raise MCPError(types.MISSING_REQUIRED_CLIENT_CAPABILITY, "URL elicitation required for approval",
                               data={"requiredCapabilities": {"elicitation": {"url": {}}}})
            return {**task, "status": "input_required", "inputRequests": {APPROVAL_INPUT: {
                "method": "elicitation/create", "params": {
                    "mode": "url", "url": approver._url(params.task_id),
                    "message": "Open the Gateway approval page and review this operation. It runs only after Passkey approval.",
                },
            }}}
        if status in ("queued", "approved") or (status == "used" and outcome is None):
            return {**task, "status": "working"}
        if status != "used" or outcome == "configuration_changed":
            reason = {
                "denied": "The approver denied this operation.",
                "expired": "The request expired before execution.",
            }.get(status, "The request was cancelled before execution.")
            if outcome == "configuration_changed":
                reason = "Gateway configuration changed before execution."
            return {**task, "status": "cancelled", "statusMessage": reason}
        result = dispatcher.result_for(gw, params.task_id, row)
        if outcome == "execution_unknown":
            task["statusMessage"] = "The operation may already have run. Verify the upstream state before taking any further action."
        if result is None:
            result = _missing_result(task.get("statusMessage", "The operation finished, but the original output is no longer available."))
        return {**task, "status": "completed", "result": result.model_dump(by_alias=True, mode="json", exclude_none=True)}

    async def update(ctx, params):
        _, row = _require(ctx, params, dispatcher)
        if row["status"] == "pending" and row["link_accepted"] is None and APPROVAL_INPUT in params.input_responses:
            if not url_enabled(ctx):
                raise MCPError(types.MISSING_REQUIRED_CLIENT_CAPABILITY, "URL elicitation required for approval",
                               data={"requiredCapabilities": {"elicitation": {"url": {}}}})
            reply = params.input_responses[APPROVAL_INPUT]
            if not isinstance(reply, dict) or reply.get("action") not in ("accept", "decline", "cancel"):
                raise MCPError(types.INVALID_PARAMS, "Invalid URL elicitation response")
            # An elicitation response may acknowledge opening the link. It cannot authorize execution.
            approver.task_control(params.task_id, reply["action"], reply=True)
        return {}

    async def cancel(ctx, params):
        _require(ctx, params, dispatcher)
        approver.task_control(params.task_id, "cancel")
        return {}

    server.add_request_handler("tasks/get", TaskParams, get)
    server.add_request_handler("tasks/update", UpdateParams, update)
    server.add_request_handler("tasks/cancel", TaskParams, cancel)
