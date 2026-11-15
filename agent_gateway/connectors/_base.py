"""What every bundled connector shares: the stdio MCP plumbing, and nothing about any service."""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import anyio
import jsonschema
import mcp_types as types
from mcp.server.lowlevel import Server

from .. import __version__

# Text that ends up inside a protocol command (a search term, a mailbox name, an id) must
# not carry control characters: a line break there would start a new command.
NO_CONTROL = r"^[^\x00-\x1f\x7f]*$"
DATE = r"^\d{4}-\d{2}-\d{2}$"


class ConnectorError(Exception):
    """A failure whose message is meant for the agent. Never put a credential in it."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    # Blocking. Called in a worker thread, one call at a time per connector.
    handler: Callable[[dict[str, Any]], Any]
    properties: dict[str, Any] = field(default_factory=dict)
    required: tuple[str, ...] = ()
    read_only: bool = True

    @property
    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": self.properties,
            "required": list(self.required),
            "additionalProperties": False,
        }


def string(description: str, max_length: int = 200, pattern: str = NO_CONTROL) -> dict[str, Any]:
    return {"type": "string", "description": description, "maxLength": max_length, "pattern": pattern}


def integer(description: str, minimum: int, maximum: int, default: int | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"type": "integer", "description": description, "minimum": minimum, "maximum": maximum}
    if default is not None:
        out["default"] = default
    return out


def setting(name: str, default: str | None = None) -> str:
    """A value from the environment the gateway built for this connector."""
    value = os.environ.get(name) or default
    if not value:
        sys.exit(f"connector: {name} is not set")  # the name only, never a value
    return value


def plain(value: str) -> str:
    """Refuse control characters in text that goes into a protocol command."""
    if re.fullmatch(NO_CONTROL, value) is None:
        raise ConnectorError("Control characters are not allowed here.")
    return value


class CredentialGate:
    """Once the service has refused the credential, stop presenting it for a while.

    A revoked password does not start working again by being retried, and repeated
    failures can get an account locked. The message tells the agent that a person
    has to act.
    """

    def __init__(self, message: str, pause_seconds: float = 60, code: str | None = None) -> None:
        self.message = message
        self.code = code
        self._pause = pause_seconds
        self._closed_until = 0.0

    def check(self) -> None:
        if time.monotonic() < self._closed_until:
            raise ConnectorError(self.message, self.code)

    def refused(self) -> ConnectorError:
        self._closed_until = time.monotonic() + self._pause
        return ConnectorError(self.message, self.code)


def text(value: str, *, is_error: bool = False, code: str | None = None) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=value)], is_error=is_error,
                                meta={"agw_error": code} if code else None)


def result(*parts: Any) -> types.CallToolResult:
    """Text blocks from strings, JSON text blocks from anything else, content blocks as they are."""
    content: list[Any] = []
    for part in parts:
        if isinstance(part, str):
            content.append(types.TextContent(type="text", text=part))
        elif isinstance(part, (dict, list)):
            content.append(types.TextContent(type="text", text=json.dumps(part, ensure_ascii=False, indent=1)))
        else:
            content.append(part)
    return types.CallToolResult(content=content)


def build_server(name: str, tools: list[Tool]) -> Server[Any]:
    by_name = {tool.name: tool for tool in tools}
    one_at_a_time = threading.Lock()  # one upstream connection per connector; calls take turns

    async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name=tool.name,
                    description=tool.description,
                    input_schema=tool.schema,
                    annotations=types.ToolAnnotations(read_only_hint=tool.read_only),
                )
                for tool in tools
            ]
        )

    async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        tool = by_name.get(params.name)
        if tool is None:
            return text("Unknown tool.", is_error=True)
        arguments = params.arguments or {}
        try:
            jsonschema.validate(arguments, tool.schema)
        except jsonschema.ValidationError as exc:
            return text(f"Invalid arguments: {exc.message}"[:300], is_error=True)

        def call() -> Any:
            with one_at_a_time:
                return tool.handler(arguments)

        try:
            value = await anyio.to_thread.run_sync(call, abandon_on_cancel=True)
        except ConnectorError as exc:
            return text(str(exc), is_error=True, code=exc.code)
        except Exception as exc:
            # The type only: exception messages from client libraries can quote requests.
            print(f"{name}: {tool.name} failed with {type(exc).__name__}", file=sys.stderr)
            return text("The request to the service failed.", is_error=True, code="connector_internal_error")
        return value if isinstance(value, types.CallToolResult) else result(value)

    server: Server[Any] = Server(name, version=__version__, on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    server.middleware.clear()  # no telemetry hook
    return server


def serve(name: str, tools: list[Tool]) -> None:
    """Run as a stdio MCP server until the gateway closes the pipe."""

    async def run() -> None:
        from mcp.server.stdio import stdio_server

        server = build_server(name, tools)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(run)
