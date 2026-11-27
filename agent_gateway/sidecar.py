"""Run stdio connectors in a separate container, reached over a Unix socket.

The gateway connects and sends one launch line: the command and environment it
would give a local stdio connector, credentials included. After that, both ends
exchange MCP messages, one JSON-RPC message per line. The sidecar starts the
command with the SDK's stdio client, exactly as the gateway starts a local
connector, so the process gets the same minimal environment and is stopped the
same way. One socket connection is one process; when either end closes, the
process stops.

Only containers that mount the socket's volume can connect. A sidecar holds no
gateway data, so a client that connects can run commands in the sidecar and
reach nothing else.

    python -m agent_gateway.sidecar /sidecars/<name>/control.sock
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import anyio
import mcp_types as types
from anyio.streams.buffered import BufferedByteReceiveStream
from mcp import StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.message import SessionMessage

logger = logging.getLogger("agent_gateway")

_MAX_LINE = 32 * 1024 * 1024
_LAUNCH_TIMEOUT = 10
_ENDED = (anyio.EndOfStream, anyio.IncompleteRead, anyio.DelimiterNotFound,
          anyio.BrokenResourceError, anyio.ClosedResourceError, OSError)


@asynccontextmanager
async def connect(path: str, params: StdioServerParameters):
    """The gateway's end: a transport like `stdio_client`, with the process in the sidecar."""
    async with await anyio.connect_unix(path) as sock:
        await sock.send(params.model_dump_json(include={"command", "args", "env"}).encode() + b"\n")
        to_session, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
        write_stream, from_session = anyio.create_memory_object_stream[SessionMessage](0)
        async with anyio.create_task_group() as tg:
            tg.start_soon(_relay, sock, BufferedByteReceiveStream(sock), to_session, from_session)
            try:
                yield read_stream, write_stream
            finally:
                tg.cancel_scope.cancel()
                for stream in (to_session, read_stream, write_stream, from_session):
                    stream.close()


async def _relay(sock, lines: BufferedByteReceiveStream, deliver, outgoing) -> None:
    """Lines from the socket go to `deliver`; messages from `outgoing` go to the socket.

    When either direction ends, both do.
    """
    async with anyio.create_task_group() as tg:
        async def inbound():
            with suppress(*_ENDED):
                async with deliver:
                    while True:
                        message = _parse(await lines.receive_until(b"\n", _MAX_LINE))
                        if message is not None:
                            await deliver.send(message)
            tg.cancel_scope.cancel()

        async def outbound():
            with suppress(*_ENDED):
                async with outgoing:
                    async for item in outgoing:
                        # The stdio client hands over an unparsable output line as an exception.
                        if isinstance(item, SessionMessage):
                            data = item.message.model_dump_json(by_alias=True, exclude_unset=True)
                            await sock.send(data.encode() + b"\n")
            tg.cancel_scope.cancel()

        tg.start_soon(inbound)
        tg.start_soon(outbound)


def _parse(line: bytes) -> SessionMessage | None:
    try:
        return SessionMessage(types.jsonrpc_message_adapter.validate_json(line, by_name=False))
    except ValueError:
        logger.warning("sidecar: dropped a line that is not a JSON-RPC message")
        return None


async def _serve_one(sock) -> None:
    """The sidecar's end: start the launch line's command and relay until either end closes."""
    try:
        async with sock:
            lines = BufferedByteReceiveStream(sock)
            try:
                with anyio.fail_after(_LAUNCH_TIMEOUT):
                    launch = await lines.receive_until(b"\n", _MAX_LINE)
            except (anyio.EndOfStream, anyio.IncompleteRead):
                return  # a health check: connected and closed
            params = StdioServerParameters.model_validate_json(launch)
            # The process's stderr is discarded, as in the gateway: connectors log private data.
            with open(os.devnull, "w") as devnull:
                async with stdio_client(params, errlog=devnull) as (from_process, to_process):
                    await _relay(sock, lines, to_process, from_process)
    except Exception as exc:
        # Class name only: the message can hold the command line or the environment.
        logger.warning("sidecar: connection ended (%s)", type(exc).__name__)


async def serve(path: Path) -> None:
    listener = await anyio.create_unix_listener(path)
    await listener.serve(_serve_one)


if __name__ == "__main__":
    logging.basicConfig(format="%(levelname)s %(message)s")
    # Only the owner (the gateway's UID) can use the socket, and connector files are private too.
    os.umask(0o077)
    anyio.run(serve, Path(sys.argv[1]))
