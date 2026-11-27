"""Upstream connections: one long-lived MCP client per (service, account).

The SDK's `Client` owns the transports (stdio subprocess, streamable HTTP);
`sidecar.connect` runs a stdio connector in another container.
This module only decides when to connect, what credentials the connection
gets, and whether the tools it offers still match the reviewed lock file.

Failure messages raised from here are fixed strings. Exception text from the
transport (command lines, URLs, environment) is never passed on.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import httpx2
import mcp_types as types
from mcp import Client, MCPError, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from . import __version__, sidecar
from .audit import Audit
from .config import ConnectionCfg
from .lock import Lock, definition_of, digest_of

logger = logging.getLogger("agent_gateway")

_CLIENT_INFO = types.Implementation(name="agent-gateway", version=__version__)
_BACKOFF_START = 1.0
_BACKOFF_MAX = 60.0
_CONNECT_WAIT = 15.0
_CONNECT_TIMEOUT = 60.0
_MAX_LIST_PAGES = 50


class UpstreamError(Exception):
    """`reason` is a short code for the audit log; `public` is safe to show an agent."""

    def __init__(self, reason: str, public: str, *, execution_uncertain=False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.public = public
        self.execution_uncertain = execution_uncertain


def _unavailable(*, execution_uncertain=False) -> UpstreamError:
    return UpstreamError("upstream_unavailable", "The upstream service is currently unavailable.",
                         execution_uncertain=execution_uncertain)


def http_client(**kwargs):
    return httpx2.AsyncClient(**kwargs)


@asynccontextmanager
async def open_client(conn: ConnectionCfg, secrets: dict[str, str], oauth=None, *, auth=None, web_sessions=None,
                      state_dir: Path | None = None, extra_env: dict[str, str] | None = None) -> AsyncIterator[Client]:
    """Connect to one upstream, handing it its own credentials and nothing else.

    `extra_env` is what the gateway itself adds for a stdio connector (new-mail events).
    """
    if conn.oauth_ref and oauth is None and auth is None:
        from .passkey import Refused
        raise Refused("oauth_reauthorization_required", 401)
    from .web_profiles import ORIGINS_ENV, PROFILE_ENV, SESSION_ENV, WebProfile, api_origins
    if conn.plugin and PROFILE_ENV in conn.env:
        from .connectors._base import build_server
        from .connectors.web import SiteSession
        web = (web_sessions.get(conn, secrets) if web_sessions else
               SiteSession(WebProfile.saved(conn.env[PROFILE_ENV]), secrets[conn.secret_env[SESSION_ENV]],
                           extra_origins=api_origins(conn.env.get(ORIGINS_ENV, "[]"))))
        async with _client(conn, build_server(conn.service, web.tools(conn.web_operation_rules))) as client:
            yield client
    elif conn.transport == "stdio":
        # The SDK starts the child with a minimal environment (HOME, PATH, ...) plus
        # what is passed here; the gateway's own environment is not inherited.
        env = dict(conn.env)
        env.update({var: secrets[name] for var, name in conn.secret_env.items()})
        if state_dir is not None:
            env["AGW_STATE_DIR"] = str(state_dir)  # this connection's private directory (sent-mail copies, mail cursor)
        env.update(extra_env or {})
        params = StdioServerParameters(command=conn.command[0], args=conn.command[1:], env=env)
        # The child's stderr is discarded: connectors log mail subjects and the like.
        with open(os.devnull, "w") as devnull:
            # With a socket, the same command runs in that sidecar container instead.
            transport = sidecar.connect(conn.socket, params) if conn.socket else stdio_client(params, errlog=devnull)
            async with _client(conn, transport) as client:
                yield client
    else:
        headers = {name: secrets[secret] for name, secret in conn.secret_headers.items()}
        if conn.bearer_secret:
            headers["Authorization"] = f"Bearer {secrets[conn.bearer_secret]}"
        assert conn.url is not None
        async def diagnose(response):
            # Preserve HTTP causes before the SDK turns a failed POST into a
            # generic JSON-RPC error. OAuth must first handle its own challenges.
            if response.request.method == "POST" and response.status_code >= 400:
                response.raise_for_status()
        # trust_env=False: proxy variables must not be able to reroute credentialed traffic.
        # Redirects: the SDK transport follows them only within the configured origin.
        async with http_client(
            headers=headers,
            event_hooks=None if auth or conn.oauth_ref else {"response": [diagnose]},
            auth=auth or (oauth.auth(conn) if conn.oauth_ref and oauth else None),
            timeout=httpx2.Timeout(30.0, read=conn.timeout_seconds + 30.0),
            trust_env=False,
            follow_redirects=False,
        ) as http:
            async with _client(conn, streamable_http_client(conn.url, http_client=http)) as client:
                yield client


def _client(conn: ConnectionCfg, transport: Any) -> Client:
    # No sampling, elicitation or roots callbacks: an upstream cannot ask the agent's
    # model for anything through the gateway. Every request is bounded by the timeout.
    return Client(transport, cache=None, client_info=_CLIENT_INFO, read_timeout_seconds=conn.timeout_seconds)


async def list_all_tools(client: Client) -> list[types.Tool]:
    tools: list[types.Tool] = []
    seen = set()
    cursor: str | None = None
    for _ in range(_MAX_LIST_PAGES):
        page = await client.list_tools(cursor=cursor)
        for tool in page.tools:
            if tool.name in seen or len(seen) >= 1000:
                from .passkey import Refused
                raise Refused("invalid_remote_tool_list", 422)
            seen.add(tool.name)
        tools.extend(page.tools)
        cursor = page.next_cursor
        if cursor is None:
            return tools
    from .passkey import Refused
    raise Refused("invalid_remote_tool_list", 422)


class Upstream:
    def __init__(self, conn: ConnectionCfg, secrets: dict[str, str], lock: Lock, audit: Audit, oauth=None, web_sessions=None,
                 state_dir: Path | None = None, extra_env: dict[str, str] | None = None) -> None:
        self.oauth = oauth
        self.state_dir = state_dir
        self.extra_env = extra_env
        self.web_sessions = web_sessions
        self.conn = conn
        self._secrets = secrets
        self._lock = lock
        self._audit = audit
        self._client: Client | None = None
        self._connecting = False
        self._settled = anyio.Event()  # set when the current connection attempt has ended either way
        self._broken = anyio.Event()
        self._limiter = anyio.CapacityLimiter(conn.max_concurrency)
        # Upstream tool name -> why it must not be called. Recomputed on every verification.
        self.blocked: dict[str, str] = {}

    async def run(self) -> None:
        """Own the connection for the gateway's lifetime: connect, verify, reconnect."""
        backoff = _BACKOFF_START
        while True:
            self._connecting = True
            try:
                async with open_client(self.conn, self._secrets, self.oauth, web_sessions=self.web_sessions, state_dir=self.state_dir,
                                       extra_env=self.extra_env) as client:
                    with anyio.fail_after(_CONNECT_TIMEOUT):
                        await self._verify(client)
                    self._client = client
                    self._connecting = False
                    self._settled.set()
                    backoff = _BACKOFF_START
                    while not self._broken.is_set():
                        with anyio.move_on_after(self.conn.verify_interval_seconds):
                            await self._broken.wait()
                        if not self._broken.is_set():
                            # Doubles as a liveness probe: a dead upstream raises here.
                            await self._verify(client)
            except Exception as exc:
                # Class name only: the message can hold a command line, a URL or a header.
                logger.warning("upstream %s: connection ended (%s)", self.conn.id, _class_name(exc))
            finally:
                self._client = None
                self._connecting = False
                settled, self._settled = self._settled, anyio.Event()
                settled.set()
                self._broken = anyio.Event()
            await anyio.sleep(backoff)
            backoff = min(backoff * 2, _BACKOFF_MAX)

    async def _verify(self, client: Client) -> None:
        """Compare the live definition of every allowlisted tool with the lock file."""
        live = {tool.name: digest_of(definition_of(tool)) for tool in await list_all_tools(client)}
        blocked: dict[str, str] = {}
        for name in {tool.upstream for tool in self.conn.tools}:
            entry = self._lock.get(self.conn.id, name)
            if entry is None:
                blocked[name] = "not_locked"
            elif name not in live:
                blocked[name] = "missing_upstream"
            elif live[name] != entry["sha256"]:
                blocked[name] = "definition_changed"
        for name, reason in blocked.items():
            if self.blocked.get(name) != reason:
                self._audit.write("tool_blocked", connection=self.conn.id, upstream_tool=name, reason=reason)
                logger.warning("upstream %s: tool %s blocked (%s)", self.conn.id, name, reason)
        self.blocked = blocked

    async def call(self, upstream_tool: str, arguments: dict[str, Any]) -> types.CallToolResult:
        client = self._client
        if client is None and self._connecting:
            settled = self._settled
            with anyio.move_on_after(_CONNECT_WAIT):
                await settled.wait()
            client = self._client
        if client is None:
            raise _unavailable()
        if upstream_tool in self.blocked:
            raise UpstreamError(
                self.blocked[upstream_tool],
                "This tool is disabled until an administrator reviews a change in its upstream definition.",
            )
        timeout = self.conn.timeout_seconds
        try:
            async with self._limiter:
                with anyio.fail_after(timeout + 5):
                    return await client.call_tool(upstream_tool, arguments, read_timeout_seconds=timeout)
        except MCPError as exc:
            if exc.code == types.CONNECTION_CLOSED:
                self._broken.set()
                raise _unavailable(execution_uncertain=True) from None
            if exc.code == types.REQUEST_TIMEOUT:
                raise UpstreamError("upstream_timeout", "The upstream service did not answer in time.") from None
            # A protocol-level refusal of this one request. Its text is not forwarded:
            # it is the upstream's free-form message, not tool output.
            raise UpstreamError("upstream_rejected", "The upstream service rejected the request.") from None
        except TimeoutError:
            raise UpstreamError("upstream_timeout", "The upstream service did not answer in time.") from None
        except (RuntimeError, ValueError):
            if self._client is not client:  # the connection went away underneath this call
                raise _unavailable(execution_uncertain=True) from None
            # The SDK's verdict that the reply does not match the tool's own output schema.
            raise UpstreamError("upstream_invalid_reply", "The upstream service returned an invalid reply.") from None
        except Exception:
            self._broken.set()
            raise _unavailable(execution_uncertain=True) from None


def _class_name(exc: BaseException) -> str:
    if isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        return _class_name(exc.exceptions[0])
    return type(exc).__name__
