"""Caller identity.

A caller is identified by the bearer token on the HTTP request and by nothing
else: not by tool arguments, not by other headers, not by anything in the MCP
payload. Each token maps to one client and each client to one principal.

Tokens are 256-bit random values, so a plain SHA-256 is the right hash (there
is nothing to brute-force) and the config file holds no usable credential.
The bearer parsing, 401 responses and request plumbing are the MCP SDK's.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Any

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken

from .config import ClientCfg

TOKEN_PREFIX = "agw_"


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Caller:
    client_id: str
    principal: str


class GatewayAccessToken(AccessToken):
    token_sha256: str


class StaticTokenVerifier:
    """Implements the SDK's `TokenVerifier` protocol over the configured clients."""

    def __init__(self, clients: list[ClientCfg]) -> None:
        self._clients = list(clients)

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token or len(token) > 512:
            return None
        digest = hash_token(token)
        match: ClientCfg | None = None
        for client in self._clients:  # no early exit: constant work per request
            if hmac.compare_digest(client.token_sha256, digest):
                match = client
        if match is None:
            return None
        # The raw token is not kept: nothing downstream needs it.
        return GatewayAccessToken(token="", client_id=match.id, scopes=[], subject=match.subject, token_sha256=digest)


def caller_of(request: Any, clients: list[ClientCfg]) -> Caller | None:
    """The authenticated caller of one HTTP request, or None.

    Read per request from what the auth middleware attached to the ASGI scope,
    so identity can never carry over from another request or session.
    """
    scope = getattr(request, "scope", None)
    user = scope.get("user") if isinstance(scope, dict) else None
    if not isinstance(user, AuthenticatedUser):
        return None
    token = user.access_token
    # The HTTP request can wait for its body or dispatch while a configuration
    # change rotates the token or renames its client. Use the active snapshot.
    if isinstance(token, GatewayAccessToken):
        for client in clients:
            if (client.id == token.client_id and client.subject == token.subject
                    and hmac.compare_digest(client.token_sha256, token.token_sha256)):
                return Caller(client_id=client.id, principal=client.subject)
    return None
