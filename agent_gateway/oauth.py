"""Encrypted upstream OAuth grants and official MCP SDK authorization.

Refresh writes its own store: it neither changes permissions nor restarts a
connection. Each grant has one refresh lock shared by every HTTP client.
"""
import copy
import json
import logging
import secrets
import time
from urllib.parse import urlsplit

import anyio
import httpx2
from mcp.client.auth.oauth2 import OAuthClientProvider
from mcp.client.auth.utils import extract_field_from_www_auth
from mcp.client.auth.exceptions import OAuthFlowError, OAuthRegistrationError, OAuthTokenError
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthMetadata, OAuthToken, ProtectedResourceMetadata

from .credentials import EncryptedFileStore
from .passkey import Refused


class _SafeSDKLog(logging.Filter):
    def filter(self, record):
        # SDK exceptions can contain token endpoint bodies and authorization URLs.
        record.msg, record.args, record.exc_info, record.exc_text, record.stack_info = "MCP OAuth operation", (), None, None, None
        return True


logging.getLogger("mcp.client.auth.oauth2").addFilter(_SafeSDKLog())


def https_url(value, *, query=False):
    try:
        p = urlsplit(value)
        valid = (p.scheme == "https" and p.hostname and not p.username and not p.password
                 and not p.fragment and (query or not p.query) and p.port != 0
                 and not any(c.isspace() or ord(c) < 32 for c in value))
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise Refused("https_url_required", 400)
    return value


def oauth_error(exc):
    from .web_errors import leaves, connector_failure
    for item in leaves(exc):
        if isinstance(item, Refused):
            return item.code
        if isinstance(item, OAuthRegistrationError):
            return "oauth_registration_rejected"
        if isinstance(item, OAuthTokenError):
            return "oauth_invalid_response"
        if isinstance(item, OAuthFlowError):
            return "oauth_discovery_failed"
    return connector_failure(exc, "http")


class OAuthVault:
    def __init__(self, cfg):
        self.file = EncryptedFileStore(cfg.admin.state.with_name(cfg.admin.state.name + ".oauth"), cfg.secrets.key_file)
        self.records = {key: json.loads(self.file.get(key)) for key in self.file.names()}
        self.persisted = set(self.records)
        self.locks = {}
        # Keep previously used values too: an in-flight reply may echo a rotated token.
        self.sensitive = set()
        for record in self.records.values():
            self.remember(record)

    def remember(self, record):
        self.sensitive.update(v for k, v in record.get("tokens", {}).items() if k in ("access_token", "refresh_token") and v)
        secret = (record.get("client") or {}).get("client_secret")
        if secret:
            self.sensitive.add(secret)

    def create(self, url, redirect, settings, client_secret=""):
        ref = secrets.token_hex(32)
        metadata = OAuthClientMetadata(redirect_uris=[redirect], client_name="Agent Gateway", application_type="web",
                                      token_endpoint_auth_method=settings.get("auth_method") or "none",
                                      scope=settings.get("scope") or None)
        record = {"url": url, "metadata": metadata.model_dump(mode="json"), "tokens": {}, "expires": None,
                  "created": time.time(), "issuer": settings.get("issuer") or None,
                  "requested_scope": settings.get("scope") or None,
                  "client_metadata_url": settings.get("client_metadata_url") or None}
        if settings.get("client_id"):
            if not record["issuer"]:
                raise Refused("oauth_issuer_required", 400)
            https_url(record["issuer"])
            method = settings.get("auth_method") or ("client_secret_post" if client_secret else "none")
            if method not in ("none", "client_secret_post", "client_secret_basic") or (method != "none" and not client_secret) or (method == "none" and client_secret):
                raise Refused("oauth_client_settings_invalid", 400)
            record["metadata"]["token_endpoint_auth_method"] = method
            record["client"] = OAuthClientInformationFull(client_id=settings["client_id"], client_secret=client_secret or None,
                issuer=record["issuer"], redirect_uris=[redirect], token_endpoint_auth_method=method).model_dump(mode="json")
        elif client_secret:
            raise Refused("oauth_client_settings_invalid", 400)
        if record["client_metadata_url"]:
            https_url(record["client_metadata_url"])
            if settings.get("client_id") or not urlsplit(record["client_metadata_url"]).path.strip("/"):
                raise Refused("oauth_client_settings_invalid", 400)
        self.records[ref] = record
        self.remember(record)
        return ref

    def get(self, ref, url=None):
        record = self.records.get(ref)
        if record is None or (url is not None and record["url"] != url):
            raise Refused("oauth_reauthorization_required", 401)
        return record

    def save(self, ref):
        record = self.get(ref)
        self.remember(record)
        if ref in self.persisted:
            record.pop("storage_pending", None)
            try:
                self.file.set(ref, json.dumps(record))
            except Exception:
                record["storage_pending"] = True
                raise

    def activate(self, refs):
        for ref in refs:
            record = self.get(ref)
            if ref not in self.persisted:
                self.file.set(ref, json.dumps(record))
                self.persisted.add(ref)

    def discard(self, ref):
        if ref in self.persisted:
            self.file.delete(ref)
            self.persisted.remove(ref)
        self.records.pop(ref, None)
        # A coroutine may hold the old lock; never resurrect a deleted reference.

    def prune(self, refs):
        for ref in list(self.persisted - refs):
            self.discard(ref)

    def auth(self, conn, **kwargs):
        self.get(conn.oauth_ref, conn.url)
        return ManagedOAuth(self, conn.oauth_ref, **kwargs)

    def _http(self):
        return httpx2.AsyncClient(trust_env=False, follow_redirects=False, timeout=10)

    async def revoke(self, ref):
        # Mark locally before the network request, so new calls stop immediately.
        async with self.locks.setdefault(ref, anyio.Lock()):
            record = self.get(ref)
            tokens = copy.deepcopy(record.get("tokens", {}))
            record.update(tokens={}, expires=None, error="oauth_reauthorization_required")
            self.save(ref)
            endpoint = (record.get("authorization_metadata") or {}).get("revocation_endpoint")
            if not endpoint:
                return "unsupported"
            provider = ManagedOAuth(self, ref)
            await provider._initialize()
            status = "revoked"
            try:
                https_url(endpoint)
                async with self._http() as http:
                    for kind in ("refresh_token", "access_token"):
                        if not tokens.get(kind):
                            continue
                        data, headers = provider.context.prepare_token_auth({"token": tokens[kind], "token_type_hint": kind,
                            "client_id": provider.context.client_info.client_id})
                        response = await http.post(endpoint, data=data, headers=headers)
                        if response.status_code != 200:
                            status = "failed"
            except Exception:
                status = "failed"
            return status

    def status(self, ref):
        record = self.records.get(ref)
        if not record:
            return {"error": "oauth_reauthorization_required"}
        return {"error": record.get("error"), "issuer": record.get("issuer"),
                "scope": record.get("tokens", {}).get("scope"), "expires": record.get("expires"),
                "refreshable": bool(record.get("tokens", {}).get("refresh_token"))}


class GrantStorage:
    def __init__(self, vault, ref):
        self.vault, self.ref = vault, ref

    async def get_tokens(self):
        data = self.vault.get(self.ref).get("tokens")
        return OAuthToken.model_validate(data) if data else None

    async def set_tokens(self, tokens):
        record = self.vault.get(self.ref)
        record["tokens"] = tokens.model_dump(mode="json")
        record["expires"] = time.time() + tokens.expires_in if tokens.expires_in is not None else None
        record.pop("error", None)
        self.vault.save(self.ref)

    async def get_client_info(self):
        data = self.vault.get(self.ref).get("client")
        return OAuthClientInformationFull.model_validate(data) if data else None

    async def set_client_info(self, info):
        self.vault.get(self.ref)["client"] = info.model_dump(mode="json")
        self.vault.save(self.ref)


class ManagedOAuth(OAuthClientProvider):
    def __init__(self, vault, ref, *, redirect_handler=None, callback_handler=None):
        self.vault, self.ref = vault, ref
        record = vault.get(ref)
        self.interactive = redirect_handler is not None
        super().__init__(record["url"], OAuthClientMetadata.model_validate(record["metadata"]), GrantStorage(vault, ref),
                         redirect_handler, callback_handler, client_metadata_url=record.get("client_metadata_url"))
        self.context.lock = vault.locks.setdefault(ref, anyio.Lock())

    def _select_authorization_server(self, advertised):
        expected = self.vault.get(self.ref).get("issuer")
        if expected and expected not in advertised:
            raise Refused("oauth_issuer_changed", 400)
        return expected or advertised[0]

    async def _perform_authorization(self):
        record = self.vault.get(self.ref)
        meta = self.context.oauth_metadata
        if not meta:
            raise Refused("oauth_metadata_missing", 400)
        if "S256" not in (meta.code_challenge_methods_supported or []):
            raise Refused("oauth_pkce_required", 400)
        https_url(str(meta.authorization_endpoint))
        https_url(str(meta.token_endpoint))
        if record.get("issuer") and record["issuer"] != str(meta.issuer):
            raise Refused("oauth_issuer_changed", 400)
        if record.get("requested_scope"):
            self.context.client_metadata.scope = record["requested_scope"]
        record.update(issuer=str(meta.issuer), authorization_metadata=meta.model_dump(mode="json"),
                      resource_metadata=self.context.protected_resource_metadata.model_dump(mode="json") if self.context.protected_resource_metadata else None)
        self.vault.save(self.ref)
        return await super()._perform_authorization()

    async def _perform_authorization_code_grant(self):
        try:
            return await super()._perform_authorization_code_grant()
        except OAuthFlowError:
            raise Refused("oauth_callback_invalid", 400) from None

    async def _handle_token_response(self, response):
        if response.status_code not in (200, 201):
            raise Refused(self._token_failure(response), 400)
        try:
            await super()._handle_token_response(response)
        except Refused:
            raise
        except Exception:
            raise Refused("oauth_invalid_response", 400) from None

    @staticmethod
    def _token_failure(response):
        try:
            code = response.json().get("error")
        except (ValueError, AttributeError):
            code = None
        return {"invalid_client": "oauth_client_rejected", "unauthorized_client": "oauth_client_rejected",
                "invalid_grant": "oauth_code_rejected", "invalid_scope": "oauth_scope_rejected"}.get(code, "oauth_token_rejected")

    async def _auth_flow(self, request):
        https_url(str(request.url), query=True)
        if self.interactive:
            flow = super()._auth_flow(request)
            try:
                outbound = await anext(flow)
                while True:
                    https_url(str(outbound.url), query=True)
                    # No credentialed fallback to a different issuer when discovery fails.
                    record = self.vault.get(self.ref)
                    if outbound.method == "POST" and str(outbound.url) != record["url"]:
                        meta = self.context.oauth_metadata
                        if not meta:
                            raise Refused("oauth_metadata_missing", 400)
                        expected = record.get("issuer")
                        if expected and expected != str(meta.issuer):
                            raise Refused("oauth_issuer_changed", 400)
                        if not self.context.client_info and not meta.registration_endpoint:
                            raise Refused("oauth_client_registration_required", 400)
                    response = yield outbound
                    if len(response.content) > 2_000_000:
                        raise Refused("oauth_invalid_response", 400)
                    try:
                        outbound = await flow.asend(response)
                    except StopAsyncIteration:
                        break
            finally:
                await flow.aclose()
            if request.method == "POST":
                response.raise_for_status()
            return
        # No browser redirects, new registrations or scope escalation during calls.
        async with self.context.lock:
            record = self.vault.get(self.ref)
            if record.get("storage_pending"):
                self.vault.save(self.ref)
            if record.get("error"):
                raise Refused(record["error"], 401)
            await self._initialize()
            meta = record.get("authorization_metadata")
            self.context.oauth_metadata = OAuthMetadata.model_validate(meta) if meta else None
            prm = record.get("resource_metadata")
            self.context.protected_resource_metadata = ProtectedResourceMetadata.model_validate(prm) if prm else None
            self.context.auth_server_url = record.get("issuer")
            self.context.token_expiry_time = record.get("expires")
            self.context.protocol_version = request.headers.get("MCP-Protocol-Version")
            if not self.context.current_tokens:
                raise Refused("oauth_reauthorization_required", 401)
            if record.get("expires") is not None and record["expires"] <= time.time() + 30:
                if not self.context.can_refresh_token():
                    record["error"] = "oauth_reauthorization_required"
                    self.vault.save(self.ref)
                    raise Refused(record["error"], 401)
                refresh = await self._refresh_token()
                https_url(str(refresh.url))
                response = yield refresh
                if response.status_code != 200:
                    reason = self._token_failure(response)
                    # Network/provider outages remain retryable, invalid grants do not.
                    if response.status_code in (400, 401, 403):
                        record["error"] = "oauth_reauthorization_required" if reason == "oauth_code_rejected" else reason
                        self.vault.save(self.ref)
                    raise Refused(record.get("error") or "oauth_refresh_failed", 401)
                if not await self._handle_refresh_response(response):
                    raise Refused("oauth_invalid_response", 400)
            self.vault.get(self.ref)  # deletion during a refresh cannot revive the grant
            self._add_auth_header(request)
            response = yield request
            if response.status_code == 401 or (response.status_code == 403 and
                    extract_field_from_www_auth(response, "error") == "insufficient_scope"):
                record["error"] = "oauth_reauthorization_required" if response.status_code == 401 else "oauth_scope_rejected"
                self.vault.save(self.ref)
                raise Refused(record["error"], 401)
            if response.status_code == 403:
                raise Refused("connector_access_denied", 403)
            if request.method == "POST":
                response.raise_for_status()
