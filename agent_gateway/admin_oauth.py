"""Browser Gmail consent. Tokens never reach the browser or a redirect URL."""
import copy
import hashlib
import secrets
import time
from urllib.parse import urlencode

import httpx2
from fido2.utils import websafe_encode
from mcp.client.auth.utils import issuers_match

from .admin_config import kind_of, make_connection
from .gmail_scopes import SCOPE, SCOPES, scope_error
from .mail_address import email_address
from .passkey import Refused

GOOGLE_ISSUER = "https://accounts.google.com"
AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN = "https://oauth2.googleapis.com/token"
PROFILE = "https://gmail.googleapis.com/gmail/v1/users/me/profile"


def saved_gmail_client(conn, values):
    if kind_of(conn) == "gmail":
        client_id = conn.env.get("GMAIL_CLIENT_ID")
        client_secret = values.get(conn.secret_env.get("GMAIL_CLIENT_SECRET"))
        if client_id and client_secret:
            return {"client_id": client_id, "client_secret": client_secret}
    return None


def gmail_compatible_client(client):
    return (issuers_match(client["issuer"], GOOGLE_ISSUER)
            and client["auth_method"] == "client_secret_post")


def store_gmail_client(state, credentials):
    clients = state.setdefault("oauth_clients", {})
    client = {**credentials, "issuer": GOOGLE_ISSUER, "auth_method": "client_secret_post"}
    identifier = next((name for name, details in clients.items() if details == client), None)
    if identifier is None:
        identifier, suffix = "gmail", 1
        while identifier in clients:
            identifier = f"gmail-{suffix}"
            suffix += 1
        clients[identifier] = client
    state["gmail_oauth_client"] = identifier
    # Older releases only read this field. Keep their configured default usable.
    state["gmail_client"] = credentials
    return identifier


def _profile_error(response):
    """Translate known Gmail reasons without sending provider text to the browser."""
    status = response.status_code
    if status == 401:
        return "oauth_profile_token_rejected"
    if status == 429:
        return "oauth_profile_rate_limit"
    if status >= 500:
        return "oauth_profile_unavailable"
    try:
        error = response.json().get("error", {})
    except (ValueError, AttributeError):
        error = {}
    reasons = set()
    if isinstance(error, dict):
        for field in ("errors", "details"):
            entries = error.get(field)
            if isinstance(entries, list):
                for item in entries:
                    if isinstance(item, dict) and isinstance(item.get("reason"), str):
                        reasons.add(item["reason"])
    for keys, code in (
        ({"SERVICE_DISABLED", "accessNotConfigured"}, "oauth_profile_api_disabled"),
        ({"domainPolicy"}, "oauth_profile_domain_policy"),
        ({"ACCESS_TOKEN_SCOPE_INSUFFICIENT", "insufficientPermissions"}, "oauth_profile_scope_rejected"),
        ({"dailyLimitExceeded"}, "oauth_profile_project_quota"),
        ({"rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded"}, "oauth_profile_rate_limit"),
        ({"failedPrecondition"}, "oauth_profile_mailbox_unavailable"),
    ):
        if keys & reasons:
            return code
    return "oauth_profile_forbidden" if status == 403 else "oauth_profile_rejected"


class ConsentSessions:
    def _active(self, flow):
        now = int(time.time())
        if not flow or flow["expires"] <= now:
            raise Refused("oauth_expired", 409)
        with self.controller.auth.approver._db() as db:
            active = db.execute("SELECT 1 FROM admin_sessions s JOIN credentials c ON c.id=s.credential "
                                "WHERE s.id=? AND s.expires>? AND c.principal=?",
                                (flow["session"], now, self.controller.auth.owner)).fetchone()
        if not active:
            raise Refused("login_required", 401)


class GoogleConsent(ConsentSessions):
    def __init__(self, controller):
        self.controller = controller
        self.flows = {}
        self.redirect = controller.store.base.approvals.origin + "/admin/oauth/google/callback"

    def start(self, body, session):
        self.controller._revision(body)
        body = copy.deepcopy(body)
        if body.get("kind") != "gmail":
            raise Refused("invalid_connector", 400)
        credentials = body.setdefault("credentials", {})
        if not isinstance(credentials, dict):
            raise Refused("invalid_connector", 400)
        gateway = self.controller.runtime.gateway
        settings = body.setdefault("settings", {})
        if not isinstance(settings, dict):
            raise Refused("invalid_connector", 400)
        # An explicit ID reuses this connection's own client or the legacy
        # API path. Without one, use the system client with a new account grant.
        selection = settings.pop("oauth_client", None)
        if selection is not None or "client_id" not in settings:
            if credentials or "client_id" in settings or (selection is not None and not isinstance(selection, str)):
                raise Refused("invalid_connector", 400)
            state = self.controller.store.state
            client = state.get("oauth_clients", {}).get(selection or state.get("gmail_oauth_client"))
            if not client:
                raise Refused("gmail_system_client_required", 400)
            if not gmail_compatible_client(client):
                raise Refused("oauth_client_unavailable", 409)
            settings["client_id"] = client["client_id"]
            credentials["client_secret"] = client["client_secret"]
        credentials["refresh_token"] = "pending-consent"
        conn, values = make_connection(body, gateway.cfg, gateway.secrets)
        client_secret = (gateway.secrets | values)[conn.secret_env["GMAIL_CLIENT_SECRET"]]
        body["credentials"] = {"client_secret": client_secret}
        access = conn.env["GMAIL_ACCESS"]
        body["settings"] = {"client_id": conn.env["GMAIL_CLIENT_ID"], "gmail_access": access}
        previous = next((c for c in gateway.cfg.connections if c.id == conn.id), None)
        expected_account = previous.mailbox_email if previous else None
        now = time.time()
        self.flows = {key: value for key, value in self.flows.items() if value["expires"] > now}
        if len(self.flows) >= 16:
            raise Refused("too_many_drafts", 429)
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        self.flows[state] = {"session": session["id"], "body": body, "expires": now + 600,
                             "verifier": verifier, "phase": "pending", "expected_account": expected_account}
        return {"url": AUTHORIZE + "?" + urlencode({
            "client_id": conn.env["GMAIL_CLIENT_ID"], "redirect_uri": self.redirect,
            "response_type": "code", "scope": " ".join(SCOPES[access]), "access_type": "offline", "prompt": "consent select_account",
            "state": state, "code_challenge": websafe_encode(hashlib.sha256(verifier.encode()).digest()),
            "code_challenge_method": "S256", "include_granted_scopes": "false",
        })}

    def _http(self):
        return httpx2.AsyncClient(trust_env=False, follow_redirects=False, timeout=20)

    async def callback(self, query):
        state = query.get("state", "")
        flow = self.flows.get(state)
        self._active(flow)
        if flow["phase"] != "pending":
            raise Refused("oauth_already_used", 409)
        flow["phase"] = "exchanging"
        try:
            if query.get("error") or not query.get("code") or len(query["code"]) > 4096:
                raise Refused("oauth_declined", 400)
            body = flow["body"]
            async with self._http() as http:
                response = await http.post(TOKEN, data={
                    "client_id": body["settings"]["client_id"], "client_secret": body["credentials"]["client_secret"],
                    "code": query["code"], "grant_type": "authorization_code", "redirect_uri": self.redirect,
                    "code_verifier": flow["verifier"],
                })
                response.raise_for_status()
                token = response.json()
                access = body["settings"]["gmail_access"]
                if set(str(token.get("scope", "")).split()) != set(SCOPES[access]):
                    raise Refused(scope_error(access), 400)
                if not isinstance(token.get("refresh_token"), str) or not 1 <= len(token["refresh_token"]) <= 16000:
                    raise Refused("oauth_refresh_token_missing", 400)
                profile = await http.get(PROFILE, headers={"Authorization": "Bearer " + token["access_token"]})
                profile.raise_for_status()
                email = email_address(profile.json().get("emailAddress"))
                if not email:
                    raise Refused("oauth_invalid_response", 400)
                if flow["expected_account"] and email.casefold() != flow["expected_account"].casefold():
                    raise Refused("gmail_account_changed", 400)
            flow["body"]["credentials"]["refresh_token"] = token["refresh_token"]
            flow["account"] = email
            flow["phase"] = "ready"
        except Exception as exc:
            flow["phase"] = "failed"
            if isinstance(exc, Refused):
                reason = exc.code
            elif isinstance(exc, httpx2.TimeoutException):
                reason = "oauth_timeout"
            elif isinstance(exc, httpx2.TransportError):
                reason = "oauth_network_failed"
            elif isinstance(exc, httpx2.HTTPStatusError):
                if str(exc.request.url) == PROFILE:
                    reason = _profile_error(exc.response)
                else:
                    reason = "oauth_failed"
                    try:
                        reason = {"invalid_client": "oauth_client_rejected", "unauthorized_client": "oauth_client_rejected",
                                  "invalid_grant": "oauth_code_rejected", "redirect_uri_mismatch": "oauth_code_rejected"}.get(
                                      exc.response.json().get("error"), reason)
                    except (ValueError, AttributeError, TypeError):
                        pass
            else:
                reason = "oauth_invalid_response"
            flow["error"] = reason
            flow["body"]["credentials"] = {}
        return "/admin/?gmail=" + state

    def complete(self, state, session):
        flow = self.flows.get(state)
        self._active(flow)
        if flow["session"] != session["id"]:
            raise Refused("oauth_wrong_session")
        if flow["phase"] == "failed":
            del self.flows[state]
            raise Refused(flow["error"], 400)
        if flow["phase"] != "ready":
            raise Refused("oauth_not_ready", 409)
        self.controller._revision(flow["body"])
        return flow["body"], flow["account"]
