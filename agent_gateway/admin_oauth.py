"""Browser Gmail consent. Tokens never reach the browser or a redirect URL."""
import copy
import hashlib
import secrets
import time
from urllib.parse import urlencode

import httpx2
from fido2.utils import websafe_encode

from .admin_config import make_connection
from .gmail_scopes import SCOPE, SCOPES, scope_error
from .mail_address import email_address
from .passkey import Refused

AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN = "https://oauth2.googleapis.com/token"
PROFILE = "https://gmail.googleapis.com/gmail/v1/users/me/profile"


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
        credentials["refresh_token"] = "pending-consent"
        gateway = self.controller.runtime.gateway
        conn, values = make_connection(body, gateway.cfg, gateway.secrets)
        client_secret = (gateway.secrets | values)[conn.secret_env["GMAIL_CLIENT_SECRET"]]
        body["credentials"] = {"client_secret": client_secret}
        access = conn.env["GMAIL_ACCESS"]
        body["settings"] = {"client_id": conn.env["GMAIL_CLIENT_ID"], "gmail_access": access}
        now = time.time()
        self.flows = {key: value for key, value in self.flows.items() if value["expires"] > now}
        if len(self.flows) >= 16:
            raise Refused("too_many_drafts", 429)
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        self.flows[state] = {"session": session["id"], "body": body, "expires": now + 600,
                             "verifier": verifier, "phase": "pending"}
        return {"url": AUTHORIZE + "?" + urlencode({
            "client_id": conn.env["GMAIL_CLIENT_ID"], "redirect_uri": self.redirect,
            "response_type": "code", "scope": " ".join(SCOPES[access]), "access_type": "offline", "prompt": "consent",
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
                    raise Refused("oauth_failed", 400)
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
                reason = "oauth_profile_rejected" if str(exc.request.url) == PROFILE else "oauth_failed"
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
