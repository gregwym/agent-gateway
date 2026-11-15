"""Passkey-only administrator login, bootstrap, and revocable server-side sessions.

Administrator identity is set by the host's immutable YAML, not by a browser or
an MCP token. Credentials are shared with approval WebAuthn; roles are not.
"""
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from fido2.utils import websafe_encode
from fido2.webauthn import AttestedCredentialData, AuthenticationResponse, RegistrationResponse
from fido2.webauthn import ResidentKeyRequirement, UserVerificationRequirement

from .approval import canonical
from .passkey import Refused

SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_bootstrap (id INTEGER PRIMARY KEY, code TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS admin_ceremonies (
 id TEXT PRIMARY KEY, action TEXT NOT NULL, target TEXT NOT NULL, state TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS admin_sessions (
 id TEXT PRIMARY KEY, credential BLOB NOT NULL, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS admin_confirmations (
 id TEXT PRIMARY KEY, session TEXT NOT NULL, nonce BLOB NOT NULL, expires INTEGER NOT NULL);
"""
COOKIE = "agw_admin"


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class AdminAuth:
    def __init__(self, cfg, approver):
        self.cfg = cfg
        self.approver = approver
        self.owner = cfg.admin.owner
        self.link_file = cfg.admin.state.with_name("admin-setup-link")
        with approver._db() as db:
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    db.execute(statement)

    def initialized(self):
        with self.approver._db() as db:
            return bool(self.approver._credentials(db, [self.owner]))

    def setup_link(self, *, rotate=False):
        """Keep the bootstrap URL in a 0600 host file, never in HTTP/log output."""
        now = int(time.time())
        with self.approver._db() as db:
            if self.approver._credentials(db, [self.owner]):
                self.link_file.unlink(missing_ok=True)
                raise Refused("already_initialized", 409)
            old = db.execute("SELECT * FROM admin_bootstrap WHERE id=1").fetchone()
            if not rotate and old and old["expires"] > now and self.link_file.exists():
                return self.link_file.read_text().strip()
            code = secrets.token_urlsafe(32)
            db.execute("INSERT OR REPLACE INTO admin_bootstrap VALUES (1,?,?)", (digest(code), now + 86400))
            db.execute("DELETE FROM admin_ceremonies WHERE action='setup'")
            link = self.cfg.approvals.origin + "/admin/#setup=" + code
            self.link_file.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.link_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as output:
                output.write(link + "\n")
        return link

    def begin(self, action, code=""):
        if action not in ("setup", "login") or not isinstance(code, str) or len(code) > 128:
            raise Refused("invalid_argument", 400)
        now = int(time.time())
        with self.approver._db() as db:
            db.execute("DELETE FROM admin_ceremonies WHERE expires<=?", (now,))
            existing = self.approver._credentials(db, [self.owner])
            if action == "setup":
                row = db.execute("SELECT * FROM admin_bootstrap WHERE id=1").fetchone()
                if existing or not row or row["expires"] <= now or not hmac.compare_digest(row["code"], digest(code)):
                    raise Refused("invalid_setup_link")
                target = row["code"]
                options, state = self.approver._server.register_begin(
                    {"id": self.owner.encode(), "name": self.approver.name_of(self.owner), "displayName": self.approver.name_of(self.owner)},
                    resident_key_requirement=ResidentKeyRequirement.REQUIRED,
                    user_verification=UserVerificationRequirement.REQUIRED,
                )
            else:
                if not existing:
                    raise Refused("not_initialized")
                target = self.owner
                options, state = self.approver._server.authenticate_begin(
                    [AttestedCredentialData(bytes(r["data"])) for r in existing],
                    user_verification=UserVerificationRequirement.REQUIRED,
                )
            if db.execute("SELECT count(*) FROM admin_ceremonies").fetchone()[0] >= 20:
                raise Refused("rate_limited", 429)
            ceremony = secrets.token_urlsafe(24)
            db.execute("INSERT INTO admin_ceremonies VALUES (?,?,?,?,?)",
                       (ceremony, action, target, json.dumps(state), now + 120))
        return {"ceremony_id": ceremony, "options": dict(options)}

    def finish(self, ceremony_id, response):
        now = int(time.time())
        with self.approver._db() as db:
            row = db.execute("SELECT * FROM admin_ceremonies WHERE id=?", (ceremony_id,)).fetchone()
            db.execute("DELETE FROM admin_ceremonies WHERE id=?", (ceremony_id,))
        if not row or row["expires"] <= now:
            raise Refused("expired_ceremony")
        registration = row["action"] == "setup"
        try:
            parsed = (RegistrationResponse if registration else AuthenticationResponse).from_dict(response)
            data = json.loads(bytes(parsed.response.client_data))
            if data.get("crossOrigin") or data.get("topOrigin"):
                raise ValueError()
        except Exception:
            raise Refused("verification_failed") from None
        with self.approver._db() as db:
            if registration:
                bootstrap = db.execute("SELECT * FROM admin_bootstrap WHERE id=1").fetchone()
                if (not bootstrap or bootstrap["expires"] <= now or bootstrap["code"] != row["target"]
                        or self.approver._credentials(db, [self.owner])):
                    raise Refused("invalid_setup_link")
                try:
                    result = self.approver._server.register_complete(json.loads(row["state"]), parsed)
                    credential = result.credential_data
                    if credential is None:
                        raise ValueError()
                    db.execute("INSERT INTO credentials VALUES (?,?,?,?,?)",
                               (credential.credential_id, self.owner, bytes(credential), result.counter, now))
                except Exception:
                    raise Refused("verification_failed") from None
                credential_id = credential.credential_id
                db.execute("DELETE FROM admin_bootstrap")
            else:
                credential_id = self._verify_assertion(db, json.loads(row["state"]), parsed)
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
            db.execute("DELETE FROM admin_sessions WHERE expires<=?", (now,))
            db.execute("DELETE FROM admin_sessions WHERE id IN (SELECT id FROM admin_sessions ORDER BY expires DESC LIMIT -1 OFFSET 7)")
            db.execute("INSERT INTO admin_sessions VALUES (?,?,?,?)",
                       (digest(token), credential_id, csrf, now + self.cfg.admin.session_seconds))
        if registration:
            self.link_file.unlink(missing_ok=True)
        self.approver.audit.write("admin_setup" if registration else "admin_login", principal=self.owner)
        return token, csrf

    def _verify_assertion(self, db, state, parsed):
        keys = self.approver._credentials(db, [self.owner])
        try:
            used = self.approver._server.authenticate_complete(
                state, [AttestedCredentialData(bytes(r["data"])) for r in keys], parsed)
            key = next(r for r in keys if bytes(r["id"]) == used.credential_id)
            handle = parsed.response.user_handle
            if handle is not None and bytes(handle) != self.owner.encode():
                raise ValueError()
            counter = parsed.response.authenticator_data.counter
            if (key["counter"] or counter) and counter <= key["counter"]:
                raise ValueError()
        except Exception:
            raise Refused("verification_failed") from None
        db.execute("UPDATE credentials SET counter=? WHERE id=?", (counter, used.credential_id))
        return used.credential_id

    @staticmethod
    def _confirmation_challenge(nonce, session, operation, body, revision):
        return hashlib.sha256(nonce + canonical({
            "purpose": "admin-confirmation", "session": session["id"],
            "operation": operation, "body": body, "revision": revision,
        })).digest()

    def begin_confirmation(self, session, operation, body, revision):
        now = int(time.time())
        nonce = secrets.token_bytes(32)
        challenge = self._confirmation_challenge(nonce, session, operation, body, revision)
        with self.approver._db() as db:
            db.execute("DELETE FROM admin_confirmations WHERE expires<=?", (now,))
            # Separate from the public login pool. Bound the prompts of each authenticated session.
            if db.execute("SELECT count(*) FROM admin_confirmations WHERE session=?", (session["id"],)).fetchone()[0] >= 12:
                raise Refused("rate_limited", 429)
            keys = self.approver._credentials(db, [self.owner])
            options, _ = self.approver._server.authenticate_begin(
                [AttestedCredentialData(bytes(r["data"])) for r in keys],
                user_verification=UserVerificationRequirement.REQUIRED, challenge=challenge)
            ceremony = secrets.token_urlsafe(24)
            db.execute("INSERT INTO admin_confirmations VALUES (?,?,?,?)",
                       (ceremony, session["id"], nonce, min(session["expires"], now + 120)))
        return {"ceremony_id": ceremony, "options": dict(options)}

    def confirm(self, session, operation, body, revision, proof):
        if not isinstance(proof, dict) or not isinstance(proof.get("ceremony_id"), str) or len(proof["ceremony_id"]) > 128:
            raise Refused("verification_failed")
        with self.approver._db() as db:
            key = (proof["ceremony_id"], session["id"])
            row = db.execute("SELECT nonce, expires FROM admin_confirmations WHERE id=? AND session=?", key).fetchone()
            db.execute("DELETE FROM admin_confirmations WHERE id=? AND session=?", key)
        if not row or row["expires"] <= int(time.time()):
            raise Refused("admin_confirmation_expired", 409)
        try:
            parsed = AuthenticationResponse.from_dict(proof.get("response"))
            data = json.loads(bytes(parsed.response.client_data))
            if data.get("crossOrigin") or data.get("topOrigin"):
                raise ValueError()
        except Exception:
            raise Refused("verification_failed") from None
        expected = self._confirmation_challenge(bytes(row["nonce"]), session, operation, body, revision)
        if not hmac.compare_digest(parsed.response.client_data.challenge, expected):
            raise Refused("admin_confirmation_changed", 409)
        with self.approver._db() as db:
            self._verify_assertion(db, {"challenge": websafe_encode(expected), "user_verification": UserVerificationRequirement.REQUIRED}, parsed)
        self.approver.audit.write("admin_confirmed", principal=self.owner, detail=operation)

    def session(self, token):
        if not token or len(token) > 128:
            raise Refused("login_required", 401)
        with self.approver._db() as db:
            row = db.execute(
                "SELECT s.* FROM admin_sessions s JOIN credentials c ON c.id=s.credential "
                "WHERE s.id=? AND s.expires>? AND c.principal=?", (digest(token), int(time.time()), self.owner)
            ).fetchone()
        if not row:
            raise Refused("login_required", 401)
        return dict(row)

    def logout(self, token):
        with self.approver._db() as db:
            db.execute("DELETE FROM admin_sessions WHERE id=?", (digest(token),))
            db.execute("DELETE FROM admin_confirmations WHERE session=?", (digest(token),))
