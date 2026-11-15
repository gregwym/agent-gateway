"""Passkey approval: where `approval_required` calls wait for a person.

How one call goes:

  1. An agent calls a tool whose effect is `approval_required`. The gateway has
     already checked policy and arguments. `authorize` finds no decision for this
     exact call, stores it as *pending*, and the agent is told where it waits.
  2. The account's owner opens that page, reads what would be done, and approves
     or declines with a passkey. Each decision is its own WebAuthn assertion
     (user verification required) over a challenge derived from that request
     and that decision, so the signature is about this request and nothing
     else. There is no login session to reuse.
  3. The agent calls the tool again with the same arguments. `authorize` finds
     the approval, marks it *used* in the same transaction, and the call runs.
     A second call finds nothing and starts over at step 1.

What a decision is bound to: the client and principal that asked, the
connection, account and upstream tool, and the SHA-256 of the exact arguments
(`ApprovalRequest.binding`). A changed argument is a different call.

An approval is spent before the upstream is contacted. If the upstream then
fails, the approval is still gone: the gateway cannot know whether a write
happened, so it never retries one on its own.

WebAuthn itself (challenges, signature and origin checks) is the `fido2`
library. State is one SQLite file. Arguments are kept only while a request can
still be decided or used, and are erased afterwards.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fido2.server import Fido2Server
from fido2.utils import websafe_encode
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticationResponse,
    RegistrationResponse,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import BaseRoute, Route

from .approval import NOT_EXECUTED, ApprovalDecision, ApprovalRequest, canonical
from .audit import Audit
from .config import ApprovalsCfg

_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    id BLOB PRIMARY KEY, principal TEXT NOT NULL, data BLOB NOT NULL, counter INTEGER NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS enrollments (
    code_sha256 TEXT PRIMARY KEY, principal TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY, binding TEXT NOT NULL, status TEXT NOT NULL,
    client TEXT NOT NULL, principal TEXT NOT NULL, tool TEXT NOT NULL, connection TEXT NOT NULL,
    service TEXT NOT NULL, account TEXT NOT NULL, owner TEXT NOT NULL, upstream_tool TEXT NOT NULL,
    approvers TEXT NOT NULL, arguments TEXT,
    created INTEGER NOT NULL, expires INTEGER NOT NULL,
    decided INTEGER, decided_by TEXT, credential TEXT, used INTEGER, outcome TEXT);
CREATE INDEX IF NOT EXISTS requests_binding ON requests (binding, created);
CREATE INDEX IF NOT EXISTS requests_ready ON requests (decided) WHERE status='approved';
CREATE TABLE IF NOT EXISTS dispatch (
    id TEXT PRIMARY KEY, revision TEXT NOT NULL, client_token_sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS enrollment_requests (
    code_sha256 TEXT PRIMARY KEY, client TEXT NOT NULL, client_token_sha256 TEXT NOT NULL, administrator TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending_credentials (
    request_id TEXT PRIMARY KEY, id BLOB NOT NULL UNIQUE, data BLOB NOT NULL, counter INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ceremonies (
    id TEXT PRIMARY KEY, action TEXT NOT NULL, target TEXT NOT NULL, binding TEXT NOT NULL,
    state TEXT NOT NULL, expires INTEGER NOT NULL);
"""

# action -> the status a request must have for that decision to be possible
_DECISIONS = {"approve": "pending", "deny": "pending", "cancel": "approved"}
_OPEN = ("pending", "approved")
_ENROLL_TTL = 900
_MEMBER_REVIEW_TTL = 86_400
ENROLL_TOOL = "gateway_approve_passkey"
_CEREMONY_TTL = 120
_MAX_CEREMONIES = 100
_MAX_CEREMONIES_PER_TARGET = 3
_MAX_PENDING_PER_CLIENT = 5
_MAX_PASSKEYS_PER_PERSON = 8
_MAX_BODY = 64_000

_STATIC = Path(__file__).parent / "static"
_PAGE_HEADERS = {
    # The page shows text chosen by an agent. Nothing inline, nothing from elsewhere, no framing.
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class Refused(Exception):
    """A request to the approval service was refused. `code` is safe to show."""

    def __init__(self, code: str, status: int = 403, *, incident: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.incident = incident


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now() -> int:
    return int(time.time())


class PasskeyApprover:
    def __init__(self, cfg: ApprovalsCfg, audit: Audit, retention_days: int = 90) -> None:
        self.cfg = cfg
        self.audit = audit
        self.member_allowed = lambda *_: False
        self._retention = retention_days * 86_400
        self._server = Fido2Server(
            {"id": cfg.rp_id, "name": "Agent Gateway"}, verify_origin=lambda origin: origin == cfg.origin
        )
        self._server.timeout = _CEREMONY_TTL * 1000
        cfg.store.parent.mkdir(parents=True, exist_ok=True)
        setup = sqlite3.connect(cfg.store, timeout=10)
        try:
            setup.executescript(_SCHEMA)
        finally:
            setup.close()

    # -- storage ----------------------------------------------------------------

    @contextmanager
    def _db(self, *, write=True) -> Iterator[sqlite3.Connection]:
        """One short transaction. IMMEDIATE, so check-then-update sequences cannot interleave."""
        db = sqlite3.connect(self.cfg.store, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    def _sweep(self, db: sqlite3.Connection, now: int) -> None:
        db.execute(
            "UPDATE requests SET status='expired', arguments=NULL WHERE status IN ('pending','approved') AND expires<=?",
            (now,),
        )
        db.execute("DELETE FROM requests WHERE status NOT IN ('pending','approved') AND created<?", (now - self._retention,))
        db.execute("DELETE FROM ceremonies WHERE expires<=?", (now,))
        db.execute("DELETE FROM enrollments WHERE expires<=?", (now,))
        db.execute("DELETE FROM enrollment_requests WHERE code_sha256 NOT IN (SELECT code_sha256 FROM enrollments)")
        db.execute("DELETE FROM dispatch WHERE id NOT IN (SELECT id FROM requests)")
        db.execute("DELETE FROM pending_credentials WHERE request_id NOT IN (SELECT id FROM requests WHERE status IN ('pending','approved') OR (status='used' AND outcome IS NULL))")

    def _url(self, request_id: str) -> str:
        return f"{self.cfg.origin}/approvals/r/{request_id}"

    def name_of(self, principal: str) -> str:
        return principal

    def identity_label(self, principal: str) -> str:
        return self.name_of(principal)

    # -- the Approver interface ---------------------------------------------------

    async def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        now = _now()
        with self._db() as db:
            self._sweep(db, now)
            row = db.execute(
                "SELECT * FROM requests WHERE binding=? ORDER BY created DESC, rowid DESC LIMIT 1", (request.binding,)
            ).fetchone()
            # Host-file edits do not have a web revision. Re-check the current
            # approval authority before reusing either a pending request or grant.
            if row is not None and set(json.loads(row["approvers"])) != set(request.approvers):
                db.execute("UPDATE requests SET status='cancelled', arguments=NULL WHERE id=? AND status IN ('pending','approved')", (row["id"],))
                row = None
            if row is not None:
                status = row["status"]
                if status in _OPEN:
                    message = self._waiting(row["id"], row["approvers"], row["expires"], now) if status == "pending" else None
                    return ApprovalDecision(False, status, message, row["id"])
                if status == "denied" and now - row["decided"] < self.cfg.request_ttl_seconds:
                    return ApprovalDecision(False, "denied", "This action was declined and was not executed.", row["id"])
                if status == "used" and now - row["used"] < self.cfg.request_ttl_seconds:
                    return ApprovalDecision(False, "submitted", approval_id=row["id"])

            enrolled = {r["principal"] for r in db.execute("SELECT DISTINCT principal FROM credentials")}
            if not enrolled & set(request.approvers):
                return ApprovalDecision(False, "no_approver_enrolled")
            waiting = db.execute(
                "SELECT count(*) FROM requests WHERE client=? AND status='pending'", (request.client_id,)
            ).fetchone()[0]
            if waiting >= _MAX_PENDING_PER_CLIENT:
                return ApprovalDecision(
                    False, "too_many_pending", "Too many actions from this client are already waiting for approval. Try again later."
                )
            request_id = secrets.token_urlsafe(24)
            approvers = json.dumps(sorted(request.approvers))
            expires = now + self.cfg.request_ttl_seconds
            self._insert_request(db, request_id, request, now, expires)
        self.audit.write(
            "approval_requested", approval=request_id, client=request.client_id, principal=request.principal,
            tool=request.tool, connection=request.connection, service=request.service, account=request.account,
            upstream_tool=request.upstream_tool,
        )  # fmt: skip
        return ApprovalDecision(False, "requested", self._waiting(request_id, approvers, expires, now), request_id)

    @staticmethod
    def _insert_request(db, request_id, request, now, expires):
        db.execute(
            "INSERT INTO requests (id, binding, status, client, principal, tool, connection, service, account, owner,"
            " upstream_tool, approvers, arguments, created, expires) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (request_id, request.binding, "pending", request.client_id, request.principal, request.tool,
             request.connection, request.service, request.account, request.owner, request.upstream_tool,
             json.dumps(sorted(request.approvers)), canonical(request.arguments).decode("utf-8"), now, expires),
        )
        db.execute("INSERT INTO dispatch VALUES (?,?,?)",
                   (request_id, request.configuration_revision, request.client_token_sha256))

    def dispatch_queue(self, limit):
        with self._db(write=False) as db:
            return [r["id"] for r in db.execute(
                "SELECT r.id FROM requests r JOIN dispatch d ON r.id=d.id WHERE r.status='approved' AND r.expires>? ORDER BY r.decided, r.rowid LIMIT ?", (_now(), limit))]

    def recover_dispatch(self):
        # A process that disappeared after claiming an operation may already have
        # changed the upstream. Never replay an execution whose outcome is unknown.
        with self._db() as db:
            db.execute("UPDATE requests SET outcome='execution_unknown' WHERE status='used' AND outcome IS NULL AND id IN (SELECT id FROM dispatch)")

    def claim_dispatch(self, request_id):
        now = _now()
        with self._db() as db:
            row = self._dispatch_row(db, request_id)
            if not row or row["status"] != "approved" or row["expires"] <= now:
                return None
            if not any(bytes(key["id"]).hex() == row["credential"] for key in self._credentials(db, [row["decided_by"]])):
                db.execute("UPDATE requests SET status='cancelled', outcome='approver_key_revoked', arguments=NULL WHERE id=?", (request_id,))
                return None
            db.execute("UPDATE requests SET status='used', used=?, arguments=NULL WHERE id=?", (now, request_id))
            return dict(row)

    @staticmethod
    def _dispatch_row(db, request_id):
        return db.execute("SELECT r.*, d.revision, d.client_token_sha256 FROM requests r JOIN dispatch d ON r.id=d.id WHERE r.id=?", (request_id,)).fetchone()

    def dispatch_status(self, request_id):
        with self._db(write=False) as db:
            row = self._dispatch_row(db, request_id)
            if not row:
                return None
            row = dict(row)
            if row["status"] in _OPEN and row["expires"] <= _now():
                row["status"] = "expired"
            return row

    def _waiting(self, request_id: str, approvers: str, expires: int, now: int) -> str:
        people = " or ".join(self.identity_label(p) for p in json.loads(approvers))
        minutes = max(1, (expires - now + 59) // 60)
        return (
            f"{NOT_EXECUTED} It is waiting at {self._url(request_id)} . Ask {people} to open that page and approve it "
            f"with their passkey within {minutes} minutes. The gateway executes the approved action automatically. "
            f"Call gateway_wait_for_approval with request_id {request_id} for its status and result. Do not resubmit the action."
        )

    async def finished(self, approval_id: str, outcome: str) -> None:
        with self._db() as db:
            db.execute("UPDATE requests SET outcome=? WHERE id=? AND status='used' AND outcome IS NULL", (outcome[:64], approval_id))

    # -- administration (the `agw approval` commands) -------------------------------

    def new_enrollment(self, principal: str) -> str:
        """A one-time link with which `principal` can register a passkey."""
        code = secrets.token_urlsafe(24)
        now = _now()
        with self._db() as db:
            self._sweep(db, now)
            db.execute("INSERT INTO enrollments VALUES (?,?,?)", (_sha256(code), principal, now + _ENROLL_TTL))
        return f"{self.cfg.origin}/approvals/enroll#{code}"

    def request_member_enrollment(self, principal, client, admin):
        if not self.member_allowed(principal, client.id, client.token_sha256, admin):
            raise Refused("enrollment_member_unavailable", 404)
        now, code = _now(), secrets.token_urlsafe(24)
        code_hash = _sha256(code)
        with self._db() as db:
            self._sweep(db, now)
            if not self._credentials(db, [admin]):
                raise Refused("administrator_passkey_required")
            outstanding = db.execute("SELECT count(*) FROM enrollment_requests WHERE client=?", (client.id,)).fetchone()[0]
            reviews = db.execute("SELECT count(*) FROM requests WHERE tool=? AND client=? AND status IN ('pending','approved')",
                                 (ENROLL_TOOL, client.id)).fetchone()[0]
            if outstanding + reviews >= 5:
                raise Refused("rate_limited", 429)
            db.execute("INSERT INTO enrollments VALUES (?,?,?)", (code_hash, principal, now + _ENROLL_TTL))
            db.execute("INSERT INTO enrollment_requests VALUES (?,?,?,?)", (code_hash, client.id, client.token_sha256, admin))
        return {"enrollment_url": f"{self.cfg.origin}/approvals/enroll#{code}", "expires_in_seconds": _ENROLL_TTL}

    def _member_metadata(self, db, enrollment):
        row = db.execute("SELECT * FROM enrollment_requests WHERE code_sha256=?", (enrollment["code_sha256"],)).fetchone()
        if row and not self.member_allowed(enrollment["principal"], row["client"], row["client_token_sha256"], row["administrator"]):
            raise Refused("invalid_enrollment_code")
        return row

    def activate_member_passkey(self, row):
        principal, admin = row["principal"], row["owner"]
        with self._db() as db:
            key = db.execute("SELECT * FROM pending_credentials WHERE request_id=?", (row["id"],)).fetchone()
            if not key or not self.member_allowed(principal, row["client"], row["client_token_sha256"], admin):
                outcome = "enrollment_member_unavailable"
            elif len(self._credentials(db, [principal])) >= _MAX_PASSKEYS_PER_PERSON:
                outcome = "too_many_passkeys"
            elif db.execute("SELECT 1 FROM credentials WHERE id=?", (key["id"],)).fetchone():
                outcome = "passkey_already_registered"
            else:
                db.execute("INSERT INTO credentials VALUES (?,?,?,?,?)", (key["id"], principal, key["data"], key["counter"], _now()))
                outcome = "ok"
            db.execute("DELETE FROM pending_credentials WHERE request_id=?", (row["id"],))
            db.execute("UPDATE requests SET outcome=? WHERE id=? AND status='used'", (outcome, row["id"]))
        self.audit.write("passkey_enrollment_reviewed", approver=admin, principal=principal, approval=row["id"], reason=outcome)

    def member_reviews(self):
        with self._db() as db:
            return [{"member": row["principal"], "agent": row["client"], "url": self._url(row["id"])}
                    for row in db.execute("SELECT id, principal, client FROM requests WHERE tool=? AND status='pending' AND expires>? ORDER BY created DESC",
                                          (ENROLL_TOOL, _now()))]

    def passkeys(self) -> list[dict[str, Any]]:
        with self._db() as db:
            rows = db.execute("SELECT id, principal, created FROM credentials ORDER BY principal, created").fetchall()
        return [{"id": bytes(r["id"]).hex(), "principal": r["principal"], "created": r["created"]} for r in rows]

    def forget_passkey(self, id_prefix: str) -> str:
        with self._db() as db:
            matches = [r for r in db.execute("SELECT id, principal FROM credentials") if bytes(r["id"]).hex().startswith(id_prefix)]
            if len(matches) != 1:
                raise Refused("no_such_passkey" if not matches else "ambiguous_passkey")
            db.execute("DELETE FROM credentials WHERE id=?", (matches[0]["id"],))
        self.audit.write("passkey_removed", approver=matches[0]["principal"])
        return matches[0]["principal"]

    def requests(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._db() as db:
            self._sweep(db, _now())
            rows = db.execute("SELECT * FROM requests ORDER BY created DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
        return [{key: row[key] for key in row.keys() if key not in ("arguments", "binding")} for row in rows]

    def cancel(self, request_id: str) -> None:
        """Withdraw a request that is waiting, or an approval that has not been used yet."""
        with self._db() as db:
            self._sweep(db, _now())
            done = db.execute(
                "UPDATE requests SET status='cancelled', arguments=NULL WHERE id=? AND status IN ('pending','approved')",
                (request_id,),
            ).rowcount
        if not done:
            raise Refused("stale_request")
        self.audit.write("approval_decided", approval=request_id, decision="cancel", approver="administrator")

    # -- WebAuthn ceremonies ------------------------------------------------------

    def view(self, request_id: str) -> dict[str, Any]:
        with self._db() as db:
            self._sweep(db, _now())
            row = db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        if row is None:
            raise Refused("not_found", 404)
        shown = {key: row[key] for key in row.keys() if key not in ("binding", "credential", "arguments", "approvers")}
        shown["automatic"] = self.dispatch_status(request_id) is not None
        if not shown["automatic"] and row["status"] in _OPEN:
            shown.update(status="cancelled", outcome="previous_version")
        shown["enrollment"] = row["tool"] == ENROLL_TOOL
        shown["approvers"] = json.loads(row["approvers"])
        shown["arguments"] = json.loads(row["arguments"]) if shown["status"] in _OPEN and row["arguments"] is not None else None
        people = {row["principal"], row["owner"], *shown["approvers"]}
        if row["decided_by"]:
            people.add(row["decided_by"])
        shown["names"] = {p: self.name_of(p) for p in people}
        return shown

    def _credentials(self, db: sqlite3.Connection, principals: list[str]) -> list[sqlite3.Row]:
        marks = ",".join("?" * len(principals))
        return db.execute(f"SELECT * FROM credentials WHERE principal IN ({marks})", principals).fetchall()

    @staticmethod
    def _open_request(db: sqlite3.Connection, action: str, request_id: str) -> sqlite3.Row:
        row = db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        if row is None or row["status"] != _DECISIONS[action] or not db.execute("SELECT 1 FROM dispatch WHERE id=?", (request_id,)).fetchone():
            raise Refused("stale_request")
        return row

    @staticmethod
    def _challenge(nonce: bytes, action: str, row: sqlite3.Row) -> bytes:
        """What the passkey signs: a fresh nonce, the decision, and every stored field of the request
        (arguments, account, tool, who asked, status, expiry). Recomputed from the stored request when
        the answer arrives, so an answer is only good for the request as it was shown."""
        request = canonical({key: row[key] for key in row.keys() if key != "outcome"})
        return hashlib.sha256(nonce + action.encode("ascii") + b"\0" + request).digest()

    def begin(self, action: str, target: str) -> dict[str, Any]:
        if action not in ("enroll", *_DECISIONS) or not isinstance(target, str) or not 0 < len(target) <= 128:
            raise Refused("invalid_argument", 400)
        now = _now()
        with self._db() as db:
            self._sweep(db, now)
            if db.execute("SELECT count(*) FROM ceremonies").fetchone()[0] >= _MAX_CEREMONIES:
                raise Refused("rate_limited", 429)
            if action == "enroll":
                code = _sha256(target)
                enrollment = db.execute("SELECT * FROM enrollments WHERE code_sha256=?", (code,)).fetchone()
                if enrollment is None:
                    raise Refused("invalid_enrollment_code")
                self._member_metadata(db, enrollment)
                principal = enrollment["principal"]
                existing = self._credentials(db, [principal])
                if len(existing) >= _MAX_PASSKEYS_PER_PERSON:
                    raise Refused("too_many_passkeys")
                options, state = self._server.register_begin(
                    {"id": principal.encode("utf-8"), "name": self.name_of(principal), "displayName": self.name_of(principal)},
                    [AttestedCredentialData(bytes(r["data"])) for r in existing],
                    resident_key_requirement=ResidentKeyRequirement.REQUIRED,
                    user_verification=UserVerificationRequirement.REQUIRED,
                )
                target, binding = code, principal
            else:
                row = self._open_request(db, action, target)
                allowed = self._credentials(db, json.loads(row["approvers"]))
                if not allowed:
                    raise Refused("not_enrolled")
                nonce = secrets.token_bytes(32)
                options, state = self._server.authenticate_begin(
                    [AttestedCredentialData(bytes(r["data"])) for r in allowed],
                    user_verification=UserVerificationRequirement.REQUIRED,
                    challenge=self._challenge(nonce, action, row),
                )
                binding = nonce.hex()
            # A few prompts per request or link at most; opening more closes the oldest. One request
            # cannot use up the room that other requests need.
            db.execute(
                "DELETE FROM ceremonies WHERE id IN (SELECT id FROM ceremonies WHERE target=?"
                " ORDER BY expires DESC, rowid DESC LIMIT -1 OFFSET ?)",
                (target, _MAX_CEREMONIES_PER_TARGET - 1),
            )
            ceremony_id = secrets.token_urlsafe(24)
            db.execute(
                "INSERT INTO ceremonies VALUES (?,?,?,?,?,?)",
                (ceremony_id, action, target, binding, json.dumps(state), now + _CEREMONY_TTL),
            )
        return {"ceremony_id": ceremony_id, "options": dict(options)}

    def finish(self, ceremony_id: str, response: Any) -> dict[str, Any]:
        now = _now()
        with self._db() as db:
            self._sweep(db, now)
            ceremony = db.execute("SELECT * FROM ceremonies WHERE id=?", (ceremony_id,)).fetchone()
            if ceremony is None:
                raise Refused("expired_ceremony")
            db.execute("DELETE FROM ceremonies WHERE id=?", (ceremony_id,))  # single use, even if what follows fails
        review_id = None
        action, target, state = ceremony["action"], ceremony["target"], json.loads(ceremony["state"])
        try:
            parsed = (RegistrationResponse if action == "enroll" else AuthenticationResponse).from_dict(response)
            client_data = json.loads(bytes(parsed.response.client_data))
        except Exception:
            raise Refused("invalid_response", 400) from None
        if client_data.get("crossOrigin") or client_data.get("topOrigin"):
            raise Refused("invalid_response", 400)

        with self._db() as db:
            if action == "enroll":
                enrollment = db.execute("SELECT * FROM enrollments WHERE code_sha256=?", (target,)).fetchone()
                if enrollment is None or enrollment["principal"] != ceremony["binding"]:
                    raise Refused("invalid_enrollment_code")
                try:
                    registered = self._server.register_complete(state, parsed)
                except Exception:
                    raise Refused("verification_failed") from None
                credential = registered.credential_data
                if credential is None:
                    raise Refused("verification_failed")
                principal = enrollment["principal"]
                metadata = self._member_metadata(db, enrollment)
                if len(self._credentials(db, [principal])) >= _MAX_PASSKEYS_PER_PERSON:
                    raise Refused("too_many_passkeys")
                if (db.execute("SELECT 1 FROM credentials WHERE id=?", (credential.credential_id,)).fetchone() or
                        db.execute("SELECT 1 FROM pending_credentials WHERE id=?", (credential.credential_id,)).fetchone()):
                    raise Refused("passkey_already_registered", 409)
                if metadata:
                    review_id = secrets.token_urlsafe(24)
                    details = {"member": self.name_of(principal), "credential_fingerprint": bytes(credential.credential_id).hex()[:16]}
                    request = ApprovalRequest(
                        principal=principal, client_id=metadata["client"], tool=ENROLL_TOOL, connection="passkeys",
                        service="passkey", account=principal, upstream_tool="register", arguments_sha256=_sha256(review_id),
                        arguments=details, owner=metadata["administrator"], approvers=(metadata["administrator"],),
                        client_token_sha256=metadata["client_token_sha256"],
                    )
                    self._insert_request(db, review_id, request, now, now + _MEMBER_REVIEW_TTL)
                    db.execute("INSERT INTO pending_credentials VALUES (?,?,?,?)",
                               (review_id, credential.credential_id, bytes(credential), registered.counter))
                else:
                    db.execute("INSERT INTO credentials VALUES (?,?,?,?,?)",
                               (credential.credential_id, principal, bytes(credential), registered.counter, now))
                db.execute("DELETE FROM enrollments WHERE code_sha256=?", (target,))
                db.execute("DELETE FROM enrollment_requests WHERE code_sha256=?", (target,))
                decided_by, request_row = enrollment["principal"], None
            else:
                row = self._open_request(db, action, target)
                expected = websafe_encode(self._challenge(bytes.fromhex(ceremony["binding"]), action, row))
                if not hmac.compare_digest(expected, str(state.get("challenge"))):
                    raise Refused("stale_request")
                allowed = self._credentials(db, json.loads(row["approvers"]))
                try:
                    used = self._server.authenticate_complete(
                        state, [AttestedCredentialData(bytes(r["data"])) for r in allowed], parsed
                    )
                except Exception:
                    raise Refused("verification_failed") from None
                owner = next(r for r in allowed if bytes(r["id"]) == used.credential_id)
                decided_by = owner["principal"]
                handle = parsed.response.user_handle
                if handle is not None and bytes(handle) != decided_by.encode("utf-8"):
                    raise Refused("verification_failed")
                # A signature counter that goes backwards means a cloned authenticator. Synced
                # passkeys always report 0, which is why 0 -> 0 is accepted.
                counter = parsed.response.authenticator_data.counter
                if (owner["counter"] or counter) and counter <= owner["counter"]:
                    raise Refused("verification_failed")
                db.execute("UPDATE credentials SET counter=? WHERE id=?", (counter, owner["id"]))
                credential_hex = bytes(owner["id"]).hex()
                if action == "approve":
                    db.execute(
                        "UPDATE requests SET status='approved', decided=?, decided_by=?, credential=?, expires=? WHERE id=?",
                        (now, decided_by, credential_hex, now + self.cfg.grant_ttl_seconds, target),
                    )
                else:
                    status = "denied" if action == "deny" else "cancelled"
                    db.execute(
                        "UPDATE requests SET status=?, decided=?, decided_by=?, credential=?, arguments=NULL WHERE id=?",
                        (status, now, decided_by, credential_hex, target),
                    )
                request_row = row

        if review_id:
            self.audit.write("passkey_enrollment_requested", principal=decided_by, approval=review_id)
            return {"action": action, "pending": True, "approval_url": self._url(review_id), "request_id": review_id}
        if request_row is None:
            self.audit.write("passkey_enrolled", approver=decided_by)
            return {"action": action}
        self.audit.write(
            "approval_decided", approval=target, decision=action, approver=decided_by, client=request_row["client"],
            principal=request_row["principal"], tool=request_row["tool"], connection=request_row["connection"],
            service=request_row["service"], account=request_row["account"], upstream_tool=request_row["upstream_tool"],
        )  # fmt: skip
        return {"action": action, "request": self.view(target)}

    # -- HTTP ---------------------------------------------------------------------

    def http_routes(self, notify=lambda: None) -> list[BaseRoute]:
        async def page(request: Request) -> Response:
            return _static("approve.html", "text/html; charset=utf-8")

        async def script(request: Request) -> Response:
            return _static("approve.js", "text/javascript; charset=utf-8")

        async def style(request: Request) -> Response:
            return _static("approve.css", "text/css; charset=utf-8")

        async def view(request: Request) -> Response:
            return self._answer(lambda: self.view(request.path_params["request_id"]))

        async def begin(request: Request) -> Response:
            body = await self._body(request)
            if isinstance(body, Response):
                return body
            return self._answer(lambda: self.begin(body.get("action"), body.get("target")))

        async def finish(request: Request) -> Response:
            body = await self._body(request)
            if isinstance(body, Response):
                return body
            result = self._answer(lambda: self.finish(str(body.get("ceremony_id")), body.get("response")))
            if result.status_code == 200:
                notify()
            return result

        return [
            Route("/approvals/r/{request_id}", page, methods=["GET"]),
            Route("/approvals/enroll", page, methods=["GET"]),
            Route("/approvals/approve.js", script, methods=["GET"]),
            Route("/approvals/approve.css", style, methods=["GET"]),
            Route("/approvals/api/request/{request_id}", view, methods=["GET"]),
            Route("/approvals/api/begin", begin, methods=["POST"]),
            Route("/approvals/api/finish", finish, methods=["POST"]),
        ]

    async def _body(self, request: Request) -> dict[str, Any] | Response:
        # Only the approval page itself may post here: a browser sends its origin, and it must be ours.
        if request.headers.get("origin") != self.cfg.origin:
            return _json({"error": "wrong_origin"}, 403)
        if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
            return _json({"error": "invalid_argument"}, 400)
        raw = await request.body()
        if len(raw) > _MAX_BODY:
            return _json({"error": "invalid_argument"}, 400)
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        return body if isinstance(body, dict) else _json({"error": "invalid_argument"}, 400)

    def _answer(self, action: Any) -> Response:
        try:
            return _json(action(), 200)
        except Refused as refused:
            return _json({"error": refused.code, **({"incident": refused.incident} if refused.incident else {})}, refused.status)
        except Exception as exc:
            from .web_errors import failure_response
            return failure_response(exc, self.audit, _PAGE_HEADERS)


def _json(data: Any, status: int) -> Response:
    return JSONResponse(data, status_code=status, headers=_PAGE_HEADERS)


def _static(name: str, media_type: str) -> Response:
    return Response((_STATIC / name).read_bytes(), media_type=media_type, headers=_PAGE_HEADERS)
