"""Durable operation queue and the Agent's idempotency keys."""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from .approval import ApprovalRequest, canonical

_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY, binding TEXT NOT NULL, status TEXT NOT NULL,
    client TEXT NOT NULL, principal TEXT NOT NULL, tool TEXT NOT NULL, connection TEXT NOT NULL,
    service TEXT NOT NULL, account TEXT NOT NULL, owner TEXT NOT NULL, upstream_tool TEXT NOT NULL,
    approvers TEXT NOT NULL, arguments TEXT,
    created INTEGER NOT NULL, expires INTEGER NOT NULL,
    decided INTEGER, decided_by TEXT, credential TEXT, used INTEGER, outcome TEXT);
CREATE INDEX IF NOT EXISTS requests_binding ON requests (binding, created);
CREATE INDEX IF NOT EXISTS requests_queued ON requests (status, expires) WHERE status IN ('approved','queued');
CREATE TABLE IF NOT EXISTS dispatch (
    id TEXT PRIMARY KEY, revision TEXT NOT NULL, client_token_sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS task_state (
    id TEXT PRIMARY KEY, link_accepted INTEGER, finished INTEGER);
CREATE TABLE IF NOT EXISTS request_keys (
    client TEXT NOT NULL, key_hash TEXT NOT NULL, input_hash TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE, PRIMARY KEY (client, key_hash));
"""
_OPEN = ("pending", "approved")
_MAX_PENDING_PER_CLIENT = 5


def key_digest(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


@dataclass(frozen=True)
class SubmissionKey:
    digest: str
    input_digest: str

    @classmethod
    def from_call(cls, arguments):
        # Mode flags affect delivery, not the identity of the operation.
        command = {field: arguments[field] for field in ("tool", "connection", "arguments", "variant") if field in arguments}
        return cls(key_digest(arguments["idempotency_key"]), hashlib.sha256(canonical(command)).hexdigest())


class QueueFull(Exception):
    pass


class IdempotencyConflict(Exception):
    pass


class RequestStore:
    def __init__(self, path, audit, retention_days, request_ttl_seconds=600, *, extra_schema=""):
        self.path = path
        self.audit = audit
        self._retention = retention_days * 86_400
        self.request_ttl_seconds = request_ttl_seconds
        path.parent.mkdir(parents=True, exist_ok=True)
        setup = sqlite3.connect(path, timeout=10)
        try:
            setup.executescript(_SCHEMA + extra_schema)
        finally:
            setup.close()

    @staticmethod
    def _clock():
        return int(time.time())

    @staticmethod
    def _matching_key(db, client_id, token_digest, key):
        row = db.execute(
            "SELECT k.input_hash, k.request_id, d.client_token_sha256 FROM request_keys k"
            " JOIN dispatch d ON d.id=k.request_id WHERE k.client=? AND k.key_hash=?",
            (client_id, key.digest)).fetchone()
        if not row:
            return None
        if row["input_hash"] != key.input_digest or row["client_token_sha256"] != token_digest:
            raise IdempotencyConflict()
        return row["request_id"]

    def existing_key(self, client_id, token_digest, key):
        with self._db(write=False) as db:
            return self._matching_key(db, client_id, token_digest, key)

    def request_for_key(self, client_id, token_digest, key):
        with self._db(write=False) as db:
            row = db.execute(
                "SELECT k.request_id FROM request_keys k JOIN dispatch d ON d.id=k.request_id"
                " WHERE k.client=? AND k.key_hash=? AND d.client_token_sha256=?",
                (client_id, key_digest(key), token_digest)).fetchone()
            return row["request_id"] if row else None

    @contextmanager
    def _db(self, *, write=True) -> Iterator[sqlite3.Connection]:
        """One short transaction. IMMEDIATE, so check-then-update sequences cannot interleave."""
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
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
            "UPDATE requests SET status='expired', arguments=NULL WHERE status IN ('pending','approved','queued') AND expires<=?",
            (now,),
        )
        db.execute("DELETE FROM requests WHERE status NOT IN ('pending','approved','queued') AND created<?", (now - self._retention,))
        db.execute("DELETE FROM dispatch WHERE id NOT IN (SELECT id FROM requests)")
        db.execute("DELETE FROM task_state WHERE id NOT IN (SELECT id FROM dispatch)")
        db.execute("DELETE FROM request_keys WHERE request_id NOT IN (SELECT id FROM dispatch)")

    def enqueue(self, request: ApprovalRequest, key: SubmissionKey | None = None) -> str:
        """Schedule a permitted background call without creating a public approval."""
        now = self._clock()
        with self._db() as db:
            self._sweep(db, now)
            if key and (existing := self._matching_key(db, request.client_id, request.client_token_sha256, key)):
                return existing
            if db.execute("SELECT count(*) FROM requests WHERE client=? AND status='queued'", (request.client_id,)).fetchone()[0] >= _MAX_PENDING_PER_CLIENT:
                raise QueueFull()
            request_id = secrets.token_urlsafe(24)
            self._insert_request(db, request_id, request, now, now + self.request_ttl_seconds, status="queued", key=key)
        return request_id

    @staticmethod
    def _insert_request(db, request_id, request, now, expires, *, status="pending", key=None):
        db.execute(
            "INSERT INTO requests (id, binding, status, client, principal, tool, connection, service, account, owner,"
            " upstream_tool, approvers, arguments, created, expires) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (request_id, request.binding, status, request.client_id, request.principal, request.tool,
             request.connection, request.service, request.account, request.owner, request.upstream_tool,
             json.dumps(sorted(request.approvers)), canonical(request.arguments).decode("utf-8"), now, expires),
        )
        db.execute("INSERT INTO dispatch VALUES (?,?,?)",
                   (request_id, request.configuration_revision, request.client_token_sha256))
        # Direct tools in full-list mode have no Gateway wrapper arguments.
        # A generated key lets their approvals use the same lookup interface.
        key = key or SubmissionKey(key_digest(request_id), "")
        db.execute("INSERT INTO request_keys VALUES (?,?,?,?)",
                   (request.client_id, key.digest, key.input_digest, request_id))

    def dispatch_queue(self, limit):
        with self._db(write=False) as db:
            return [r["id"] for r in db.execute(
                "SELECT r.id FROM requests r JOIN dispatch d ON r.id=d.id WHERE r.status IN ('approved','queued') AND r.expires>? ORDER BY coalesce(r.decided, r.created), r.rowid LIMIT ?", (self._clock(), limit))]

    def recover_dispatch(self):
        # A process that disappeared after claiming an operation may already have
        # changed the upstream. Never replay an execution whose outcome is unknown.
        with self._db() as db:
            db.execute("UPDATE requests SET outcome='execution_unknown' WHERE status='used' AND outcome IS NULL AND id IN (SELECT id FROM dispatch)")

    def _approved_key_is_active(self, db, row):
        return False  # Only a Passkey store can accept an approved operation.

    def claim_dispatch(self, request_id):
        now = self._clock()
        with self._db() as db:
            row = self._dispatch_row(db, request_id)
            if not row or row["status"] not in ("approved", "queued") or row["expires"] <= now:
                return None
            if row["status"] == "approved" and not self._approved_key_is_active(db, row):
                db.execute("UPDATE requests SET status='cancelled', outcome='approver_key_revoked', arguments=NULL WHERE id=?", (request_id,))
                return None
            db.execute("UPDATE requests SET status='used', used=?, arguments=NULL WHERE id=?", (now, request_id))
            return dict(row)

    @staticmethod
    def _dispatch_row(db, request_id):
        return db.execute("SELECT r.*, d.revision, d.client_token_sha256 FROM requests r JOIN dispatch d ON r.id=d.id WHERE r.id=?", (request_id,)).fetchone()

    def dispatch_status(self, request_id):
        with self._db(write=False) as db:
            row = db.execute(
                "SELECT r.status, r.client, r.outcome, r.created, r.expires, r.decided, r.used, r.approvers,"
                " d.revision, d.client_token_sha256, t.link_accepted, t.finished"
                " FROM requests r JOIN dispatch d ON r.id=d.id LEFT JOIN task_state t ON r.id=t.id WHERE r.id=?",
                (request_id,)).fetchone()
            if not row:
                return None
            row = dict(row)
            if row["status"] in (*_OPEN, "queued") and row["expires"] <= self._clock():
                row["status"] = "expired"
            return row

    @property
    def task_retention_ms(self):
        return self._retention * 1000

    def task_control(self, request_id, action, *, reply=False):
        now = self._clock()
        with self._db() as db:
            row = self._dispatch_row(db, request_id)
            if not row or row["expires"] <= now:
                return
            if reply and (row["status"] != "pending" or db.execute(
                    "SELECT 1 FROM task_state WHERE id=? AND link_accepted IS NOT NULL", (request_id,)).fetchone()):
                return
            if action == "accept":
                db.execute("INSERT INTO task_state (id, link_accepted) VALUES (?,?)"
                           " ON CONFLICT(id) DO UPDATE SET link_accepted=excluded.link_accepted", (request_id, now))
                return
            if row["status"] not in ("pending", "approved", "queued"):
                return
            db.execute("UPDATE requests SET status='cancelled', decided=?, arguments=NULL WHERE id=?",
                       (now, request_id))
        self.audit.write("approval_cancelled", approval=request_id, client=row["client"], reason="client_cancelled")

    async def finished(self, approval_id: str, outcome: str) -> None:
        with self._db() as db:
            updated = db.execute("UPDATE requests SET outcome=? WHERE id=? AND status='used' AND outcome IS NULL",
                                 (outcome[:64], approval_id))
            if updated.rowcount:
                db.execute("INSERT INTO task_state (id, finished) VALUES (?,?)"
                           " ON CONFLICT(id) DO UPDATE SET finished=excluded.finished", (approval_id, self._clock()))
