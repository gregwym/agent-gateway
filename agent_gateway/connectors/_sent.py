"""Keep exactly one copy of every submitted message in the Sent folder.

A pending record (the submitted bytes and Message-ID) is written before the end
of SMTP DATA and removed only once Sent is known to hold the message, so a
lost connection, an unknown SMTP outcome or a restart is resolved later by
looking at the mailbox. A background worker does that work; every step looks
before it acts, so any step can be retried.

How the copy gets there depends on the provider:

- Servers that file submitted mail themselves (known SMTP hosts, or learned):
  nothing is added; the worker confirms the message is in Sent.
- Otherwise the sender is added as an envelope-only Bcc. The delivered copy,
  wherever a rule put it, is marked read and moved to Sent.
- A server that accepted the message but never delivers the sender's copy is
  remembered; from then on the submitted bytes are appended to Sent instead.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import imaplib
import json
import os
import tempfile
import threading
import time
from email.parser import BytesHeaderParser
from pathlib import Path
from typing import Any

from ._imap_ops import special_folders

SERVER_SAVES, SELF_BCC, APPEND = "server_saves", "self_bcc", "append"
# Submission servers that file every message in the account's Sent folder themselves.
SAVING_HOSTS = frozenset({"smtp.gmail.com", "smtp.googlemail.com", "smtp.office365.com", "smtp-mail.outlook.com", "smtp.outlook.com"})
SENT_NAMES = ("sent", "sent messages", "sent items", "sent mail")
GRACE = 120  # provider not known yet: give the server's own copy this long before filing ours
ARRIVAL = 900  # a copy should appear in the mailbox within this long after an accepted submission
DECIDE = 900  # an unknown submission with no copy anywhere after this long was not delivered
WAIT = 5  # how long send_message waits for the copy before reporting it pending
_HEADER = "BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]"


def _write(path: Path, data: bytes) -> None:
    """Atomically replace `path`, readable only by this user, and make it durable."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _message_id(header: bytes) -> str:
    return (BytesHeaderParser().parsebytes(header)["Message-ID"] or "").strip()


def _flags(flags) -> set[str]:
    return {(f.decode() if isinstance(f, bytes) else str(f)).lower() for f in flags}


class SentCopies:
    def __init__(self, directory, connect, smtp_host: str, sender: str, own=(), *, clock=time.time,
                 grace: float = GRACE, arrival: float = ARRIVAL, decide: float = DECIDE, wait: float = WAIT) -> None:
        # Without a gateway state directory, records survive only as long as this process.
        self.dir = Path(directory) if directory else Path(tempfile.mkdtemp(prefix="agw-sent-"))
        self.pending = self.dir / "pending"
        self.pending.mkdir(parents=True, exist_ok=True)
        for path in (self.dir, self.pending):
            os.chmod(path, 0o700)  # pending records contain whole messages
        self.connect, self.host, self.sender = connect, smtp_host.lower(), sender
        self.own = {a.lower() for a in (sender, *own)}  # the sender and the mailbox's other addresses
        self.clock, self.grace, self.arrival, self.decide, self.wait_seconds = clock, grace, arrival, decide, wait
        self._results: dict[str, dict[str, Any]] = {}
        self._waiting: set[str] = set()
        self._changed = threading.Condition()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    # -- what this connection does --------------------------------------------------

    def _learned(self) -> dict[str, Any]:
        try:
            data = json.loads((self.dir / "mode.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) and data.get("smtp_host") == self.host else {}

    def _learn(self, **values) -> None:
        _write(self.dir / "mode.json", json.dumps({**self._learned(), **values, "smtp_host": self.host}).encode())

    def mode(self) -> str | None:
        return SERVER_SAVES if self.host in SAVING_HOSTS else self._learned().get("mode")

    def self_bcc(self, recipients: list[str]) -> bool:
        # A message to this mailbox's own address is that person's mail, never something to move.
        return self.mode() in (None, SELF_BCC) and not self.own & {r.lower() for r in recipients}

    # -- records ------------------------------------------------------------------

    def _path(self, message_id: str) -> Path:
        return self.pending / (hashlib.sha256(message_id.encode()).hexdigest() + ".json")

    def _save(self, record: dict[str, Any]) -> None:
        _write(self._path(record["message_id"]), json.dumps(record).encode())

    def _records(self) -> list[dict[str, Any]]:
        records = []
        for path in sorted(self.pending.glob("*.json")):
            try:
                records.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        return records

    def begin(self, raw: bytes, message_id: str, self_bcc: bool) -> None:
        """Record a message before the end of DATA; its outcome is unknown until the server replies."""
        with self._changed:
            self._waiting.add(message_id)  # so a result reached before wait() is not lost
        # Not due until settle(): the worker leaves it alone while SMTP is still running. A record
        # left by a process that died here comes due later and is resolved as an unknown outcome.
        self._save({"message_id": message_id, "raw": base64.b64encode(raw).decode(), "self_bcc": self_bcc,
                    "outcome": "unknown", "created": self.clock(), "stage": None, "filed": False,
                    "attempts": 0, "next": self.clock() + 600})

    def settle(self, message_id: str, accepted: bool) -> None:
        """SMTP finished: the server accepted the message, or the outcome stays unknown."""
        record = json.loads(self._path(message_id).read_text(encoding="utf-8"))
        record["outcome"], record["next"] = "accepted" if accepted else "unknown", 0
        self._save(record)

    def discard(self, message_id: str) -> None:
        """The message was certainly not sent."""
        self._path(message_id).unlink(missing_ok=True)
        with self._changed:
            self._waiting.discard(message_id)

    def wait(self, message_id: str) -> dict[str, Any] | None:
        """Ask the worker to handle the message now; return its result if it finishes in time."""
        self._wake.set()
        with self._changed:
            try:
                self._changed.wait_for(lambda: message_id in self._results, self.wait_seconds)
                return self._results.pop(message_id, None)
            finally:
                self._waiting.discard(message_id)

    def _finish(self, record: dict[str, Any], copy: dict[str, Any], delivered: bool) -> None:
        self._path(record["message_id"]).unlink(missing_ok=True)
        with self._changed:
            if record["message_id"] in self._waiting:
                self._results[record["message_id"]] = {"sent_copy": copy, "delivered": delivered}
                self._changed.notify_all()

    # -- the worker ---------------------------------------------------------------

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="sent-copies", daemon=True)
            self._thread.start()

    def _loop(self) -> None:
        while True:
            self._wake.clear()
            try:
                delay = self.run_once()
            except Exception:
                delay = 60
            self._wake.wait(3600 if delay is None else delay)

    def run_once(self) -> float | None:
        """Work on every due record; return seconds until the next one is due (None: nothing pending)."""
        if not self._records():
            return None
        with open(self.dir / "lock", "a") as lock:
            try:
                # Another process of this connection (for example during a reload) is already at it.
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return 30
            records = self._records()
            now = self.clock()
            due = [r for r in records if r["next"] <= now]
            if due:
                try:
                    client = self.connect()
                except Exception:
                    for record in due:
                        self._retry(record)
                else:
                    try:
                        for record in due:
                            try:
                                self._resolve(client, record)
                            except (imaplib.IMAP4.abort, OSError, EOFError):
                                self._retry(record)
                                break  # the connection is gone; the others wait for the next round
                            except Exception:
                                self._retry(record)
                    finally:
                        try:
                            client.logout()
                        except Exception:
                            pass
            remaining = self._records()
            return max(1.0, min(r["next"] for r in remaining) - self.clock()) if remaining else None

    def _retry(self, record: dict[str, Any], delay: float | None = None) -> None:
        if delay is None:
            record["attempts"] += 1
            delay = min(600, 5 * 2 ** min(record["attempts"], 7))
        record["next"] = self.clock() + delay
        if self._path(record["message_id"]).exists():
            self._save(record)

    # -- one record -----------------------------------------------------------------

    def _resolve(self, client, record: dict[str, Any]) -> None:
        message_id, age, mode = record["message_id"], self.clock() - record["created"], self.mode()
        # Virtual folders (Gmail's All Mail and the like) show the same message again; never touch them.
        folders = [(flags, delimiter, name) for flags, delimiter, name in client.list_folders()
                   if not _flags(flags) & {"\\noselect", "\\nonexistent", "\\all", "\\flagged", "\\important"}]
        sent = self._sent_folder(folders)
        if record["stage"]:
            if self._staged(client, record):
                return self._saved(client, record, record["stage"]["folder"], self._find(client, folders, message_id), age)
            record["stage"], record["filed"] = None, False  # the step did not happen; decide again from what is there
            self._save(record)
        hits = self._find(client, folders, message_id)
        if sent and hits.get(sent):
            return self._saved(client, record, sent, hits, age)
        others = {name: uids for name, uids in hits.items() if name != sent}
        if others and record["self_bcc"]:
            if mode is None and age < self.grace:
                return self._retry(record, self.grace - age)  # the server may still file its own copy
            sent = sent or self._create_sent(client, folders)
            source = next(iter(others))
            self._stage(client, record, sent)
            self._move(client, source, others[source][0], sent)
            if mode is None:
                self._learn(mode=SELF_BCC)
            return self._confirm(client, record, folders, age)
        if others and sent is None and mode == SERVER_SAVES:
            # The server filed it in a folder that is not recognisably Sent: that is its Sent folder.
            folder = next((n for n in others if n.upper() != "INBOX"), None)
            if folder:
                self._learn(sent_folder=folder)
                return self._saved(client, record, folder, hits, age)
        if record["outcome"] == "unknown":
            if age < self.decide:
                return self._retry(record, min(60, self.decide - age))
            if record["self_bcc"] or mode == SERVER_SAVES:
                return self._finish(record, {"status": "skipped", "reason": "No copy of the message appeared, so it was not sent."}, False)
            return self._finish(record, {"status": "skipped", "reason": "The submission outcome is unknown and this server offers no copy to confirm it. Check with the recipient before resending."}, None)
        wait = {APPEND: 0, None: self.arrival if record["self_bcc"] else self.grace,
                SELF_BCC: self.arrival if record["self_bcc"] else 0}.get(mode, self.arrival)
        if age < wait:
            return self._retry(record, min(60, wait - age))
        if record["self_bcc"] and mode is None:
            self._learn(mode=APPEND)  # accepted with 250, yet the sender's copy never arrived
        sent = sent or self._create_sent(client, folders)
        self._stage(client, record, sent)
        client.append(sent, base64.b64decode(record["raw"]), flags=(b"\\Seen",))
        return self._confirm(client, record, folders, age)

    def _confirm(self, client, record, folders, age: float) -> None:
        record["filed"] = True
        self._save(record)
        if self._staged(client, record):
            return self._saved(client, record, record["stage"]["folder"], self._find(client, folders, record["message_id"]), age)
        self._retry(record)  # the next round looks again before doing anything

    def _saved(self, client, record, folder: str, hits: dict[str, list[int]], age: float) -> None:
        if record["self_bcc"] and not record["filed"]:
            # The server filed its own copy, so ours is surplus. Remove exactly one: any other copy
            # outside Sent was delivered to an address of this mailbox and belongs to the person.
            extra = next(((name, uids[0]) for name, uids in hits.items() if name != folder), None)
            if extra:
                self._delete(client, *extra)
            elif age < self.arrival:
                # The server filed its own copy; wait for ours so it does not linger in the inbox.
                return self._retry(record, 30)
        if self.mode() is None and not record["filed"]:
            self._learn(mode=SERVER_SAVES, sent_folder=folder)
        self._finish(record, {"status": "saved", "mailbox": folder}, True)

    # -- mailbox steps --------------------------------------------------------------

    def _sent_folder(self, folders) -> str | None:
        flagged = special_folders(folders, "\\Sent")
        if len(flagged) == 1:
            return flagged[0]
        names = [name for _, _, name in folders]
        learned = self._learned().get("sent_folder")
        if learned in names:
            return learned
        for wanted in SENT_NAMES:
            for _, delimiter, name in folders:
                leaf = name.rsplit(delimiter.decode() if isinstance(delimiter, bytes) else delimiter, 1)[-1] if delimiter else name
                if wanted in (name.lower(), leaf.lower()):
                    return name
        return None

    def _create_sent(self, client, folders) -> str:
        delimiter = next((d for _, d, n in folders if n.upper() == "INBOX" and d), b".")
        delimiter = delimiter.decode() if isinstance(delimiter, bytes) else delimiter
        for name in ("Sent", "INBOX" + delimiter + "Sent"):  # some servers keep every folder under INBOX
            try:
                client.create_folder(name)
            except imaplib.IMAP4.error:
                continue
            self._learn(sent_folder=name)
            return name
        raise RuntimeError("no Sent folder could be created")

    def _find(self, client, folders, message_id: str) -> dict[str, list[int]]:
        hits = {}
        for _, _, name in folders:
            client.select_folder(name, readonly=True)
            uids = client.search(["HEADER", "Message-ID", message_id])
            if uids:
                # SEARCH HEADER matches substrings; keep exact matches only.
                fetched = client.fetch(uids, [_HEADER])
                exact = sorted(uid for uid, data in fetched.items()
                               if _message_id(next((v for k, v in data.items() if k.startswith(b"BODY[")), b"")) == message_id)
                if exact:
                    hits[name] = exact
        return hits

    def _stage(self, client, record, folder: str) -> None:
        """Note where a new message would appear before adding it, so a retry checks instead of adding again."""
        status = client.folder_status(folder, ["UIDNEXT", "UIDVALIDITY"])
        record["stage"] = {"folder": folder, "uidnext": status[b"UIDNEXT"], "uidvalidity": status[b"UIDVALIDITY"]}
        self._save(record)

    def _staged(self, client, record) -> bool:
        stage = record["stage"]
        info = client.select_folder(stage["folder"], readonly=True)
        if info.get(b"UIDVALIDITY") != stage["uidvalidity"]:
            return False
        if info.get(b"UIDNEXT", stage["uidnext"] + 1) <= stage["uidnext"]:
            return False  # nothing was added since the step was staged
        # A UID range, not a text SEARCH: it does not depend on the server's search index.
        added = [uid for uid in client.search(["UID", f"{stage['uidnext']}:*"]) if uid >= stage["uidnext"]]
        fetched = client.fetch(added, [_HEADER]) if added else {}
        return any( _message_id(next((v for k, v in data.items() if k.startswith(b"BODY[")), b"")) == record["message_id"]
                   for uid, data in fetched.items())

    def _move(self, client, folder: str, uid: int, destination: str) -> None:
        client.select_folder(folder)
        client.add_flags([uid], [b"\\Seen"])
        if client.has_capability("MOVE"):
            client.move([uid], destination)
        else:
            client.copy([uid], destination)
            self._remove(client, uid)

    def _delete(self, client, folder: str, uid: int) -> None:
        client.select_folder(folder)
        self._remove(client, uid)

    @staticmethod
    def _remove(client, uid: int) -> None:
        client.add_flags([uid], [b"\\Deleted"])
        if client.has_capability("UIDPLUS"):
            client.uid_expunge([uid])  # never an unscoped EXPUNGE
