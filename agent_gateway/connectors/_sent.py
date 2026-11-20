"""Keep one copy of every submitted message in the mailbox's Sent folder.

send_message writes the submitted message here before the end of SMTP DATA. A
background thread files it later: once a record is DELAY old, it looks for the
Message-ID in Sent and appends the message only if it is not there yet. A
server that files sent mail itself (Gmail, Outlook and others) has put it there
by then, so it gets no second copy. A record is deleted once Sent holds the
message; until then every round simply tries again, also after a restart.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import shutil
import tempfile
import threading
import time
from email.parser import BytesHeaderParser
from pathlib import Path

from ._imap_ops import special_folders

DELAY = 120  # time for a server that files sent mail itself to do so
INTERVAL = 60  # how often pending copies are retried
SENT_NAMES = ("sent", "sent messages", "sent items", "sent mail")


class SentCopies:
    def __init__(self, directory, account: str, connect, *, clock=time.time, delay: float = DELAY) -> None:
        # One subdirectory per mailbox account, so a record is never filed into another account.
        root = Path(directory)
        name = "sent-" + hashlib.sha256(account.lower().encode()).hexdigest()[:16]
        root.mkdir(parents=True, exist_ok=True)
        for other in root.glob("sent-*"):
            if other.name != name:
                shutil.rmtree(other, ignore_errors=True)  # left behind by an earlier account of this connection
        self.dir = root / name
        self.dir.mkdir(exist_ok=True)
        for path in (root, self.dir):
            os.chmod(path, 0o700)  # records are whole messages
        self.connect, self.clock, self.delay = connect, clock, delay

    def _path(self, message_id: str) -> Path:
        return self.dir / (hashlib.sha256(message_id.encode()).hexdigest() + ".eml")

    def add(self, message_id: str, raw: bytes) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".tmp-")  # created 0600
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._path(message_id))
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def discard(self, message_id: str) -> None:
        self._path(message_id).unlink(missing_ok=True)

    def pending(self) -> list[Path]:
        return sorted(self.dir.glob("*.eml"))

    def start(self) -> None:
        threading.Thread(target=self._loop, name="sent-copies", daemon=True).start()

    def _loop(self) -> None:
        while True:
            try:
                self.run_once()
            except Exception:
                pass  # the records stay; the next round tries again
            time.sleep(INTERVAL)

    def run_once(self) -> None:
        due = [p for p in self.pending() if self.clock() - p.stat().st_mtime >= self.delay]
        if not due:
            return
        with open(self.dir / ".lock", "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)  # another process of this connection is at it
            except BlockingIOError:
                return
            client = self.connect()
            try:
                folder = self._sent_folder(client)
                for path in due:
                    if not path.exists():
                        continue
                    raw = path.read_bytes()
                    message_id = (BytesHeaderParser().parsebytes(raw)["Message-ID"] or "").strip()
                    client.select_folder(folder, readonly=True)
                    if not message_id or not client.search(["HEADER", "Message-ID", message_id]):
                        client.append(folder, raw, flags=(b"\\Seen",))
                    path.unlink()
            finally:
                try:
                    client.logout()
                except Exception:
                    pass

    @staticmethod
    def _sent_folder(client) -> str:
        folders = client.list_folders()
        flagged = special_folders(folders, "\\Sent")
        if flagged:
            return flagged[0]
        for wanted in SENT_NAMES:
            for _, delimiter, name in folders:
                delimiter = delimiter.decode() if isinstance(delimiter, bytes) else delimiter
                leaf = name.rsplit(delimiter, 1)[-1] if delimiter else name
                if wanted in (name.lower(), leaf.lower()):
                    return name
        # Some servers keep every folder under INBOX.
        delimiter = next((d for _, d, n in folders if n.upper() == "INBOX" and d), b".")
        delimiter = delimiter.decode() if isinstance(delimiter, bytes) else delimiter
        for name in ("Sent", "INBOX" + delimiter + "Sent"):
            try:
                client.create_folder(name)
                return name
            except Exception:
                continue
        raise RuntimeError("no Sent folder could be found or created")
