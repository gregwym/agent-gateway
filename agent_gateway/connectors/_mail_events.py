"""Tell a webhook about new mail in INBOX: the connection id and message identifiers, nothing else.

New identifiers and the advanced cursor are saved before anything is sent, and an event
keeps its delivery id until the receiver accepts it. See docs/design.md 7.8.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx2

from ._base import ConnectorError, setting

INTERVAL = 30  # seconds between checks
MAX_DELAY = 300  # the longest pause after repeated failures (Gmail's own credential pause)
CHUNK = 200  # identifiers per event, far below webhook body limits (OpenBot: 64 KB)
OUTBOX_LIMIT = 1000  # events kept for a receiver that stays unreachable; the oldest go first
MARGIN = 60  # a resync also covers this much before the last good check (clock differences)
STATE = "mail-events.json"


def from_environment(source: Callable[[], Any]) -> MailEvents | None:
    """The watcher the gateway asked for, or None.

    Admin commands that start a connector only to list its tools get no state directory,
    so they never watch.
    """
    url, directory = os.environ.get("AGW_MAIL_EVENTS_URL"), os.environ.get("AGW_STATE_DIR")
    if not url or not directory:
        return None
    return MailEvents(directory, url, setting("AGW_MAIL_EVENTS_TYPE"), setting("AGW_MAIL_EVENTS_SECRET"),
                      setting("AGW_MAIL_EVENTS_MAILBOX"), source())


class MailEvents:
    def __init__(self, directory, url: str, event_type: str, secret: str, mailbox: str, source, *,
                 clock: Callable[[], float] = time.time) -> None:
        self.dir = Path(directory)
        self.url, self.type, self.mailbox, self.source, self.clock = url, event_type, mailbox, source, clock
        self._secret = secret.encode()
        # No proxy from the environment, no redirects: requests go to the configured address only.
        self._http = httpx2.Client(timeout=15, trust_env=False, follow_redirects=False)
        self._next = self._delay = 0.0

    def start(self) -> None:
        threading.Thread(target=self._loop, name="mail-events", daemon=True).start()

    def _loop(self) -> None:
        while True:
            try:
                self.run_once()
            except Exception:
                pass  # nothing was saved half-way; the next round starts from the state on disk
            time.sleep(INTERVAL)

    def run_once(self) -> None:
        now = self.clock()
        if now < self._next:
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        with open(self.dir / "mail-events.lock", "a") as lock:
            try:
                # A configuration change starts the new connector process before the old one stops.
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            state, ok = self._load(), True
            try:
                self._check(state, now)
            except Exception:  # server down, credential refused: the cursor keeps its place
                state, ok = self._load(), False  # send only what is on disk
            if state["outbox"] and not self._send(state):  # receiver offline or refusing: events wait
                ok = False
            # Any failure: ask less often (30 s doubling to 5 min); success: back to every round.
            self._delay = 0.0 if ok else min(max(self._delay * 2, INTERVAL), MAX_DELAY)
            self._next = now + self._delay

    def _check(self, state: dict[str, Any], now: float) -> None:
        ids, fields, cursor = self.source.check(state["cursor"], state["checked_at"])
        for start in range(0, len(ids), CHUNK):
            state["outbox"].append({"id": uuid.uuid4().hex, "at": _iso(now),
                                    "data": {**fields, self.source.key: ids[start:start + CHUNK]}})
        del state["outbox"][:-OUTBOX_LIMIT]
        state["cursor"], state["checked_at"] = cursor, now
        self._save(state)

    def _send(self, state: dict[str, Any]) -> bool:
        """Deliver the outbox in order; False when the receiver has to be asked again later."""
        done = 0
        for entry in state["outbox"]:
            status = self._post(entry)
            # 2xx: accepted, or a repeat of an accepted delivery. 400 and 413 refuse the body
            # itself, which a retry cannot change; keeping it would hold back every later event.
            if status is None or not (200 <= status < 300 or status in (400, 413)):
                break
            done += 1
        if done:
            del state["outbox"][:done]
            self._save(state)
        return not state["outbox"]

    def _post(self, entry: dict[str, Any]) -> int | None:
        # The connection's current id, so events queued before a rename go out under the new name.
        body = json.dumps({"type": self.type, "occurredAt": entry["at"], "data": {"mailbox": self.mailbox, **entry["data"]}},
                          ensure_ascii=False, separators=(",", ":")).encode()
        stamp = str(int(time.time()))  # signed afresh on every attempt: receivers check freshness
        signature = hmac.new(self._secret, f"{stamp}.{entry['id']}.".encode() + body, hashlib.sha256).hexdigest()
        try:
            reply = self._http.post(self.url, content=body, headers={
                "content-type": "application/json",
                "x-openbot-timestamp": stamp,
                "x-openbot-delivery-id": entry["id"],
                "x-openbot-signature": "sha256=" + signature,
            })
        except httpx2.HTTPError:
            return None
        return reply.status_code

    def _load(self) -> dict[str, Any]:
        try:
            saved = json.loads((self.dir / STATE).read_text(encoding="utf-8"))
        except FileNotFoundError:
            saved = {}
        return {"cursor": saved.get("cursor"), "checked_at": saved.get("checked_at"), "outbox": saved.get("outbox", [])}

    def _save(self, state: dict[str, Any]) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".tmp-mail-events-")  # created 0600
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.dir / STATE)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


class GmailSource:
    """New INBOX mail of a Gmail mailbox, from its history. Needs only gmail.readonly."""

    key = "message_ids"

    def __init__(self, gmail) -> None:
        self.gmail = gmail

    def check(self, cursor: dict[str, Any] | None, since: float | None) -> tuple[list[str], dict[str, Any], dict[str, Any]]:
        if cursor is None:  # the first check starts from now: older mail is not new
            return [], {}, {"history_id": self._latest()}
        try:
            ids, latest = self._history(cursor["history_id"])
        except ConnectorError as exc:
            if exc.code != "gmail_message_missing":  # how Gmail.get reports any 404
                raise
            # The cursor is older than the history Gmail keeps: list what arrived since the last good check.
            latest = self._latest()
            ids = self._arrived_after((since or 0) - MARGIN)
        return ids, {}, {"history_id": latest}

    def _latest(self) -> str:
        return str(self.gmail.get("profile")["historyId"])

    def _history(self, start: str) -> tuple[list[str], str]:
        ids: list[str] = []
        latest, token = start, None
        while True:
            params = [("startHistoryId", start), ("labelId", "INBOX"), ("historyTypes", "messageAdded"),
                      ("historyTypes", "labelAdded"), ("maxResults", "500")] + ([("pageToken", token)] if token else [])
            page = self.gmail.get("history", params)
            latest = str(page.get("historyId", latest))
            for record in page.get("history", []):
                # A record's message has only id and threadId; labelId=INBOX already chose the messages.
                ids += [item.get("message", {}).get("id") for item in record.get("messagesAdded", [])]
                # labelsAdded[].labelIds are the labels added in this change: INBOX, not e.g. a star.
                ids += [item.get("message", {}).get("id") for item in record.get("labelsAdded", [])
                        if "INBOX" in item.get("labelIds", [])]
            token = page.get("nextPageToken")
            if not token:
                return _gmail_ids(ids), latest

    def _arrived_after(self, after: float) -> list[str]:
        ids: list[str] = []
        token = None
        while True:
            params = [("labelIds", "INBOX"), ("q", f"after:{int(after)}"), ("maxResults", "500")]
            page = self.gmail.get("messages", params + ([("pageToken", token)] if token else []))
            ids += [item.get("id") for item in page.get("messages", [])]
            token = page.get("nextPageToken")
            if not token:
                return _gmail_ids(reversed(ids))  # the list is newest first


def _gmail_ids(values) -> list[str]:
    # Gmail message ids are hexadecimal; anything else is not passed on.
    return list(dict.fromkeys(v for v in values if isinstance(v, str) and re.fullmatch(r"[0-9a-fA-F]{1,32}", v)))


def _iso(stamp: float) -> str:
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
