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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
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
WEB_STATE = "mail-events-web.json"


@dataclass(frozen=True)
class DeliveryTarget:
    url: str
    event_type: str
    secret: str = field(repr=False)


def from_environment(source: Callable[[], Any]) -> MailEvents | None:
    """The watcher the gateway asked for, or None.

    Admin commands that start a connector only to list its tools get no state directory,
    so they never watch.
    """
    directory = os.environ.get("AGW_STATE_DIR")
    if not directory:
        return None
    if targets := os.environ.get("AGW_MAIL_EVENTS_TARGETS"):
        destinations = {key: DeliveryTarget(**value) for key, value in json.loads(targets).items()}
        return MailEvents(directory, setting("AGW_MAIL_EVENTS_MAILBOX"), source(), destinations)
    if not (url := os.environ.get("AGW_MAIL_EVENTS_URL")):
        return None
    destination = DeliveryTarget(url, setting("AGW_MAIL_EVENTS_TYPE"), setting("AGW_MAIL_EVENTS_SECRET"))
    return MailEvents(directory, setting("AGW_MAIL_EVENTS_MAILBOX"), source(), {"": destination}, legacy=True)


class MailEvents:
    def __init__(self, directory, mailbox: str, source, targets: dict[str, DeliveryTarget], *,
                 clock: Callable[[], float] = time.time, legacy: bool = False) -> None:
        self.dir = Path(directory)
        self.mailbox, self.source, self.clock = mailbox, source, clock
        self._legacy = legacy
        self._targets = targets
        self._state_file = self.dir / (STATE if self._legacy else WEB_STATE)
        # No proxy from the environment, no redirects: requests go to the configured address only.
        self._http = httpx2.Client(timeout=15, trust_env=False, follow_redirects=False)
        self._next = self._delay = 0.0
        self._delivery_wait: dict[str, tuple[float, float]] = {}
        self._account: str | None = None  # the mailbox this process reads, once known

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
        if self._legacy and now < self._next:
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
            checked = now >= self._next
            if checked:
                try:
                    self._check(state, now)
                except Exception:  # server down, credential refused: the cursor keeps its place
                    state, ok = self._load(), False  # send only what is on disk
            # Events go out only from the mailbox they were found in (see _check).
            if state["account"] == self._account:
                self._deliver(state, now)
            if checked:
                if self._legacy and state["queues"].get(""):
                    ok = False
                self._delay = 0.0 if ok else min(max(self._delay * 2, INTERVAL), MAX_DELAY)
                self._next = now + self._delay

    def _check(self, state: dict[str, Any], now: float) -> None:
        self._account = self._account or self.source.account()
        if state["account"] not in (None, self._account):
            # The connection now reads another mailbox: the old cursor and pending events mean nothing
            # there. Start from now, as when events are first turned on (docs/design.md 7.8).
            state.update(cursor=None, checked_at=None, queues={})
        queues = state["queues"]
        if queues and not (queues.keys() & self._targets.keys()):
            state.update(cursor=None, checked_at=None)
        state["account"] = self._account
        ids, fields, cursor = self.source.check(state["cursor"], state["checked_at"])
        state["queues"] = {key: queues.get(key, []) for key in self._targets}
        for outbox in state["queues"].values():
            for start in range(0, len(ids), CHUNK):
                outbox.append({"id": uuid.uuid4().hex, "at": _iso(now),
                               "data": {"mailbox": self.mailbox, **fields, self.source.key: ids[start:start + CHUNK]}})
            del outbox[:-OUTBOX_LIMIT]
        state["cursor"], state["checked_at"] = cursor, now
        self._save(state)

    def _deliver(self, state: dict[str, Any], now: float) -> None:
        queues = state["queues"]
        pending = [key for key in self._targets if queues.get(key) and now >= self._delivery_wait.get(key, (0, 0))[0]]
        if not pending:
            return
        if len(pending) == 1:
            key = pending[0]
            counts = [self._send(self._targets[key], queues[key])]
        else:
            with ThreadPoolExecutor(max_workers=min(len(pending), 8)) as pool:
                counts = list(pool.map(self._send, (self._targets[key] for key in pending),
                                       (queues[key] for key in pending)))
        for key, count in zip(pending, counts, strict=True):
            del queues[key][:count]
            if queues[key]:
                delay = min(max(self._delivery_wait.get(key, (0, 0))[1] * 2, INTERVAL), MAX_DELAY)
                self._delivery_wait[key] = (now + delay, delay)
            else:
                self._delivery_wait.pop(key, None)
        if any(counts):
            self._save(state)

    def _send(self, target: DeliveryTarget, outbox: list[dict[str, Any]]) -> int:
        done = 0
        for entry in outbox:
            status = self._post(target, entry)
            # 2xx: accepted, or a repeat of an accepted delivery. 400 and 413 refuse the body
            # itself, which a retry cannot change; keeping it would hold back every later event.
            if status is None or not (200 <= status < 300 or status in (400, 413)):
                break
            done += 1
        return done

    def _post(self, target: DeliveryTarget, entry: dict[str, Any]) -> int | None:
        body = json.dumps({"type": target.event_type, "occurredAt": entry["at"], "data": entry["data"]},
                          ensure_ascii=False, separators=(",", ":")).encode()
        stamp = str(int(time.time()))  # signed afresh on every attempt: receivers check freshness
        signature = hmac.new(target.secret.encode(), f"{stamp}.{entry['id']}.".encode() + body, hashlib.sha256).hexdigest()
        try:
            reply = self._http.post(target.url, content=body, headers={
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
            saved = json.loads(self._state_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            saved = {}
        queues = {"": saved.get("outbox", [])} if self._legacy else saved.get("queues", {})
        return {"account": saved.get("account"), "cursor": saved.get("cursor"), "checked_at": saved.get("checked_at"),
                "queues": queues}

    def _save(self, state: dict[str, Any]) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".tmp-mail-events-")  # created 0600
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                record = dict(state)
                if self._legacy:
                    record["outbox"] = record.pop("queues").get("", [])
                json.dump(record, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._state_file)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


class GmailSource:
    """New INBOX mail of a Gmail mailbox, from its history. Needs only gmail.readonly."""

    key = "message_ids"

    def __init__(self, gmail) -> None:
        self.gmail = gmail

    def account(self) -> str:
        return self.gmail.get("profile")["emailAddress"]

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


class ImapSource:
    """New INBOX mail of an IMAP mailbox, by UID. INBOX is opened read-only (EXAMINE)."""

    key = "uids"

    def __init__(self, mailbox) -> None:
        self.mailbox = mailbox  # its own session, so a check never interleaves with a tool call

    def account(self) -> str:
        return self.mailbox.address

    def check(self, cursor: dict[str, Any] | None, since: float | None) -> tuple[list[int], dict[str, Any], dict[str, Any]]:
        def run(client) -> tuple[list[int], dict[str, Any], dict[str, Any]]:
            info = client.select_folder("INBOX", readonly=True)
            validity = int(info[b"UIDVALIDITY"])
            top = int(info[b"UIDNEXT"]) - 1 if info.get(b"UIDNEXT") else max(client.search(["ALL"]), default=0)
            if cursor is None:  # the first check starts from now: older mail is not new
                return [], {"uidvalidity": validity}, {"uidvalidity": validity, "last_uid": top}
            if cursor["uidvalidity"] == validity:
                last = cursor["last_uid"]
                uids = sorted(uid for uid in client.search(["UID", f"{last + 1}:*"]) if uid > last)  # n:* also matches the top UID
            else:
                # The mailbox was renumbered: report what arrived since the last good check.
                after = (since or 0) - MARGIN
                found = client.search(["SINCE", date.fromtimestamp(after - 86_400)])  # whole days on the server; exact below
                arrived = client.fetch(found, ["INTERNALDATE"]) if found else {}
                uids = sorted(uid for uid, data in arrived.items() if data[b"INTERNALDATE"].timestamp() >= after)
                last = 0
            return uids, {"uidvalidity": validity}, {"uidvalidity": validity, "last_uid": max([last, top, *uids])}

        return self.mailbox.run(run)


def _gmail_ids(values) -> list[str]:
    # Gmail message ids are hexadecimal; anything else is not passed on.
    return list(dict.fromkeys(v for v in values if isinstance(v, str) and re.fullmatch(r"[0-9a-fA-F]{1,32}", v)))


def _iso(stamp: float) -> str:
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
