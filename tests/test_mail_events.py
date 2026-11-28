"""New-mail events: what reaches the webhook, when, and what happens when something fails.

Gmail is `FakeGoogle` (documented response shapes, not Google); IMAP is pymap, a real
IMAP server. The receiver checks signatures the way an OpenBot webhook URL does. These
tests do not show how Google, iCloud or OpenBot behave in production.
"""

from __future__ import annotations

import copy
import fcntl
import json
import shutil
import sys
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from types import SimpleNamespace

import anyio
import pytest
import yaml
from helpers import SECRETS as BASE_SECRETS
from helpers import base_config, prepare, running_gateway
from imapclient import IMAPClient
from passkey_helpers import approval_config
from service_helpers import FakeGoogle, WebhookReceiver, free_port, mail_account
from test_admin import change, login, setup, state, web_gateway
from test_connector_mail import mail_connection

from agent_gateway import cli
from agent_gateway.config import ConfigError, load_config
from agent_gateway.connectors import _mail_events
from agent_gateway.connectors._mail_events import INTERVAL, DeliveryTarget, GmailSource, ImapSource, MailEvents
from agent_gateway.connectors.gmail import Gmail
from agent_gateway.connectors.imap_mail import Mailbox
from agent_gateway.upstream import Upstream

pytestmark = pytest.mark.anyio

CLIENT_ID = "1234567890-testclient.apps.googleusercontent.com"
CLIENT_SECRET = "GOCSPX-test-client-secret-000000"
SIGNING_SECRET = "whsec-test-signing-secret-0000"
USER, PASSWORD = "account@example.test", "fake-app-password"


def raw(subject: str) -> bytes:
    out = EmailMessage()
    out["Subject"], out["From"], out["To"] = subject, "sender@example.test", "person.a@gmail.example"
    out.set_content("Private body text.")
    return out.as_bytes()


class Clock:
    def __init__(self) -> None:
        self.now = time.time()

    def __call__(self) -> float:
        return self.now

    def later(self, seconds: float = INTERVAL) -> None:
        self.now += seconds


@pytest.fixture
def google():
    fake = FakeGoogle()
    yield fake
    fake.close()


@pytest.fixture
def receiver():
    fake = WebhookReceiver(SIGNING_SECRET)
    yield fake
    fake.close()


def gmail_events(tmp_path, google, receiver, refresh="1//refresh-token-a", *, secret=SIGNING_SECRET, clock=None):
    if refresh not in google.accounts:
        google.add_account(refresh, CLIENT_ID, CLIENT_SECRET)
    gmail = Gmail(CLIENT_ID, CLIENT_SECRET, refresh, google.base, f"{google.base}/token")
    target = DeliveryTarget(receiver.url, "person.mail.new", secret)
    return MailEvents(tmp_path / "state", "gmail-a", GmailSource(gmail), {"": target},
                      clock=clock or Clock(), legacy=True)


def saved(tmp_path) -> dict:
    return json.loads((tmp_path / "state" / "mail-events.json").read_text())


def test_gmail_reports_mail_that_reaches_the_inbox_with_identifiers_only(tmp_path, google, receiver):
    refresh = "1//refresh-token-a"
    google.add_account(refresh, CLIENT_ID, CLIENT_SECRET)
    google.add_message(refresh, "18c0a0", raw("before the first check"))
    google.add_message(refresh, "18c0a3", raw("archived earlier"), ("CATEGORY_UPDATES",))
    clock = Clock()
    events = gmail_events(tmp_path, google, receiver, refresh, clock=clock)

    events.run_once()  # the first check only marks where "new" starts
    assert receiver.attempts == [] and saved(tmp_path)["cursor"]["history_id"] == "1002"

    google.add_message(refresh, "18c0a1", raw("Your order has shipped"))
    google.add_message(refresh, "18c0a2", raw("sent by the owner"), ("SENT",))
    google.add_label(refresh, "18c0a3", "INBOX")  # moved back into the inbox
    google.requests.clear()
    clock.later()
    events.run_once()

    assert len(receiver.events) == 1
    event = receiver.events[0]
    assert event["type"] == "person.mail.new"
    assert event["data"] == {"mailbox": "gmail-a", "message_ids": ["18c0a1", "18c0a3"]}
    assert datetime.fromisoformat(event["occurredAt"].replace("Z", "+00:00")).tzinfo == timezone.utc
    assert receiver.headers[0]["content-type"] == "application/json"
    text = json.dumps(event)
    assert "shipped" not in text and "Private body" not in text and "sender@example" not in text
    # Only the history was asked for: no message was opened.
    assert {path for _, path in google.requests} <= {"/token", "/gmail/v1/users/me/history"}
    assert saved(tmp_path)["outbox"] == []
    # As from Google, the history names messages by id and threadId only: no labels to filter on.
    page = events.source.gmail.get("history", [("startHistoryId", "1000"), ("labelId", "INBOX")])
    assert all(set(item["message"]) == {"id", "threadId"}
               for record in page["history"] for field in ("messagesAdded", "labelsAdded") for item in record.get(field, []))

    google.add_label(refresh, "18c0a1", "STARRED")  # a label added to inbox mail, but not INBOX
    clock.later()
    events.run_once()
    assert len(receiver.attempts) == 1  # nothing new, nothing sent


def test_an_undelivered_event_keeps_its_delivery_id_across_retries_and_restarts(tmp_path, google, receiver):
    refresh = "1//refresh-token-a"
    clock = Clock()
    events = gmail_events(tmp_path, google, receiver, refresh, clock=clock)
    events.run_once()
    google.add_message(refresh, "18c0b1", raw("while the receiver is offline"))
    receiver.statuses = [503, 503]

    clock.later()
    events.run_once()  # 503
    clock.later()
    events.run_once()  # 503 again: the next attempt waits longer
    clock.later()
    events.run_once()
    assert [status for _, status in receiver.attempts] == [503, 503]

    # The connector restarts; the event is still in the outbox on disk.
    restarted = gmail_events(tmp_path, google, receiver, refresh, clock=clock)
    restarted.run_once()
    assert [status for _, status in receiver.attempts] == [503, 503, 202]
    assert len({delivery for delivery, _ in receiver.attempts}) == 1
    assert receiver.events[0]["data"]["message_ids"] == ["18c0b1"]
    assert saved(tmp_path)["outbox"] == []


def test_multitarget_checks_once_and_retries_only_undelivered_destinations(tmp_path, google, receiver):
    refresh = "1//refresh-token-a"
    google.add_account(refresh, CLIENT_ID, CLIENT_SECRET)
    source = GmailSource(Gmail(CLIENT_ID, CLIENT_SECRET, refresh, google.base, f"{google.base}/token"))
    other = WebhookReceiver("another-signing-key")
    try:
        clock = Clock()
        targets = {
            "primary": DeliveryTarget(receiver.url, "mail.new", SIGNING_SECRET),
            "secondary": DeliveryTarget(other.url, "mail.new", "another-signing-key"),
        }
        events = MailEvents(tmp_path, "gmail-a", source, targets, clock=clock)
        events.run_once()
        receiver.statuses = [503, 503]
        google.add_message(refresh, "18c0b1", raw("first"))
        google.requests.clear()
        clock.later()
        events.run_once()
        assert sum(path == "/gmail/v1/users/me/history" for _, path in google.requests) == 1
        assert [code for _, code in receiver.attempts] == [503]
        assert [event["data"]["message_ids"] for event in other.events] == [["18c0b1"]]

        clock.later()
        google.add_message(refresh, "18c0b2", raw("second"))
        events.run_once()
        assert [event["data"]["message_ids"] for event in other.events] == [["18c0b1"], ["18c0b2"]]

        restarted = MailEvents(tmp_path, "gmail-a", source, targets, clock=clock)
        restarted.run_once()
        assert [event["data"]["message_ids"] for event in receiver.events] == [["18c0b1"], ["18c0b2"]]
        assert receiver.attempts[0][0] == receiver.attempts[2][0]
        assert len(other.attempts) == 2

        receiver.statuses = [503]
        google.add_message(refresh, "18c0b3", raw("while removing a destination"))
        clock.later()
        restarted.run_once()
        replacement = MailEvents(tmp_path, "gmail-a", source, {"replacement": targets["primary"],
                                                               "secondary": targets["secondary"]}, clock=clock)
        replacement.run_once()
        assert len(receiver.attempts) == 5
        assert [event["data"]["message_ids"] for event in other.events][-1] == ["18c0b3"]
    finally:
        other.close()


def test_waits_grow_after_failures_and_stop_at_five_minutes(tmp_path, google, receiver):
    refresh = "1//refresh-token-a"
    clock = Clock()
    events = gmail_events(tmp_path, google, receiver, refresh, clock=clock)
    events.run_once()
    google.add_message(refresh, "18c0b2", raw("receiver offline for an hour"))
    receiver.statuses = [503] * 100
    for _ in range(120):  # one hour of rounds
        clock.later()
        events.run_once()
    times = len(receiver.attempts)
    assert 12 <= times <= 20  # 30 s, 1, 2, 4 min, then every 5 min; not 120
    receiver.statuses = []
    for _ in range(10):
        clock.later()
        events.run_once()
    assert receiver.events[0]["data"]["message_ids"] == ["18c0b2"]


def test_a_refused_signature_keeps_the_event_and_a_refused_body_does_not_block_later_ones(tmp_path, google, receiver):
    refresh = "1//refresh-token-a"
    clock = Clock()
    wrong = gmail_events(tmp_path, google, receiver, refresh, secret="not-the-secret", clock=clock)
    wrong.run_once()
    google.add_message(refresh, "18c0c1", raw("one"))
    clock.later()
    wrong.run_once()
    assert receiver.attempts[0][1] == 401 and len(saved(tmp_path)["outbox"]) == 1

    # The secret is corrected (a new process); the receiver refuses this body for good.
    fixed = gmail_events(tmp_path, google, receiver, refresh, clock=clock)
    receiver.statuses = [400]
    google.add_message(refresh, "18c0c2", raw("two"))
    clock.later(300)
    fixed.run_once()
    assert [status for _, status in receiver.attempts] == [401, 400, 202]
    assert receiver.events[0]["data"]["message_ids"] == ["18c0c2"] and saved(tmp_path)["outbox"] == []


def test_an_expired_gmail_history_reports_what_arrived_since_the_last_good_check(tmp_path, google, receiver):
    refresh = "1//refresh-token-a"
    google.add_account(refresh, CLIENT_ID, CLIENT_SECRET)
    google.add_message(refresh, "18c0d2", raw("archived a month ago"), ("INBOX",), at=time.time() - 30 * 86_400)
    google.remove_label(refresh, "18c0d2", "INBOX")
    clock = Clock()
    events = gmail_events(tmp_path, google, receiver, refresh, clock=clock)
    events.run_once()
    last_good = saved(tmp_path)["checked_at"]
    google.add_message(refresh, "18c0d0", raw("long before"), at=last_good - 3600)
    google.add_message(refresh, "18c0d1", raw("after the last check"), at=last_good + 5)
    google.add_label(refresh, "18c0d2", "INBOX")  # moved back while the history expires
    google.forget_history(refresh)

    clock.later()
    events.run_once()
    # By arrival time only: the message moved back during the gap is not reported (docs/design.md 7.8).
    assert [event["data"]["message_ids"] for event in receiver.events] == [["18c0d1"]]
    assert saved(tmp_path)["cursor"]["history_id"] == str(google.accounts[refresh]["history_id"])

    google.remove_label(refresh, "18c0d2", "INBOX")
    google.add_label(refresh, "18c0d2", "INBOX")  # with a valid cursor, a move back is reported
    clock.later()
    events.run_once()
    assert receiver.events[-1]["data"]["message_ids"] == ["18c0d2"]


def test_large_batches_are_split_and_an_unreachable_receiver_keeps_a_bounded_outbox(tmp_path, google, receiver, monkeypatch):
    monkeypatch.setattr(_mail_events, "CHUNK", 2)
    monkeypatch.setattr(_mail_events, "OUTBOX_LIMIT", 3)
    refresh = "1//refresh-token-a"
    clock = Clock()
    events = gmail_events(tmp_path, google, receiver, refresh, clock=clock)
    events.run_once()
    for n in range(5):
        google.add_message(refresh, f"18c0e{n}", raw(f"message {n}"))
    clock.later()
    events.run_once()
    assert [e["data"]["message_ids"] for e in receiver.events] == [["18c0e0", "18c0e1"], ["18c0e2", "18c0e3"], ["18c0e4"]]

    receiver.statuses = [503] * 100
    for n in range(4):
        google.add_message(refresh, f"18c0f{n}", raw(f"later {n}"))
        clock.later(300)
        events.run_once()
    outbox = saved(tmp_path)["outbox"]
    assert [entry["data"]["message_ids"] for entry in outbox] == [["18c0f1"], ["18c0f2"], ["18c0f3"]]


def test_nothing_is_sent_that_was_not_saved_first(tmp_path, google, receiver, monkeypatch):
    refresh = "1//refresh-token-a"
    clock = Clock()
    events = gmail_events(tmp_path, google, receiver, refresh, clock=clock)
    events.run_once()
    google.add_message(refresh, "18c0aa", raw("arrives while the disk is full"))
    save, failures = MailEvents._save, [OSError("disk full")]

    def flaky(self, state):
        if failures:
            raise failures.pop()
        save(self, state)

    monkeypatch.setattr(MailEvents, "_save", flaky)
    clock.later()
    events.run_once()
    assert receiver.attempts == []  # found, but not on disk: not sent
    clock.later()
    events.run_once()
    assert [event["data"]["message_ids"] for event in receiver.events] == [["18c0aa"]]


def test_a_second_process_of_the_same_connection_stays_out(tmp_path, google, receiver):
    events = gmail_events(tmp_path, google, receiver)
    (tmp_path / "state").mkdir()
    with open(tmp_path / "state" / "mail-events.lock", "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        events.run_once()
        assert not (tmp_path / "state" / "mail-events.json").exists() and google.requests == []
    events.run_once()
    assert (tmp_path / "state" / "mail-events.json").exists()


def append(account, subject: str, when: datetime | None = None) -> int:
    with IMAPClient("127.0.0.1", account.plain_port, ssl=False) as client:
        client.login(account.user, account.password)
        out = EmailMessage()
        out["Subject"], out["From"], out["To"] = subject, "sender@example.test", USER
        out.set_content("Private body text.")
        result = client.append("INBOX", out.as_bytes(), flags=(), msg_time=when or datetime.now(timezone.utc))
        return int(result.split(b"]")[0].split()[-1])  # [APPENDUID <validity> <uid>]


def flags(account, uid: int):
    with IMAPClient("127.0.0.1", account.plain_port, ssl=False) as client:
        client.login(account.user, account.password)
        client.select_folder("INBOX", readonly=True)
        return client.fetch([uid], ["FLAGS"])[uid][b"FLAGS"]


def imap_events(tmp_path, account, receiver, clock):
    mailbox = Mailbox("localhost", account.front.port, USER, PASSWORD)
    target = DeliveryTarget(receiver.url, "person.mail.new", SIGNING_SECRET)
    return MailEvents(tmp_path / "state", "icloud-a", ImapSource(mailbox), {"": target}, clock=clock, legacy=True)


def test_imap_reports_new_uids_without_marking_anything_read(tmp_path, monkeypatch, receiver):
    with mail_account(tmp_path / "imap", USER, PASSWORD) as account:
        monkeypatch.setenv("SSL_CERT_FILE", str(account.cert))
        clock = Clock()
        events = imap_events(tmp_path, account, receiver, clock)
        events.run_once()
        cursor = saved(tmp_path)["cursor"]
        assert receiver.attempts == [] and cursor["last_uid"] == 104

        first, second = append(account, "Invoice"), append(account, "Receipt")
        clock.later()
        events.run_once()
        assert receiver.events[0]["data"] == {"mailbox": "icloud-a", "uidvalidity": cursor["uidvalidity"], "uids": [first, second]}
        assert b"\\Seen" not in flags(account, first) and b"\\Seen" not in flags(account, second)
        assert "Invoice" not in json.dumps(receiver.events)

        clock.later()
        events.run_once()
        assert len(receiver.attempts) == 1


def test_a_renumbered_imap_inbox_reports_what_arrived_since_the_last_good_check(tmp_path, monkeypatch, receiver):
    with mail_account(tmp_path / "imap", USER, PASSWORD) as account:
        monkeypatch.setenv("SSL_CERT_FILE", str(account.cert))
        clock = Clock()
        events = imap_events(tmp_path, account, receiver, clock)
        events.run_once()
        state = saved(tmp_path)
        validity = state["cursor"]["uidvalidity"]
        # As if the server had given INBOX a new UIDVALIDITY since the last check.
        state["cursor"] = {"uidvalidity": validity + 1, "last_uid": 9}
        (tmp_path / "state" / "mail-events.json").write_text(json.dumps(state))
        fresh = append(account, "after the last check")
        moved = move_to_inbox(account, "archived a month ago", datetime.now(timezone.utc) - timedelta(days=30))

        clock.later()
        events.run_once()
        # By arrival time only (docs/design.md 7.8): the demo messages from decades ago and the old
        # message moved back during the gap are not reported; the new one is.
        assert [event["data"] for event in receiver.events] == [{"mailbox": "icloud-a", "uidvalidity": validity, "uids": [fresh]}]
        assert saved(tmp_path)["cursor"] == {"uidvalidity": validity, "last_uid": moved}

        again = move_to_inbox(account, "archived again", datetime.now(timezone.utc) - timedelta(days=30))
        clock.later()
        events.run_once()  # with a valid cursor, a message moved in gets a new UID and is reported
        assert receiver.events[-1]["data"]["uids"] == [again]


def move_to_inbox(account, subject: str, when: datetime) -> int:
    """File an old message in another folder, then MOVE it to INBOX: it keeps its INTERNALDATE."""
    with IMAPClient("127.0.0.1", account.plain_port, ssl=False) as client:
        client.login(account.user, account.password)
        if not client.folder_exists("Archive"):
            client.create_folder("Archive")
        out = EmailMessage()
        out["Subject"], out["From"], out["To"] = subject, "sender@example.test", USER
        out.set_content("Private body text.")
        client.append("Archive", out.as_bytes(), flags=(), msg_time=when)
        client.select_folder("Archive")
        client.move(client.search(["ALL"]), "INBOX")
        client.select_folder("INBOX", readonly=True)
        return max(client.search(["ALL"]))


def events_config(google: FakeGoogle, url: str, **entry) -> dict:
    out = copy.deepcopy(base_config())
    out["connections"] = [{
        "id": "gmail-a", "service": "gmail", "account": "person_a", "owner": "person_a", "transport": "stdio",
        "command": [sys.executable, "-m", "agent_gateway.connectors.gmail"],
        "env": {"GMAIL_CLIENT_ID": CLIENT_ID, "GMAIL_API_BASE": google.base, "GMAIL_TOKEN_URL": f"{google.base}/token"},
        "secret_env": {"GMAIL_CLIENT_SECRET": "gmail_client_secret", "GMAIL_REFRESH_TOKEN": "gmail_token_a"},
        "timeout_seconds": 20,
        "tools": [{"upstream": "search_messages", "name": "a_gmail_search_messages"}],
    }]
    out["policy"] = [{"principals": ["person_a"], "connection": "gmail-a", "tools": ["a_gmail_search_messages"], "effect": "allow"}]
    out["mail_events"] = [{"connection": "gmail-a", "url": url, "type": "person.mail.new", "secret": "mail_events_signing", **entry}]
    return out


SECRETS = {"gmail_client_secret": CLIENT_SECRET, "gmail_token_a": "1//refresh-token-a", "mail_events_signing": SIGNING_SECRET}


async def test_the_gateway_starts_the_watcher_for_a_configured_connection(tmp_path, google, receiver):
    google.add_account("1//refresh-token-a", CLIENT_ID, CLIENT_SECRET)
    google.add_message("1//refresh-token-a", "18c0a7", raw("before"))
    path = await prepare(tmp_path / "gw", events_config(google, receiver.url), secrets=SECRETS)
    state = load_config(path).audit.path.parent / "connectors" / "gmail-a"
    state.mkdir(parents=True)
    # A cursor saved before a restart; mail arrived while the gateway was down.
    (state / "mail-events.json").write_text(json.dumps({"cursor": {"history_id": "1001"}, "checked_at": time.time() - 60, "outbox": []}))
    google.add_message("1//refresh-token-a", "18c0a8", raw("while the gateway was down"))
    async with running_gateway(path) as gw:
        with anyio.fail_after(20):
            while not receiver.events:
                await anyio.sleep(0.1)
        assert gw.gateway.upstreams["gmail-a"].extra_env["AGW_MAIL_EVENTS_MAILBOX"] == "gmail-a"
    assert receiver.events[0]["type"] == "person.mail.new"
    assert receiver.events[0]["data"] == {"mailbox": "gmail-a", "message_ids": ["18c0a8"]}
    assert SIGNING_SECRET not in json.dumps(json.loads((state / "mail-events.json").read_text()))


async def test_admin_commands_never_watch(tmp_path, google, receiver):
    google.add_account("1//refresh-token-a", CLIENT_ID, CLIENT_SECRET)
    # `agw lock` (run by prepare: a new FakeGoogle port is a new set of connections) starts the
    # connector to read its tools; it gets no state directory.
    path = await prepare(tmp_path, events_config(google, receiver.url), secrets=SECRETS)
    assert not (load_config(path).audit.path.parent / "connectors" / "gmail-a" / "mail-events.json").exists()
    assert ("GET", "/gmail/v1/users/me/profile") not in google.requests


async def test_check_lists_the_events_and_reports_an_entry_without_a_mail_connection(tmp_path, google, receiver, capsys):
    raw_config = events_config(google, receiver.url)
    path = await prepare(tmp_path / "ok", raw_config, secrets=SECRETS)
    assert cli.main(["check", "-c", str(path)]) == 0
    out = capsys.readouterr().out
    assert "new-mail events: gmail-a -> 127.0.0.1 (type person.mail.new)" in out and SIGNING_SECRET not in out

    raw_config["mail_events"].append({"connection": "notes-a", "url": receiver.url, "type": "x", "secret": "mail_events_signing"})
    path = await prepare(tmp_path / "other", raw_config, secrets=SECRETS)
    assert cli.main(["check", "-c", str(path)]) == 1
    assert "mail_events notes-a: no bundled Gmail or IMAP connection has this id" in capsys.readouterr().err

    missing = await prepare(tmp_path / "missing", events_config(google, receiver.url), lock=False,
                            secrets={k: v for k, v in SECRETS.items() if k != "mail_events_signing"})
    shutil.copy(tmp_path / "ok" / "tools.lock.json", tmp_path / "missing" / "tools.lock.json")
    assert cli.main(["check", "-c", str(missing)]) == 1
    assert "secrets missing from the store: mail_events_signing" in capsys.readouterr().err


STUB = SimpleNamespace(base="http://127.0.0.1:9")  # a Google address for configurations that are only loaded


@pytest.mark.parametrize(("change", "message"), [
    ({"url": "http://hooks.example.test/x"}, "url must be https"),
    ({"url": "https://user:pw@hooks.example.test/x"}, "put credentials in the secret store"),
    ({"type": "bad\ntype"}, "type"),
    ({"connection": "Not A Name"}, "connection"),
])
def test_a_mail_events_entry_is_checked_when_the_configuration_is_loaded(tmp_path, change, message):
    raw_config = events_config(STUB, "https://hooks.example.test/v1/webhooks/x")
    raw_config["mail_events"][0].update(change)
    path = tmp_path / "gateway.yaml"
    path.write_text(yaml.safe_dump(raw_config))
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_mail_events_need_one_entry_per_connection_and_a_secret_store(tmp_path):
    raw_config = events_config(STUB, "https://hooks.example.test/v1/webhooks/x")
    raw_config["mail_events"].append(dict(raw_config["mail_events"][0]))
    (tmp_path / "a.yaml").write_text(yaml.safe_dump(raw_config))
    with pytest.raises(ConfigError, match="duplicate mail_events connection"):
        load_config(tmp_path / "a.yaml")
    raw_config["mail_events"].pop()
    raw_config.pop("secrets")
    raw_config["connections"][0]["secret_env"] = {}
    (tmp_path / "b.yaml").write_text(yaml.safe_dump(raw_config))
    with pytest.raises(ConfigError, match="mail_events needs a `secrets:` store"):
        load_config(tmp_path / "b.yaml")


async def test_the_gateway_starts_the_watcher_for_an_imap_connection(tmp_path, receiver):
    with mail_account(tmp_path / "imap", USER, PASSWORD) as account:
        raw_config = copy.deepcopy(base_config())
        raw_config["connections"] = [{
            "id": "icloud-a", "service": "icloud-mail", "account": "person_a", "owner": "person_a", "transport": "stdio",
            "command": [sys.executable, "-m", "agent_gateway.connectors.imap_mail"],
            "env": {"IMAP_HOST": "localhost", "IMAP_PORT": str(account.front.port), "IMAP_USERNAME": USER,
                    "SSL_CERT_FILE": str(account.cert), "SMTP_HOST": ""},
            "secret_env": {"IMAP_PASSWORD": "mail_a"}, "timeout_seconds": 20,
            "tools": [{"upstream": "list_mailboxes", "name": "a_mail_list_mailboxes"}],
        }]
        raw_config["policy"] = [{"principals": ["person_a"], "connection": "icloud-a", "tools": ["a_mail_list_mailboxes"], "effect": "allow"}]
        raw_config["mail_events"] = [{"connection": "icloud-a", "url": receiver.url, "type": "person.mail.new", "secret": "signing"}]
        path = await prepare(tmp_path / "gw", raw_config, secrets={"mail_a": PASSWORD, "signing": SIGNING_SECRET})
        with IMAPClient("127.0.0.1", account.plain_port, ssl=False) as client:
            client.login(USER, PASSWORD)
            validity = int(client.select_folder("INBOX", readonly=True)[b"UIDVALIDITY"])
        state = load_config(path).audit.path.parent / "connectors" / "icloud-a"
        state.mkdir(parents=True)
        (state / "mail-events.json").write_text(json.dumps({"cursor": {"uidvalidity": validity, "last_uid": 104},
                                                            "checked_at": time.time() - 60, "outbox": []}))
        uid = append(account, "while the gateway was down")
        async with running_gateway(path):
            with anyio.fail_after(20):
                while not receiver.events:
                    await anyio.sleep(0.1)
        assert receiver.events[0]["data"] == {"mailbox": "icloud-a", "uidvalidity": validity, "uids": [uid]}
        assert b"\\Seen" not in flags(account, uid)


async def test_a_connection_managed_in_the_web_administration_keeps_its_events(tmp_path, monkeypatch):
    async def idle(self):  # look at what each connector would be started with; start none (no network)
        await anyio.sleep_forever()

    monkeypatch.setattr(Upstream, "run", idle)
    port = free_port()
    path = await prepare(tmp_path / "gateway", web_config(port, STUB, "https://hooks.example.test/v1/webhooks/x"),
                         secrets={**BASE_SECRETS, **SECRETS})
    async with web_gateway(tmp_path / "gateway", path=path, port=port) as (gw, http, origin, path):
        await setup(http, origin, path)
        before = gw.app.state.runtime.gateway
        # An edit in the web form: the connection then lives in the web-managed state, whose form has
        # no field for a webhook; the host-level mail_events still reaches the connector.
        saved = await change(http, "connections/save", kind="gmail", id="gmail-a", owner="person_a",
                             settings={"client_id": CLIENT_ID},
                             credentials={"client_secret": CLIENT_SECRET, "refresh_token": "1//refresh-token-new"})
        assert saved.status_code == 200 and saved.json()["saved"], saved.text
        assert "gmail-a" in [c["id"] for c in gw.app.state.admin.store.state["config"]["connections"]]
        upstream = gw.app.state.runtime.gateway.upstreams["gmail-a"]
        assert gw.app.state.runtime.gateway is not before and upstream.state_dir is not None
        assert upstream.extra_env == {"AGW_MAIL_EVENTS_URL": "https://hooks.example.test/v1/webhooks/x",
                                      "AGW_MAIL_EVENTS_TYPE": "person.mail.new", "AGW_MAIL_EVENTS_SECRET": SIGNING_SECRET,
                                      "AGW_MAIL_EVENTS_MAILBOX": "gmail-a"}


def web_config(port: int, google, url: str, **entry) -> dict:
    """The Gmail connection with mail_events, plus web administration."""
    out = approval_config(origin=f"http://localhost:{port}")
    out["admin"] = {"owner": "person_a", "state": "admin.enc"}
    mail = events_config(google, url, **entry)
    out["connections"] += mail["connections"]
    out["policy"] += mail["policy"]
    out["mail_events"] = mail["mail_events"]
    return out


async def test_webhook_configuration_requires_confirmation_and_reloads_both_mailboxes(tmp_path):
    port = free_port()
    first_url = "https://signal.openbot.run/v1/webhooks/first-target"
    second_url = "https://signal.openbot.run/v1/webhooks/second-target"
    signing_key = "fake-webhook-key-never-export"
    with mail_account(tmp_path / "imap", USER, PASSWORD) as account:
        config = web_config(port, STUB, "https://hooks.example.test/v1/webhooks/old")
        config["connections"].append(mail_connection("imap-a", "person_a", account, "imap-password", "i"))
        path = await prepare(tmp_path / "gateway", config, secrets={**BASE_SECRETS, **SECRETS, "imap-password": PASSWORD})
        operation = "settings/mail-webhooks"
        first = {"id": "", "label": "Mail", "url": first_url, "event_type": "mail.new", "secret": signing_key,
                 "connections": ["gmail-a", "imap-a"], "take_over": False}
        async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, path):
            assert (await http.post("/admin/api/" + operation, json=first)).status_code == 401
            key, _ = await setup(http, origin, path)
            current = await state(http)
            assert current["mail_webhooks"]["host_managed"] == ["gmail-a"]
            pending = await http.post("/admin/api/" + operation, json={**first, "revision": current["revision"]})
            assert pending.json()["error"] == "admin_confirmation_required"
            first["take_over"] = True
            invalid = await change(http, operation, **{**first, "url": first_url + "?leak=key"})
            assert invalid.json()["error"] == "mail_webhook_invalid"
            refused = await change(http, operation, **{**first, "take_over": False})
            assert refused.json()["error"] == "mail_webhook_takeover_required"
            reply = await change(http, operation, **first)
            assert reply.status_code == 200, reply.text
            first["id"] = reply.json()["id"]
            runtime = gw.app.state.runtime
            first_targets = runtime.gateway.upstreams["gmail-a"].extra_env["AGW_MAIL_EVENTS_TARGETS"]
            assert runtime.gateway.upstreams["gmail-a"].extra_env.keys() == {"AGW_MAIL_EVENTS_TARGETS", "AGW_MAIL_EVENTS_MAILBOX"}
            reply = await change(http, operation, **{**first, "id": "", "label": "Backup", "url": second_url,
                                                       "connections": ["gmail-a"], "take_over": False})
            assert reply.status_code == 200, reply.text
            assert len(json.loads(runtime.gateway.upstreams["gmail-a"].extra_env["AGW_MAIL_EVENTS_TARGETS"])) == 2
            assert len(json.loads(runtime.gateway.upstreams["imap-a"].extra_env["AGW_MAIL_EVENTS_TARGETS"])) == 1
            assert signing_key not in json.dumps(await state(http)) and signing_key not in gw.audit_text()
            assert signing_key.encode() not in (path.parent / "admin.enc").read_bytes()
            assert (await change(http, operation, **{**first, "url": first_url + "-changed", "secret": ""})).json()[
                "error"] == "mail_webhook_secret_required"

        async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, path):
            await login(http, key, origin)
            assert len((await state(http))["mail_webhooks"]["targets"]) == 2
            turned_off = await change(http, operation, **{**first, "connections": [], "secret": ""})
            assert turned_off.status_code == 200, turned_off.text
            runtime = gw.app.state.runtime
            assert runtime.gateway.upstreams["imap-a"].extra_env is None
            gmail_targets = runtime.gateway.upstreams["gmail-a"].extra_env["AGW_MAIL_EVENTS_TARGETS"]
            assert gmail_targets != first_targets and second_url in gmail_targets and first_url not in gmail_targets


@pytest.mark.browser
async def test_browser_saves_one_webhook_for_two_mailboxes(tmp_path):
    playwright = pytest.importorskip("playwright.async_api")
    port = free_port()
    with mail_account(tmp_path / "imap", USER, PASSWORD) as account:
        config = web_config(port, STUB, "https://hooks.example.test/v1/webhooks/old")
        config["mail_events"] = []
        config["connections"].append(mail_connection("imap-a", "person_a", account, "imap-password", "i"))
        path = await prepare(tmp_path / "gateway", config, secrets={**BASE_SECRETS, **SECRETS, "imap-password": PASSWORD})
        async with web_gateway(tmp_path, path=path, port=port):
            async with playwright.async_playwright() as driver:
                browser = await driver.chromium.launch()
                try:
                    context = await browser.new_context(locale="en-US")
                    page = await context.new_page()
                    cdp = await context.new_cdp_session(page)
                    await cdp.send("WebAuthn.enable")
                    await cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
                    await page.goto((path.parent / "admin-setup-link").read_text().strip())
                    await page.get_by_role("button", name="Create administrator passkey").click()
                    await page.get_by_role("link", name="Settings", exact=True).click()
                    await page.get_by_role("button", name="Add OpenBot webhook").click()
                    dialog = page.get_by_role("dialog", name="Add OpenBot webhook")
                    await dialog.get_by_label("Name", exact=True).fill("Inbox workflow")
                    await dialog.get_by_label("Webhook URL").fill("https://signal.openbot.run/v1/webhooks/test")
                    await dialog.get_by_label("Signing key").fill("browser-test-signing-key")
                    await dialog.get_by_role("checkbox", name="gmail-a").check()
                    await dialog.get_by_role("checkbox", name="imap-a").check()
                    await dialog.get_by_role("button", name="Save webhook").click()
                    await playwright.expect(page.get_by_text("Inbox workflow · gmail-a, imap-a")).to_be_visible()
                    await page.reload()
                    await page.get_by_role("button", name="Edit", exact=True).click()
                    dialog = page.get_by_role("dialog", name="Edit OpenBot webhook")
                    await playwright.expect(dialog.get_by_label("Signing key")).to_have_value("")
                    await playwright.expect(dialog.get_by_role("checkbox", name="gmail-a")).to_be_checked()
                    await playwright.expect(dialog.get_by_role("checkbox", name="imap-a")).to_be_checked()
                finally:
                    await browser.close()


async def test_a_connection_with_events_is_renamed_only_after_gateway_yaml(tmp_path, monkeypatch):
    async def idle(self):  # no connector is started (no network)
        await anyio.sleep_forever()

    monkeypatch.setattr(Upstream, "run", idle)
    port = free_port()
    path = await prepare(tmp_path / "gateway", web_config(port, STUB, "https://hooks.example.test/v1/webhooks/x"),
                         secrets={**BASE_SECRETS, **SECRETS})
    async with web_gateway(tmp_path / "gateway", path=path, port=port) as (gw, http, origin, path):
        await setup(http, origin, path)
        refused = await change(http, "connections/rename", id="gmail-a", name="gmail-b")
        # Renaming here would leave gateway.yaml naming a connection that no longer exists: events would stop.
        assert refused.status_code == 409 and refused.json()["error"] == "mail_events_rename_first"
        assert gw.app.state.runtime.gateway.upstreams["gmail-a"].extra_env["AGW_MAIL_EVENTS_MAILBOX"] == "gmail-a"


async def test_a_connection_renamed_after_gateway_yaml_starts_from_the_rename(tmp_path, google, receiver):
    refresh = "1//refresh-token-a"
    google.add_account(refresh, CLIENT_ID, CLIENT_SECRET)
    port = free_port()
    # gateway.yaml already names the new id (and the gateway was restarted), so the old connection is not watching.
    raw_config = web_config(port, google, receiver.url, connection="gmail-b")
    path = await prepare(tmp_path / "gateway", raw_config, secrets={**BASE_SECRETS, **SECRETS})
    connectors = load_config(path).audit.path.parent / "connectors"
    (connectors / "gmail-a").mkdir(parents=True)
    pending = {"id": "pending0delivery", "at": "2026-11-23T20:00:00Z", "data": {"mailbox": "gmail-a", "message_ids": ["18c0e9"]}}
    old = {"account": "mailbox@example.test", "cursor": {"history_id": "1000"}, "checked_at": time.time() - 60, "outbox": [pending]}
    (connectors / "gmail-a" / "mail-events.json").write_text(json.dumps(old))
    new = connectors / "gmail-b" / "mail-events.json"
    async with web_gateway(tmp_path / "gateway", path=path, port=port) as (gw, http, origin, path):
        await setup(http, origin, path)
        google.add_message(refresh, "18c0ea", raw("arrives between the restart and the rename"))
        renamed = await change(http, "connections/rename", id="gmail-a", name="gmail-b")
        assert renamed.status_code == 200, renamed.text
        with anyio.fail_after(20):
            while not new.exists():
                await anyio.sleep(0.1)
    # Nothing moves with the name: the new id starts from the rename, as newly enabled events do (docs/design.md 7.8).
    assert json.loads(new.read_text())["cursor"] == {"history_id": "1001"}
    assert json.loads(new.read_text())["outbox"] == [] and receiver.attempts == []
    assert json.loads((connectors / "gmail-a" / "mail-events.json").read_text()) == old


def test_another_mailbox_under_the_same_connection_starts_from_now(tmp_path, google, receiver):
    clock = Clock()
    events = gmail_events(tmp_path, google, receiver, "1//refresh-token-a", clock=clock)
    events.run_once()
    google.add_message("1//refresh-token-a", "18c0f1", raw("for mailbox A"))
    receiver.statuses = [503]
    clock.later()
    events.run_once()
    assert saved(tmp_path)["outbox"][0]["data"]["message_ids"] == ["18c0f1"]

    # The connection is saved with another account's credential (web administration): a new connector process.
    google.add_account("1//refresh-token-b", CLIENT_ID, CLIENT_SECRET)
    google.add_message("1//refresh-token-b", "18c0f2", raw("already in mailbox B"))
    google.add_message("1//refresh-token-b", "18c0f3", raw("also already in mailbox B"))
    switched = gmail_events(tmp_path, google, receiver, "1//refresh-token-b", clock=clock)
    switched.run_once()
    # A's pending event is not sent for B, and B is not asked from A's cursor (1001): B starts from now.
    assert len(receiver.attempts) == 1
    assert saved(tmp_path) | {"checked_at": None} == {"account": "mailbox1@example.test", "cursor": {"history_id": "1002"},
                                                      "checked_at": None, "outbox": []}
    google.add_message("1//refresh-token-b", "18c0f4", raw("new in mailbox B"))
    clock.later()
    switched.run_once()
    assert [event["data"] for event in receiver.events] == [{"mailbox": "gmail-a", "message_ids": ["18c0f4"]}]


async def test_an_imap_connection_renamed_after_gateway_yaml_starts_from_the_rename(tmp_path, receiver):
    with mail_account(tmp_path / "imap", USER, PASSWORD) as account:
        port = free_port()
        raw_config = approval_config(origin=f"http://localhost:{port}")
        raw_config["admin"] = {"owner": "person_a", "state": "admin.enc"}
        raw_config["connections"].append({
            "id": "icloud-a", "service": "icloud-mail", "account": "person_a", "owner": "person_a", "transport": "stdio",
            "command": [sys.executable, "-m", "agent_gateway.connectors.imap_mail"],
            "env": {"IMAP_HOST": "localhost", "IMAP_PORT": str(account.front.port), "IMAP_USERNAME": USER,
                    "SSL_CERT_FILE": str(account.cert), "SMTP_HOST": ""},
            "secret_env": {"IMAP_PASSWORD": "mail_a"}, "timeout_seconds": 20,
            "tools": [{"upstream": "list_mailboxes", "name": "a_mail_list_mailboxes"}],
        })
        # gateway.yaml already names the new id (the gateway was restarted): the old connection is not watching.
        raw_config["mail_events"] = [{"connection": "icloud-b", "url": receiver.url, "type": "person.mail.new", "secret": "signing"}]
        path = await prepare(tmp_path / "gw", raw_config, secrets={**BASE_SECRETS, "mail_a": PASSWORD, "signing": SIGNING_SECRET})
        with IMAPClient("127.0.0.1", account.plain_port, ssl=False) as client:
            client.login(USER, PASSWORD)
            validity = int(client.select_folder("INBOX", readonly=True)[b"UIDVALIDITY"])
        connectors = load_config(path).audit.path.parent / "connectors"
        (connectors / "icloud-a").mkdir(parents=True)
        old = {"account": f"{USER}@localhost:{account.front.port}", "cursor": {"uidvalidity": validity, "last_uid": 104},
               "checked_at": time.time() - 60, "outbox": []}
        (connectors / "icloud-a" / "mail-events.json").write_text(json.dumps(old))
        new = connectors / "icloud-b" / "mail-events.json"
        async with web_gateway(tmp_path / "gw", path=path, port=port) as (gw, http, origin, path):
            await setup(http, origin, path)
            uid = append(account, "arrives between the restart and the rename")
            renamed = await change(http, "connections/rename", id="icloud-a", name="icloud-b")
            assert renamed.status_code == 200, renamed.text
            with anyio.fail_after(20):
                while not new.exists():
                    await anyio.sleep(0.1)
        # As for Gmail: the new id starts from the rename (docs/design.md 7.8).
        assert json.loads(new.read_text())["cursor"] == {"uidvalidity": validity, "last_uid": uid}
        assert json.loads(new.read_text())["outbox"] == [] and receiver.attempts == []
        assert json.loads((connectors / "icloud-a" / "mail-events.json").read_text()) == old


def test_another_imap_mailbox_under_the_same_connection_starts_from_now(tmp_path, monkeypatch, receiver):
    # Same host, same user name, another port: a separate mailbox all the same.
    with mail_account(tmp_path / "a", USER, PASSWORD) as a, mail_account(tmp_path / "b", USER, PASSWORD) as b:
        monkeypatch.setenv("SSL_CERT_FILE", str(a.cert))
        clock = Clock()
        events = imap_events(tmp_path, a, receiver, clock)
        events.run_once()
        append(a, "for mailbox A")
        receiver.statuses = [503]
        clock.later()
        events.run_once()
        assert len(saved(tmp_path)["outbox"]) == 1

        # The connection is saved with the other mailbox's port (web administration): a new connector process.
        monkeypatch.setenv("SSL_CERT_FILE", str(b.cert))  # each fake server has its own self-signed certificate
        switched = imap_events(tmp_path, b, receiver, clock)
        switched.run_once()
        assert len(receiver.attempts) == 1  # A's pending event is not sent for B
        assert saved(tmp_path)["account"] == f"{USER}@localhost:{b.front.port}" and saved(tmp_path)["outbox"] == []
        uid = append(b, "new in mailbox B")  # A's cursor is already past this UID number: it would skip it
        clock.later()
        switched.run_once()
        assert [event["data"]["uids"] for event in receiver.events] == [[uid]]
