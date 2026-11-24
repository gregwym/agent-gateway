"""New-mail events: what reaches the webhook, when, and what happens when something fails.

Gmail is `FakeGoogle` (documented response shapes, not Google). The receiver checks
signatures the way an OpenBot webhook URL does. These tests do not show how Google or
OpenBot behave in production.
"""

from __future__ import annotations

import copy
import fcntl
import json
import shutil
import sys
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from types import SimpleNamespace

import anyio
import pytest
import yaml
from helpers import base_config, prepare, running_gateway
from service_helpers import FakeGoogle, WebhookReceiver

from agent_gateway import cli
from agent_gateway.config import ConfigError, load_config
from agent_gateway.connectors import _mail_events
from agent_gateway.connectors._mail_events import INTERVAL, GmailSource, MailEvents
from agent_gateway.connectors.gmail import Gmail

pytestmark = pytest.mark.anyio

CLIENT_ID = "1234567890-testclient.apps.googleusercontent.com"
CLIENT_SECRET = "GOCSPX-test-client-secret-000000"
SIGNING_SECRET = "whsec-test-signing-secret-0000"


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
    return MailEvents(tmp_path / "state", receiver.url, "person.mail.new", secret, "gmail-a", GmailSource(gmail),
                      clock=clock or Clock())


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
    assert "mail_events notes-a: no bundled Gmail connection has this id" in capsys.readouterr().err

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

