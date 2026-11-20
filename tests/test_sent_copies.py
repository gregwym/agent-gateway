"""Every sent message ends up in Sent exactly once: a real SMTP exchange and a real IMAP server (pymap)."""
import email
import json
import smtplib
import time
from contextlib import contextmanager

import pytest
from imapclient import IMAPClient

from agent_gateway.connectors import _sent
from agent_gateway.connectors._sent import APPEND, SELF_BCC, SERVER_SAVES, SentCopies
from agent_gateway.connectors._smtp import Submission
from agent_gateway.connectors.imap_mail import Mailbox
from service_helpers import mail_account
from test_smtp import smtp_server

USER, PASSWORD = "account@example.test", "fake-app-password"


@contextmanager
def inspect(account):
    with IMAPClient("127.0.0.1", account.plain_port, ssl=False) as client:
        client.login(account.user, account.password)
        yield client


def copies_of(account, message_id):
    """Message-ID -> {folder: [(uid, flags)]}, read straight from the server."""
    found = {}
    with inspect(account) as client:
        for _, _, name in client.list_folders():
            client.select_folder(name, readonly=True)
            uids = client.search(["HEADER", "Message-ID", message_id])
            if uids:
                found[name] = [(uid, data[b"FLAGS"], data[b"BODY[]"]) for uid, data in client.fetch(uids, ["FLAGS", "BODY.PEEK[]"]).items()]
    return found


class Mail:
    """One account: SMTP that can file sent mail and deliver the sender's copy, and IMAP to look at."""

    def __init__(self, account, port, messages, state, clock, smtp_host, **timing):
        self.account, self.messages, self.clock = account, messages, clock
        background = Mailbox("localhost", account.front.port, USER, PASSWORD)
        self.copies = SentCopies(state, background._connect, smtp_host, USER, clock=lambda: clock[0], wait=0, **timing)
        self.submission = Submission("localhost", port, "starttls", USER, PASSWORD, USER, sent=self.copies)

    def send(self, **args):
        return self.submission.send({"to": ["ok@example.test"], "subject": "copy", "text": "hello\n.\nworld", **args})

    def later(self, seconds):
        self.clock[0] += seconds
        return self.copies.run_once()

    def pending(self):
        return sorted(p.name for p in self.copies.pending.glob("*.json"))


@contextmanager
def mail(tmp_path, monkeypatch, *, smtp_host="smtp.example.test", server_saves=False, deliver_to=None, **options):
    with mail_account(tmp_path / "imap", USER, PASSWORD) as account:
        def deliver(recipients, raw):
            # Stand-ins for what real servers do after accepting a message.
            with inspect(account) as client:
                if server_saves:
                    client.append("Sent", raw)
                if deliver_to and {USER, "alias@example.test"} & set(recipients):  # one delivery per mailbox
                    client.append(deliver_to, b"Received: from smtp.example.test\r\n" + raw)
        with smtp_server(tmp_path / "smtp", cert_pair=(account.cert, account.cert.parent / "key.pem"), deliver=deliver, **options) as (port, cert, events, messages, _):
            monkeypatch.setenv("SSL_CERT_FILE", str(cert))
            yield Mail(account, port, messages, tmp_path / "state", [1_800_000_000.0], smtp_host)


@pytest.mark.parametrize("folder", ["INBOX", "Rules"])
def test_the_senders_own_copy_is_moved_to_sent_wherever_it_lands(tmp_path, monkeypatch, folder):
    with mail(tmp_path, monkeypatch, deliver_to=folder) as m:
        with inspect(m.account) as client:
            client.create_folder("Rules")  # a server-side rule files the copy here
        result = m.send(to=["ok@example.test", "bad@example.test"], bcc=["private@example.test"])
        assert [r["status"] for r in result["results"]] == ["accepted", "rejected", "accepted"]
        assert result["sent_copy"]["status"] == "pending"
        envelope, raw = m.messages[0]
        assert envelope == ["TO:<ok@example.test>", "TO:<bad@example.test>", "TO:<private@example.test>", f"TO:<{USER}>"]
        assert b"Bcc" not in raw and b"private@example.test" not in raw
        assert m.later(1) is not None  # an unknown provider gets time to file its own copy first
        assert set(copies_of(m.account, result["message_id"])) == {folder}
        m.later(_sent.GRACE)
        found = copies_of(m.account, result["message_id"])
        assert list(found) == ["Sent"] and len(found["Sent"]) == 1
        assert b"\\Seen" in found["Sent"][0][1]
        assert not m.pending() and m.copies.mode() == SELF_BCC
        # Now known: the next copy is filed as soon as it arrives.
        second = m.send()
        m.later(1)
        assert list(copies_of(m.account, second["message_id"])) == ["Sent"]


def test_a_server_known_to_file_sent_mail_gets_no_extra_copy(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch, smtp_host="smtp.gmail.com", server_saves=True) as m:
        result = m.send()
        assert m.messages[0][0] == ["TO:<ok@example.test>"]  # no self-Bcc
        m.later(1)
        found = copies_of(m.account, result["message_id"])
        assert list(found) == ["Sent"] and len(found["Sent"]) == 1
        assert "APPEND" not in m.account.front.commands and not m.pending()


def test_only_the_senders_own_copy_is_removed_when_an_unknown_alias_also_received_it(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch, server_saves=True, deliver_to="INBOX") as m:
        result = m.send(to=["unlisted-alias@example.test"])
        with inspect(m.account) as client:  # an alias the gateway does not know delivers here too
            client.append("INBOX", m.messages[0][1])
        m.later(1)
        found = copies_of(m.account, result["message_id"])
        assert len(found["Sent"]) == 1 and len(found["INBOX"]) == 1


def test_an_unknown_server_that_files_sent_mail_is_recognised_and_the_extra_copy_removed(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch, server_saves=True, deliver_to="INBOX") as m:
        result = m.send()
        m.later(1)
        found = copies_of(m.account, result["message_id"])
        assert list(found) == ["Sent"] and len(found["Sent"]) == 1  # the self copy in INBOX was removed
        assert m.copies.mode() == SERVER_SAVES and not m.pending()
        m.send()
        assert m.messages[1][0] == ["TO:<ok@example.test>"]


def test_without_a_delivered_copy_the_submitted_bytes_are_appended_once(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch) as m:
        result = m.send()
        m.later(_sent.ARRIVAL - 1)
        assert not copies_of(m.account, result["message_id"]) and m.pending()
        m.later(1)
        found = copies_of(m.account, result["message_id"])
        assert list(found) == ["Sent"] and len(found["Sent"]) == 1
        assert found["Sent"][0][2] == m.messages[0][1] and b"\\Seen" in found["Sent"][0][1]
        assert m.copies.mode() == APPEND and not m.pending()
        second = m.send()
        assert m.messages[1][0] == ["TO:<ok@example.test>"]
        m.later(1)
        assert len(copies_of(m.account, second["message_id"])["Sent"]) == 1


def test_a_lost_step_is_checked_and_not_repeated_even_after_a_restart(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch) as m:
        m.copies._learn(mode=APPEND)
        result = m.send()
        confirm = SentCopies._confirm

        def crash(self, *args):
            raise OSError("connection lost after APPEND")

        monkeypatch.setattr(SentCopies, "_confirm", crash)
        m.later(1)
        assert m.pending() and len(copies_of(m.account, result["message_id"])["Sent"]) == 1
        monkeypatch.setattr(SentCopies, "_confirm", confirm)
        # A new process for the same connection resumes from the record on disk.
        restarted = SentCopies(tmp_path / "state", Mailbox("localhost", m.account.front.port, USER, PASSWORD)._connect,
                               "smtp.example.test", USER, clock=lambda: m.clock[0] + 600)
        assert restarted.run_once() is None
        assert len(copies_of(m.account, result["message_id"])["Sent"]) == 1


def test_an_unknown_outcome_is_settled_by_the_senders_copy(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch, disconnect_data=True, deliver_to="INBOX") as m:
        m.copies._learn(mode=SELF_BCC)
        m.copies.wait_seconds, m.copies.clock = 10, time.time
        m.copies.start()
        result = m.send()
        assert result["results"] == [{"recipient": "ok@example.test", "status": "accepted"}]
        assert result["sent_copy"] == {"status": "saved", "mailbox": "Sent"}
        assert list(copies_of(m.account, result["message_id"])) == ["Sent"]


def test_an_unknown_outcome_without_any_copy_was_not_sent(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch, disconnect_data=True) as m:
        result = m.send()
        assert result["results"][0]["status"] == "unknown" and result["sent_copy"]["status"] == "pending"
        m.later(_sent.DECIDE)
        assert not m.pending() and not copies_of(m.account, result["message_id"])


def test_a_disconnect_before_the_end_of_data_is_a_certain_failure(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch) as m:
        original = smtplib.SMTP.send

        def send(self, data):
            if isinstance(data, bytes) and data.endswith(b"\r\n.\r\n"):
                raise smtplib.SMTPServerDisconnected("lost while sending the body")
            return original(self, data)

        monkeypatch.setattr(smtplib.SMTP, "send", send)
        result = m.send()
        assert result["results"][0]["status"] == "failed" and "safe to retry" in result["results"][0]["error"]
        assert result["sent_copy"]["status"] == "skipped" and not m.pending() and not m.messages


def test_a_record_that_cannot_be_updated_never_turns_an_accepted_send_into_an_error(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch) as m:
        def full(self, *args):
            raise OSError("No space left on device")

        monkeypatch.setattr(SentCopies, "settle", full)
        result = m.send()
        assert result["results"] == [{"recipient": "ok@example.test", "status": "accepted"}]
        assert result["sent_copy"]["status"] == "pending" and len(m.messages) == 1


def test_an_unreachable_mailbox_never_delays_the_send_result(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch) as m:
        def unreachable():
            time.sleep(3)
            raise OSError("IMAP unreachable")

        m.copies.connect, m.copies.wait_seconds, m.copies.clock = unreachable, 1, time.time
        m.copies.start()
        started = time.monotonic()
        result = m.send()
        assert time.monotonic() - started < 5
        assert result["results"] == [{"recipient": "ok@example.test", "status": "accepted"}]
        assert result["sent_copy"]["status"] == "pending" and m.pending()


def test_pending_records_are_private_and_removed_once_saved(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch, deliver_to="INBOX") as m:
        m.copies._learn(mode=SELF_BCC)
        m.send()
        (record,) = m.copies.pending.glob("*.json")
        assert record.stat().st_mode & 0o777 == 0o600 and m.copies.pending.stat().st_mode & 0o777 == 0o700
        assert json.loads(record.read_text())["self_bcc"] is True
        m.later(1)
        assert not m.pending()


@pytest.mark.parametrize("own", [USER, "alias@example.test"])
def test_sending_to_oneself_never_moves_the_received_message(tmp_path, monkeypatch, own):
    with mail(tmp_path, monkeypatch, deliver_to="INBOX") as m:
        m.copies.own.add("alias@example.test")  # given by the gateway from the connection's addresses
        result = m.send(to=[own])
        assert m.messages[0][0] == [f"TO:<{own}>"]
        m.later(_sent.GRACE)
        found = copies_of(m.account, result["message_id"])
        assert set(found) == {"INBOX", "Sent"} and len(found["Sent"]) == 1


class Folders:
    """IMAP fault injection for folder discovery."""

    def __init__(self, folders, refuse=()):
        self.folders, self.refuse, self.created = folders, refuse, []

    def list_folders(self):
        return self.folders

    def create_folder(self, name):
        import imaplib
        if name in self.refuse:
            raise imaplib.IMAP4.error("NO [CANNOT] not here")
        self.created.append(name)


@pytest.mark.parametrize("folders, expected", [
    ([((), b"/", "INBOX"), ((b"\\Sent",), b"/", "Gesendet"), ((), b"/", "Sent")], "Gesendet"),
    ([((), b"/", "INBOX"), ((), b"/", "Sent Items")], "Sent Items"),
    ([((), b".", "INBOX"), ((), b".", "INBOX.Sent")], "INBOX.Sent"),
    ([((), b"/", "INBOX")], None),
])
def test_sent_folder_is_the_flagged_one_then_a_familiar_name(tmp_path, folders, expected):
    copies = SentCopies(tmp_path, None, "smtp.example.test", USER)
    assert copies._sent_folder(folders) == expected


def test_a_missing_sent_folder_is_created_where_the_server_allows(tmp_path):
    copies = SentCopies(tmp_path, None, "smtp.example.test", USER)
    client = Folders([((), b".", "INBOX")], refuse={"Sent"})
    assert copies._create_sent(client, client.folders) == "INBOX.Sent"
    assert copies._sent_folder(client.folders + [((), b".", "INBOX.Sent")]) == "INBOX.Sent"
