"""Every sent message is kept in Sent: a real SMTP exchange and a real IMAP server (pymap)."""
import email
import fcntl
import smtplib
import time
from contextlib import contextmanager

import pytest
from imapclient import IMAPClient

from agent_gateway.connectors._base import ConnectorError
from agent_gateway.connectors._sent import DELAY, SentCopies
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
    """{folder: [(flags, message bytes)]} for one Message-ID, read straight from the server."""
    found = {}
    with inspect(account) as client:
        for _, _, name in client.list_folders():
            client.select_folder(name, readonly=True)
            uids = client.search(["HEADER", "Message-ID", message_id])
            if uids:
                found[name] = [(data[b"FLAGS"], data[b"BODY[]"]) for data in client.fetch(uids, ["FLAGS", "BODY.PEEK[]"]).values()]
    return found


class Mail:
    def __init__(self, account, port, messages, state):
        self.account, self.messages, self.offset = account, messages, 0
        self.copies = SentCopies(state, USER, Mailbox("localhost", account.front.port, USER, PASSWORD)._connect,
                                 clock=lambda: time.time() + self.offset)
        self.submission = Submission("localhost", port, "starttls", USER, PASSWORD, USER, sent=self.copies)

    def send(self, **args):
        return self.submission.send({"to": ["ok@example.test"], "subject": "copy", "text": "hello\n.\nworld", **args})

    def later(self, seconds=DELAY):
        self.offset += seconds
        self.copies.run_once()


@contextmanager
def mail(tmp_path, monkeypatch, *, server_saves=False, **options):
    with mail_account(tmp_path / "imap", USER, PASSWORD) as account:
        def deliver(recipients, raw):
            if server_saves:  # what Gmail or Outlook do after accepting a message
                with inspect(account) as client:
                    client.append("Sent", raw)
        with smtp_server(tmp_path / "smtp", cert_pair=(account.cert, account.cert.parent / "key.pem"), deliver=deliver, **options) as (port, cert, events, messages, _):
            monkeypatch.setenv("SSL_CERT_FILE", str(cert))
            yield Mail(account, port, messages, tmp_path / "state")


def test_the_submitted_message_is_appended_to_sent_once_after_the_delay(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch) as m:
        result = m.send(to=["ok@example.test", "bad@example.test"], bcc=["private@example.test"])
        assert [r["status"] for r in result["results"]] == ["accepted", "rejected", "accepted"]
        assert result["sent_copy"]["status"] == "pending"
        envelope, submitted = m.messages[0]
        assert envelope == ["TO:<ok@example.test>", "TO:<bad@example.test>", "TO:<private@example.test>"]
        assert b"Bcc" not in submitted and b"private@example.test" not in submitted
        (record,) = m.copies.pending()
        assert record.stat().st_mode & 0o777 == 0o600 and m.copies.dir.stat().st_mode & 0o777 == 0o700
        m.later(DELAY - 10)
        assert not copies_of(m.account, result["message_id"]) and m.copies.pending()
        m.later(10)
        (flags, saved), = copies_of(m.account, result["message_id"])["Sent"]
        assert saved == b"Bcc: private@example.test\r\n" + submitted  # what a mail client keeps
        assert b"\\Seen" in flags and not m.copies.pending()
        assert email.message_from_bytes(saved)["Message-ID"] == result["message_id"]


def test_a_server_that_files_sent_mail_itself_gets_no_second_copy(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch, server_saves=True) as m:
        result = m.send()
        m.later()
        assert len(copies_of(m.account, result["message_id"])["Sent"]) == 1
        assert "APPEND" not in m.account.front.commands and not m.copies.pending()


def test_a_copy_whose_record_survived_a_lost_connection_is_not_appended_again(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch) as m:
        result = m.send()
        append = IMAPClient.append

        def lost(self, *args, **kwargs):
            append(self, *args, **kwargs)
            raise OSError("connection lost after APPEND")

        monkeypatch.setattr(IMAPClient, "append", lost)
        with pytest.raises(OSError):
            m.later()
        assert m.copies.pending()
        monkeypatch.setattr(IMAPClient, "append", append)
        # A new process for the same connection files what was left on disk.
        restarted = SentCopies(tmp_path / "state", USER, Mailbox("localhost", m.account.front.port, USER, PASSWORD)._connect,
                               clock=lambda: time.time() + DELAY)
        restarted.run_once()
        assert len(copies_of(m.account, result["message_id"])["Sent"]) == 1 and not restarted.pending()


def test_an_unreachable_mailbox_keeps_the_record_for_the_next_round(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch) as m:
        def unreachable():
            raise OSError("IMAP unreachable")

        m.copies.connect = unreachable
        result = m.send()
        assert result["results"] == [{"recipient": "ok@example.test", "status": "accepted"}]
        with pytest.raises(OSError):
            m.later()
        assert m.copies.pending()


def test_another_process_working_on_the_records_is_left_alone(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch) as m:
        m.send()
        with open(m.copies.dir / ".lock", "a") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            m.later()
            assert m.copies.pending()
        m.copies.run_once()
        assert not m.copies.pending()


def test_an_unknown_outcome_is_treated_as_sent(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch, disconnect_data=True) as m:
        result = m.send()
        assert result["results"][0]["status"] == "unknown" and result["sent_copy"]["status"] == "pending"
        m.later()
        assert len(copies_of(m.account, result["message_id"])["Sent"]) == 1


def test_a_disconnect_before_data_is_a_certain_failure_without_a_copy(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch) as m:
        def lost(self, *args, **kwargs):
            raise smtplib.SMTPServerDisconnected("lost before DATA")

        monkeypatch.setattr(smtplib.SMTP, "rcpt", lost)
        result = m.send()
        assert result["results"][0]["status"] == "failed" and "safe to retry" in result["results"][0]["error"]
        assert result["sent_copy"]["status"] == "skipped" and not m.copies.pending() and not m.messages


def test_rejected_message_data_leaves_no_copy(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch) as m:
        monkeypatch.setattr(smtplib.SMTP, "data", lambda self, msg: (554, b"5.6.0 rejected"))
        result = m.send()
        assert result["results"] == [{"recipient": "ok@example.test", "status": "rejected", "smtp_code": 554,
                                       "error": "SMTP rejected the message data. Check message limits and server policy."}]
        assert not m.copies.pending()


def test_no_message_is_sent_when_its_copy_cannot_be_stored(tmp_path, monkeypatch):
    with mail(tmp_path, monkeypatch) as m:
        def full(self, *args):
            raise OSError("No space left on device")

        monkeypatch.setattr(SentCopies, "add", full)
        with pytest.raises(ConnectorError) as exc:
            m.send()
        assert exc.value.code == "sent_copy_unavailable" and not m.messages


def test_records_of_an_earlier_account_are_removed(tmp_path):
    earlier = SentCopies(tmp_path, "old@example.test", None)
    earlier.add("<a@example.test>", b"Message-ID: <a@example.test>\r\n\r\nbody\r\n")
    current = SentCopies(tmp_path, USER, None)
    assert not earlier.dir.exists() and not current.pending()


class Folders:
    def __init__(self, folders, refuse=()):
        self.folders, self.refuse, self.created = folders, refuse, []

    def list_folders(self):
        return self.folders

    def create_folder(self, name):
        if name in self.refuse:
            raise Exception("NO [CANNOT] not here")
        self.created.append(name)


@pytest.mark.parametrize("folders, expected, created", [
    ([((), b"/", "INBOX"), ((b"\\Sent",), b"/", "Gesendet"), ((), b"/", "Sent")], "Gesendet", []),
    ([((), b"/", "INBOX"), ((), b"/", "Sent Items")], "Sent Items", []),
    ([((), b".", "INBOX"), ((), b".", "INBOX.Sent")], "INBOX.Sent", []),
    ([((), b"/", "INBOX")], "Sent", ["Sent"]),
])
def test_sent_is_the_flagged_folder_then_a_familiar_name_then_created(folders, expected, created):
    client = Folders(folders)
    assert SentCopies._sent_folder(client) == expected and client.created == created


def test_sent_is_created_under_inbox_where_the_server_requires_it():
    client = Folders([((), b".", "INBOX")], refuse={"Sent"})
    assert SentCopies._sent_folder(client) == "INBOX.Sent"
