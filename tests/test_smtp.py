"""SMTP acceptance against a local TLS server, never a real mailbox."""
import base64
import email
import socket
import socketserver
import ssl
import threading
from contextlib import contextmanager

import pytest

from agent_gateway.connectors._base import ConnectorError
from agent_gateway.connectors._smtp import Submission
from service_helpers import localhost_certificate


@contextmanager
def smtp_server(path, *, implicit=False, reject_auth=False, disconnect_data=False, cert_pair=None):
    cert, key = cert_pair or localhost_certificate(path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    events, messages, envelopes = [], [], []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            conn = context.wrap_socket(self.request, server_side=True) if implicit else self.request
            encrypted = implicit
            conn.settimeout(5)
            reader = conn.makefile("rb")
            recipients = []
            try:
                conn.sendall(b"220 localhost test SMTP\r\n")
                while line := reader.readline():
                    command, _, arg = line.rstrip(b"\r\n").partition(b" ")
                    command = command.upper()
                    events.append(command.decode())
                    if command in (b"EHLO", b"HELO"):
                        conn.sendall(b"250-localhost\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
                    elif command == b"STARTTLS":
                        conn.sendall(b"220 Start TLS\r\n")
                        reader.close()
                        conn = context.wrap_socket(conn, server_side=True)
                        reader = conn.makefile("rb")
                        encrypted = True
                    elif command == b"AUTH":
                        assert encrypted  # credentials must never be sent before TLS
                        assert base64.b64decode(arg.split()[1]) == b"\x00account@example.test\x00fake-app-password"
                        conn.sendall(b"535 Auth refused\r\n" if reject_auth else b"235 Auth accepted\r\n")
                    elif command == b"MAIL":
                        assert encrypted
                        envelopes.append(arg.decode())
                        conn.sendall(b"250 Sender accepted\r\n")
                    elif command == b"RCPT":
                        recipients.append(arg.decode())
                        conn.sendall(b"550 Recipient refused\r\n" if b"bad@" in arg else b"250 Recipient accepted\r\n")
                    elif command == b"DATA":
                        conn.sendall(b"354 Send data\r\n")
                        chunks = []
                        while (part := reader.readline()) != b".\r\n":
                            if not part:
                                return
                            chunks.append(part[1:] if part.startswith(b"..") else part)
                        messages.append((recipients[:], b"".join(chunks)))
                        if disconnect_data:
                            return
                        conn.sendall(b"250 Queued\r\n")
                    elif command == b"QUIT":
                        conn.sendall(b"221 Bye\r\n")
                        return
                    elif command == b"RSET":
                        conn.sendall(b"250 Reset\r\n")
                    else:
                        conn.sendall(b"502 Unsupported\r\n")
            except (OSError, ssl.SSLError):
                pass
            finally:
                reader.close()
                conn.close()

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    with Server(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1], cert, events, messages, envelopes
        finally:
            server.shutdown()
            thread.join(5)


@pytest.mark.parametrize("implicit", [False, True])
def test_unified_smtp_tls_auth_partial_recipients_and_bcc_privacy(tmp_path, monkeypatch, implicit):
    with smtp_server(tmp_path, implicit=implicit) as (port, cert, events, messages, envelopes):
        monkeypatch.setenv("SSL_CERT_FILE", str(cert))
        sender = Submission("localhost", port, "tls" if implicit else "starttls", "account@example.test", "fake-app-password", "account@example.test")
        assert sender.check({}) == {"smtp": "authenticated", "sent": False}
        assert not messages and "MAIL" not in events
        result = sender.send({"to": ["ok@example.test", "bad@example.test"], "cc": ["cc@example.test"],
                              "bcc": ["private@example.test"], "subject": "中文 subject", "text": "hello\nworld", "html": "<p>hello</p>"})
        assert [r["status"] for r in result["results"]] == ["accepted", "rejected", "accepted", "accepted"]
        assert result["results"][1]["smtp_code"] == 550
        assert len(messages) == 1
        recipients, raw = messages[0]
        parsed = email.message_from_bytes(raw)
        assert parsed["From"] == "account@example.test" and parsed["Bcc"] is None
        assert b"private@example.test" not in raw and any("private@example.test" in r for r in recipients)
        assert parsed.is_multipart()
        assert envelopes == ["FROM:<account@example.test>"]
        assert events.count("AUTH") == 2 and events.count("STARTTLS") == (0 if implicit else 2)


def test_smtp_ambiguous_delivery_does_not_retry(tmp_path, monkeypatch):
    with smtp_server(tmp_path, disconnect_data=True) as (port, cert, events, messages, _):
        monkeypatch.setenv("SSL_CERT_FILE", str(cert))
        sender = Submission("localhost", port, "starttls", "account@example.test", "fake-app-password", "account@example.test")
        value = sender.send({"to": ["ok@example.test"], "subject": "disconnect", "text": "one submission"})
        assert value["results"][0]["status"] == "unknown"
        assert len(messages) == events.count("DATA") == 1


def test_smtp_credential_gate_and_certificate_validation(tmp_path, monkeypatch):
    with smtp_server(tmp_path, reject_auth=True) as (port, cert, events, messages, _):
        sender = Submission("localhost", port, "starttls", "account@example.test", "fake-app-password", "account@example.test")
        with pytest.raises(ConnectorError) as failure:
            sender.check({})
        assert failure.value.code == "smtp_tls_failed" and "AUTH" not in events
        monkeypatch.setenv("SSL_CERT_FILE", str(cert))
        for _ in range(2):
            with pytest.raises(ConnectorError) as failure:
                sender.check({})
            assert failure.value.code == "smtp_credentials_rejected"
        assert events.count("AUTH") == 1 and not messages


@pytest.mark.parametrize("recipient", ["somebody\r\nBcc: secret@example.test", "Name <x@example.test>", "a@b@example.test"])
def test_smtp_rejects_address_and_header_injection_without_connecting(recipient):
    sender = Submission("unused", 587, "starttls", "unused", "unused", "account@example.test")
    with pytest.raises(ConnectorError):
        sender.send({"to": [recipient], "subject": "hi", "text": "body"})
