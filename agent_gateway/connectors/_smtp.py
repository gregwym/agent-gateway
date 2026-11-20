"""SMTP submission for the same mailbox connection and app-specific password."""
from __future__ import annotations

import smtplib
import socket
import ssl
from ipaddress import ip_address
from email.errors import HeaderParseError
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from ._base import ConnectorError, CredentialGate, Tool, plain, string


def address_literal(value):
    ip = ip_address(value.split("%", 1)[0])
    return f"[IPv6:{ip}]" if ip.version == 6 else f"[{ip}]"


def address(value):
    try:
        plain(value)
        parsed = Address(addr_spec=value)
        if not value.isascii() or not parsed.username or not parsed.domain or parsed.addr_spec != value:
            raise ValueError
    except (ValueError, IndexError, HeaderParseError):
        raise ConnectorError("Use a bare email address such as name@example.com, without a display name.", "smtp_invalid_address") from None
    return value


class Submission:
    def __init__(self, host, port, security, username, password, sender, sent=None):
        self.host, self.port, self.security = host, port, security
        self.username, self.password, self.sender = username, password, sender
        self.sent = sent  # a _sent.SentCopies that files the copy in Sent
        self.gate = CredentialGate("SMTP rejected the account credentials. Check the SMTP username and app-specific password in this mail connection.", code="smtp_credentials_rejected")

    def open(self):
        if not self.host:
            raise ConnectorError("SMTP is not configured. Edit this mail connection and set the SMTP server.", "smtp_not_configured")
        if self.security not in ("starttls", "tls"):
            raise ConnectorError("SMTP security must be STARTTLS or TLS; plaintext submission is not supported.", "smtp_invalid_security")
        address(self.sender)
        self.gate.check()
        smtp, ready = None, False
        try:
            context = ssl.create_default_context()
            # Avoid smtplib's unbounded getfqdn() lookup of the gateway host.
            # Before EHLO, replace this constructor placeholder with the local
            # socket address (RFC 5321 sections 4.1.1.1 and 4.1.3).
            if self.security == "tls":
                smtp = smtplib.SMTP_SSL(self.host, self.port, timeout=30, context=context, local_hostname="localhost")
            else:
                smtp = smtplib.SMTP(self.host, self.port, timeout=30, local_hostname="localhost")
            smtp.local_hostname = address_literal(smtp.sock.getsockname()[0])
            if self.security == "starttls":
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
            smtp.login(self.username, self.password)
            ready = True
            return smtp
        except smtplib.SMTPAuthenticationError:
            raise self.gate.refused() from None
        except ssl.SSLError:
            raise ConnectorError("SMTP TLS certificate verification or handshake failed. Check the SMTP server, security mode and gateway clock.", "smtp_tls_failed") from None
        except socket.gaierror:
            raise ConnectorError("The SMTP server hostname could not be resolved.", "smtp_dns_failed") from None
        except smtplib.SMTPNotSupportedError:
            raise ConnectorError("The SMTP server does not support the required TLS or authentication method. Check its port and security mode.", "smtp_not_supported") from None
        except smtplib.SMTPResponseException as exc:
            raise ConnectorError(f"The SMTP server refused connection or authentication (SMTP {exc.smtp_code}). Check SMTP settings and account access.", "smtp_request_rejected") from None
        except OSError:
            raise ConnectorError("The SMTP server could not be reached or disconnected before submission.", "smtp_unreachable") from None
        finally:
            # On failure, never leave a partially authenticated connection open.
            if not ready and smtp is not None:
                smtp.close()

    def check(self, args):
        smtp = self.open()
        smtp.close()
        return {"smtp": "authenticated", "sent": False}

    def send(self, args):
        groups = {key: [address(v) for v in args.get(key, [])] for key in ("to", "cc", "bcc")}
        recipients = list(dict.fromkeys(v for values in groups.values() for v in values))
        if not 1 <= len(recipients) <= 50:
            raise ConnectorError("Use between 1 and 50 recipients in total.", "smtp_recipient_limit")
        sender = address(self.sender)
        msg = EmailMessage()
        msg["From"], msg["To"] = sender, ", ".join(groups["to"])
        if groups["cc"]:
            msg["Cc"] = ", ".join(groups["cc"])
        # Bcc appears only in the envelope, never in the transmitted headers.
        msg["Subject"] = plain(args["subject"])
        message_id = make_msgid(domain=Address(addr_spec=sender).domain)
        msg["Date"], msg["Message-ID"] = formatdate(localtime=False), message_id
        msg.set_content(args["text"])
        if args.get("html"):
            msg.add_alternative(args["html"], subtype="html")
        # Flatten once: these bytes are submitted, and kept in Sent with the Bcc line a mail client would keep.
        raw = msg.as_bytes(policy=msg.policy.clone(linesep="\r\n"))
        copy = (b"Bcc: " + ", ".join(groups["bcc"]).encode() + b"\r\n" if groups["bcc"] else b"") + raw

        def everyone(status, **extra):
            return {"message_id": message_id, "results": [{"recipient": r, "status": status, **extra} for r in recipients],
                    "sent_copy": {"status": "skipped", "reason": "The message was not sent."}}

        smtp = self.open()
        recorded = False
        try:
            # Step by step, so a lost connection before DATA is known not to have sent anything.
            try:
                smtp.ehlo_or_helo_if_needed()
                code, _ = smtp.mail(sender)
                if code != 250:
                    return everyone("rejected", smtp_code=code, error="SMTP rejected the sender. Check sender permissions and server policy.")
                refused = {}
                for recipient in recipients:
                    code, reply = smtp.rcpt(recipient)
                    if code not in (250, 251):
                        refused[recipient] = code
            except (OSError, smtplib.SMTPException):
                return everyone("failed", error="SMTP disconnected before the message was sent, so it was not sent. It is safe to retry.")
            if len(refused) == len(recipients):
                return {"message_id": message_id, "results": [
                    {"recipient": r, "status": "rejected", "smtp_code": refused[r], "error": _REFUSED} for r in recipients],
                    "sent_copy": {"status": "skipped", "reason": "SMTP accepted no recipient."}}
            if self.sent:
                try:
                    self.sent.add(message_id, copy)
                except OSError:
                    raise ConnectorError("The gateway could not store the Sent copy (for example: its disk is full), so the message was not sent.", "sent_copy_unavailable") from None
                recorded = True
            try:
                code, _ = smtp.data(raw)
                outcome = "accepted" if code == 250 else code
            except smtplib.SMTPDataError as exc:
                outcome = exc.smtp_code
            except (OSError, smtplib.SMTPException):
                outcome = "unknown"  # the server may have the whole message: treat it as sent
            if outcome not in ("accepted", "unknown"):
                if recorded:
                    self.sent.discard(message_id)
                return everyone("rejected", smtp_code=outcome, error="SMTP rejected the message data. Check message limits and server policy.")
        finally:
            # A failed QUIT must not turn acknowledged submission into a failure.
            smtp.close()
        results = [{"recipient": r, "status": "rejected", "smtp_code": refused[r], "error": _REFUSED} if r in refused else
                   {"recipient": r, "status": outcome} if outcome == "accepted" else
                   {"recipient": r, "status": "unknown", "error": "SMTP disconnected during submission. Delivery may have been accepted; do not resend automatically. Check the mailbox or recipient first."}
                   for r in recipients]
        return {"message_id": message_id, "results": results,
                "sent_copy": {"status": "pending", "reason": "It is filed in the Sent folder within a few minutes, and retried until it is there."} if recorded else
                             {"status": "skipped", "reason": "This connector runs without a gateway state directory, so it keeps no Sent copy."},
                "note": "Accepted means the SMTP server accepted submission, not confirmed delivery. Never resend because of sent_copy."}


_REFUSED = "SMTP refused this recipient. Check the address and recipient mailbox policy; retry only rejected recipients."


def tools(submission):
    addresses = {"type": "array", "items": string("Bare recipient email address.", 254), "maxItems": 50, "uniqueItems": True}
    return [
        Tool("check_smtp", "Check TLS and authentication for this mail account's SMTP server without sending a message.", submission.check),
        Tool("send_message", "Send an email from this connection's configured sender using its SMTP server and shared account credential. Supports text and optional HTML, To/Cc/Bcc, up to 50 recipients in total. Returns accepted/rejected/unknown/failed per recipient; failed means certainly not sent and may be retried, unknown must not be retried automatically. The message is kept in the Sent folder within a few minutes (sent_copy); that never means it should be resent. No attachments.", submission.send,
             {"to": {**addresses, "minItems": 1}, "cc": addresses, "bcc": addresses,
              "subject": string("Email subject.", 998), "text": {"type": "string", "maxLength": 200000, "description": "Plain-text message body."},
              "html": {"type": "string", "maxLength": 200000, "description": "Optional HTML alternative."}},
             ("to", "subject", "text"), read_only=False),
    ]
