"""SMTP submission for the same mailbox connection and app-specific password."""
from __future__ import annotations

import re
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
        self.sent = sent  # a _sent.SentCopies that keeps the copy in Sent
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
        if not 1 <= len(recipients) <= MAX_RECIPIENTS:
            raise ConnectorError(f"Use between 1 and {MAX_RECIPIENTS} recipients in total.", "smtp_recipient_limit")
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
        # Flatten once: these exact bytes are submitted and, if needed, appended to Sent.
        raw = msg.as_bytes(policy=msg.policy.clone(linesep="\r\n"))
        # Where the server does not file sent mail itself, the sender's own copy (envelope only) goes to Sent.
        self_bcc = bool(self.sent) and self.sent.self_bcc(recipients)
        outcome, refused, recorded = self._submit(sender, recipients + [sender] * self_bcc, raw, message_id, self_bcc)
        if isinstance(outcome, tuple):
            code, error = outcome
            return {"message_id": message_id, "results": [{"recipient": r, "status": "rejected", "smtp_code": code, "error": error} for r in recipients],
                    "sent_copy": {"status": "skipped", "reason": "The message was not sent."}}
        if outcome == "refused":
            return {"message_id": message_id, "results": [
                {"recipient": r, "status": "rejected", "smtp_code": refused[r][0],
                 "error": "SMTP refused this recipient. Check the address and recipient mailbox policy; retry only rejected recipients."} for r in recipients],
                "sent_copy": {"status": "skipped", "reason": "SMTP accepted no recipient."}}
        if outcome == "failed":
            return {"message_id": message_id, "results": [
                {"recipient": r, "status": "failed", "error": "SMTP disconnected before the message was complete, so it was not sent. It is safe to retry."} for r in recipients],
                "sent_copy": {"status": "skipped", "reason": "The message was not sent."}}
        results = [{"recipient": r, "status": "rejected", "smtp_code": refused[r][0],
                    "error": "SMTP refused this recipient. Check the address and recipient mailbox policy; retry only rejected recipients."}
                   if r in refused else {"recipient": r, "status": outcome} for r in recipients]
        if outcome == "unknown":
            for row in results:
                if row["status"] == "unknown":
                    row["error"] = "SMTP disconnected after the whole message was sent. Delivery may have been accepted; do not resend automatically."
        copy = {"status": "skipped", "reason": "This connector runs without a gateway state directory, so it keeps no Sent copy."}
        if recorded:
            done = self.sent.wait(message_id)
            copy = done["sent_copy"] if done else {"status": "pending", "reason": "The copy is being saved to Sent in the background and will be retried until it is there."}
            if done and outcome == "unknown" and done["delivered"] is not None:
                results = [row if row["status"] != "unknown" else
                           {"recipient": row["recipient"], "status": "accepted"} if done["delivered"] else
                           {"recipient": row["recipient"], "status": "failed", "error": "No copy of the message appeared, so it was not sent."}
                           for row in results]
        return {"message_id": message_id, "results": results, "sent_copy": copy,
                "note": "Accepted means the SMTP server accepted submission, not confirmed delivery. sent_copy reports the copy "
                        "in the Sent folder separately; whatever it says, never resend a message that was accepted."}

    def _submit(self, sender, envelope, raw, message_id, self_bcc):
        """Run SMTP step by step so a lost connection is known to be before or after the end of the message.

        Returns (outcome, refused, recorded): outcome is "accepted", "unknown", "failed" (certainly
        not sent) or a (code, error) rejection of the whole message.
        """
        smtp = self.open()
        recorded = False
        try:
            try:
                code, _ = smtp.mail(sender)
                if code != 250:
                    return (code, "SMTP rejected the sender. Check sender permissions and server policy."), {}, False
                refused = {}
                for recipient in envelope:
                    code, reply = smtp.rcpt(recipient)
                    if code not in (250, 251):
                        refused[recipient] = (code, reply)
                if all(r in refused for r in envelope if r != sender or not self_bcc):
                    try:
                        smtp.rset()
                    except (OSError, smtplib.SMTPException):
                        pass
                    return "refused", refused, False  # every real recipient was refused: nothing was sent
                if self_bcc and sender in refused:
                    self_bcc = False  # the server will not deliver the sender's copy
                if self.sent:
                    self.sent.begin(raw, message_id, self_bcc)
                    recorded = True
                code, _ = smtp.docmd("DATA")
                if code != 354:
                    raise _Rejected(code)
                smtp.send(_dot_stuffed(raw))
            except (OSError, smtplib.SMTPException):
                if recorded:
                    _quietly(self.sent.discard, message_id)
                return "failed", {}, False
            try:
                code, _ = smtp.getreply()
            except (OSError, smtplib.SMTPException):
                if recorded:
                    _quietly(self.sent.settle, message_id, False)  # the mailbox will show what happened
                return "unknown", refused, recorded
            if code != 250:
                raise _Rejected(code)
            if recorded:
                # Once the server has the message, nothing here may turn the send into an error.
                _quietly(self.sent.settle, message_id, True)
            return "accepted", refused, recorded
        except _Rejected as exc:
            if recorded:
                _quietly(self.sent.discard, message_id)
            return (exc.code, "SMTP rejected the message data. Check message limits and server policy."), {}, False
        finally:
            # A failed QUIT must not turn acknowledged submission into a failure.
            smtp.close()


MAX_RECIPIENTS = 49  # one envelope slot is kept for the sender's own copy


def _quietly(action, *args):
    try:
        action(*args)
    except Exception:
        pass


class _Rejected(Exception):
    def __init__(self, code):
        self.code = code


def _dot_stuffed(raw):
    # RFC 5321 section 4.5.2, as smtplib.SMTP.data does, followed by the end-of-data line.
    data = re.sub(rb"(?m)^\.", b"..", raw)
    return data + (b"" if data.endswith(b"\r\n") else b"\r\n") + b".\r\n"


def tools(submission):
    addresses = {"type": "array", "items": string("Bare recipient email address.", 254), "maxItems": MAX_RECIPIENTS, "uniqueItems": True}
    return [
        Tool("check_smtp", "Check TLS and authentication for this mail account's SMTP server without sending a message.", submission.check),
        Tool("send_message", "Send an email from this connection's configured sender using its SMTP server and shared account credential. Supports text and optional HTML, To/Cc/Bcc, up to 49 recipients in total. Returns accepted/rejected/unknown/failed per recipient; failed means certainly not sent and may be retried, unknown must not be retried automatically. Every sent message is kept once in the Sent folder; sent_copy reports that separately (saved, or pending while it is completed in the background) and never means the message should be resent. No attachments.", submission.send,
             {"to": {**addresses, "minItems": 1}, "cc": addresses, "bcc": addresses,
              "subject": string("Email subject.", 998), "text": {"type": "string", "maxLength": 200000, "description": "Plain-text message body."},
              "html": {"type": "string", "maxLength": 200000, "description": "Optional HTML alternative."}},
             ("to", "subject", "text"), read_only=False),
    ]
