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
    def __init__(self, host, port, security, username, password, sender):
        self.host, self.port, self.security = host, port, security
        self.username, self.password, self.sender = username, password, sender
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
        msg["Date"], msg["Message-ID"] = formatdate(localtime=False), make_msgid(domain=Address(addr_spec=sender).domain)
        msg.set_content(args["text"])
        if args.get("html"):
            msg.add_alternative(args["html"], subtype="html")
        smtp = self.open()
        try:
            refused = smtp.send_message(msg, from_addr=sender, to_addrs=recipients)
        except smtplib.SMTPRecipientsRefused as exc:
            refused = exc.recipients
        except (smtplib.SMTPSenderRefused, smtplib.SMTPDataError) as exc:
            return {"message_id": str(msg["Message-ID"]), "results": [
                {"recipient": r, "status": "rejected", "smtp_code": exc.smtp_code,
                 "error": "SMTP rejected the sender or message data. Check sender permissions, message limits and server policy."} for r in recipients]}
        except (OSError, smtplib.SMTPException):
            return {"message_id": str(msg["Message-ID"]), "results": [
                {"recipient": r, "status": "unknown", "error": "SMTP disconnected during submission. Delivery may have been accepted; do not resend automatically. Check the mailbox or recipient first."} for r in recipients]}
        finally:
            # A failed QUIT must not turn acknowledged submission into a failure.
            smtp.close()
        return {"message_id": str(msg["Message-ID"]), "results": [
            {"recipient": r, "status": "rejected", "smtp_code": refused[r][0],
             "error": "SMTP refused this recipient. Check the address and recipient mailbox policy; retry only rejected recipients."}
            if r in refused else {"recipient": r, "status": "accepted"} for r in recipients],
            "note": "Accepted means the SMTP server accepted submission, not confirmed delivery. This tool does not append a second copy to Sent."}


def tools(submission):
    addresses = {"type": "array", "items": string("Bare recipient email address.", 254), "maxItems": 50, "uniqueItems": True}
    return [
        Tool("check_smtp", "Check TLS and authentication for this mail account's SMTP server without sending a message.", submission.check),
        Tool("send_message", "Send an email from this connection's configured sender using its SMTP server and shared account credential. Supports text and optional HTML, To/Cc/Bcc. Returns accepted/rejected/unknown per recipient. Unknown submission outcomes must not be retried automatically. No attachments or separate Sent-folder copy.", submission.send,
             {"to": {**addresses, "minItems": 1}, "cc": addresses, "bcc": addresses,
              "subject": string("Email subject.", 998), "text": {"type": "string", "maxLength": 200000, "description": "Plain-text message body."},
              "html": {"type": "string", "maxLength": 200000, "description": "Optional HTML alternative."}},
             ("to", "subject", "text"), read_only=False),
    ]
