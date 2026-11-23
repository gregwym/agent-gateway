"""Local stand-ins for the real services, for the connector tests.

Nothing here imitates a protocol by hand: the mail server is pymap (a real IMAP
server), and `TLSFront` only terminates TLS in front of it, the way a real mail
host presents itself, while noting which commands go through.
"""

from __future__ import annotations

import asyncio
import datetime
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def localhost_process(module: str) -> list[str]:
    """Run a local fixture without external hostname discovery; see the wrapper."""
    return [sys.executable, str(Path(__file__).parent / "fixtures" / "localhost_process.py"), module]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_port(port: int, timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.05)


def localhost_certificate(directory: Path) -> tuple[Path, Path]:
    """A self-signed certificate for `localhost`. A client trusts it only if told to (SSL_CERT_FILE)."""
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = directory / "cert.pem", directory / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_file, key_file


class TLSFront:
    """Accepts TLS on a local port and forwards to a plaintext port. Records IMAP command names."""

    def __init__(self, cert: Path, key: Path, target_port: int) -> None:
        self.target_port = target_port
        self.commands: list[str] = []
        self.connections = 0
        self._writers: set[asyncio.StreamWriter] = set()
        self._loop = asyncio.new_event_loop()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        threading.Thread(target=self._loop.run_forever, daemon=True).start()
        self._server = asyncio.run_coroutine_threadsafe(
            asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=context), self._loop
        ).result(10)
        self.port: int = self._server.sockets[0].getsockname()[1]

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            up_reader, up_writer = await asyncio.open_connection("127.0.0.1", self.target_port)
        except OSError:
            writer.close()
            return
        pair = {writer, up_writer}
        self._writers |= pair

        async def pump(source: asyncio.StreamReader, sink: asyncio.StreamWriter, record: bool) -> None:
            try:
                while data := await source.read(65536):
                    if record:
                        for line in data.split(b"\r\n"):
                            found = re.match(rb"^[A-Z]+\d+ (?:UID )?([A-Za-z]+)", line)
                            if found:
                                self.commands.append(found.group(1).decode().upper())
                    sink.write(data)
                    await sink.drain()
            except (OSError, ssl.SSLError):
                pass
            finally:
                sink.close()

        await asyncio.gather(pump(reader, up_writer, True), pump(up_reader, writer, False))
        self._writers -= pair

    def drop_connections(self) -> None:
        """Cut every open connection, as a server restart or an idle timeout would."""
        done = threading.Event()

        def cut() -> None:
            for writer in list(self._writers):
                writer.transport.abort()
            done.set()

        self._loop.call_soon_threadsafe(cut)
        done.wait(5)

    def close(self) -> None:
        self.drop_connections()
        self._loop.call_soon_threadsafe(self._server.close)
        self._loop.call_soon_threadsafe(self._loop.stop)


@dataclass
class MailAccount:
    user: str
    password: str
    plain_port: int  # the IMAP server itself; tests use it to put mail in and to look at flags
    front: TLSFront  # what the connector connects to
    cert: Path
    process: subprocess.Popen[bytes]


@contextmanager
def mail_account(directory: Path, user: str, password: str) -> Iterator[MailAccount]:
    """One mailbox on its own IMAP server: pymap's in-memory backend with its demo mailbox."""
    cert, key = localhost_certificate(directory)
    port = free_port()
    log = directory / "pymap.log"
    output = log.open("wb")
    process = subprocess.Popen(
        [sys.executable, "-c", "from pymap.main import main; main()", "--host", "127.0.0.1", "--port", str(port),
         "--no-tls", "dict", "--demo-data", "--demo-user", user, "--demo-password", password],
        stdout=output, stderr=subprocess.STDOUT, env={**os.environ, "FQDN": "localhost"},
    )  # fmt: skip
    output.close()
    front = None
    try:
        try:
            wait_for_port(port)
        except OSError as exc:
            raise RuntimeError(f"IMAP test server did not start:\n{log.read_text(errors='replace')}") from exc
        front = TLSFront(cert, key, port)
        yield MailAccount(user, password, port, front, cert, process)
    finally:
        if front is not None:
            front.close()
        process.kill()
        process.wait(10)


@dataclass
class CalendarServer:
    url: str
    log: Path
    process: subprocess.Popen[bytes]

    def requests(self, since: int = 0) -> list[str]:
        """HTTP methods the server has logged, in order (from position `since` of its log)."""
        text = self.log.read_text(encoding="utf-8", errors="replace")[since:]
        return re.findall(r"\] ([A-Z]+) request for ", text)

    def mark(self) -> int:
        return len(self.log.read_text(encoding="utf-8", errors="replace"))


@contextmanager
def calendar_server(directory: Path, users: dict[str, str]) -> Iterator[CalendarServer]:
    """Radicale, a real CalDAV server, with one login per user. Each user sees only their own calendars."""
    directory.mkdir(parents=True, exist_ok=True)
    passwords = directory / "users"
    passwords.write_text("".join(f"{user}:{password}\n" for user, password in users.items()), encoding="utf-8")
    port, log = free_port(), directory / "radicale.log"
    with open(log, "wb") as output:
        process = subprocess.Popen(
            [*localhost_process("radicale"), "--server-hosts", f"127.0.0.1:{port}", "--auth-type", "htpasswd",
             "--auth-htpasswd-filename", str(passwords), "--auth-htpasswd-encryption", "plain",
             "--storage-filesystem-folder", str(directory / "data"), "--logging-level", "info"],
            stdout=output, stderr=subprocess.STDOUT,
        )  # fmt: skip
    try:
        try:
            wait_for_port(port)
        except OSError as exc:
            raise RuntimeError(f"CalDAV test server did not start:\n{log.read_text(errors='replace')}") from exc
        yield CalendarServer(f"http://127.0.0.1:{port}", log, process)
    finally:
        process.kill()
        process.wait(10)


class FakeGoogle:
    """Stands in for Google's token endpoint and the Gmail API on localhost.

    This is not Google. It answers with the request and response shapes from Google's
    documentation that the Gmail connector relies on, and it enforces what Google
    enforces: a valid client and refresh token for the token endpoint, a valid access
    token for the API, and one mailbox per account.
    """

    READONLY = "https://www.googleapis.com/auth/gmail.readonly"
    SEND = "https://www.googleapis.com/auth/gmail.send"
    MODIFY = "https://www.googleapis.com/auth/gmail.modify"

    def __init__(self) -> None:
        import uvicorn
        from starlette.applications import Starlette
        from starlette.routing import Route

        self.accounts: dict[str, dict] = {}  # refresh token -> account
        self.access: dict[str, str] = {}  # access token -> refresh token
        self.requests: list[tuple[str, str]] = []
        self.token_requests = 0
        self.sent: list[bytes] = []
        self.send_status = 200
        self.change_status = 200
        self.labels = [{"id": "INBOX", "name": "INBOX", "type": "system"},
                       {"id": "Label_1", "name": "Receipts", "type": "user"},
                       {"id": "Label_2", "name": "Keep", "type": "user"}]
        self.consenting: str | None = None  # the account whose owner is "at the browser"
        self.codes: dict[str, str] = {}  # authorisation code -> refresh token
        app = Starlette(
            routes=[
                Route("/token", self._token, methods=["POST"]),
                Route("/auth", self._consent, methods=["GET"]),
                Route("/gmail/v1/users/me/profile", self._profile, methods=["GET"]),
                Route("/gmail/v1/users/me/history", self._history, methods=["GET"]),
                Route("/gmail/v1/users/me/labels", self._labels, methods=["GET"]),
                Route("/gmail/v1/users/me/messages/{message_id}/{operation}", self._change, methods=["POST"]),
                Route("/gmail/v1/users/me/messages/send", self._send, methods=["POST"]),
                Route("/gmail/v1/users/me/messages", self._list, methods=["GET"]),
                Route("/gmail/v1/users/me/messages/{message_id}", self._get, methods=["GET"]),
                Route("/{rest:path}", self._other, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]),
            ]
        )
        self.port = free_port()
        self._server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error"))
        threading.Thread(target=self._server.run, daemon=True).start()
        wait_for_port(self.port)
        self.base = f"http://127.0.0.1:{self.port}"

    def add_account(self, refresh_token: str, client_id: str, client_secret: str, scope: str | None = None) -> dict:
        account = {"client_id": client_id, "client_secret": client_secret, "scope": scope or self.READONLY,
                   "messages": {}, "revoked": False,
                   "history": [], "history_id": 1000, "oldest_history": 1000}  # fmt: skip
        self.accounts[refresh_token] = account
        return account

    def add_message(self, refresh_token: str, message_id: str, raw: bytes, labels: tuple[str, ...] = ("INBOX", "UNREAD"),
                    *, at: float | None = None) -> None:
        account = self.accounts[refresh_token]
        account["messages"][message_id] = {"raw": raw, "labels": list(labels), "date": time.time() if at is None else at}
        self._record(account, {"messagesAdded": [{"message": {"id": message_id, "threadId": message_id, "labelIds": list(labels)}}]})

    def add_label(self, refresh_token: str, message_id: str, label: str) -> None:
        account = self.accounts[refresh_token]
        message = account["messages"][message_id]
        message["labels"].append(label)
        self._record(account, {"labelsAdded": [{"message": {"id": message_id, "threadId": message_id, "labelIds": list(message["labels"])},
                                                "labelIds": [label]}]})

    def forget_history(self, refresh_token: str) -> None:
        """What Google does after about a week: older start points answer 404."""
        account = self.accounts[refresh_token]
        account["oldest_history"] = account["history_id"]

    @staticmethod
    def _record(account: dict, change: dict) -> None:
        account["history_id"] += 1
        account["history"].append({"id": str(account["history_id"]), **change})

    def expire_access_tokens(self) -> None:
        self.access.clear()

    def close(self) -> None:
        self._server.should_exit = True

    async def _token(self, request):  # type: ignore[no-untyped-def]
        from starlette.responses import JSONResponse

        self.token_requests += 1
        self.requests.append(("POST", "/token"))
        form = await request.form()
        if form.get("grant_type") == "authorization_code":
            import base64

            # The client's id and secret arrive in the form or as HTTP Basic; Google accepts both.
            client = (form.get("client_id"), form.get("client_secret"))
            basic = request.headers.get("authorization", "")
            if basic.startswith("Basic "):
                client = tuple(base64.b64decode(basic[6:]).decode().split(":", 1))
            refresh = self.codes.pop(str(form.get("code")), None)
            account = self.accounts.get(refresh or "")
            if account is None or client != (account["client_id"], account["client_secret"]) or not form.get("code_verifier"):
                return JSONResponse({"error": "invalid_grant"}, 400)
            return JSONResponse({"access_token": "ya29.first", "expires_in": 3599, "refresh_token": refresh,
                                 "scope": account["scope"], "token_type": "Bearer"})  # fmt: skip
        account = self.accounts.get(str(form.get("refresh_token")))
        if form.get("grant_type") != "refresh_token" or account is None or account["revoked"]:
            return JSONResponse({"error": "invalid_grant", "error_description": "Token has been expired or revoked."}, 400)
        if (form.get("client_id"), form.get("client_secret")) != (account["client_id"], account["client_secret"]):
            return JSONResponse({"error": "invalid_client"}, 401)
        import secrets as _secrets

        access = "ya29." + _secrets.token_urlsafe(24)
        self.access[access] = str(form.get("refresh_token"))
        return JSONResponse({"access_token": access, "expires_in": 3599, "scope": account["scope"], "token_type": "Bearer"})

    async def _consent(self, request):  # type: ignore[no-untyped-def]
        """Google's consent page, with the person pressing "Allow" at once."""
        import secrets as _secrets
        from urllib.parse import urlencode

        from starlette.responses import RedirectResponse

        query = request.query_params
        self.consent_request = dict(query)
        code = _secrets.token_urlsafe(16)
        self.codes[code] = self.consenting or ""
        return RedirectResponse(query["redirect_uri"] + "?" + urlencode({"state": query["state"], "code": code}), 302)

    def _account(self, request):  # type: ignore[no-untyped-def]
        self.requests.append((request.method, request.url.path))
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        return self.accounts.get(self.access.get(token, ""))

    async def _profile(self, request):
        from starlette.responses import JSONResponse

        account = self._account(request)
        if account is None:
            return JSONResponse({}, 401)
        return JSONResponse({"emailAddress": "mailbox@example.test", "historyId": str(account["history_id"])})

    async def _history(self, request):
        """users.history.list: messageAdded / labelAdded records after startHistoryId, paged."""
        from starlette.responses import JSONResponse

        account = self._account(request)
        if account is None:
            return JSONResponse({}, 401)
        query = request.query_params
        start = int(query["startHistoryId"])
        if start < account["oldest_history"]:
            return JSONResponse({"error": {"code": 404, "message": "Requested entity was not found."}}, 404)
        types = set(query.getlist("historyTypes")) or {"messageAdded", "labelAdded"}
        label = query.get("labelId")
        records = []
        for record in account["history"]:
            if int(record["id"]) <= start:
                continue
            kept = {"id": record["id"]}
            for kind, field in (("messageAdded", "messagesAdded"), ("labelAdded", "labelsAdded")):
                items = [item for item in record.get(field, []) if kind in types and (not label or label in item["message"]["labelIds"])]
                if items:
                    kept[field] = items
            if len(kept) > 1:
                records.append(kept)
        size, offset = int(query.get("maxResults", "100")), int(query.get("pageToken", "0"))
        out = {"historyId": str(account["history_id"])}
        if records[offset:offset + size]:
            out["history"] = records[offset:offset + size]
        if offset + size < len(records):
            out["nextPageToken"] = str(offset + size)
        return JSONResponse(out)

    async def _send(self, request):
        import base64

        from starlette.responses import JSONResponse

        account = self._account(request)
        if account is None or not {self.SEND, self.MODIFY}.intersection(account["scope"].split()):
            return JSONResponse({}, 403)
        body = await request.json()
        self.sent.append(base64.urlsafe_b64decode(body["raw"]))
        return JSONResponse({"id": "18c0f1"}, self.send_status)

    async def _labels(self, request):
        from starlette.responses import JSONResponse

        if self._account(request) is None:
            return JSONResponse({}, 401)
        return JSONResponse({"labels": self.labels})

    async def _change(self, request):
        from starlette.responses import JSONResponse

        account = self._account(request)
        if account is None or self.MODIFY not in account["scope"].split():
            return JSONResponse({}, 403)
        message_id = request.path_params["message_id"]
        message = account["messages"].get(message_id)
        if message is None:
            return JSONResponse({}, 404)
        labels = set(message["labels"])
        operation = request.path_params["operation"]
        if operation == "modify":
            body = await request.json()
            labels.update(body["addLabelIds"])
            labels.difference_update(body["removeLabelIds"])
        elif operation == "trash":
            assert not await request.body()
            labels.add("TRASH")
            labels.discard("INBOX")
        elif operation == "untrash":
            assert not await request.body()
            labels.discard("TRASH")
        else:
            return JSONResponse({}, 404)
        message["labels"] = sorted(labels)
        return JSONResponse({"id": message_id, "labelIds": message["labels"]}, self.change_status)

    async def _list(self, request):  # type: ignore[no-untyped-def]
        from starlette.responses import JSONResponse

        account = self._account(request)
        if account is None:
            return JSONResponse({"error": {"code": 401, "status": "UNAUTHENTICATED"}}, 401)
        words = request.query_params.get("q", "").lower().split()
        # `after:<epoch seconds>` compares the time the message arrived; other words match its text.
        after = max((int(word[6:]) for word in words if word.startswith("after:")), default=None)
        words = [word for word in words if not word.startswith("after:")]
        hits = []
        for message_id, message in sorted(account["messages"].items(), reverse=True):
            text = message["raw"].decode("utf-8", "replace").lower()
            if after is not None and message["date"] <= after:
                continue
            if all(word.split(":", 1)[-1] in text for word in words):
                hits.append({"id": message_id, "threadId": message_id})
        limit = int(request.query_params.get("maxResults", "100"))
        return JSONResponse({"messages": hits[:limit], "resultSizeEstimate": len(hits)} if hits else {"resultSizeEstimate": 0})

    async def _get(self, request):  # type: ignore[no-untyped-def]
        import base64
        from email import message_from_bytes

        from starlette.responses import JSONResponse

        account = self._account(request)
        if account is None:
            return JSONResponse({"error": {"code": 401, "status": "UNAUTHENTICATED"}}, 401)
        message_id = request.path_params["message_id"]
        message = account["messages"].get(message_id)
        if message is None:
            return JSONResponse({"error": {"code": 404, "message": "Requested entity was not found."}}, 404)
        out = {"id": message_id, "threadId": message_id, "labelIds": message["labels"], "sizeEstimate": len(message["raw"]),
               "snippet": "preview of " + message_id}  # fmt: skip
        kind = request.query_params.get("format", "full")
        if kind == "raw":
            out["raw"] = base64.urlsafe_b64encode(message["raw"]).decode("ascii")
        elif kind == "metadata":
            wanted = {name.lower() for name in request.query_params.getlist("metadataHeaders")}
            parsed = message_from_bytes(message["raw"])
            out["payload"] = {"headers": [{"name": k, "value": v} for k, v in parsed.items() if k.lower() in wanted]}
        return JSONResponse(out)

    async def _other(self, request):  # type: ignore[no-untyped-def]
        from starlette.responses import JSONResponse

        self.requests.append((request.method, request.url.path))
        return JSONResponse({"error": {"code": 404}}, 404)


class WebhookReceiver:
    """Stands in for an OpenBot webhook URL on localhost.

    It checks what OpenBot checks (an HMAC-SHA256 signature over timestamp, delivery
    id and body; a timestamp within 300 seconds) and treats a repeated delivery id as a
    duplicate (200). `statuses` lists answers to give first, such as 503 for "offline".
    """

    PATH = "/v1/webhooks/route-1"

    def __init__(self, secret: str) -> None:
        import uvicorn
        from starlette.applications import Starlette
        from starlette.routing import Route

        self.secret = secret.encode()
        self.statuses: list[int] = []
        self.attempts: list[tuple[str, int]] = []  # (delivery id, answer) for every request
        self.events: list[dict] = []  # bodies of accepted deliveries
        self.headers: list[dict[str, str]] = []
        self._accepted: set[str] = set()
        app = Starlette(routes=[Route(self.PATH, self._receive, methods=["POST"])])
        self.port = free_port()
        self._server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error"))
        threading.Thread(target=self._server.run, daemon=True).start()
        wait_for_port(self.port)
        self.url = f"http://127.0.0.1:{self.port}{self.PATH}"

    def close(self) -> None:
        self._server.should_exit = True

    async def _receive(self, request):  # type: ignore[no-untyped-def]
        import hashlib
        import hmac
        import json

        from starlette.responses import Response

        body = await request.body()
        stamp = request.headers.get("x-openbot-timestamp", "")
        delivery = request.headers.get("x-openbot-delivery-id", "")
        expected = "sha256=" + hmac.new(self.secret, f"{stamp}.{delivery}.".encode() + body, hashlib.sha256).hexdigest()
        if not stamp.isdecimal() or abs(time.time() - int(stamp)) > 300 or not hmac.compare_digest(
                expected, request.headers.get("x-openbot-signature", "")):
            status = 401
        elif self.statuses:
            status = self.statuses.pop(0)
        else:
            status = 200 if delivery in self._accepted else 202
        self.attempts.append((delivery, status))
        if status == 202:
            self._accepted.add(delivery)
            self.events.append(json.loads(body))
            self.headers.append(dict(request.headers))
        return Response(status_code=status)
