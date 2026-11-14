"""The IMAP mail connector behind the gateway, against a real IMAP server.

The server is pymap on localhost, reached through TLS as iCloud is. What these
tests cannot show is how Apple's server behaves (its search, its limits, its
errors): that needs a real account and is listed in docs/design.md.
"""

from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timezone
from email.message import EmailMessage

import pytest
from helpers import TOKEN_A, TOKEN_B, TOKEN_HOUSE, agent, base_config, prepare, running_gateway, text_of, tool_names
from imapclient import IMAPClient
from mcp import Client, MCPError, StdioServerParameters
from mcp.client.stdio import stdio_client
from service_helpers import MailAccount, mail_account

pytestmark = pytest.mark.anyio

PASSWORD_A = "app-specific-AAAA-aaaa-bbbb-cccc"
PASSWORD_B = "app-specific-BBBB-dddd-eeee-ffff"
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
PDF = b"%PDF-1.4\n" + bytes(range(256)) * 4
LONG = "\n".join(f"line {n}: the quick brown fox" for n in range(3000))


def message(subject: str, sender: str, to: str, body: str = "", **headers: str) -> EmailMessage:
    out = EmailMessage()
    out["Subject"], out["From"], out["To"] = subject, sender, to
    out["Date"] = "Tue, 03 Nov 2026 09:30:00 +0000"
    out["Message-ID"] = f"<{abs(hash(subject))}@example.com>"
    for name, value in headers.items():
        out[name.replace("_", "-")] = value
    out.set_content(body)
    return out


def fill(account: MailAccount, *messages: EmailMessage) -> None:
    with IMAPClient("127.0.0.1", account.plain_port, ssl=False) as client:
        client.login(account.user, account.password)
        for item in messages:
            client.append("INBOX", item.as_bytes(), flags=(), msg_time=datetime(2026, 11, 3, 9, 30, tzinfo=timezone.utc))


def flags_of(account: MailAccount, subject: str) -> tuple[bytes, ...]:
    with IMAPClient("127.0.0.1", account.plain_port, ssl=False) as client:
        client.login(account.user, account.password)
        client.select_folder("INBOX", readonly=True)
        uids = client.search(["SUBJECT", subject])
        return client.fetch(uids, ["FLAGS"])[uids[0]][b"FLAGS"]


@pytest.fixture(scope="module")
def accounts(tmp_path_factory):
    root = tmp_path_factory.mktemp("mail")
    with mail_account(root / "a", "person.a@icloud.example", PASSWORD_A) as a:
        with mail_account(root / "b", "person.b@icloud.example", PASSWORD_B) as b:
            invoice = message("Invoice 2026-11 from the dentist", "Billing <billing@dentist.example>", "person.a@icloud.example", "Amount due: 120.00\nThank you.")
            invoice.add_attachment(b"date,amount\n2026-11-01,120.00\n", maintype="text", subtype="csv", filename="invoice.csv")
            invoice.add_attachment(PNG, maintype="image", subtype="png", filename="stamp.png")
            invoice.add_attachment(PDF, maintype="application", subtype="pdf", filename="invoice.pdf")
            newsletter = message("Weekly newsletter", "news@shop.example", "person.a@icloud.example")
            newsletter.set_content(
                "<html><head><style>p{color:red}</style><title>t</title></head><body><p>Autumn <b>sale</b> starts now.</p>"
                "<script>steal()</script><p>See <a href='https://shop.example/sale?id=1'>the offers</a>.</p></body></html>",
                subtype="html",
            )
            relay = message(
                "Your order has shipped", "Shop <orders_at_shop_example_abc123@privaterelay.appleid.com>",
                "k3xq9zt2vm@privaterelay.appleid.com", "Parcel 42 is on its way.",
                Delivered_To="person.a@icloud.example", Reply_To="orders@shop.example",
            )  # fmt: skip
            chinese = message("体检报告已出", "医院 <report@hospital.example>", "person.a@icloud.example", "您的体检报告已经生成，请登录查看。")
            fill(a, invoice, newsletter, relay, chinese, message("A very long letter", "friend@example.com", "person.a@icloud.example", LONG))
            fill(b, message("Private to B: salary review", "hr@employer.example", "person.b@icloud.example", "B's confidential letter."))
            yield a, b


def mail_connection(conn_id: str, owner: str, account: MailAccount, secret: str, prefix: str, **env: str) -> dict:
    return {
        "id": conn_id,
        "service": "icloud-mail",
        "account": owner,
        "owner": owner,
        "transport": "stdio",
        "command": [sys.executable, "-m", "agent_gateway.connectors.imap_mail"],
        "env": {
            "IMAP_HOST": "localhost",
            "IMAP_PORT": str(account.front.port),
            "IMAP_USERNAME": account.user,
            "SSL_CERT_FILE": str(account.cert),  # trust the test server's certificate
            **env,
        },
        "secret_env": {"IMAP_PASSWORD": secret},
        "timeout_seconds": 20,
        "tools": [
            {"upstream": name, "name": f"{prefix}_mail_{name}"}
            for name in ("list_mailboxes", "search_messages", "get_message", "get_attachment")
        ],
    }


TOOLS = ["list_mailboxes", "search_messages", "get_message", "get_attachment"]
SECRETS = {"mail_a": PASSWORD_A, "mail_b": PASSWORD_B}


def config(a: MailAccount, b: MailAccount, **env_a: str) -> dict:
    raw = base_config()
    raw["connections"] = [mail_connection("mail-a", "person_a", a, "mail_a", "a", **env_a), mail_connection("mail-b", "person_b", b, "mail_b", "b")]
    raw["policy"] = [
        {"principals": ["person_a"], "connection": "mail-a", "tools": [f"a_mail_{t}" for t in TOOLS], "effect": "allow"},
        {"principals": ["person_b"], "connection": "mail-b", "tools": [f"b_mail_{t}" for t in TOOLS], "effect": "allow"},
    ]
    return raw


async def call(client, tool: str, **arguments):
    return await client.call_tool(tool, arguments)


async def found(client, tool: str = "a_mail_search_messages", **arguments) -> dict:
    result = await call(client, tool, **arguments)
    assert not result.is_error, text_of(result)
    return json.loads(text_of(result))


async def test_search_and_read_real_mail(accounts, tmp_path):
    a, b = accounts
    async with running_gateway(await prepare(tmp_path, config(a, b), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as client:
            boxes = json.loads(text_of(await call(client, "a_mail_list_mailboxes")))
            assert {"INBOX", "Sent", "Trash"} <= {box["name"] for box in boxes}

            hits = await found(client, subject="Invoice")
            assert hits["matches"] == 1 and hits["messages"][0]["from"] == "Billing <billing@dentist.example>"
            invoice = hits["messages"][0]
            assert invoice["subject"] == "Invoice 2026-11 from the dentist" and invoice["date"] == "2026-11-03T09:30:00+00:00"
            assert "body" not in invoice and "Amount due" not in json.dumps(hits)  # a search returns headers only

            assert (await found(client, **{"from": "dentist.example"}))["matches"] == 1
            assert (await found(client, text="Amount due"))["matches"] == 1
            assert (await found(client, subject="Invoice", since="2026-11-03", before="2026-11-04"))["matches"] == 1
            assert (await found(client, subject="Invoice", since="2026-11-04"))["matches"] == 0
            assert (await found(client, subject="no such subject anywhere"))["messages"] == []
            assert (await found(client, subject="体检"))["messages"][0]["from"] == "医院 <report@hospital.example>"
            everything = await found(client, limit=3)
            assert everything["matches"] >= 5 and everything["returned"] == 3
            uids = [m["uid"] for m in everything["messages"]]
            assert uids == sorted(uids, reverse=True)  # newest first
            assert (await found(client, mailbox="Sent"))["mailbox"] == "Sent"

            read = await call(client, "a_mail_get_message", uid=invoice["uid"])
            about, body = json.loads(read.content[0].text), read.content[1].text
            assert body.strip() == "Amount due: 120.00\nThank you."
            assert (about["to"], about["truncated"], about["body_chars"]) == ("person.a@icloud.example", False, len(body))
            assert [(x["index"], x["filename"], x["content_type"], x["size"]) for x in about["attachments"]] == [
                (0, "invoice.csv", "text/csv", 30),
                (1, "stamp.png", "image/png", len(PNG)),
                (2, "invoice.pdf", "application/pdf", len(PDF)),
            ]


async def test_bodies_html_long_messages_and_relay_addresses(accounts, tmp_path):
    a, b = accounts
    async with running_gateway(await prepare(tmp_path, config(a, b), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as client:
            uid = (await found(client, subject="Weekly newsletter"))["messages"][0]["uid"]
            text = (await call(client, "a_mail_get_message", uid=uid)).content[1].text
            assert text == "Autumn sale starts now.\n\nSee the offers (https://shop.example/sale?id=1)."
            html = (await call(client, "a_mail_get_message", uid=uid, format="html")).content[1].text
            assert "<script>steal()</script>" in html  # the original, when asked for

            # A long body comes in pieces, and all of it can be read.
            uid = (await found(client, subject="A very long letter"))["messages"][0]["uid"]
            first = await call(client, "a_mail_get_message", uid=uid)
            about = json.loads(first.content[0].text)
            assert about["truncated"] and about["body_chars"] >= len(LONG) and len(first.content[1].text) == 20_000
            pieces, offset = [], 0
            while offset < about["body_chars"]:
                piece = await call(client, "a_mail_get_message", uid=uid, offset=offset, max_chars=50_000)
                pieces.append(piece.content[1].text)
                offset += 50_000
            assert "".join(pieces).strip() == LONG

            # Mail that arrived through an Apple relay address: found by that address, and shown with it.
            hits = await found(client, to="k3xq9zt2vm@privaterelay.appleid.com")
            assert hits["matches"] == 1
            relay = hits["messages"][0]
            assert relay["to"] == "k3xq9zt2vm@privaterelay.appleid.com" and relay["delivered_to"] == "person.a@icloud.example"
            assert relay["reply_to"] == "orders@shop.example" and "privaterelay.appleid.com" in relay["from"]


async def test_attachments(accounts, tmp_path):
    a, b = accounts
    async with running_gateway(await prepare(tmp_path, config(a, b, IMAP_MAX_ATTACHMENT_BYTES="800"), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as client:
            uid = (await found(client, subject="Invoice"))["messages"][0]["uid"]
            csv = await call(client, "a_mail_get_attachment", uid=uid, index=0)
            assert json.loads(csv.content[0].text) == {"filename": "invoice.csv", "content_type": "text/csv", "size": 30}
            assert csv.content[1].text == "date,amount\n2026-11-01,120.00\n"
            image = await call(client, "a_mail_get_attachment", uid=uid, index=1)
            assert (image.content[1].type, image.content[1].mime_type) == ("image", "image/png")
            assert base64.b64decode(image.content[1].data) == PNG
            too_big = await call(client, "a_mail_get_attachment", uid=uid, index=2)
            assert too_big.is_error and "limit is 800" in text_of(too_big)
            missing = await call(client, "a_mail_get_attachment", uid=uid, index=7)
            assert missing.is_error and text_of(missing) == "No such attachment."
            gone = await call(client, "a_mail_get_message", uid=999_999)
            assert gone.is_error and text_of(gone) == "No such message."
            nowhere = await call(client, "a_mail_search_messages", mailbox="No such box")
            assert nowhere.is_error and "refused" in text_of(nowhere)
    async with running_gateway(await prepare(tmp_path / "big", config(a, b), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as client:
            pdf = await call(client, "a_mail_get_attachment", uid=uid, index=2)
            resource = pdf.content[1].resource
            assert (pdf.content[1].type, resource.mime_type) == ("resource", "application/pdf")
            assert base64.b64decode(resource.blob) == PDF


async def test_each_person_reaches_only_their_own_mailbox(accounts, tmp_path):
    a, b = accounts
    async with running_gateway(await prepare(tmp_path, config(a, b), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as as_a, agent(gw.url, TOKEN_B) as as_b, agent(gw.url, TOKEN_HOUSE) as shared:
            assert await tool_names(as_a) == {f"a_mail_{t}" for t in TOOLS}
            assert await tool_names(as_b) == {f"b_mail_{t}" for t in TOOLS}
            assert await tool_names(shared) == set()  # a shared agent gets no personal mailbox

            assert (await found(as_a, subject="salary review"))["matches"] == 0
            mine = await found(as_b, "b_mail_search_messages", subject="salary review")
            assert mine["matches"] == 1
            assert (await found(as_b, "b_mail_search_messages", subject="Invoice"))["matches"] == 0

            for client, other in ((as_a, "b_mail_search_messages"), (as_b, "a_mail_get_message"), (shared, "a_mail_search_messages")):
                with pytest.raises(MCPError):
                    await client.call_tool(other, {"uid": 1})
            # No argument selects an account: there is none to pass.
            for extra in ({"account": "person_b"}, {"user": "person.b@icloud.example"}, {"username": "person.b@icloud.example"}):
                assert (await as_a.call_tool("a_mail_search_messages", {"subject": "salary", **extra})).is_error

        log = gw.audit_text()
        for private in ("salary", "Invoice", "dentist", PASSWORD_A, PASSWORD_B, "person.a@icloud.example"):
            assert private not in log, private


async def test_nothing_is_written_to_the_mailbox(accounts, tmp_path):
    a, b = accounts
    assert b"\\Seen" not in flags_of(a, "Your order has shipped")
    a.front.commands.clear()
    async with running_gateway(await prepare(tmp_path, config(a, b), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as client:
            await call(client, "a_mail_list_mailboxes")
            uid = (await found(client, subject="Your order has shipped", unseen=True))["messages"][0]["uid"]
            for _ in range(2):
                read = await call(client, "a_mail_get_message", uid=uid)
                assert "Parcel 42" in read.content[1].text
                assert "\\Seen" not in json.loads(read.content[0].text)["flags"]
            uid = (await found(client, subject="Invoice"))["messages"][0]["uid"]
            await call(client, "a_mail_get_attachment", uid=uid, index=0)
            assert (await found(client, subject="Your order has shipped", unseen=True))["matches"] == 1
    assert b"\\Seen" not in flags_of(a, "Your order has shipped")  # reading did not mark it as read
    # Everything the connector sent, by command name. EXAMINE is the read-only form of SELECT.
    assert set(a.front.commands) <= {"CAPABILITY", "LOGIN", "LIST", "EXAMINE", "SEARCH", "FETCH", "NOOP", "LOGOUT"}
    assert {"LOGIN", "EXAMINE", "SEARCH", "FETCH"} <= set(a.front.commands)


async def test_a_dropped_connection_is_reopened(accounts, tmp_path):
    a, b = accounts
    async with running_gateway(await prepare(tmp_path, config(a, b), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as client:
            assert (await found(client, subject="Invoice"))["matches"] == 1
            before = a.front.connections
            for _ in range(2):
                a.front.drop_connections()  # the server went away between two calls
                assert (await found(client, subject="Invoice"))["matches"] == 1
            assert a.front.connections == before + 2
            assert (await found(client, subject="Invoice"))["matches"] == 1
            assert a.front.connections == before + 2  # and the connection is kept between calls


async def test_a_refused_password_and_an_unreachable_or_untrusted_server(accounts, tmp_path):
    a, b = accounts
    wrong = {"mail_a": "app-specific-REVOKED-0000-0000", "mail_b": PASSWORD_B}
    async with running_gateway(await prepare(tmp_path / "wrong", config(a, b), secrets=wrong)) as gw:
        async with agent(gw.url, TOKEN_A) as as_a, agent(gw.url, TOKEN_B) as as_b:
            before = a.front.connections
            for _ in range(3):
                refused = await call(as_a, "a_mail_search_messages", subject="Invoice")
                assert refused.is_error and "rejected this account's credentials" in text_of(refused)
                assert "REVOKED" not in text_of(refused)
            assert a.front.connections == before + 1  # it does not keep trying a password that was refused
            # The other person's mailbox is unaffected.
            assert (await found(as_b, "b_mail_search_messages", subject="salary review"))["matches"] == 1
        assert "REVOKED" not in gw.audit_text()

    # The server presents a certificate this machine does not trust: no connection, and no plaintext fallback.
    untrusted = config(a, b)
    del untrusted["connections"][0]["env"]["SSL_CERT_FILE"]
    a.front.commands.clear()
    async with running_gateway(await prepare(tmp_path / "untrusted", untrusted, secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as client:
            failed = await call(client, "a_mail_search_messages", subject="Invoice")
            assert failed.is_error and "could not be reached" in text_of(failed)
    assert "LOGIN" not in a.front.commands  # the password was never sent

    # Nothing is listening at all.
    dead = config(a, b)
    dead["connections"][0]["env"]["IMAP_PORT"] = "1"
    async with running_gateway(await prepare(tmp_path / "dead", dead, secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as client:
            failed = await call(client, "a_mail_search_messages", subject="Invoice")
            assert failed.is_error and "could not be reached" in text_of(failed)


async def test_the_connector_refuses_what_could_break_out_of_a_command(accounts):
    """Called directly, without the gateway in front: the connector checks its own input."""
    a, _ = accounts
    env = {"IMAP_HOST": "localhost", "IMAP_PORT": str(a.front.port), "IMAP_USERNAME": a.user,
           "IMAP_PASSWORD": PASSWORD_A, "SSL_CERT_FILE": str(a.cert)}  # fmt: skip
    params = StdioServerParameters(command=sys.executable, args=["-m", "agent_gateway.connectors.imap_mail"], env=env)
    a.front.commands.clear()
    async with Client(stdio_client(params), cache=None) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        assert set(tools) == set(TOOLS)
        for tool in tools.values():
            assert tool.annotations.read_only_hint and tool.input_schema["additionalProperties"] is False
            # No tool takes an account, a user or a credential.
            assert not {"account", "user", "username", "password", "host"} & set(tool.input_schema["properties"])
        for arguments in (
            {"subject": 'x"\r\nA1 DELETE INBOX'},
            {"subject": "x\nA1 LOGOUT"},
            {"mailbox": "INBOX\r\nA1 DELETE INBOX"},
            {"from": "a\x00b"},
            {"since": "2026-11-03 OR ALL"},
            {"limit": 100_000},
            {"password": "x"},
        ):
            refused = await client.call_tool("search_messages", arguments)
            assert refused.is_error, arguments
        assert (await client.call_tool("get_message", {"uid": 1, "mailbox": "INBOX\r\nA1 DELETE INBOX"})).is_error
        # Characters that are special in IMAP but harmless inside a quoted string still work.
        ok = await client.call_tool("search_messages", {"subject": 'Invoice "2026-11" \\ (dentist)'})
        assert not ok.is_error and json.loads(text_of(ok))["matches"] == 0
    assert "DELETE" not in a.front.commands and set(a.front.commands) <= {"CAPABILITY", "LOGIN", "EXAMINE", "SEARCH", "FETCH", "LOGOUT", "NOOP"}


def test_without_a_credential_the_connector_does_not_start():
    import subprocess

    done = subprocess.run(
        [sys.executable, "-m", "agent_gateway.connectors.imap_mail"],
        env={"IMAP_USERNAME": "someone@icloud.example", "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
    )  # fmt: skip
    assert done.returncode != 0 and "IMAP_PASSWORD is not set" in done.stderr
