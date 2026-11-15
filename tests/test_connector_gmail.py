"""The Gmail connector behind the gateway, against a stand-in for Google.

`FakeGoogle` is not Google: it answers with the documented shapes of the token
endpoint and the Gmail API. These tests show how the connector uses them and how
it reacts to expiry, revocation and a token with too much permission. They do not
show that a real Google account works; that takes a real OAuth client and consent.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

import httpx2
import pytest
from helpers import TOKEN_A, TOKEN_B, TOKEN_HOUSE, agent, base_config, prepare, running_gateway, text_of, tool_names
from mcp import Client, MCPError, StdioServerParameters
from mcp.client.stdio import stdio_client
from service_helpers import FakeGoogle, localhost_process

pytestmark = pytest.mark.anyio

CLIENT_ID = "1234567890-testclient.apps.googleusercontent.com"
CLIENT_SECRET = "GOCSPX-test-client-secret-000000"
REFRESH_A = "1//refresh-token-of-person-a-aaaaaaaaaaaaaaaa"
REFRESH_B = "1//refresh-token-of-person-b-bbbbbbbbbbbbbbbb"
TOOLS = ["search_messages", "get_message", "get_attachment"]
SECRETS = {"gmail_client_secret": CLIENT_SECRET, "gmail_token_a": REFRESH_A, "gmail_token_b": REFRESH_B}
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")


def message(subject: str, sender: str, to: str, body: str) -> EmailMessage:
    out = EmailMessage()
    out["Subject"], out["From"], out["To"] = subject, sender, to
    out["Date"] = "Tue, 03 Nov 2026 09:30:00 +0000"
    out.set_content(body)
    return out


@pytest.fixture(scope="module")
def google():
    fake = FakeGoogle()
    fake.add_account(REFRESH_A, CLIENT_ID, CLIENT_SECRET)
    fake.add_account(REFRESH_B, CLIENT_ID, CLIENT_SECRET)
    order = message("Your Amazon order has shipped", "Amazon <ship-confirm@amazon.example>", "person.a@gmail.example", "Order 111-222 arrives Friday.")
    order.add_attachment(b"item,qty\nkettle,1\n", maintype="text", subtype="csv", filename="order.csv")
    order.add_attachment(PNG, maintype="image", subtype="png", filename="label.png")
    fake.add_message(REFRESH_A, "18c0a1", order.as_bytes())
    fake.add_message(REFRESH_A, "18c0a2", message("电费账单", "电力公司 <bill@power.example>", "person.a@gmail.example", "本月电费 88.50 元。").as_bytes(), ("INBOX",))
    fake.add_message(REFRESH_B, "18c0b1", message("B's lab results", "clinic@clinic.example", "person.b@gmail.example", "Confidential results for B.").as_bytes())
    yield fake
    fake.close()


def gmail_connection(conn_id: str, owner: str, google: FakeGoogle, token_secret: str, prefix: str) -> dict:
    return {
        "id": conn_id,
        "service": "gmail",
        "account": owner,
        "owner": owner,
        "transport": "stdio",
        "command": [sys.executable, "-m", "agent_gateway.connectors.gmail"],
        "env": {"GMAIL_CLIENT_ID": CLIENT_ID, "GMAIL_API_BASE": google.base, "GMAIL_TOKEN_URL": f"{google.base}/token"},
        "secret_env": {"GMAIL_CLIENT_SECRET": "gmail_client_secret", "GMAIL_REFRESH_TOKEN": token_secret},
        "timeout_seconds": 20,
        "tools": [{"upstream": name, "name": f"{prefix}_gmail_{name}"} for name in TOOLS],
    }


def config(google: FakeGoogle) -> dict:
    raw = base_config()
    raw["connections"] = [gmail_connection("gmail-a", "person_a", google, "gmail_token_a", "a"), gmail_connection("gmail-b", "person_b", google, "gmail_token_b", "b")]
    raw["policy"] = [
        {"principals": ["person_a"], "connection": "gmail-a", "tools": [f"a_gmail_{t}" for t in TOOLS], "effect": "allow"},
        {"principals": ["person_b"], "connection": "gmail-b", "tools": [f"b_gmail_{t}" for t in TOOLS], "effect": "allow"},
    ]
    return raw


async def ask(client, tool: str, **arguments):
    result = await client.call_tool(tool, arguments)
    assert not result.is_error, text_of(result)
    return result


async def test_search_read_and_attachments(google, tmp_path):
    async with running_gateway(await prepare(tmp_path, config(google), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            hits = json.loads(text_of(await ask(a, "a_gmail_search_messages", query="from:amazon")))
            assert (hits["estimated_matches"], hits["returned"]) == (1, 1)
            found = hits["messages"][0]
            assert (found["id"], found["subject"], found["from"]) == ("18c0a1", "Your Amazon order has shipped", "Amazon <ship-confirm@amazon.example>")
            assert found["date"] == "2026-11-03T09:30:00+00:00" and found["labels"] == ["INBOX", "UNREAD"] and "snippet" in found
            assert "arrives Friday" not in json.dumps(hits)  # no body in a search result

            recent = json.loads(text_of(await ask(a, "a_gmail_search_messages", limit=1)))
            assert [m["id"] for m in recent["messages"]] == ["18c0a2"] and recent["messages"][0]["subject"] == "电费账单"
            assert json.loads(text_of(await ask(a, "a_gmail_search_messages", query="nothing-matches-this")))["messages"] == []

            read = await ask(a, "a_gmail_get_message", id="18c0a1")
            about = json.loads(read.content[0].text)
            assert read.content[1].text.strip() == "Order 111-222 arrives Friday."
            assert (about["to"], about["truncated"]) == ("person.a@gmail.example", False)
            assert [(x["index"], x["filename"], x["content_type"]) for x in about["attachments"]] == [(0, "order.csv", "text/csv"), (1, "label.png", "image/png")]
            assert (await ask(a, "a_gmail_get_message", id="18c0a2")).content[1].text.strip() == "本月电费 88.50 元。"

            csv = await ask(a, "a_gmail_get_attachment", id="18c0a1", index=0)
            assert csv.content[1].text == "item,qty\nkettle,1\n"
            image = await ask(a, "a_gmail_get_attachment", id="18c0a1", index=1)
            assert image.content[1].type == "image" and base64.b64decode(image.content[1].data) == PNG

            missing = await a.call_tool("a_gmail_get_message", {"id": "deadbeef"})
            assert missing.is_error and text_of(missing) == "No such message."
            assert (await a.call_tool("a_gmail_get_message", {"id": "../../../other/path"})).is_error
            assert (await a.call_tool("a_gmail_get_attachment", {"id": "18c0a1", "index": 9})).is_error


async def test_each_person_reaches_only_their_own_account(google, tmp_path):
    async with running_gateway(await prepare(tmp_path, config(google), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as a, agent(gw.url, TOKEN_B) as b, agent(gw.url, TOKEN_HOUSE) as shared:
            assert await tool_names(a) == {f"a_gmail_{t}" for t in TOOLS} and await tool_names(shared) == set()
            assert json.loads(text_of(await ask(b, "b_gmail_search_messages", query="clinic")))["messages"][0]["id"] == "18c0b1"
            assert json.loads(text_of(await ask(a, "a_gmail_search_messages", query="clinic")))["messages"] == []
            # B's message id, asked for through A's account, does not exist there.
            assert text_of(await a.call_tool("a_gmail_get_message", {"id": "18c0b1"})) == "No such message."
            with pytest.raises(MCPError):
                await a.call_tool("b_gmail_get_message", {"id": "18c0b1"})
            for extra in ({"user": "person.b@gmail.example"}, {"userId": "person.b@gmail.example"}, {"account": "person_b"}):
                assert (await a.call_tool("a_gmail_search_messages", {"query": "clinic", **extra})).is_error
        log = gw.audit_text()
        for private in ("clinic", "Amazon", "Confidential", REFRESH_A, REFRESH_B, CLIENT_SECRET, "ya29."):
            assert private not in log, private


async def test_token_refresh_revocation_and_scope(google, tmp_path):
    google.requests.clear()
    async with running_gateway(await prepare(tmp_path / "ok", config(google), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            before = google.token_requests
            for _ in range(3):
                await ask(a, "a_gmail_search_messages", query="amazon")
            assert google.token_requests == before + 1  # one access token, reused
            google.expire_access_tokens()  # Google ends the access token early
            await ask(a, "a_gmail_get_message", id="18c0a1")
            assert google.token_requests == before + 2  # refreshed once, and the call went through

            # Everything sent to Google: reads of messages, and token refreshes.
            assert {method for method, path in google.requests if path != "/token"} == {"GET"}
            assert all(path == "/token" or path.startswith("/gmail/v1/users/me/messages") for _, path in google.requests)

            # The person revokes access (or a "Testing" consent runs out after 7 days).
            google.accounts[REFRESH_A]["revoked"] = True
            google.expire_access_tokens()
            try:
                before = google.token_requests
                for _ in range(3):
                    gone = await a.call_tool("a_gmail_search_messages", {"query": "amazon"})
                    assert gone.is_error and "expired or was revoked" in text_of(gone)
                    for secret in (REFRESH_A, CLIENT_SECRET):
                        assert secret not in text_of(gone)
                assert google.token_requests == before + 1  # it does not keep presenting a revoked token
            finally:
                google.accounts[REFRESH_A]["revoked"] = False

    # A token that can do more than read mail is refused, even though it would work.
    broad = "1//refresh-token-with-full-mail-access-cccccccc"
    google.add_account(broad, CLIENT_ID, CLIENT_SECRET, scope="https://mail.google.com/")
    google.add_message(broad, "18c0c1", message("x", "a@example.com", "b@example.com", "y").as_bytes())
    for index, scope in enumerate(("https://mail.google.com/", FakeGoogle.READONLY + " https://www.googleapis.com/auth/gmail.send", "")):
        google.accounts[broad]["scope"] = scope
        directory = tmp_path / f"broad{index}"
        async with running_gateway(await prepare(directory, config(google), secrets={**SECRETS, "gmail_token_a": broad})) as gw:
            async with agent(gw.url, TOKEN_A) as a:
                refused = await a.call_tool("a_gmail_search_messages", {})
                assert refused.is_error and "allows more than reading mail" in text_of(refused), scope

    # Google is unreachable.
    dead = config(google)
    dead["connections"][0]["env"].update({"GMAIL_API_BASE": "http://127.0.0.1:1", "GMAIL_TOKEN_URL": "http://127.0.0.1:1/token"})
    async with running_gateway(await prepare(tmp_path / "dead", dead, secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            failed = await a.call_tool("a_gmail_search_messages", {})
            assert failed.is_error and text_of(failed) == "Google could not be reached."


async def test_the_connector_checks_its_own_input_and_settings(google):
    env = {"GMAIL_CLIENT_ID": CLIENT_ID, "GMAIL_CLIENT_SECRET": CLIENT_SECRET, "GMAIL_REFRESH_TOKEN": REFRESH_A,
           "GMAIL_API_BASE": google.base, "GMAIL_TOKEN_URL": f"{google.base}/token"}  # fmt: skip
    params = StdioServerParameters(command=sys.executable, args=["-m", "agent_gateway.connectors.gmail"], env=env)
    google.requests.clear()
    async with Client(stdio_client(params), cache=None) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        assert set(tools) == set(TOOLS) | {"list_labels"}
        for tool in tools.values():
            assert tool.annotations.read_only_hint and tool.input_schema["additionalProperties"] is False
            assert not {"account", "user", "userId", "token", "url"} & set(tool.input_schema["properties"])
        for tool, arguments in (
            ("get_message", {"id": "18c0a1/../../18c0b1"}),
            ("get_message", {"id": "18c0a1?format=full"}),
            ("get_message", {"id": "me/messages/18c0b1"}),
            ("get_message", {"id": ""}),
            ("search_messages", {"query": "a\r\nHost: evil.example"}),
            ("search_messages", {"limit": 500}),
            ("search_messages", {"userId": "someone-else"}),
        ):
            assert (await client.call_tool(tool, arguments)).is_error, arguments
    assert all(path == "/token" or path.startswith("/gmail/v1/users/me/messages") for _, path in google.requests)

    for bad, message_text in (
        ({"GMAIL_TOKEN_URL": "http://oauth2.example.com/token"}, "GMAIL_TOKEN_URL must be https"),
        ({"GMAIL_API_BASE": "http://gmail.example.com"}, "GMAIL_API_BASE must be https"),
        ({"GMAIL_REFRESH_TOKEN": ""}, "GMAIL_REFRESH_TOKEN is not set"),
    ):
        done = subprocess.run(
            [sys.executable, "-m", "agent_gateway.connectors.gmail"], env={**env, **bad, "PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
        )  # fmt: skip
        assert done.returncode != 0 and message_text in done.stderr, bad
        assert REFRESH_A not in done.stderr and CLIENT_SECRET not in done.stderr


def test_the_consent_helper_hands_over_a_read_only_token_and_nothing_else(google, tmp_path):
    """`gmail_auth` with Google's real client library, against the stand-in consent page."""
    client_file = tmp_path / "client_secret.json"
    client_file.write_text(json.dumps({"installed": {
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "redirect_uris": ["http://localhost"],
        "auth_uri": f"{google.base}/auth", "token_uri": f"{google.base}/token"}}))  # fmt: skip

    def consent(refresh_token: str) -> subprocess.CompletedProcess:
        google.consenting = refresh_token
        process = subprocess.Popen(
            [*localhost_process("agent_gateway.connectors.gmail_auth"), str(client_file), "--no-browser"],
            # The stand-in is plain http on localhost; Google's library needs to be told that is intended.
            env={"PATH": "/usr/bin:/bin", "OAUTHLIB_INSECURE_TRANSPORT": "1"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True,
        )  # fmt: skip
        shown = ""
        while "/auth?" not in shown:  # the address a person would open in their browser
            line = process.stderr.readline()
            assert line, shown
            shown += line
        address = next(word for word in shown.split() if "/auth?" in word)
        assert httpx2.get(address, follow_redirects=True, trust_env=False, timeout=20).status_code == 200
        out, err = process.communicate(timeout=30)
        return subprocess.CompletedProcess(process.args, process.returncode, out, shown + err)

    done = consent(REFRESH_A)
    assert done.returncode == 0, done.stderr
    assert done.stdout == REFRESH_A + "\n"  # the token, and only the token, on standard output
    assert REFRESH_A not in done.stderr and CLIENT_SECRET not in done.stderr and CLIENT_ID in done.stderr
    asked = google.consent_request
    assert asked["scope"] == FakeGoogle.READONLY and asked["access_type"] == "offline" and asked["response_type"] == "code"

    # Google grants something broader than was asked for: no token is handed over.
    broad = "1//refresh-token-from-a-broader-consent-dddddddd"
    google.add_account(broad, CLIENT_ID, CLIENT_SECRET, scope="https://mail.google.com/")
    refused = consent(broad)
    assert refused.returncode != 0 and refused.stdout == "" and broad not in refused.stderr


async def test_gmail_send_uses_the_mailbox_and_never_retries_an_uncertain_submission():
    google = FakeGoogle()
    account = google.add_account(REFRESH_A, CLIENT_ID, CLIENT_SECRET, scope=f"{FakeGoogle.READONLY} {FakeGoogle.SEND}")
    env = {"GMAIL_CLIENT_ID": CLIENT_ID, "GMAIL_CLIENT_SECRET": CLIENT_SECRET, "GMAIL_REFRESH_TOKEN": REFRESH_A,
           "GMAIL_API_BASE": google.base, "GMAIL_TOKEN_URL": f"{google.base}/token", "GMAIL_ACCESS": "read_send"}
    params = StdioServerParameters(command=sys.executable, args=["-m", "agent_gateway.connectors.gmail"], env=env)
    try:
        async with Client(stdio_client(params), cache=None) as client:
            send = next(tool for tool in (await client.list_tools()).tools if tool.name == "send_message")
            assert send.annotations.read_only_hint is False
            args = {"to": ["to@example.test"], "bcc": ["bcc@example.test"], "subject": "模拟邮件", "text": "Only the fake provider sees this."}
            reply = await ask(client, 'send_message', **args)
            assert json.loads(text_of(reply)) == {"id": "18c0f1", "status": "accepted"}
            sent = BytesParser(policy=policy.default).parsebytes(google.sent[0])
            assert str(sent["From"]) == "mailbox@example.test"
            assert str(sent["Bcc"]) == "bcc@example.test"
            assert str(sent["Subject"]) == args["subject"]
            assert sent.get_content().strip() == args["text"]
            google.send_status = 503
            reply = await client.call_tool("send_message", args)
            assert reply.is_error and "Check Sent before retrying" in text_of(reply)
            assert len(google.sent) == 2

        account["scope"] = FakeGoogle.READONLY
        async with Client(stdio_client(params), cache=None) as client:
            missing_scope = await client.call_tool("send_message", args)
            assert missing_scope.is_error and "different scope" in text_of(missing_scope)
            assert len(google.sent) == 2
    finally:
        google.close()


async def test_gmail_organize_preserves_unrelated_labels_and_reports_each_message():
    google = FakeGoogle()
    account = google.add_account(REFRESH_A, CLIENT_ID, CLIENT_SECRET, scope=FakeGoogle.MODIFY)
    raw = message("Example", "a@example.test", "b@example.test", "Synthetic only.").as_bytes()
    google.add_message(REFRESH_A, "a1", raw, ("INBOX", "UNREAD", "Label_2", "IMPORTANT"))
    google.add_message(REFRESH_A, "a2", raw, ("UNREAD",))
    env = {"GMAIL_CLIENT_ID": CLIENT_ID, "GMAIL_CLIENT_SECRET": CLIENT_SECRET, "GMAIL_REFRESH_TOKEN": REFRESH_A,
           "GMAIL_API_BASE": google.base, "GMAIL_TOKEN_URL": f"{google.base}/token", "GMAIL_ACCESS": "read_organize"}
    params = StdioServerParameters(command=sys.executable, args=["-m", "agent_gateway.connectors.gmail"], env=env)
    try:
        async with Client(stdio_client(params), cache=None) as client:
            tools = {tool.name: tool for tool in (await client.list_tools()).tools}
            assert "send_message" not in tools
            assert not tools["set_message_state"].annotations.read_only_hint

            async def run(name, **kwargs):
                return json.loads(text_of(await ask(client, name, **kwargs)))

            labels = await run("list_labels", query="receipts")
            assert labels["labels"] == [{"id": "Label_1", "name": "Receipts", "type": "user"}]
            await ask(client, "get_message", id="a1")
            assert "UNREAD" in account["messages"]["a1"]["labels"]

            state = (await run("set_message_state", ids=["a1", "dead"], read=True, starred=True))["results"]
            assert [(r["id"], r["status"]) for r in state] == [("a1", "success"), ("dead", "error")]
            assert set(state[0]["labels"]) == {"INBOX", "STARRED", "Label_2", "IMPORTANT"}
            assert state[1]["code"] == "gmail_message_missing"
            reverse = await run("set_message_state", ids=["a1"], read=False, starred=False)
            assert set(reverse["results"][0]["labels"]) == {"INBOX", "UNREAD", "Label_2", "IMPORTANT"}

            moved = (await run("move_messages", ids=["a1", "a2"], source="INBOX", destination="Label_1"))["results"]
            assert [r["status"] for r in moved] == ["success", "error"]
            assert set(moved[0]["labels"]) == {"Label_1", "Label_2", "UNREAD", "IMPORTANT"}
            assert set(account["messages"]["a2"]["labels"]) == {"UNREAD"}
            reject = (await run("set_message_labels", ids=["a1"], add=["TRASH"]))["results"]
            assert reject[0]["status"] == "not_attempted"
            changed = (await run("set_message_labels", ids=["a1"], remove=["Label_2"]))["results"]
            assert set(changed[0]["labels"]) == {"Label_1", "UNREAD", "IMPORTANT"}
            await run("move_messages", ids=["a1"], source="Label_1", destination="INBOX")
            archived = (await run("archive_messages", ids=["a1"]))["results"]
            assert set(archived[0]["labels"]) == {"UNREAD", "IMPORTANT"}

            trashed = (await run("trash_messages", ids=["a1"]))["results"]
            assert "TRASH" in trashed[0]["labels"]
            restored = (await run("restore_messages", ids=["a1"]))["results"]
            assert "TRASH" not in restored[0]["labels"]
            google.change_status = 503
            uncertain = (await run("trash_messages", ids=["a1", "a2"]))["results"]
            assert [r["status"] for r in uncertain] == ["unknown", "not_attempted"]
            assert google.requests.count(("POST", "/gmail/v1/users/me/messages/a1/trash")) == 2
            assert "TRASH" not in account["messages"]["a2"]["labels"]
            assert not any(method == "DELETE" for method, _ in google.requests)
    finally:
        google.close()
