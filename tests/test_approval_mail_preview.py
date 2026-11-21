"""The approval page names the messages a mail change would touch, if the Agent could read them itself."""
import json

import pytest

from helpers import SECRETS, TOKEN_A, agent, prepare, running_gateway, text_of
from passkey_helpers import TOKEN_A2, Page, approval_config, request_id_in
from service_helpers import mail_account
from test_connector_mail import fill, flags_of, message
from test_imap_operations import direct, extended_connection

pytestmark = pytest.mark.anyio

READS = ["mail_list_mailboxes", "mail_search_messages", "mail_get_message", "mail_list_messages", "mail_get_messages"]
CHANGES = ["mail_archive_messages", "mail_trash_messages"]
DATE = "2026-11-03T09:30:00+00:00"


def mail_config(account, reads, **pins):
    raw = approval_config()
    conn = extended_connection(account)
    for tool in conn["tools"]:
        if tool["name"] in pins:
            tool["pin"] = pins[tool["name"]]
    raw["connections"].append(conn)
    raw["policy"] += [
        {"principals": ["person_a"], "connection": conn["id"], "tools": reads, "effect": "allow"},
        {"principals": ["person_a"], "connection": conn["id"], "tools": CHANGES, "effect": "approval_required"},
    ]
    return raw, conn


def inbox(account, *subjects):
    """The arguments that name these messages (the test server's inbox also holds other mail)."""
    with direct(account) as inspect:
        validity = inspect.select_folder("INBOX", readonly=True)[b"UIDVALIDITY"]
        return {"uidvalidity": validity, "uids": [uid for subject in subjects for uid in inspect.search(["SUBJECT", subject])]}


async def test_the_page_shows_who_sent_what_only_while_the_request_is_open_and_only_to_an_agent_that_can_read(tmp_path):
    with mail_account(tmp_path / "server", "preview@example.test", "fake-mail-password") as account:
        fill(account, message("Quarterly invoice", "billing@example.test", account.user, "confidential body"),
             message("Lunch on Friday?", "friend@example.test", account.user, "another body"))
        raw, conn = mail_config(account, READS)
        # The person's second Agent may ask to change mail, but may not read it.
        raw["policy"].append({"clients": ["agent-a2"], "connection": conn["id"], "tools": READS, "effect": "deny"})
        async with running_gateway(await prepare(tmp_path / "gateway", raw, secrets={**SECRETS, "mail_password": account.password})) as gw:
            page = Page(gw.base)
            key_a = await page.enroll(gw.gateway, "person_a")
            arguments = inbox(account, "Quarterly invoice", "Lunch on Friday?")
            first, second = arguments["uids"]
            async with agent(gw.url, TOKEN_A) as a:
                request_id = request_id_in(text_of(await a.call_tool("mail_archive_messages", arguments)))
                status, shown = await page.view(request_id)
                assert status == 200 and shown["arguments"] == arguments
                assert shown["preview"] == {"messages": [
                    {"uid": first, "from": "billing@example.test", "subject": "Quarterly invoice", "date": DATE},
                    {"uid": second, "from": "friend@example.test", "subject": "Lunch on Friday?", "date": DATE},
                ]}
                assert "confidential body" not in json.dumps(shown)
                assert b"\\Seen" not in flags_of(account, "Quarterly invoice")  # looking does not mark it read
                # Asking again reuses the request and does not look the messages up again.
                assert request_id_in(text_of(await a.call_tool("mail_archive_messages", arguments))) == request_id

            async with agent(gw.url, TOKEN_A2) as a2:
                blind = request_id_in(text_of(await a2.call_tool("mail_trash_messages", arguments)))
                status, shown = await page.view(blind)
                assert status == 200 and shown["preview"] == {"unavailable": "no_read_access"}

            assert (await page.decide("deny", request_id, key_a))[0] == 200
            status, shown = await page.view(request_id)
            assert shown["status"] == "denied" and shown["preview"] is None and shown["arguments"] is None

        previews = [(e["client"], e["reason"]) for e in gw.audit() if e["event"] == "approval_preview"]
        assert previews == [("agent-a", "shown"), ("agent-a2", "no_read_access")]
        assert "Quarterly invoice" not in gw.audit_text()


@pytest.mark.parametrize("pinned, expected", [("INBOX", "shown"), ("Private", "no_read_access")])
async def test_a_read_tool_pinned_elsewhere_does_not_open_the_preview(tmp_path, pinned, expected):
    with mail_account(tmp_path / "server", "pinned@example.test", "fake-mail-password") as account:
        fill(account, message("Only in the inbox", "a@example.test", account.user, "body"))
        with direct(account) as inspect:
            inspect.create_folder("Private")
        raw, _ = mail_config(account, ["mail_get_messages"], mail_get_messages={"mailbox": pinned})
        async with running_gateway(await prepare(tmp_path / "gateway", raw, secrets={**SECRETS, "mail_password": account.password})) as gw:
            page = Page(gw.base)
            await page.enroll(gw.gateway, "person_a")
            async with agent(gw.url, TOKEN_A) as a:
                request_id = request_id_in(text_of(await a.call_tool("mail_trash_messages", inbox(account, "Only in the inbox"))))
            status, shown = await page.view(request_id)
            assert status == 200
            if expected == "shown":
                assert [m["subject"] for m in shown["preview"]["messages"]] == ["Only in the inbox"]
            else:
                assert shown["preview"] == {"unavailable": "no_read_access"}
