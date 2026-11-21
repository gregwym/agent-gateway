"""Subject, sender and date of the messages a mail change waiting for approval would touch.

Without them the approver sees only message ids. The approval page has no access
control of its own (its address is in the Agent's conversation), so the gateway
looks headers up only when the Agent could read them itself without approval:
through one of its read tools on the same connection, allowed outright, with the
same mailbox restriction and pinned values satisfied.
"""

from __future__ import annotations

import json
from typing import Any

import mcp_types as types

from .connectors._mail_scope import ARGUMENT

# Bundled mail tools whose approval shows a preview: the ones that change messages named by id.
TOOLS = {
    "imap": frozenset({"set_message_state", "move_messages", "archive_messages", "trash_messages"}),
    "gmail": frozenset({"set_message_state", "set_message_labels", "move_messages", "archive_messages",
                        "trash_messages", "restore_messages"}),
}
SECONDS = 8  # the request waits for its preview no longer than this
# A pinned value of one of these limits how much of a message a read returns, not which messages it reaches.
_FREE = frozenset({"format", "offset", "max_chars", "limit"})
_FIELDS = ("from", "subject", "date")
_STATUSES = frozenset({"missing", "hidden", "skipped"})
_MAX_CHARS = 300


def reads(kind: str, arguments: dict[str, Any]) -> list[tuple[str, list[dict[str, Any]]]]:
    """Ways the Agent could read the same headers: (read tool, every call it would take). One way is enough."""
    if kind == "imap":
        mailbox = arguments.get("mailbox", "INBOX")
        return [
            ("get_messages", [{"mailbox": mailbox, "uidvalidity": arguments["uidvalidity"], "uids": arguments["uids"]}]),
            ("get_message", [{"mailbox": mailbox, "uid": uid} for uid in arguments["uids"]]),
            ("list_messages", [{"mailbox": mailbox}]),
            ("search_messages", [{"mailbox": mailbox}]),
        ]
    return [("get_message", [{"id": item} for item in arguments["ids"]]), ("search_messages", [{}])]


def same_reach(wanted: dict[str, Any], final: dict[str, Any]) -> bool:
    """Whether the read, with its pinned values added, still reaches what `wanted` names, and no narrower."""
    return {key: value for key, value in final.items() if key not in _FREE} == wanted


def arguments(kind: str, upstream_arguments: dict[str, Any]) -> dict[str, Any]:
    """The preview call: the same messages, under the same mailbox restriction."""
    keys = ("mailbox", "uidvalidity", "uids") if kind == "imap" else ("ids",)
    return {key: upstream_arguments[key] for key in (*keys, ARGUMENT) if key in upstream_arguments}


def parse(kind: str, result: types.CallToolResult) -> dict[str, Any] | None:
    """The connector's reply, reduced to what the page shows; None if it is not a preview."""
    if result.is_error or len(result.content) != 1 or not isinstance(result.content[0], types.TextContent):
        return None
    try:
        data = json.loads(result.content[0].text)
    except ValueError:
        return None
    key = "uid" if kind == "imap" else "id"
    messages = data.get("messages") if isinstance(data, dict) else None
    if not isinstance(messages, list) or len(messages) > 50:
        return None
    shown = []
    for entry in messages:
        if not isinstance(entry, dict) or not isinstance(entry.get(key), (int, str)):
            return None
        item = {key: entry[key]}
        if entry.get("status") in _STATUSES:
            item["status"] = entry["status"]
        else:
            item.update({name: entry[name][:_MAX_CHARS] for name in _FIELDS if isinstance(entry.get(name), str)})
        shown.append(item)
    return {"messages": shown}

