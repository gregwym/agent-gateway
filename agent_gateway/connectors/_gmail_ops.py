"""Gmail label and trash operations, with an outcome for every message."""
from __future__ import annotations

import time

from ._base import ConnectorError, Tool, integer, string
from ._mail_scope import ARGUMENT, PREVIEW, denied, exposed_labels


class ChangeError(ConnectorError):
    def __init__(self, message, code, *, outcome="error", stop=False):
        super().__init__(message, code)
        self.outcome, self.stop = outcome, stop


def labels_of(body):
    values = body.get("labelIds", [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ConnectorError("Gmail returned an invalid label list.", "gmail_labels_invalid")
    return set(values)


def _list(gmail, timeout=30):
    raw = gmail.get("labels", timeout=timeout).get("labels", [])
    if not isinstance(raw, list) or any(not isinstance(entry, dict) or
                                        not all(isinstance(entry.get(k), str) for k in ("id", "name", "type")) for entry in raw):
        raise ConnectorError("Gmail returned an invalid label list.", "gmail_labels_invalid")
    return [{"id": entry["id"], "name": entry["name"], "type": entry["type"]} for entry in raw]


def tools(gmail, message_id, *, organize):
    def list_labels(args):
        labels = _list(gmail)
        scope = args.get(ARGUMENT)
        if scope is not None:
            labels = [label for label in labels if label["id"] in scope]
        query = args.get("query", "").casefold()
        labels = [label for label in labels if query in label["name"].casefold() or query in label["id"].casefold()]
        offset, limit = args.get("offset", 0), args.get("limit", 50)
        next_offset = offset + limit if offset + limit < len(labels) else None
        return {"labels": labels[offset:offset + limit], "total": len(labels), "next_offset": next_offset}

    definitions = [Tool("list_labels", "List label IDs, names and types for this Gmail account. Use these IDs with label and move tools.",
                        list_labels, {"query": string("Filter by label name or ID.", 100),
                                      "offset": integer("Label offset.", 0, 10000, 0),
                                      "limit": integer("Labels per page.", 1, 100, 50)})]
    if not organize:
        return definitions

    def mutate(args, op):
        if not gmail.can_organize:
            raise ConnectorError("Organizing was not authorized for this Gmail connector.")
        ids = args["ids"]
        scope = args.get(ARGUMENT)
        deadline = time.monotonic() + 15
        added, removed, source, endpoint = set(), set(), None, "modify"

        def rejected(msg_id, message, code, status="error"):
            return {"id": msg_id, "status": status, "code": code, "error": message}

        try:
            if op in ("labels", "move"):
                user_labels = {label["id"] for label in _list(gmail, timeout=4) if label["type"] == "user"}
                if op == "move":
                    source, destination = args["source"], args["destination"]
                    if source == destination or not {source, destination} <= user_labels | {"INBOX"}:
                        raise ConnectorError("Choose different source and destination label IDs: use INBOX or an existing user label.", "gmail_move_labels_invalid")
                    added, removed = {destination}, {source}
                else:
                    added, removed = set(args.get("add", [])), set(args.get("remove", []))
                    if not (added | removed) or not (added | removed) <= user_labels or added & removed:
                        raise ConnectorError("Choose existing user label IDs to add or remove; the two sets must be different and cannot overlap.", "gmail_label_change_invalid")
            elif op == "state":
                for name, label, condition in (("read", "UNREAD", False), ("starred", "STARRED", True)):
                    if name in args:
                        (added if args[name] == condition else removed).add(label)
                if not (added | removed):
                    raise ConnectorError("Set read, starred, or both.", "gmail_state_required")
            elif op == "archive":
                removed = {"INBOX"}
            elif op == "trash":
                endpoint, added = "trash", {"TRASH"}
            elif op == "restore":
                endpoint, removed = "untrash", {"TRASH"}
            if scope is not None and (op in ("trash", "restore") or (op != "state" and not (added | removed) <= scope)):
                # Trash and restore can affect other labels implicitly.
                raise denied()
        except ConnectorError as exc:
            return {"results": [rejected(item, str(exc), exc.code or "gmail_labels_unavailable", "not_attempted") for item in ids]}

        body = {"addLabelIds": sorted(added), "removeLabelIds": sorted(removed)} if endpoint == "modify" else None
        results = []
        stopped = False
        for item in ids:
            if stopped or time.monotonic() >= deadline:
                message = ("A preceding Gmail request could not be completed. Check its outcome before retrying." if stopped else
                           "This batch reached its time limit. Retry only the remaining message IDs.")
                results.append(rejected(item, message, "gmail_batch_stopped", "not_attempted"))
                continue
            try:
                if source or scope is not None:
                    message = gmail.get(f"messages/{item}", [("format", "minimal")], timeout=4)
                    if message.get("id") != item:
                        raise ConnectorError("Gmail did not confirm the source message.", "gmail_read_failed")
                    current = labels_of(message)
                    if scope is not None and not current & scope:
                        raise denied()
                    if source and ("TRASH" in current or "SPAM" in current or source not in current):
                        raise ConnectorError("The message is not in the requested source, or is in Trash or Spam.", "gmail_move_source_missing")
                    if time.monotonic() >= deadline:
                        results.append(rejected(item, "This batch reached its time limit before the move.", "gmail_batch_stopped", "not_attempted"))
                        continue
                changed = gmail.change(item, endpoint, body, added, removed)
                labels = sorted(changed)
                results.append({"id": item, "status": "success", "labels": labels if scope is None else exposed_labels(labels, scope)})
            except ChangeError as exc:
                stopped = exc.stop
                results.append(rejected(item, str(exc), exc.code, exc.outcome))
            except ConnectorError as exc:
                if scope is not None and exc.code == "gmail_message_missing":
                    exc = denied()
                results.append(rejected(item, str(exc), exc.code or "gmail_read_failed"))
        return {"results": results}

    ids = {"type": "array", "items": message_id, "minItems": 1, "maxItems": 50, "uniqueItems": True}
    label = string("Existing label ID from list_labels.", 128)
    label_ids = {"type": "array", "items": label, "maxItems": 50, "uniqueItems": True}
    effects = " Returns one outcome per message ID. Inspect unknown outcomes before retrying."
    specs = [
        ("set_message_state", "state", "Mark Gmail messages read/unread and/or starred/unstarred. Set read, starred, or both.",
         {"read": {"type": "boolean"}, "starred": {"type": "boolean"}}, ()),
        ("set_message_labels", "labels", "Add or remove existing user labels on Gmail messages, preserving unrelated labels.",
         {"add": label_ids, "remove": label_ids}, ()),
        ("move_messages", "move", "Move Gmail messages from a source label to a destination label, adding the destination and removing the source. Use existing user labels or INBOX. Other labels stay in place.",
         {"source": label, "destination": label}, ("source", "destination")),
        ("archive_messages", "archive", "Archive Gmail messages by removing INBOX. Other labels stay in place.", {}, ()),
        ("trash_messages", "trash", "Move Gmail messages to Trash.", {}, ()),
        ("restore_messages", "restore", "Restore Gmail messages from Trash.", {}, ()),
    ]
    return definitions + [
        Tool(name, description + effects, lambda args, operation=op: mutate(args, operation),
             {"ids": ids, **fields}, ("ids", *required), read_only=False)
        for name, op, description, fields, required in specs
    ]


def preview_tool(gmail, message_id):
    """Sender, subject and date of the messages a pending change names, for the gateway's approval page."""
    from . import _mail

    wanted = [("format", "metadata")] + [("metadataHeaders", name) for name in _mail.PREVIEW_HEADERS]

    def preview(args):
        scope = args.get(ARGUMENT)
        deadline = time.monotonic() + 6
        messages, stopped = [], False
        for item in args["ids"]:
            if stopped or time.monotonic() >= deadline:
                messages.append({"id": item, "status": "skipped"})
                continue
            try:
                message = gmail.get(f"messages/{item}", wanted, timeout=4)
            except ConnectorError as exc:
                if exc.code == "gmail_message_missing":
                    # Under a label restriction, "missing" and "outside the labels" look the same, as for get_message.
                    messages.append({"id": item, "status": "hidden" if scope is not None else "missing"})
                else:
                    stopped = True
                    messages.append({"id": item, "status": "skipped"})
                continue
            if message.get("id") != item or (scope is not None and not labels_of(message) & scope):
                messages.append({"id": item, "status": "hidden" if scope is not None else "missing"})
                continue
            pairs = [(str(h.get("name", "")), str(h.get("value", ""))) for h in message.get("payload", {}).get("headers", [])]
            messages.append({"id": item, **_mail.preview(_mail.headers_from_pairs(pairs))})
        return {"messages": messages}

    ids = {"type": "array", "items": message_id, "minItems": 1, "maxItems": 50, "uniqueItems": True}
    return Tool(PREVIEW, "For the gateway's approval page only: sender, subject and date of the named messages. Not offered to Agents.",
                preview, {"ids": ids}, ("ids",))
