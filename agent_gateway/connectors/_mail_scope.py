"""Pass the gateway's mailbox allowance to the bundled connector, never to the Agent."""
from ._base import ConnectorError

ARGUMENT = "_gateway_mail_scope"
TOOLS = {
    "imap": frozenset({
        "list_mailboxes", "search_messages", "list_messages", "get_message", "get_messages", "get_attachment",
        "set_message_state", "move_messages", "archive_messages", "trash_messages",
    }),
    "gmail": frozenset({
        "list_labels", "search_messages", "get_message", "get_attachment", "set_message_state", "set_message_labels",
        "move_messages", "archive_messages", "trash_messages", "restore_messages",
    }),
}


def denied():
    return ConnectorError("This action is outside the Agent's allowed mailbox folders or labels.", "mail_scope_denied")


def in_folder(name, allowed):
    return name in allowed or (name.upper() == "INBOX" and "INBOX" in allowed)


def check_source(args, allowed):
    if allowed is not None and not in_folder(args.get("mailbox", "INBOX"), allowed):
        raise denied()


def check_labels(message, allowed):
    from ._gmail_ops import labels_of
    if not labels_of(message) & allowed:
        raise denied()


def exposed_labels(labels, allowed):
    # Keep state flags needed for workflows, without exposing names of other folders.
    return [label for label in labels if label in allowed or label in ("UNREAD", "STARRED")]
