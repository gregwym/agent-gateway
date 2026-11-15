"""OAuth presets and capability gates shared by Gmail consent and the connector."""

SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"
MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
SCOPES = {
    "read": (SCOPE,),
    "read_send": (SCOPE, SEND_SCOPE),
    "read_organize": (MODIFY_SCOPE,),
    "read_organize_send": (MODIFY_SCOPE,),
}
ORGANIZE_TOOLS = (
    ("set_message_state", "set_state"),
    ("set_message_labels", "set_labels"),
    ("move_messages", "move"),
    ("archive_messages", "archive"),
    ("trash_messages", "trash"),
    ("restore_messages", "restore"),
)


def can_organize(access):
    return access in ("read_organize", "read_organize_send")


def can_send(access):
    return access in ("read_send", "read_organize_send")


def tool_enabled(name, access):
    if name == "send_message":
        return can_send(access)
    if name in {tool for tool, _ in ORGANIZE_TOOLS}:
        return can_organize(access)
    return True


def scope_error(access):
    return "gmail_readonly_required" if access == "read" else "gmail_scope_mismatch"
