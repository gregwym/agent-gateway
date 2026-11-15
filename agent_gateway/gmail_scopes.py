"""OAuth scope presets shared by Gmail consent and token refresh."""

SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"
SCOPES = {"read": (SCOPE,), "read_send": (SCOPE, SEND_SCOPE)}


def scope_error(access):
    return "gmail_readonly_required" if access == "read" else "gmail_scope_mismatch"
