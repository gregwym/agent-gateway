"""Validate the mailbox metadata shown to authorized Agents."""
from email.errors import HeaderParseError
from email.headerregistry import Address


def email_address(value):
    if not isinstance(value, str) or not value or len(value) > 320 or not value.isascii():
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    try:
        parsed = Address(addr_spec=value)
    except (ValueError, IndexError, HeaderParseError):
        return None
    if parsed.username and parsed.domain and parsed.addr_spec == value:
        return value
    return None
