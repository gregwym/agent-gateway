"""Bounded, administrator-only projection of the existing audit files."""

import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from .config import NAME

MAX_ROWS = 200
MAX_BYTES = 2 * 1024 * 1024
MAX_FILES = 8
MAX_LINE = 32 * 1024

RESULTS = frozenset({"allow", "deny", "error", "queued", "pending", "approve", "cancel"})
EVENTS = frozenset({
    "admin_confirmed", "admin_connector_preview", "admin_connector_test", "admin_login",
    "admin_mailbox_paths", "admin_oauth_revoked", "admin_setup", "admin_updated",
    "approval_cancelled", "approval_decided", "approval_dispatch_error", "approval_preview",
    "approval_queue_error", "approval_requested", "auth_failed", "configuration_proposal_rejected",
    "configuration_proposed", "oauth_cleanup_failed", "passkey_enrolled", "passkey_removed",
    "startup", "tool_blocked", "tool_call", "web_error", "web_session_cleanup_failed",
    "website_catalog_cleanup_failed", "website_catalog_published", "website_login_terminated",
    "website_operation_rules_approved", "website_operation_rules_proposed",
    "website_operation_rules_rejected",
})
REASONS = frozenset({
    "ambiguous_variant", "approval:denied", "approval:expired", "approval:no_approver_enrolled",
    "approval:pending", "approval:requested", "approval:submitted", "approval:unavailable",
    "approved", "background_completed", "catalog_operation", "client_cancelled",
    "configuration_changed", "discovery", "internal_error", "invalid_arguments",
    "invalid_token", "mail_scope_denied", "no_token", "not_locked", "ok",
    "pinned_argument_supplied", "policy_deny", "result_too_large", "schema_unusable",
    "storage_unavailable", "submission", "too_many_queued", "unknown_tool",
    "upstream_invalid_reply", "upstream_rejected", "upstream_timeout",
    "web_origin_not_approved", "web_redirect_restricted",
})


def identifier(value):
    return isinstance(value, str) and re.fullmatch(NAME, value) is not None


def filters(body):
    result = {}
    for key, value in body.items():
        if not isinstance(value, str):
            raise ValueError
        if key in ("client", "connection") and (not value or identifier(value)):
            result[key] = value
        elif key == "result" and (not value or value in RESULTS):
            result[key] = value
        else:
            raise ValueError
    return {key: value for key, value in result.items() if value}


def _choice(value, choices):
    return value if isinstance(value, str) and value in choices else None


def _project(line, tools):
    if not line or len(line) > MAX_LINE:
        return None
    try:
        record = json.loads(line)
        if not isinstance(record, dict) or not isinstance(record.get("ts"), str):
            return None
        stamp = datetime.fromisoformat(record["ts"])
        if stamp.tzinfo is None:
            return None
        stamp = stamp.astimezone(timezone.utc).isoformat(timespec="milliseconds")
    except (ValueError, OverflowError, RecursionError):
        return None
    event = _choice(record.get("event"), EVENTS)
    if event is None:
        return None
    reason = _choice(record.get("reason"), REASONS)
    result = _choice(record.get("decision"), RESULTS)
    if record.get("is_error") is True:
        result = "error"
    elif event == "approval_requested" or reason in ("approval:pending", "approval:requested", "approval:submitted"):
        result = "pending"
    elif result is None:
        result = {"auth_failed": "deny", "tool_blocked": "deny", "approval_cancelled": "cancel"}.get(event)
    return {
        "ts": stamp, "event": event, "result": result, "reason": reason,
        "client": record["client"] if identifier(record.get("client")) else None,
        "connection": record["connection"] if identifier(record.get("connection")) else None,
        "tool": _choice(record.get("tool"), tools) if reason != "unknown_tool" else None,
    }


def _read_tail(path, budget):
    # Check the opened file as well as its name so a rotation cannot redirect a read.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            return b"", 0, False
        start = max(0, info.st_size - budget)
        stream.seek(start)
        data = stream.read(min(info.st_size, budget))
    used = len(data)
    # Skip partial records at either end of the byte window.
    if start:
        data = data.partition(b"\n")[2]
    if not data.endswith(b"\n"):
        data = data.rpartition(b"\n")[0]
    return data, used, bool(start)


def recent(path: Path, retention_days: int, query, tools):
    pattern = re.compile(re.escape(path.name) + r"\.\d{4}-\d{2}-\d{2}")
    try:
        with os.scandir(path.parent) as entries:
            rotated = sorted(
                (entry.name for entry in entries
                 if pattern.fullmatch(entry.name) and entry.is_file(follow_symlinks=False)),
                reverse=True,
            )
    except FileNotFoundError:
        return {"items": [], "truncated": False}
    file_count = min(retention_days, MAX_FILES - 1)
    truncated = len(rotated) > file_count
    budget = MAX_BYTES
    items = []
    for candidate in [path, *(path.with_name(name) for name in rotated[:file_count])]:
        if not budget:
            truncated = True
            break
        try:
            data, used, partial = _read_tail(candidate, budget)
        except FileNotFoundError:
            continue
        budget -= used
        truncated |= partial
        for line in reversed(data.split(b"\n")):
            item = _project(line, tools)
            if item is not None and all(item[key] == value for key, value in query.items()):
                items.append(item)
    items.sort(key=lambda item: item["ts"], reverse=True)
    return {"items": items[:MAX_ROWS], "truncated": truncated or len(items) > MAX_ROWS}
