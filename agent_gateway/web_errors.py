"""Safe, actionable browser errors. Never serialize exception text or input values."""
import errno
import secrets
import socket
import sqlite3
import ssl

import httpx2
import mcp_types as types
from mcp import MCPError
from pydantic import ValidationError
from starlette.responses import JSONResponse

from .credentials import SecretStoreError


def leaves(error):
    if isinstance(error, BaseExceptionGroup):
        return [item for child in error.exceptions for item in leaves(child)]
    return [error]


def connector_failure(error, transport):
    items = leaves(error)
    for item in list(items):
        cause = item.__cause__
        for _ in range(8):
            if cause is None or cause in items:
                break
            items.append(cause)
            cause = cause.__cause__
    if any(isinstance(item, ssl.SSLError) or type(item).__name__ == "SSLError" for item in items):
        return "connector_tls_failed"
    if any(isinstance(item, socket.gaierror) or type(item).__name__ == "NameResolutionError" for item in items):
        return "connector_dns_failed"
    for item in items:
        if isinstance(item, (TimeoutError, httpx2.TimeoutException)) or (
                isinstance(item, MCPError) and item.code == types.REQUEST_TIMEOUT):
            return "connector_timeout"
        if isinstance(item, ssl.SSLCertVerificationError):
            return "connector_tls_failed"
        if isinstance(item, socket.gaierror):
            return "connector_dns_failed"
        if isinstance(item, FileNotFoundError):
            return "connector_executable_missing"
        if isinstance(item, PermissionError):
            return "connector_executable_denied"
        if isinstance(item, httpx2.HTTPStatusError):
            return {401: "connector_auth_rejected", 403: "connector_access_denied", 404: "connector_endpoint_missing",
                    429: "connector_rate_limited"}.get(item.response.status_code, "connector_http_error")
        if isinstance(item, (httpx2.TransportError, ConnectionError, OSError)):
            return "connector_network_failed"
        if isinstance(item, MCPError) and item.code == types.CONNECTION_CLOSED:
            return "connector_process_exited" if transport == "stdio" else "connector_network_failed"
        if isinstance(item, MCPError):
            return "connector_protocol_error"
    return "connector_unavailable"


def probe_error(kind, result):
    # Compare only fixed errors from bundled connectors. A remote helper's free
    # text may echo credentials, so an unrecognized response is never displayed.
    allowed = {"imap_credentials_rejected", "imap_server_unreachable", "caldav_credentials_rejected",
               "gmail_authorization_rejected", "connector_timeout", "connector_tls_failed", "connector_dns_failed",
               "connector_network_failed", "connector_internal_error", "smtp_credentials_rejected", "smtp_not_configured",
               "smtp_invalid_security", "smtp_invalid_address", "smtp_tls_failed", "smtp_dns_failed", "smtp_not_supported",
               "smtp_request_rejected", "smtp_unreachable"}
    code = result.meta.get("agw_error") if isinstance(result.meta, dict) else None
    if isinstance(code, str) and code in allowed:
        return code
    known = {}
    if kind == "imap":
        from .connectors.imap_mail import _REJECTED, _UNREACHABLE
        known = {_REJECTED: "imap_credentials_rejected", _UNREACHABLE: "imap_server_unreachable"}
    elif kind == "caldav":
        from .connectors.caldav_calendar import _REJECTED, _UNREACHABLE
        known = {_REJECTED: "caldav_credentials_rejected", _UNREACHABLE: "caldav_server_unreachable",
                 "The calendar server denied access to that calendar.": "connector_access_denied",
                 "The calendar server refused the request.": "connector_request_rejected",
                 "No such calendar or event.": "connector_resource_missing"}
    elif kind == "gmail":
        from .connectors.gmail import _REVOKED, _TOO_BROAD, _UNREACHABLE, _UNAVAILABLE
        known = {_REVOKED: "gmail_authorization_rejected", _TOO_BROAD: "gmail_readonly_required",
                 _UNREACHABLE: "gmail_server_unreachable", _UNAVAILABLE: "gmail_request_rejected"}
    elif kind == "reminders":
        from .connectors.reminders_eventkit import _NOT_GRANTED
        known = {_NOT_GRANTED: "reminders_permission_required", "Reminders did not answer in time.": "connector_timeout"}
    for part in result.content:
        if getattr(part, "type", None) == "text" and part.text in known:
            return known[part.text]
    return "connector_login_or_read_failed"


def failure_response(error, audit, headers):
    code, status, extra = "operation_failed", 500, {}
    if isinstance(error, ValidationError):
        code, status = "invalid_configuration", 400
        fields = {"id", "name", "owner", "principal", "url", "effect", "pin", "allow_values", "tools",
                  "connections", "clients", "policy", "principals", "shared", "upstream", "cross_account"}
        extra["fields"] = [{"path": ".".join(str(p) if isinstance(p, int) or p in fields else "field" for p in e["loc"]) or "configuration",
                            "reason": e["type"]} for e in error.errors(include_input=False, include_context=False, include_url=False)[:8]]
    elif isinstance(error, SecretStoreError):
        code = "credential_store_unavailable"
    elif isinstance(error, sqlite3.Error):
        code = {sqlite3.SQLITE_BUSY: "storage_busy", sqlite3.SQLITE_LOCKED: "storage_busy",
                sqlite3.SQLITE_FULL: "storage_full", sqlite3.SQLITE_READONLY: "storage_readonly",
                sqlite3.SQLITE_CANTOPEN: "storage_unavailable", sqlite3.SQLITE_CORRUPT: "storage_corrupt"}.get(
                    getattr(error, "sqlite_errorcode", 0) & 255, "storage_unavailable")
    elif isinstance(error, OSError):
        code = {errno.ENOSPC: "storage_full", errno.EROFS: "storage_readonly", errno.EACCES: "storage_permission_denied",
                errno.EPERM: "storage_permission_denied", errno.ENOENT: "storage_missing"}.get(error.errno, "storage_unavailable")
    incident = secrets.token_hex(6)
    audit.write("web_error", reason=code, detail=f"{incident}:{type(error).__name__}")
    return JSONResponse({"error": code, "incident": incident, **extra}, status_code=status, headers=headers)
