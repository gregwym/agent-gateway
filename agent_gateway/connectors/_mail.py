"""From a raw RFC 822 message to what a mail tool returns. Parsing is the standard library's."""

from __future__ import annotations

import base64
import re
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote

import mcp_types as types

from ._base import ConnectorError, result

# Delivered-To and the original To are what tell an Apple "Hide My Email" or
# "Sign in with Apple" relay address apart from the mailbox's own address.
HEADERS = ("From", "To", "Cc", "Reply-To", "Delivered-To", "Subject", "Date", "Message-ID")
_IMAGES = ("image/png", "image/jpeg", "image/gif", "image/webp")
_TEXTUAL = ("application/json", "application/xml", "application/x-ndjson")


def parse(raw: bytes) -> EmailMessage:
    return message_from_bytes(raw, policy=policy.default)  # type: ignore[return-value]


def headers(message: EmailMessage) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in HEADERS:
        try:
            values = [str(value) for value in message.get_all(name, [])]
        except Exception:  # a header the parser cannot make sense of
            continue
        if not values:
            continue
        value = " ".join(", ".join(values).split())[:2000]
        if name == "Date":
            try:
                value = parsedate_to_datetime(value).isoformat()
            except (TypeError, ValueError):
                pass
        out[name.lower().replace("-", "_")] = value
    return out


PREVIEW_HEADERS = ("From", "Subject", "Date")
PREVIEW_CHARS = 300


def preview(fields: dict[str, str]) -> dict[str, str]:
    """Sender, subject and date only, shortened: what a person needs to recognize a message."""
    return {key: fields[key][:PREVIEW_CHARS] for key in ("from", "subject", "date") if key in fields}


def headers_from_pairs(pairs: list[tuple[str, str]]) -> dict[str, str]:
    """The same summary from (name, value) pairs, as a mail API returns them."""
    lines = [f"{name}: {' '.join(str(value).split())}" for name, value in pairs if name.lower() in {h.lower() for h in HEADERS}]
    return headers(parse(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")))


def _decoded(part: EmailMessage) -> str:
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except (LookupError, ValueError, KeyError):
        pass
    payload = part.get_payload(decode=True)
    return payload.decode("utf-8", "replace") if isinstance(payload, bytes) else ""


def body(message: EmailMessage, wanted: str = "text") -> str:
    """The message text. `text`: the plain part, or the HTML part reduced to text. `html`: the HTML as sent."""
    try:
        part = message.get_body(("html",) if wanted == "html" else ("plain", "html"))
    except Exception:
        part = None
    if part is None:
        return ""
    content = _decoded(part).replace("\r\n", "\n")  # type: ignore[arg-type]
    if wanted != "html" and part.get_content_type() == "text/html":
        return html_to_text(content)
    return content


def _leaves(part: EmailMessage) -> list[EmailMessage]:
    if part.get_content_type() == "message/rfc822" or not part.is_multipart():
        return [part]
    return [leaf for child in part.iter_parts() for leaf in _leaves(child)]  # type: ignore[arg-type]


def _attachment_parts(message: EmailMessage) -> list[EmailMessage]:
    """Every part that is not the message text itself, in document order."""
    bodies = set()
    for kind in ("plain", "html"):
        try:
            part = message.get_body((kind,))
        except Exception:
            part = None
        if part is not None:
            bodies.add(id(part))
    return [part for part in _leaves(message) if id(part) not in bodies]


def _bytes(part: EmailMessage) -> bytes:
    if part.get_content_type() == "message/rfc822":
        inner = part.get_payload()
        return inner[0].as_bytes() if isinstance(inner, list) and inner else b""
    payload = part.get_payload(decode=True)
    return payload if isinstance(payload, bytes) else b""


def _name(part: EmailMessage, index: int) -> str:
    name = part.get_filename() or f"attachment-{index}"
    return " ".join(str(name).split())[:200]


def attachments(message: EmailMessage) -> list[dict[str, Any]]:
    return [
        {
            "index": index,
            "filename": _name(part, index),
            "content_type": part.get_content_type(),
            "size": len(_bytes(part)),
            "inline": part.get_content_disposition() == "inline",
        }
        for index, part in enumerate(_attachment_parts(message))
    ]


def attachment(message: EmailMessage, index: int, max_bytes: int) -> types.CallToolResult:
    """One attachment: text as text, common images as images, anything else as an embedded blob."""
    parts = _attachment_parts(message)
    if not 0 <= index < len(parts):
        raise ConnectorError("No such attachment.")
    part = parts[index]
    data, kind, name = _bytes(part), part.get_content_type(), _name(part, index)
    if len(data) > max_bytes:
        raise ConnectorError(f"The attachment is {len(data)} bytes; the limit is {max_bytes}. Open it in the mail app, "
                             "or ask the gateway administrator to raise this connection's attachment limit.")
    about = {"filename": name, "content_type": kind, "size": len(data)}
    if kind.startswith("text/") or kind in _TEXTUAL:
        charset = part.get_content_charset() or "utf-8"
        try:
            decoded = data.decode(charset, "replace")
        except LookupError:
            decoded = data.decode("utf-8", "replace")
        return result(about, decoded)
    encoded = base64.b64encode(data).decode("ascii")
    if kind in _IMAGES:
        return result(about, types.ImageContent(type="image", data=encoded, mime_type=kind))
    blob = types.BlobResourceContents(uri=f"attachment:///{index}/{quote(name, safe='')}", mime_type=kind, blob=encoded)
    return result(about, types.EmbeddedResource(type="resource", resource=blob))


def page(text: str, offset: int, max_chars: int) -> dict[str, Any]:
    """Which slice of a long body a result carries, so the rest can be asked for."""
    return {"body_chars": len(text), "body_offset": offset, "truncated": offset + max_chars < len(text)}


class _Text(HTMLParser):
    _SKIP = frozenset({"script", "style", "head", "title", "template"})
    _BREAK = frozenset(
        {"p", "div", "br", "tr", "li", "ul", "ol", "table", "blockquote", "section", "article", "hr", "pre",
         "h1", "h2", "h3", "h4", "h5", "h6"}
    )  # fmt: skip

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skipping = 0
        self.href: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self.skipping += 1
        elif tag in self._BREAK:
            self.out.append("\n")
        elif tag == "a":
            self.href = dict(attrs).get("href")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP:
            self.skipping = max(0, self.skipping - 1)
        elif tag in self._BREAK:
            self.out.append("\n")
        elif tag == "a":
            if self.href and self.href.startswith(("http://", "https://")) and not self.skipping:
                self.out.append(f" ({self.href})")
            self.href = None

    def handle_data(self, data: str) -> None:
        if not self.skipping:
            self.out.append(data)


def html_to_text(html: str) -> str:
    """Readable text from an HTML mail: no scripts or styles, link targets kept. Not a sanitiser."""
    parser = _Text()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass
    lines = [" ".join(line.split()) for line in "".join(parser.out).replace("​", "").splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
