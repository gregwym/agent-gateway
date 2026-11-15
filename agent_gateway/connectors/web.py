"""Credentialed reads of explicitly profiled pages; no redirects or browser code."""
from __future__ import annotations

import html
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
import threading
from contextlib import closing
from html.parser import HTMLParser
from http.cookiejar import Cookie, CookieJar
from types import SimpleNamespace
from urllib.parse import quote, unquote, urlencode, urlsplit
from urllib.request import Request

from ..web_profiles import PROFILE_ENV, SESSION_ENV, WebProfile
from ._base import ConnectorError, CredentialGate, Tool, serve, setting, string

MAX_RESPONSE = 4 * 1024 * 1024
MAX_TEXT = 60_000
IDENTIFIER = r"^[a-zA-Z0-9_-]{1,128}$"
_COOKIE_NAME = re.compile(r"^[a-zA-Z0-9!#$%&'*+.^_`|~-]{1,128}$")
_COOKIE_VALUE = re.compile(r"^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]{1,8192}$")
_SECRET_FIELD = re.compile(r"token|secret|cookie|csrf|xsrf|credential|password|authorization|session|api.?key", re.I)
_TLS = ssl.create_default_context()


def _session_error():
    return ConnectorError("The browser session expired or requires signing in again. Import a fresh session.",
                          "web_login_required")


def _shape_error():
    return ConnectorError("The page did not match this site's read profile.", "web_profile_mismatch")


def import_session(raw, profile):
    """Accept a cookie array or a Playwright storageState, discarding other sites and storage."""
    host = urlsplit(profile.origin).hostname
    if len(raw.encode("utf-8")) > 60_000:
        raise ValueError("browser session too large")
    data = json.loads(raw)
    source = data.get("cookies") if isinstance(data, dict) else data
    if not isinstance(source, list) or len(source) > 250:
        raise ValueError("expected an exported cookie array")
    kept = {}
    for item in source:
        if not isinstance(item, dict):
            raise ValueError("expected a cookie object")
        domain = item.get("domain")
        if not isinstance(domain, str) or len(domain) > 255:
            continue
        domain = domain.lower()
        if domain != host and not (domain.startswith(".") and "." in domain[1:] and
                                   (domain[1:] == host or host.endswith(domain))):
            continue
        name, value, path = item.get("name"), item.get("value"), item.get("path", "/")
        expires = item.get("expires", item.get("expirationDate", -1))
        if not (isinstance(name, str) and _COOKIE_NAME.fullmatch(name) and isinstance(value, str)
                and _COOKIE_VALUE.fullmatch(value) and isinstance(path, str) and path.startswith("/")
                and len(path) <= 512 and re.fullmatch(r"[^\x00-\x20\x7f;]*", path)
                and type(expires) in (int, float) and -1 <= expires <= 253402300799):
            continue
        if expires != -1 and expires <= time.time():
            continue
        # The client is fixed to this HTTPS host; imported parent domain cookies are re-bound to it.
        kept[name, path] = {"name": name, "value": value, "path": path, "domain": host, "expires": int(expires)}
    if not kept:
        raise ValueError("no unexpired cookies for this site")
    return json.dumps(list(kept.values()), separators=(",", ":"), ensure_ascii=True)


def _public_socket(address, timeout, source_address):
    host, port = address
    records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not records or any(not (ip := ipaddress.ip_address(record[4][0])).is_global or ip.is_multicast for record in records):
        raise ConnectorError("The Web profile resolved to a non-public address.", "web_unsafe_address")
    error = None
    deadline = time.monotonic() + timeout
    for family, kind, protocol, _, sockaddr in records:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        try:
            client = socket.socket(family, kind, protocol)
            try:
                client.settimeout(remaining)
                if source_address:
                    client.bind(source_address)
                client.connect(sockaddr)  # Use the validated result, without resolving the name again.
                return client
            except BaseException:
                client.close()
                raise
        except OSError as exc:
            error = exc
    raise error


class _PublicHTTPS(http.client.HTTPSConnection):
    def __init__(self, host):
        super().__init__(host, timeout=8, context=_TLS)
        self._create_connection = _public_socket  # SNI and certificate checks still use the profile hostname.


def _fetch(host, target, headers, receiver):
    # No proxy, redirect, compression, scripts, or other asset requests.
    with closing(_PublicHTTPS(host)) as connection:
        connection.request("GET", target, headers=headers)
        response = connection.getresponse()
        return receiver(response.status, response.headers, response)


class _VisibleText(HTMLParser):
    SKIP = {"script", "style", "template", "noscript", "head", "svg", "iframe", "textarea", "input", "select"}
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in self.VOID:
            return
        attrs = dict(attrs)
        hidden = (tag in self.SKIP or "hidden" in attrs or attrs.get("aria-hidden") == "true"
                  or bool(re.search(r"(?:display:\s*none|visibility:\s*hidden)", attrs.get("style") or "", re.I)))
        if len(self.stack) >= 256:
            raise _shape_error()
        self.stack.append((tag, hidden or (self.stack[-1][1] if self.stack else False)))

    def handle_startendtag(self, tag, attrs):
        pass

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, text):
        if not self.stack or not self.stack[-1][1]:
            value = " ".join(text.split())
            if value:
                self.parts.append(value)


def _filter_json(value):
    if isinstance(value, dict):
        return {k: _filter_json(v) for k, v in value.items() if not _SECRET_FIELD.search(k)}
    if isinstance(value, list):
        return [_filter_json(v) for v in value]
    return value


class SiteSession:
    def __init__(self, profile, raw, *, fetch=None, persist=None, redactions=()):
        self.profile = profile
        self.host = urlsplit(profile.origin).hostname
        self.jar = CookieJar()
        self.fetch = fetch or _fetch
        self.persist = persist
        self.lock = threading.Lock()
        self.seen_secrets = set(redactions)
        self.gate = CredentialGate(str(_session_error()), code="web_login_required")
        for item in json.loads(raw):
            self.jar.set_cookie(Cookie(
                version=0, name=item["name"], value=item["value"], port=None, port_specified=False,
                domain=self.host, domain_specified=False, domain_initial_dot=False, path=item["path"],
                path_specified=True, secure=True, expires=None if item["expires"] == -1 else item["expires"],
                discard=item["expires"] == -1, comment=None, comment_url=None, rest={"HttpOnly": None}))
        self._remember_cookies()

    def _cookies(self):
        return json.dumps([{"name": c.name, "value": c.value, "path": c.path,
                            "expires": c.expires if c.expires is not None else -1} for c in self.jar],
                          separators=(",", ":"), ensure_ascii=True)

    def _remember_cookies(self):
        for cookie in self.jar:
            self._remember(cookie.value)
        if len(self.jar) > 250 or len(self.seen_secrets) > 2000 or sum(map(len, self.seen_secrets)) > 256_000:
            raise ConnectorError("The website exceeded the session cookie limit.", "web_response_limit")

    def _remember(self, value):
        if value:
            self.seen_secrets.update((value, quote(value, safe=""), unquote(value), html.escape(value)))

    def _redact(self, value):
        secrets = sorted(self.seen_secrets - {""}, key=len, reverse=True)
        if secrets:
            value = re.sub("|".join(re.escape(s) for s in secrets), "[REDACTED]", value)
        return value

    def read(self, action, args):
        if not self.lock.acquire(timeout=2):
            raise ConnectorError("Another read is in progress for this browser session.", "web_session_busy")
        try:
            return self._read(action, args)
        finally:
            self.lock.release()

    def _read(self, action, args):
        self.gate.check()
        query = action.query | {param: args[key] for key, param in action.parameters.items() if key in args}
        target = action.path + (("?" + urlencode(query)) if query else "")
        request = Request(self.profile.origin + target, headers={"User-Agent": "Agent-Gateway/1.0",
                          "Accept": "text/html" if action.format == "html" else "application/json",
                          "Accept-Language": "en-US,en;q=0.9"})
        self.jar.add_cookie_header(request)
        if not request.has_header("Cookie"):
            raise _session_error()
        started = time.monotonic()
        prior_state = self._cookies()
        prior_secrets = len(self.seen_secrets)

        def receive(status, headers, stream):
            # Track rotated values before looking at the body; they may be echoed within it.
            rotating = headers.get_all("Set-Cookie", [])
            if sum(map(len, rotating)) > 60_000:
                raise ConnectorError("The website exceeded the session cookie limit.", "web_response_limit")
            for item in rotating:
                value = item.split(";", 1)[0].partition("=")[2].strip('"')
                if _COOKIE_VALUE.fullmatch(value):
                    self._remember(value)
            self.jar.extract_cookies(SimpleNamespace(info=lambda: headers), request)
            for cookie in list(self.jar):
                if not _COOKIE_NAME.fullmatch(cookie.name) or not _COOKIE_VALUE.fullmatch(cookie.value or ""):
                    self.jar.clear(cookie.domain, cookie.path, cookie.name)
            self._remember_cookies()
            current_state = self._cookies()
            if self.persist and (current_state != prior_state or len(self.seen_secrets) != prior_secrets):
                from ..credentials import SecretStoreError
                try:
                    self.persist(current_state, self.seen_secrets)
                except (OSError, SecretStoreError):
                    self.jar.clear()
                    raise ConnectorError("The updated browser session could not be saved.", "web_session_storage_failed") from None
            if status in (401, 403) or (300 <= status < 400 and re.search(
                    r"sign[-_]?in|login|captcha|challenge", headers.get("Location", "").split("?", 1)[0], re.I)):
                raise self.gate.refused()
            if 300 <= status < 400:
                raise ConnectorError("The site redirected the request. The redirect was blocked.", "web_redirect_refused")
            if status == 429:
                raise ConnectorError("The website is rate limiting this connection.", "connector_rate_limited")
            if status != 200:
                raise ConnectorError("The Web read returned HTTP " + str(status) + ".", "web_http_rejected")
            expected = "text/html" if action.format == "html" else "application/json"
            if headers.get_content_type() != expected or headers.get("Content-Encoding", "identity") != "identity":
                raise _shape_error()
            buffer = bytearray()
            while data := stream.read1(16384):
                buffer.extend(data)
                if len(buffer) > MAX_RESPONSE:
                    raise ConnectorError("The Web read exceeded the response size limit.", "web_response_limit")
                if time.monotonic() - started > 23:
                    raise TimeoutError()
            return bytes(buffer).decode("utf-8", errors="replace")

        try:
            page = self.fetch(self.host, target, dict(request.header_items()), receive)
        except TimeoutError:
            raise ConnectorError("The Web read timed out.", "connector_timeout") from None
        except ssl.SSLError:
            raise ConnectorError("The website TLS check failed.", "connector_tls_failed") from None
        except socket.gaierror:
            raise ConnectorError("The website's name could not be resolved.", "connector_dns_failed") from None
        except (OSError, http.client.HTTPException):
            raise ConnectorError("The website could not be reached.", "connector_network_failed") from None
        if any(marker.casefold() in page.casefold() for marker in action.reject):
            raise self.gate.refused()
        if action.expect and not any(marker.casefold() in page.casefold() for marker in action.expect):
            raise _shape_error()
        if action.format == "json":
            try:
                body = json.loads(page)
                if not isinstance(body, dict) or not set(action.json_fields) & body.keys():
                    raise _shape_error()
                rendered = json.dumps(_filter_json({k: body[k] for k in action.json_fields if k in body}), ensure_ascii=False)
            except (ValueError, RecursionError):
                raise _shape_error() from None
        else:
            parser = _VisibleText()
            parser.feed(page)
            parser.close()
            rendered = "\n".join(parser.parts)
            if not rendered:
                raise _shape_error()
        rendered = self._redact(rendered)
        if len(rendered) > MAX_TEXT:
            raise ConnectorError("The Web read exceeded the output limit.", "web_response_limit")
        return rendered

    def tools(self):
        return [Tool(name, action.description, lambda args, action=action: self.read(action, args),
                     {key: string("Identifier for " + key, 128, IDENTIFIER) for key in action.parameters},
                     tuple(action.required)) for name, action in self.profile.actions.items()]


def main():
    profile = WebProfile.model_validate_json(setting(PROFILE_ENV))
    session = SiteSession(profile, setting(SESSION_ENV))
    serve(urlsplit(profile.origin).hostname, session.tools())


if __name__ == "__main__":
    main()
