"""Bound-origin HTTP and GraphQL requests using a stored website session."""
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
from dataclasses import dataclass
from http.cookiejar import Cookie, CookieJar
from types import SimpleNamespace
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlsplit
from urllib.request import Request

from graphql import GraphQLError, OperationDefinitionNode, FragmentDefinitionNode, OperationType, parse

from ..web_profiles import PROFILE_ENV, SESSION_ENV, WEB_TOOLS, WebProfile
from ._base import ConnectorError, Tool, serve, setting, string

MAX_RESPONSE = 4 * 1024 * 1024
MAX_TEXT = 60_000
MAX_BODY = 128_000
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 4
_READ_METHODS = {"GET", "HEAD", "OPTIONS"}
_METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
_COOKIE_NAME = re.compile(r"^[a-zA-Z0-9!#$%&'*+.^_`|~-]{1,128}$")
_COOKIE_VALUE = re.compile(r"^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]{1,8192}$")
_TLS = ssl.create_default_context()


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


def _fetch(host, target, method, headers, body, receiver):
    with closing(_PublicHTTPS(host)) as connection:
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        return receiver(response.status, response.headers, response)


_HEADERS = {name.lower(): name for name in (
    "Accept", "Accept-Language", "Content-Type", "If-Match", "If-None-Match", "Range", "X-Requested-With",
)}
_PATH = r"^/(?!/)[\x21-\x7e]*$"
_MAX_QUERY = 16_384


@dataclass(frozen=True)
class RequestPlan:
    method: str
    target: str
    headers: dict[str, str]
    body: bytes | None
    access: str
    follow_redirects: bool = False


def _invalid(message):
    return ConnectorError(message, "web_invalid_request")


def _target(value):
    try:
        if (not isinstance(value, str) or len(value) > 4096 or not re.fullmatch(_PATH, value)
                or re.search(r"[#\\]|%(?![0-9a-fA-F]{2})", value)):
            raise ValueError()
        return urlsplit(value)
    except ValueError:
        raise _invalid("Use a relative path on the website, starting with a single slash.") from None


def _operation(document, name):
    try:
        if not isinstance(document, str) or not document or len(document) > _MAX_QUERY:
            raise ValueError()
        parsed = parse(document, no_location=True, max_tokens=2000)
        operations = [op for op in parsed.definitions if isinstance(op, OperationDefinitionNode)]
        names = [op.name.value if op.name else None for op in operations]
        if (not operations or len(set(names)) != len(names) or (len(names) > 1 and None in names)
                or any(not isinstance(node, (OperationDefinitionNode, FragmentDefinitionNode)) for node in parsed.definitions)):
            raise ValueError()
        if name is None and len(operations) == 1:
            return operations[0].operation
        if isinstance(name, str) and name in names:
            return operations[names.index(name)].operation
    except (GraphQLError, ValueError, RecursionError):
        pass
    raise _invalid("Provide a valid GraphQL document and select its operation if it has more than one.")


def _http_query(parts, is_read):
    try:
        parameters = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=150)
    except ValueError:
        raise _invalid("The HTTP path contains too many query parameters.") from None
    grouped = {}
    for key, value in parameters:
        folded = key.lower()
        if folded in ("_method", "_http_method", "x-http-method-override", "x-method-override"):
            raise _invalid("HTTP method overrides are not supported.")
        grouped.setdefault(folded, []).append(value)
    if not is_read:
        return
    # Standard GraphQL GET must never execute a mutation. Require the typed
    # tool for any executable document or named/persisted operation we detect
    # on this path, while allowing normal REST searches such as ?query=apples.
    if "operationname" in grouped or "extensions" in grouped or "persistedquery" in grouped:
        raise _invalid("Use graphql_request for GraphQL operations.")
    for value in grouped.get("query", ()):
        begin = re.sub(r"(?m)#[^\r\n]*", "", value).lstrip(",\ufeff \r\n\t")
        if re.match(r"(?:\{|(?:query|mutation|subscription|fragment)\b)", begin):
            raise _invalid("Use graphql_request for GraphQL operations.")


def _request_headers(values):
    if not isinstance(values, dict) or len(values) > len(_HEADERS):
        raise _invalid("Invalid HTTP request headers.")
    headers = {}
    for name, value in values.items():
        canonical = _HEADERS.get(name.lower())
        if (not canonical or canonical in headers or not isinstance(value, str)
                or not re.fullmatch(r"[\x20-\x7e]{1,1024}", value)):
            raise _invalid("Unsupported or invalid HTTP request header. The gateway supplies the session.")
        headers[canonical] = value
    return headers


def plan_request(tool, args):
    target = args.get("path")
    parts = _target(target)
    headers = _request_headers(args.get("headers", {}))
    body = None
    try:
        if tool == "http_request":
            method = args.get("method")
            if method not in _METHODS:
                raise _invalid("Unsupported HTTP method.")
            read = method in _READ_METHODS
            if args.get("follow_redirects") and method not in ("GET", "HEAD"):
                raise _invalid("Only HTTP GET and HEAD can follow redirects.")
            _http_query(parts, read)
            if "body" in args:
                if read:
                    raise _invalid("GET, HEAD and OPTIONS cannot include a request body.")
                body = args["body"].encode("utf-8")
        elif tool == "graphql_request":
            if "?" in target:
                raise _invalid("Use a GraphQL endpoint path without a URL query string.")
            document, name = args.get("query"), args.get("operation_name")
            operation = _operation(document, name)
            if operation == OperationType.SUBSCRIPTION:
                raise _invalid("GraphQL subscriptions are not supported.")
            method, read = "POST", operation == OperationType.QUERY
            payload = {"query": document}
            if name is not None:
                payload["operationName"] = name
            if "variables" in args:
                payload["variables"] = args["variables"]
            body = json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
            headers.setdefault("Accept", "application/graphql-response+json, application/json;q=0.9")
            headers["Content-Type"] = "application/json"
        else:
            raise _invalid("Unknown Web request tool.")
    except (ValueError, RecursionError):
        raise _invalid("The request body could not be encoded.") from None
    if body is not None and len(body) > MAX_BODY:
        raise _invalid("The request body is too large.")
    return RequestPlan(method, target, headers, body, "read" if read else "write",
                       bool(args.get("follow_redirects")) if tool == "http_request" else False)


def _same_origin_location(origin, current_path, locations):
    if len(locations) != 1:
        return None
    location = locations[0]
    if not re.fullmatch(r"[\x21-\x7e]{1,4096}", location) or "\\" in location:
        return None
    try:
        parts = urlsplit(urljoin(origin + current_path, location))
        if f"{parts.scheme}://{parts.netloc}" != origin:
            return None
        target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        _target(target)
        return target
    except (ValueError, ConnectorError):
        return None


def build_tools(handler=None):
    path = string("Relative path on the connection's website, starting with /. Percent-encode URL values.", 4096, _PATH)
    headers = {"type": "object", "maxProperties": len(_HEADERS), "description":
               "Optional HTTP headers: Accept, Accept-Language, Content-Type, If-Match, If-None-Match, Range, X-Requested-With. The session is supplied by the Gateway.",
               "additionalProperties": string("Header value", 1024, r"^[\x20-\x7e]+$")}
    http, graphql = WEB_TOOLS
    result = " Returns the HTTP status and text body. Cross-site redirects are blocked."
    redirects = (" Set follow_redirects=true on GET or HEAD to follow up to four same-site redirects, even when the "
                 "destination is hidden by credential redaction. Otherwise a safe relative location is returned if available.")
    return [
        Tool(http, "Make an HTTP request to the connection's website. GET, HEAD and OPTIONS are reads; POST, PUT, PATCH and DELETE are writes." + result + redirects,
             lambda args: handler(http, args),
             {"path": path, "method": {"type": "string", "enum": list(_METHODS)}, "headers": headers,
              "body": {"type": "string", "maxLength": MAX_BODY, "description": "Optional UTF-8 request body for write methods."},
              "follow_redirects": {"type": "boolean", "default": False, "description": "Follow same-site GET or HEAD redirects inside the Gateway."}},
             ("path", "method"), read_only=False),
        Tool(graphql, "Send a GraphQL request to the connection's website. A selected query is a read and a mutation is a write." + result,
             lambda args: handler(graphql, args),
             {"path": path, "query": {"type": "string", "minLength": 1, "maxLength": _MAX_QUERY}, "headers": headers,
              "operation_name": string("Operation to execute when the document contains multiple operations.", 128,
                                       r"^[_A-Za-z][_0-9A-Za-z]*$"),
              "variables": {"type": "object", "maxProperties": 100}},
             ("path", "query"), read_only=False),
    ]


class SiteSession:
    def __init__(self, profile, raw, *, fetch=None, persist=None, redactions=()):
        self.profile = profile
        self.host = urlsplit(profile.origin).hostname
        self.jar = CookieJar()
        self.fetch = fetch or _fetch
        self.persist = persist
        self.lock = threading.Lock()
        self.seen_secrets = set(redactions)
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

    def request(self, tool, arguments):
        plan = plan_request(tool, arguments)
        if not self.lock.acquire(timeout=2):
            raise ConnectorError("Another request is in progress for this website session.", "web_session_busy")
        try:
            return self._request(plan)
        finally:
            self.lock.release()

    def _request(self, plan):
        started = time.monotonic()
        target = plan.target
        visited = {target}
        while True:
            if time.monotonic() - started >= 23:
                raise ConnectorError("The Web request timed out.", "connector_timeout")
            result, location = self._request_hop(plan, target, started)
            if location is None or not plan.follow_redirects or result["status"] not in _REDIRECT_STATUSES:
                if len(visited) > 1:
                    result["redirects_followed"] = len(visited) - 1
                return result
            if location in visited:
                raise ConnectorError("The website repeated a redirect.", "web_redirect_loop")
            if len(visited) > _MAX_REDIRECTS:
                raise ConnectorError("The website exceeded the same-site redirect limit.", "web_redirect_limit")
            # A redirect is still a new request. Refuse method overrides or a
            # GraphQL operation hidden in a Location query string.
            _http_query(_target(location), is_read=True)
            target = location
            visited.add(target)

    def _request_hop(self, plan, target, started):
        request = Request(self.profile.origin + target, headers={
            "User-Agent": "Agent-Gateway/1.0", "Accept-Encoding": "identity",
            **plan.headers,
        }, method=plan.method)
        self.jar.clear_expired_cookies()
        if not len(self.jar):
            raise ConnectorError("The website session has expired. Sign in again.", "web_login_required")
        self.jar.add_cookie_header(request)
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
            content_type = headers.get_content_type()
            result = {"status": status, "content_type": self._redact(content_type), "body": ""}
            if fields := {name.lower(): self._redact(value) for name in ("ETag", "Last-Modified", "Content-Range")
                          if (value := headers.get(name)) and len(value) <= 1024}:
                result["headers"] = fields
            if 300 <= status < 400 and (locations := headers.get_all("Location", [])):
                location = _same_origin_location(self.profile.origin, target, locations)
                if location is None:
                    result["redirect_blocked"] = True
                elif self._redact(location) != location:
                    result["location_redacted"] = True
                else:
                    result["location"] = location
                return result, location
            if plan.method == "HEAD" or status in (204, 304):
                return result, None
            if headers.get("Content-Encoding", "identity").lower() != "identity":
                raise ConnectorError("The website returned an unsupported content encoding.", "web_response_encoding")
            if (not content_type.startswith("text/") and not content_type.endswith(("+json", "+xml"))
                    and content_type not in ("application/json", "application/xml", "application/javascript")):
                # Preserve the status of empty or binary responses, without
                # copying an opaque body that we cannot redact.
                result["body_omitted"] = True
                return result, None
            buffer = bytearray()
            while data := stream.read1(16384):
                buffer.extend(data)
                if len(buffer) > MAX_RESPONSE:
                    raise ConnectorError("The Web request exceeded the response size limit.", "web_response_limit")
                if time.monotonic() - started > 23:
                    raise TimeoutError()
            rendered = self._redact(bytes(buffer).decode("utf-8", errors="replace"))
            result["body"] = rendered[:MAX_TEXT]
            if len(rendered) > MAX_TEXT:
                result["truncated"] = True
            return result, None

        try:
            return self.fetch(self.host, target, plan.method, dict(request.header_items()), plan.body, receive)
        except TimeoutError:
            raise ConnectorError("The Web request timed out.", "connector_timeout") from None
        except ssl.SSLError:
            raise ConnectorError("The website TLS check failed.", "connector_tls_failed") from None
        except socket.gaierror:
            raise ConnectorError("The website's name could not be resolved.", "connector_dns_failed") from None
        except (OSError, http.client.HTTPException):
            raise ConnectorError("The website could not be reached.", "connector_network_failed") from None

    def tools(self):
        return build_tools(self.request)


def main():
    profile = WebProfile.saved(setting(PROFILE_ENV))
    session = SiteSession(profile, setting(SESSION_ENV))
    serve(urlsplit(profile.origin).hostname, session.tools())


if __name__ == "__main__":
    main()
