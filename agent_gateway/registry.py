"""Browse the public MCP Registry without contacting the listed servers."""
import hashlib
import json
import re

import anyio
import httpx2

from .oauth import https_url
from .passkey import Refused

URL = "https://registry.modelcontextprotocol.io/v0.1/servers"
OFFICIAL = "io.modelcontextprotocol.registry/official"
MAX_RESPONSE = 2_000_000

# Authentication is not a standard Registry field. Use provider documentation
# for these exact endpoints, and ask the administrator for all other entries.
AUTH = {
    "https://ai.todoist.net/mcp": ("oauth", "https://developer.todoist.com/api/v1/#todoist-mcp"),
    "https://mcp.notion.com/mcp": ("oauth", "https://developers.notion.com/guides/mcp/get-started-with-mcp"),
    "https://mcp.linear.app/mcp": ("oauth", "https://linear.app/docs/mcp"),
    "https://mcp.linear.app/mcp/readonly": ("oauth", "https://linear.app/docs/mcp"),
    "https://api.githubcopilot.com/mcp/": ("bearer", "https://docs.github.com/en/copilot/how-tos/provide-context/use-mcp-in-your-ide/set-up-the-github-mcp-server"),
}


def _http():
    return httpx2.AsyncClient(trust_env=False, follow_redirects=False, timeout=7)


def _results(data):
    results = []
    for entry in data["servers"]:
        status = entry["_meta"][OFFICIAL]["status"]
        if status != "active":
            continue
        server = entry["server"]
        name = server["name"]
        if not isinstance(name, str) or not 1 <= len(name) <= 255:
            continue
        slug = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")
        digest = hashlib.sha256(name.encode()).hexdigest()[:10]
        service = f"mcp-{slug[:32]}-{digest}"
        title = server.get("title") or name
        description = server.get("description") or ""
        urls = set()
        for remote in server.get("remotes") or []:
            url = remote.get("url")
            if remote.get("type") != "streamable-http" or not isinstance(url, str) or len(url) > 2048:
                continue
            # Templated URLs need additional information from the provider.
            if url in urls or any(char in url for char in "{}\\"):
                continue
            try:
                https_url(url)
            except Refused:
                continue
            urls.add(url)
            auth, docs = AUTH.get(url, (None, None))
            results.append({"name": name, "title": title[:200], "description": description[:300],
                            "url": url, "service": service, "auth": auth, "docs": docs})
    return results


async def search(body):
    query, cursor = body.get("query"), body.get("cursor")
    if not isinstance(query, str) or not 3 <= len(query.strip()) <= 100:
        raise Refused("registry_query_invalid", 400)
    if cursor is not None and (not isinstance(cursor, str) or not 1 <= len(cursor) <= 2048):
        raise Refused("registry_cursor_invalid", 400)
    params = {"search": query.strip(), "version": "latest", "limit": "30"}
    if cursor:
        params["cursor"] = cursor
    try:
        with anyio.fail_after(8):
            async with _http() as http:
                async with http.stream("GET", URL, params=params, headers={"Accept": "application/json"}) as response:
                    if response.status_code == 429:
                        raise Refused("registry_rate_limited", 503)
                    response.raise_for_status()
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > MAX_RESPONSE:
                            raise Refused("registry_response_invalid", 502)
        data = json.loads(raw)
        next_cursor = data["metadata"].get("nextCursor")
        if next_cursor is not None and (not isinstance(next_cursor, str) or len(next_cursor) > 2048):
            raise ValueError()
        return {"results": _results(data), "next_cursor": next_cursor or None}
    except (TimeoutError, httpx2.TimeoutException):
        raise Refused("registry_timeout", 504) from None
    except httpx2.HTTPError:
        raise Refused("registry_unavailable", 502) from None
    except (ValueError, TypeError, KeyError, AttributeError):
        raise Refused("registry_response_invalid", 502) from None
