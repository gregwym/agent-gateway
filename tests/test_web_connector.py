"""Simulated retailer pages: real Gateway permissions and file-backed session rotation."""
import json
import socket
from email.message import Message
from io import BytesIO

import pytest

from agent_gateway.connectors import web
from agent_gateway.web_profiles import SESSION_ENV, bundled_profiles
from helpers import TOKEN_A
from test_admin import change, rpc, setup, state, web_gateway


def response(receive, body=b'', *, status=200, rotate=None, location=None):
    headers = Message()
    headers["Content-Type"] = "text/html; charset=utf-8"
    if rotate:
        headers["Set-Cookie"] = f"auth={rotate}; Secure; HttpOnly; Path=/"
    if location:
        headers["Location"] = location
    return receive(status, headers, BytesIO(body))


@pytest.mark.parametrize("plugin,host,marker,path,query", [
    ("amazon-us", "www.amazon.com", 'id="ordersContainer"', "/your-orders/orders", {"start_index": "10"}),
    ("weee-orders", "www.weee.com", 'class="order-list"', "/en/account/my_orders", {}),
])
@pytest.mark.anyio
async def test_retail_profile_isolation_renewal_and_permissions(tmp_path, monkeypatch, plugin, host, marker, path, query):
    calls = []
    alpha = "alpha-private-cookie"
    bravo = "bravo-private-cookie"
    rotated = "rotated-private-cookie"

    def fake_fetch(hostname, target, headers, receive):
        assert hostname == host and target.split("?", 1)[0] == path
        assert "unrelated-private-cookie" not in str(headers)
        auth = headers["Cookie"]
        calls.append((target, auth))
        if auth == "auth=" + bravo:
            return response(receive, status=302, location="https://cross-origin.example/session")
        assert auth in ["auth=" + alpha, "auth=" + rotated]
        return response(receive, f"""
            <main {marker}><p>Rice and apples</p><p>{alpha} {rotated}</p>
            <script>hidden-script-credential</script><span hidden>hidden-field-value</span>
            <input value="hidden-input-value"></main>
        """.encode(), rotate=rotated)

    monkeypatch.setattr(web, "_fetch", fake_fetch)
    port, cfg_path = None, None
    for restarting in (False, True):
        async with web_gateway(tmp_path, path=cfg_path, port=port) as (gw, http, origin, cfg_file):
            if not restarting:
                cfg_path = cfg_file
                port = int(origin.rsplit(":", 1)[-1])
                key, _ = await setup(http, origin, cfg_file)
                for name, cookie in [("web-a", alpha), ("web-b", bravo)]:
                    creds = {"cookies": [{"domain": host, "name": "auth", "value": cookie},
                                         {"domain": "unrelated.example", "name": "auth", "value": "unrelated-private-cookie"}]}
                    body = dict(id=name, kind="web", owner="person_a", settings={"plugin": plugin},
                                credentials={SESSION_ENV: json.dumps(creds)})
                    test = await change(http, "connections/preview", **{
                        **body, "credentials": {SESSION_ENV: json.dumps({"cookies": creds["cookies"][1:]})}})
                    assert test.json()["error"] == "web_session_invalid"
                    review = await change(http, "connections/preview", **body)
                    assert review.status_code == 200, review.text
                    preview = review.json()
                    assert preview["read_only"] and not calls
                    assert all(tool["access"] == "read" for tool in preview["tools"])
                    selection = dict(draft=preview["draft"], reviewed=True, tools=preview["tools"])
                    invalid = await change(http, "connections/apply", **{**selection, "tools": [
                        {**preview["tools"][0], "access": "write"}]})
                    assert invalid.json()["error"] == "invalid_remote_tool_selection"
                    assert (await change(http, "connections/apply", **selection)).status_code == 200
                    config = await state(http)
                    conn = next(c for c in config["connections"] if c["id"] == name)
                    assert conn["access"]["agent-a"] == "none"
                    assert cookie not in str(config) + review.text
                    tool = next(t["name"] for t in conn["tools"] if t["upstream"] == "list_orders")
                    denied = await rpc(origin, TOKEN_A, "tools/call", {"name": tool, "arguments": {}})
                    assert denied.json()["error"]
                assert not calls
                assert (await change(http, "permissions/connection", connection="web-a", client="agent-a", access="read")).status_code == 200
                assert (await change(http, "connections/test", id="web-a")).status_code == 200
                assert calls == [(path, "auth=" + alpha)]
                failed = await change(http, "connections/test", id="web-b")
                assert failed.json()["error"] == "web_redirect_refused"
                conn = next(c for c in (await state(http))["connections"] if c["id"] == "web-a")
                tool = next(t["name"] for t in conn["tools"] if t["upstream"] == "list_orders")
                assert (await rpc(origin, TOKEN_A, "tools/call", {"name": tool, "arguments": {"url": "https://evil.example/"}})).json()["result"]["isError"]
                assert calls == [(path, "auth=" + alpha), (path, "auth=" + bravo)]
                assert rotated.encode() not in (tmp_path / "admin.enc.web-sessions").read_bytes()
            else:
                from test_admin import login
                await login(http, key, origin)
            result = (await rpc(origin, TOKEN_A, "tools/call", {"name": tool, "arguments": query})).json()["result"]
            assert not result.get("isError"), result
            combined = str(result) + gw.audit_text()
            assert "Rice and apples" in combined
            assert all(value not in combined for value in (alpha, bravo, rotated, "hidden-script-credential",
                                                            "hidden-input-value", "hidden-field-value"))
            assert calls[-1] == (path + ("?startIndex=10" if query else ""), "auth=" + rotated)
            if restarting:
                assert (await change(http, "connections/remove", id="web-a")).status_code == 200
                assert not gw.app.state.admin.web_sessions.file.names()


def test_non_public_dns_answer_is_refused_before_connect(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))])
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: pytest.fail("attempted a private connection"))
    with pytest.raises(web.ConnectorError) as exc:
        web._public_socket(("www.amazon.com", 443), 1, None)
    assert exc.value.code == "web_unsafe_address"


def test_unknown_page_and_login_failure_are_distinct():
    profile = bundled_profiles()["amazon-us"][1]
    raw = web.import_session('[{"name":"auth","value":"private-test","domain":".amazon.com"}]', profile)
    wrong = web.SiteSession(profile, raw, fetch=lambda h, t, headers, recv: response(recv, b'<main>Changed page</main>'))
    expired = web.SiteSession(profile, raw, fetch=lambda h, t, headers, recv: response(recv, status=302, location='/ap/signin'))
    expected = profile.actions["list_orders"]
    for session, code in [(wrong, "web_profile_mismatch"), (expired, "web_login_required")]:
        with pytest.raises(web.ConnectorError) as exc:
            session.read(expected, {})
        assert exc.value.code == code
