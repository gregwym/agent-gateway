"""Member registration is initiated by a human administrator, not by MCP."""
from hashlib import sha256

import pytest
from mcp import MCPError

from agent_gateway.approval import ApprovalRequest, arguments_digest
from helpers import TOKEN_HOUSE, agent, tool_names
from passkey_helpers import Authenticator, Page, request_id_in, wait_for_approval
from service_helpers import free_port
from test_admin import admin_post, change, login, setup, state, web_gateway

pytestmark = pytest.mark.anyio


async def test_admin_link_is_one_time_and_members_can_approve_without_an_admin_session(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        assert (await http.post("/admin/api/members/enroll", json={"id": "person_b"})).status_code == 401
        await setup(http, origin, path)
        added = await change(http, "members/add", name="Alex 林", household="household")
        assert added.status_code == 200, added.text
        member = added.json()["id"]
        reply = await http.post("/admin/api/members/enroll", json={"id": member})
        assert reply.status_code == 403 and reply.json()["error"] == "admin_confirmation_required"
        link = (await admin_post(http, "members/enroll", json={"id": member})).json()["url"]
        code = link.split("#", 1)[1]
        page = Page(origin, origin)
        member_key = Authenticator()
        assert await page.decide("enroll", code, member_key, origin=origin) == (200, {"action": "enroll"})
        assert await page.decide("enroll", code, Authenticator(), origin=origin) == (403, {"error": "invalid_enrollment_code"})
        assert any(k["principal"] == member for k in (await state(http))["passkeys"])
        async with agent(origin + "/mcp", TOKEN_HOUSE) as shared:
            assert "gateway_watch" in await tool_names(shared)
            for name, args in {
                "gateway_request_passkey": {"member": member},
                "gateway_wait_for_approval": {"request_id": "a" * 32},
            }.items():
                assert name not in await tool_names(shared)
                with pytest.raises(MCPError):
                    await shared.call_tool(name, args)
            note = await shared.call_tool("house_add_note", {"folder": "family", "text": "member approval"})
            note_id = request_id_in(note.content[0].text)
            assert (await page.decide("approve", note_id, member_key, origin=origin))[0] == 200
            assert (await wait_for_approval(shared, note_id)).content[1].text == "added"
        ceremony = (await http.post("/admin/api/auth/begin", json={"action": "login"})).json()
        denied = await http.post("/admin/api/auth/finish", json={
            "ceremony_id": ceremony["ceremony_id"], "response": member_key.response(ceremony, origin=origin)})
        assert denied.status_code == 403


async def test_upgrade_disables_legacy_agent_links_and_reviews_only(tmp_path):
    port = free_port()
    async with web_gateway(tmp_path, port=port) as (gw, http, origin, path):
        admin, _ = await setup(http, origin, path)
        approver = gw.gateway.approver
        good = (await admin_post(http, "members/enroll", json={"id": "person_b"})).json()["url"].split("#")[1]
        old = approver.new_enrollment("person_b").split("#")[1]
        client = next(c for c in gw.app.state.runtime.gateway.cfg.clients if c.id == "agent-a")
        args = {"member": "person_b"}
        request = ApprovalRequest(principal="person_b", client_id=client.id, tool="gateway_approve_passkey",
                                  connection="passkeys", service="passkey", account="person_b", upstream_tool="register",
                                  arguments_sha256=arguments_digest(args), arguments=args, owner="person_a",
                                  approvers=("person_a",), client_token_sha256=client.token_sha256)
        review_id = "r" * 32
        with approver._db() as db:
            db.execute("INSERT INTO enrollment_requests VALUES (?,?,?,?)",
                       (sha256(old.encode()).hexdigest(), client.id, client.token_sha256, "person_a"))
            approver._insert_request(db, review_id, request, int(request.created_at), int(request.expires_at))
            db.execute("INSERT INTO pending_credentials VALUES (?,?,?,?)", (review_id, b"legacy-key", b"suspended", 0))
        pending = await Page(origin, origin).begin("enroll", old)
        assert pending[0] == 200
    async with web_gateway(tmp_path, port=port, path=path) as (gw, http, origin, _):
        await login(http, admin, origin)
        page = Page(origin, origin)
        assert await page.begin("enroll", old) == (403, {"error": "invalid_enrollment_code"})
        assert await page.begin("approve", review_id) == (403, {"error": "stale_request"})
        assert (await page.view(review_id))[1]["status"] == "cancelled"
        assert (await page.decide("enroll", good, Authenticator(), origin=origin))[0] == 200
        assert {k["principal"] for k in (await state(http))["passkeys"]} == {"person_a", "person_b"}
