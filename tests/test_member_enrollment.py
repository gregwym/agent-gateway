"""A family member registers a key without a management session."""
import pytest

from helpers import TOKEN_A, TOKEN_HOUSE, agent
from passkey_helpers import Authenticator, Page, request_id_in, wait_for_approval
from test_admin import change, rpc, setup, state, web_gateway

pytestmark = pytest.mark.anyio


async def test_agent_can_request_member_passkey_but_only_admin_can_activate(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        admin, _ = await setup(http, origin, path)
        assert (await change(http, "members/rename", id="person_b", name="Alex 林")).status_code == 200
        page = Page(origin, origin)
        member_key = Authenticator()
        async with agent(origin + "/mcp", TOKEN_A) as requester, agent(origin + "/mcp", TOKEN_HOUSE) as shared:
            assert (await requester.call_tool("gateway_request_passkey", {"member": "person_a"})).is_error
            link = (await requester.call_tool("gateway_request_passkey", {"member": "Alex 林"})).structured_content["enrollment_url"]
            code = link.split("#", 1)[1]
            status, pending = await page.decide("enroll", code, member_key, origin=origin)
            assert status == 200 and pending["pending"]
            assert await page.decide("enroll", code, Authenticator(), origin=origin) == (403, {"error": "invalid_enrollment_code"})
            review_id = pending["request_id"]
            members = await state(http)
            assert [r["url"] for r in members["passkey_reviews"]] == [pending["approval_url"]]
            assert not any(k["principal"] == "person_b" for k in members["passkeys"])
            note = await shared.call_tool("house_add_note", {"folder": "family", "text": "member approval"})
            note_id = request_id_in(note.content[0].text)
            assert await page.decide("approve", note_id, member_key, origin=origin) == (403, {"error": "verification_failed"})
            assert await page.decide("approve", review_id, member_key, origin=origin) == (403, {"error": "verification_failed"})
            assert (await page.decide("approve", review_id, admin, origin=origin))[0] == 200
            assert (await wait_for_approval(requester, review_id)).structured_content["status"] == "succeeded"
            assert any(k["principal"] == "person_b" for k in (await state(http))["passkeys"])
            assert (await page.decide("approve", note_id, member_key, origin=origin))[0] == 200
            assert (await wait_for_approval(shared, note_id)).content[1].text == "added"
            # The registered member can approve operations, but cannot open the admin console.
            denied = await http.post("/admin/api/auth/begin", json={"action": "login"})
            ceremony = denied.json()
            denied = await http.post("/admin/api/auth/finish", json={
                "ceremony_id": ceremony["ceremony_id"], "response": member_key.response(ceremony, origin=origin)})
            assert denied.status_code == 403


async def test_replacing_agent_token_invalidates_unfinished_member_link(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        response = await rpc(origin, TOKEN_A, "tools/call", {"name": "gateway_request_passkey",
                                                            "arguments": {"member": "person_b"}})
        link = response.json()["result"]["structuredContent"]["enrollment_url"]
        assert (await change(http, "clients/rotate", id="agent-a")).status_code == 200
        assert await Page(origin, origin).begin("enroll", link.split("#", 1)[1]) == (403, {"error": "invalid_enrollment_code"})
