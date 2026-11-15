"""Member registration is initiated by a human administrator, not by MCP."""
import pytest
from mcp import MCPError

from helpers import TOKEN_HOUSE, agent, tool_names
from passkey_helpers import Authenticator, Page, request_id_in, wait_for_approval
from test_admin import admin_post, change, setup, state, web_gateway

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
            assert "gateway_call_tool" in await tool_names(shared)
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
