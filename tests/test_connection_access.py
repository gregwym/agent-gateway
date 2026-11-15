"""Connection presets enforce reads/writes and delegated, one-use approvals."""
import pytest
from dataclasses import replace

from agent_gateway.approval import ApprovalRequest, arguments_digest
from agent_gateway.admin_config import tool_access
from agent_gateway.config import ConnectionCfg, ToolCfg
from helpers import TOKEN_A, TOKEN_HOUSE
from passkey_helpers import Authenticator, Page, request_id_in
from test_admin import change, rpc, setup, state, web_gateway

pytestmark = pytest.mark.anyio


async def enroll(http, origin, member):
    key = Authenticator()
    url = (await http.post('/admin/api/members/enroll', json={'id': member})).json()['url']
    ceremony = (await http.post('/approvals/api/begin', json={'action': 'enroll', 'target': url.split('#')[1]})).json()
    reply = await http.post('/approvals/api/finish', json={'ceremony_id': ceremony['ceremony_id'], 'response': key.response(ceremony, origin=origin)})
    assert reply.status_code == 200
    return key


async def test_connection_presets_are_atomic_isolated_and_do_not_invent_writes(tmp_path, monkeypatch):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        before_a = (await rpc(origin, TOKEN_A)).json()['result']['tools']
        response = await change(http, 'permissions/connection', client='shared-agent', connection='notes-a', access='read')
        assert response.status_code == 200, response.text
        listed = {t['name'] for t in (await rpc(origin, TOKEN_HOUSE)).json()['result']['tools']}
        assert {'a_list_notes', 'a_get_note', 'a_family_notes'} <= listed
        assert 'a_add_note' not in listed and 'a_debug_dump' not in listed
        assert (await rpc(origin, TOKEN_A)).json()['result']['tools'] == before_a
        denied = await rpc(origin, TOKEN_HOUSE, 'tools/call', {'name': 'a_add_note', 'arguments': {'folder': 'inbox', 'text': 'never written'}})
        assert denied.json()['error']['code'] == -32602
        before = await state(http)
        def failed(_):
            raise OSError('failed')
        with monkeypatch.context() as patch:
            patch.setattr(gw.app.state.admin.store, 'save', failed)
            assert (await change(http, 'permissions/connection', client='shared-agent', connection='notes-a', access='none')).status_code == 500
        assert (await state(http))['connections'] == before['connections']
        assert (await change(http, 'permissions/connection', client='shared-agent', connection='notes-a', access='none')).status_code == 200
        assert not any(t['name'].startswith('a_') for t in (await rpc(origin, TOKEN_HOUSE)).json()['result']['tools'])
        preview = await change(http, 'connections/preview', id='mail', kind='imap', owner='person_a',
                               settings={'username': 'fake@example.test', 'host': '127.0.0.1', 'port': '1'}, credentials={'password': 'fake-password-for-classification'})
        assert preview.status_code == 200
        assert (await change(http, 'connections/apply', draft=preview.json()['draft'], reviewed=True)).status_code == 200
        assert (await change(http, 'permissions/connection', client='shared-agent', connection='mail', access='read_write')).status_code == 200
        assert (await change(http, 'permissions/connection', client='shared-agent', connection='mail', access='read_write_direct')).status_code == 200
        assert (await change(http, 'permissions/connection', client='shared-agent', connection='mail', access='read')).status_code == 200
        mail = next(c for c in (await state(http))['connections'] if c['id'] == 'mail')
        assert mail['access']['shared-agent'] == 'read'
        assert {t['upstream'] for t in mail['tools'] if t['access'] == 'write'} == {'set_message_state', 'move_messages', 'archive_messages', 'trash_messages', 'send_message'}
        assert all(t['permissions']['shared-agent'] == ('allow' if t['access'] == 'read' else 'deny') for t in mail['tools'])


async def test_direct_write_mode_needs_no_approval_and_is_scoped_to_one_agent(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        result = await change(http, 'permissions/connection', client='shared-agent', connection='notes-a', access='read_write_direct')
        assert result.status_code == 200, result.text
        conn = next(c for c in (await state(http))['connections'] if c['id'] == 'notes-a')
        assert conn['access']['shared-agent'] == 'read_write_direct'
        assert all(t['permissions']['shared-agent'] == 'allow' for t in conn['tools'])
        args = {'folder': 'inbox', 'text': 'explicitly permitted direct write'}
        for _ in range(2):
            response = (await rpc(origin, TOKEN_HOUSE, 'tools/call', {'name': 'a_add_note', 'arguments': args})).json()
            assert not response['result'].get('isError')
        assert gw.app.state.runtime.gateway.approver.requests() == []
        other = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'a_add_note', 'arguments': args})).json()
        assert other['result']['isError'] and request_id_in(other['result']['content'][0]['text'])
        assert (await change(http, 'permissions/connection', client='shared-agent', connection='notes-a', access='read_write', approver='person_a')).status_code == 200
        gated = (await rpc(origin, TOKEN_HOUSE, 'tools/call', {'name': 'a_add_note', 'arguments': args})).json()
        assert gated['result']['isError'] and request_id_in(gated['result']['content'][0]['text'])


async def test_read_approval_is_independent_of_write_approval(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        owner, _ = await setup(http, origin, path)
        page = Page(origin, origin)
        assert (await change(http, 'permissions/connection', client='shared-agent', connection='notes-a', access='read_approval', approver='person_a')).status_code == 200
        read = {'name': 'a_list_notes', 'arguments': {'folder': 'inbox'}}
        pending = (await rpc(origin, TOKEN_HOUSE, 'tools/call', read)).json()
        request_id = request_id_in(pending['result']['content'][0]['text'])
        assert (await page.decide('approve', request_id, owner, origin=origin))[0] == 200
        assert not (await rpc(origin, TOKEN_HOUSE, 'tools/call', read)).json()['result'].get('isError')
        again = (await rpc(origin, TOKEN_HOUSE, 'tools/call', read)).json()
        assert request_id_in(again['result']['content'][0]['text']) != request_id
        write = {'name': 'a_add_note', 'arguments': {'folder': 'inbox', 'text': 'independently controlled writes'}}
        assert (await rpc(origin, TOKEN_HOUSE, 'tools/call', write)).json()['error']['code'] == -32602
        conn = next(c for c in (await state(http))['connections'] if c['id'] == 'notes-a')
        assert conn['access']['shared-agent'] == 'read_approval'
        assert (await change(http, 'permissions/connection', client='shared-agent', connection='notes-a', access='read_write_approval', approver='person_a')).status_code == 200
        conn = next(c for c in (await state(http))['connections'] if c['id'] == 'notes-a')
        assert conn['access']['shared-agent'] == 'read_write_approval'
        assert all(t['permissions']['shared-agent'] == 'approval_required' for t in conn['tools'])
        gated_write = (await rpc(origin, TOKEN_HOUSE, 'tools/call', write)).json()
        assert request_id_in(gated_write['result']['content'][0]['text'])
        assert (await change(http, 'permissions/connection', client='shared-agent', connection='notes-a', access='read_approval_write_direct', approver='person_a')).status_code == 200
        conn = next(c for c in (await state(http))['connections'] if c['id'] == 'notes-a')
        assert conn['access']['shared-agent'] == 'read_approval_write_direct'
        assert not (await rpc(origin, TOKEN_HOUSE, 'tools/call', write)).json()['result'].get('isError')
        gated_read = (await rpc(origin, TOKEN_HOUSE, 'tools/call', read)).json()
        assert request_id_in(gated_read['result']['content'][0]['text'])


async def test_delegate_approval_to_member_or_household_without_changing_owner(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        owner, _ = await setup(http, origin, path)
        delegate = await enroll(http, origin, 'person_b')
        result = await change(http, 'permissions/connection', client='shared-agent', connection='notes-a', access='read_write', approver='person_b')
        assert result.status_code == 200, result.text
        conn = next(c for c in (await state(http))['connections'] if c['id'] == 'notes-a')
        assert conn['owner'] == 'person_a' and conn['approvers'] == ['person_b'] and conn['access']['shared-agent'] == 'read_write'
        assert (await change(http, 'members/remove', id='person_b')).json()['error'] == 'member_is_approver'
        args = {'folder': 'inbox', 'text': 'delegated write'}
        page = Page(origin, origin)
        async def request():
            reply = (await rpc(origin, TOKEN_HOUSE, 'tools/call', {'name': 'a_add_note', 'arguments': args})).json()
            return request_id_in(reply['result']['content'][0]['text'])
        pending = await request()
        assert (await page.decide('approve', pending, owner, origin=origin))[0] == 403
        assert (await page.decide('approve', pending, delegate, origin=origin))[0] == 200
        result = (await rpc(origin, TOKEN_HOUSE, 'tools/call', {'name': 'a_add_note', 'arguments': args})).json()
        assert not result['result'].get('isError')
        second = await request()
        assert second != pending
        assert (await change(http, 'permissions/connection', client='shared-agent', connection='notes-a', access='read_write', approver='household')).status_code == 200
        assert (await page.view(second))[1]['status'] == 'cancelled'
        third = await request()
        assert set((await page.view(third))[1]['approvers']) == {'person_a', 'person_b'}
        assert (await page.decide('approve', third, owner, origin=origin))[0] == 200
        assert not (await rpc(origin, TOKEN_HOUSE, 'tools/call', {'name': 'a_add_note', 'arguments': args})).json()['result'].get('isError')
        assert (await change(http, 'permissions/connection', client='shared-agent', connection='notes-a', access='read_write', approver='missing')).json()['error'] == 'invalid_connection_approver'
        # Editing the connector must preserve its independent approval authority.
        preview = await change(http, 'connections/preview', id='notes-a', kind='demo', owner='person_a')
        assert preview.status_code == 200
        assert (await change(http, 'connections/apply', draft=preview.json()['draft'], reviewed=True)).status_code == 200
        conn = next(c for c in (await state(http))['connections'] if c['id'] == 'notes-a')
        assert conn['approver'] == 'household' and conn['owner'] == 'person_a'


def test_custom_tools_are_not_assumed_readonly():
    conn = ConnectionCfg(id='custom', service='custom', account='a', owner='person_a', transport='stdio', command=['untrusted-tool'], tools=[])
    assert tool_access(conn, ToolCfg(name='looks_like_a_read', upstream='get_everything')) == 'write'
    assert tool_access(conn, ToolCfg(name='reviewed_read', upstream='fetch', access='read')) == 'read'


async def test_changing_authority_invalidates_a_grant_even_without_web_revision(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        owner, _ = await setup(http, origin, path)
        await enroll(http, origin, 'person_b')
        args = {'folder': 'inbox', 'text': 'authority must still match'}
        request = ApprovalRequest(principal='household', client_id='shared-agent', tool='a_add_note',
            connection='notes-a', service='notes', account='person_a', upstream_tool='add_note',
            arguments=args, arguments_sha256=arguments_digest(args), owner='person_a', approvers=('person_a',))
        approver = gw.app.state.runtime.gateway.approver
        first = await approver.authorize(request)
        page = Page(origin, origin)
        assert (await page.decide('approve', first.approval_id, owner, origin=origin))[0] == 200
        second = await approver.authorize(replace(request, approvers=('person_b',)))
        assert not second.approved and second.approval_id != first.approval_id
        assert (await page.view(first.approval_id))[1]['status'] == 'cancelled'
        assert (await page.view(second.approval_id))[1]['approvers'] == ['person_b']
