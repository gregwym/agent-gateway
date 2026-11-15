"""Agent names change without replacing credentials or losing grants."""
import pytest

from helpers import TOKEN_A
from passkey_helpers import request_id_in
from service_helpers import free_port
from test_admin import change, login, rpc, setup, state, web_gateway

pytestmark = pytest.mark.anyio


async def test_rename_preserves_token_grants_restart_and_rejects_old_approvals(tmp_path):
    port = free_port()
    async with web_gateway(tmp_path, port=port) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        before = await state(http)
        agent = next(c for c in before['clients'] if c['id'] == 'agent-a')
        tools = (await rpc(origin, TOKEN_A)).json()['result']['tools']
        args = {'folder': 'inbox', 'text': 'approval must not transfer across renamed identities'}
        pending = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'a_add_note', 'arguments': args})).json()
        request_id = request_id_in(pending['result']['content'][0]['text'])
        changed = await change(http, 'clients/rename', id='agent-a', name='openclaw')
        assert changed.status_code == 200 and changed.json()['id'] == 'openclaw'
        after = await state(http)
        assert next(c for c in after['clients'] if c['id'] == 'openclaw') == {**agent, 'id': 'openclaw'}
        assert (await rpc(origin, TOKEN_A)).json()['result']['tools'] == tools
        assert (await http.get('/approvals/api/request/' + request_id)).json()['status'] == 'cancelled'
        for old, new in zip(before['connections'], after['connections']):
            for a, b in zip(old['tools'], new['tools']):
                assert b['permissions']['openclaw'] == a['permissions']['agent-a']
                assert 'agent-a' not in b['permissions']
        recreated = await change(http, 'clients/create', id='agent-a', household='household')
        assert {t['name'] for t in (await rpc(origin, recreated.json()['token'])).json()['result']['tools']} == {'gateway_wait_for_approval', 'gateway_request_passkey'}
        assert (await rpc(origin, TOKEN_A)).json()['result']['tools'] == tools
    async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, path):
        await login(http, key, origin)
        assert any(c['id'] == 'openclaw' for c in (await state(http))['clients'])
        assert (await rpc(origin, TOKEN_A)).json()['result']['tools'] == tools


async def test_rename_validation_csrf_stale_revision_and_failed_save(tmp_path, monkeypatch):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        assert (await http.post('/admin/api/clients/rename', json={'id': 'agent-a', 'name': 'openclaw', 'revision': 0})).status_code == 401
        await setup(http, origin, path)
        before = await state(http)
        for name in ('', 'Open Claw', 'x' * 49, None, []):
            reply = await change(http, 'clients/rename', id='agent-a', name=name)
            assert reply.status_code == 400 and reply.json()['error'] == 'invalid_client_name'
        assert (await change(http, 'clients/rename', id='agent-a', name='agent-b')).json()['error'] == 'duplicate_client'
        assert (await change(http, 'clients/rename', id='missing', name='openclaw')).status_code == 404
        assert (await change(http, 'clients/rename', id='agent-a', name='openclaw', revision=999)).status_code == 409
        assert (await http.post('/admin/api/clients/rename', json={'id': 'agent-a', 'name': 'openclaw', 'revision': 0}, headers={'X-CSRF-Token': ''})).status_code == 403
        assert (await change(http, 'clients/rename', id='agent-a', name='agent-a')).json()['revision'] == before['revision']
        def failure(_):
            raise OSError('disk unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(gw.app.state.admin.store, 'save', failure)
            assert (await change(http, 'clients/rename', id='agent-a', name='openclaw')).status_code == 500
        assert (await state(http))['clients'] == before['clients']
        assert (await rpc(origin, TOKEN_A)).status_code == 200
