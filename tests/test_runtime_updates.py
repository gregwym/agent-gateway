"""Administrative changes keep live connector pagination, but revoke access immediately."""
import json
import time

import pytest

from helpers import TOKEN_A, prepare
from passkey_helpers import approval_config
from service_helpers import free_port, mail_account
from test_admin import change, rpc, setup, state, web_gateway
from test_connector_mail import fill, message
from test_imap_operations import extended_connection

pytestmark = pytest.mark.anyio


async def test_permissions_keep_imap_cursor_and_revocation_takes_effect(tmp_path):
    with mail_account(tmp_path / 'mail', 'fake@example.test', 'fake-password') as account:
        fill(account, *(message(f'cursor {n}', 'from@example.test', account.user, 'body') for n in range(3)))
        port = free_port()
        raw = approval_config(origin=f'http://localhost:{port}')
        raw['admin'] = {'owner': 'person_a', 'state': 'admin.enc'}
        conn = extended_connection(account)
        raw['connections'] = [conn]
        raw['policy'] = [{'principals': ['person_a'], 'connection': conn['id'], 'tools': [t['name'] for t in conn['tools']], 'effect': 'allow'}]
        path = await prepare(tmp_path / 'gateway', raw, secrets={'mail_password': account.password})
        async with web_gateway(tmp_path / 'gateway', path=path, port=port) as (gw, http, origin, path):
            await setup(http, origin, path)
            first = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'mail_list_messages', 'arguments': {'limit': 1, 'subject': 'cursor'}})).json()['result']
            cursor = json.loads(first['content'][0]['text'])['next_cursor']
            assert cursor
            before = gw.app.state.runtime.gateway.upstreams[conn['id']]
            assert (await change(http, 'permissions/connection', client='agent-a', connection=conn['id'], access='read')).status_code == 200
            assert gw.app.state.runtime.gateway.upstreams[conn['id']] is before
            next_page = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'mail_list_messages', 'arguments': {'cursor': cursor}})).json()['result']
            assert not next_page.get('isError')
            assert len(json.loads(next_page['content'][0]['text'])['results']) == 2
            assert (await change(http, 'permissions/connection', client='agent-a', connection=conn['id'], access='none')).status_code == 200
            denied = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'mail_list_messages', 'arguments': {}})).json()
            assert denied['error']['code'] == -32602


async def test_busy_admin_queue_has_bounded_actionable_error(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        revision = (await state(http))['revision']
        async with gw.app.state.admin.mutex:
            started = time.monotonic()
            reply = await http.post('/admin/api/permissions/connection', json={'revision': revision, 'client': 'agent-a', 'connection': 'notes-a', 'access': 'none'}, timeout=10)
            assert reply.status_code == 409 and reply.json()['error'] == 'admin_busy'
            assert time.monotonic() - started < 7
        assert (await state(http))['revision'] == revision
