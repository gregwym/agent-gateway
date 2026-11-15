"""Administrative changes keep live connector pagination, but revoke access immediately."""
import json
import time

import anyio
import httpx2
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


async def test_connector_saves_with_mcp_listener_and_stalled_post(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        headers = {'Authorization': 'Bearer ' + TOKEN_A, 'Accept': 'text/event-stream'}
        listener = await http.get('/mcp', headers=headers, timeout=3)
        assert listener.status_code == 405

        started, release = anyio.Event(), anyio.Event()
        responses = []

        async def body():
            started.set()
            await release.wait()
            yield b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

        async def stalled_request():
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=gw.app), base_url=origin) as client:
                responses.append(await client.post('/mcp', content=body(), headers={
                    **headers, 'Accept': 'application/json, text/event-stream', 'Content-Type': 'application/json'}))

        with anyio.fail_after(10):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(stalled_request)
                await started.wait()
                saved = await change(http, 'connections/save', kind='imap', id='mail', owner='person_a',
                                     settings={'username':'demo@example.test'}, credentials={'password':'fake-password'})
                assert saved.status_code == 200 and saved.json()['saved'], saved.text
                rotated = await change(http, 'clients/rotate', id='agent-a')
                assert rotated.status_code == 200, rotated.text
                release.set()
        assert responses[0].json()['error']['message'] == 'Not authenticated'
        assert (await rpc(origin, TOKEN_A)).status_code == 401
        assert (await rpc(origin, rotated.json()['token'])).status_code == 200


async def test_permission_change_waits_for_a_running_tool(tmp_path, monkeypatch):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        runtime = gw.app.state.runtime
        upstream = runtime.gateway.upstreams['notes-a']
        original = upstream.call
        started, release = anyio.Event(), anyio.Event()
        calls, saves = [], []

        async def held_call(*args):
            started.set()
            await release.wait()
            return await original(*args)

        async def call():
            calls.append(await rpc(origin, TOKEN_A, 'tools/call', {'name':'a_whoami','arguments':{}}))

        async def save():
            saves.append(await change(http, 'permissions/connection', client='agent-a', connection='notes-a', access='none'))

        monkeypatch.setattr(upstream, 'call', held_call)
        with anyio.fail_after(10):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(call)
                await started.wait()
                tasks.start_soon(save)
                while not runtime.changing:
                    await anyio.sleep(0.01)
                assert not saves
                release.set()
        assert 'person_a' in calls[0].json()['result']['content'][0]['text']
        assert saves[0].status_code == 200
        await call()
        assert 'error' in calls[1].json()
