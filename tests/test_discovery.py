"""Fixed discovery entry points, actual MCP clients, isolated account processes."""
import json

import pytest
from mcp import MCPError

from helpers import TOKEN_A, TOKEN_B, TOKEN_HOUSE, agent, base_config, prepare, running_gateway, text_of, tool_names
from passkey_helpers import Page, approval_config, request_id_in, wait_for_approval
from service_helpers import free_port
from test_admin import change, login, rpc, setup, state, web_gateway

pytestmark = pytest.mark.anyio
CORE = {'gateway_search_tools', 'gateway_search_connections', 'gateway_call_tool'}


async def search(client, name, **args):
    result = await client.call_tool('gateway_search_' + name, args)
    assert not result.is_error, text_of(result)
    return json.loads(text_of(result))


async def execute(client, tool, connection, arguments, **extra):
    return await client.call_tool('gateway_call_tool', dict(tool=tool, connection=connection, arguments=arguments, **extra))


async def test_mailbox_addresses_and_connector_rename_follow_agent_grants(tmp_path):
    port = free_port()
    origin = f'http://localhost:{port}'
    raw = approval_config(origin=origin)
    raw['server']['tool_discovery'] = 'search'
    raw['admin'] = {'owner': 'person_a', 'state': 'admin.enc'}
    path = await prepare(tmp_path, raw)
    async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)

        async def add_mail(name, username, password, **settings):
            preview = await change(http, 'connections/preview', id=name, kind='imap', owner='person_a',
                                   settings={'username': username, **settings}, credentials={'password': password})
            assert preview.status_code == 200, preview.text
            applied = await change(http, 'connections/apply', draft=preview.json()['draft'], reviewed=True)
            assert applied.status_code == 200, applied.text

        await add_mail('inbox', 'account', 'fake-original-password', mailbox_email='primary@example.test',
                       mailbox_aliases='alias@example.test\nother@example.test\nALIAS@example.test',
                       smtp_sender='outbound@example.test')
        await add_mail('work', 'work@example.test', 'fake-work-password')
        granted = await change(http, 'permissions/connection', client='agent-a', connection='inbox', access='read')
        assert granted.status_code == 200, granted.text
        before = next(c for c in (await state(http))['connections'] if c['id'] == 'inbox')
        async with agent(origin + '/mcp', TOKEN_A) as allowed, agent(origin + '/mcp', TOKEN_B) as denied:
            assert (await search(denied, 'connections', query='alias@example.test'))['total'] == 0
            assert (await search(allowed, 'connections', query='work@example.test'))['total'] == 0
            item, = (await search(allowed, 'connections', query='ALIAS@example.test'))['connections']
            assert item['connection'] == 'inbox'
            assert item['email'] == 'primary@example.test'
            assert item['aliases'] == ['alias@example.test', 'other@example.test']
            assert item['sender_email'] == 'outbound@example.test'
            assert (await change(http, 'connections/rename', id='inbox', name='work')).json()['error'] == 'duplicate_connector'
            assert (await change(http, 'connections/rename', id='inbox', name='Bad name')).json()['error'] == 'invalid_connector_name'
            renamed = await change(http, 'connections/rename', id='inbox', name='personal')
            assert renamed.status_code == 200, renamed.text
            found, = (await search(allowed, 'connections', query='other@example.test'))['connections']
            assert found == {**item, 'connection': 'personal'}
            assert (await search(allowed, 'connections', query='inbox'))['total'] == 0
            after = next(c for c in (await state(http))['connections'] if c['id'] == 'personal')
            assert after['access'] == before['access']
            assert after['tools'] == before['tools']

        await add_mail('inbox', 'new-account', 'fake-replacement-password')
        effective = gw.app.state.admin.runtime.gateway
        for name, password in [('personal', 'fake-original-password'), ('inbox', 'fake-replacement-password')]:
            conn = effective.cfg.connection(name)
            assert effective.secrets[conn.secret_env['IMAP_PASSWORD']] == password
        granted = await change(http, 'permissions/connection', client='agent-a', connection='inbox', access='read')
        assert granted.status_code == 200, granted.text
    async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, _):
        await login(http, key, origin)
        async with agent(origin + '/mcp', TOKEN_A) as allowed:
            assert (await search(allowed, 'connections', query='primary@example.test'))['connections'][0]['connection'] == 'personal'
            assert (await search(allowed, 'connections', query='new-account@icloud.com'))['connections'][0]['connection'] == 'inbox'


async def test_fixed_list_search_paging_and_connection_selected_execution(tmp_path):
    raw = base_config()
    del raw['server']  # exercise the production default
    async with running_gateway(await prepare(tmp_path, raw)) as gw:
        async with agent(gw.url, TOKEN_A) as a, agent(gw.url, TOKEN_B) as b:
            assert await tool_names(a) == await tool_names(b) == CORE
            found = await search(a, 'tools', query='list_notes')
            assert len(found['tools']) == 1
            assert found['tools'][0]['name'] == 'notes_list_notes'
            assert found['tools'][0]['connection_count'] == 2
            connections = await search(a, 'connections', tool='notes_list_notes')
            assert [c['connection'] for c in connections['connections']] == ['notes-a', 'notes-house']
            assert 'notes-b' not in json.dumps(connections)
            house = connections['connections'][1]['variants'][0]
            assert house['inputSchema']['properties']['folder']['enum'] == ['family']
            assert not house['approval_required']
            assert (await search(a, 'connections', query='notes-b'))['total'] == 0
            assert (await search(a, 'tools', connection='notes-b'))['total'] == 0
            assert (await search(b, 'tools', query='add_note'))['total'] == 0
            all_tools = await search(a, 'tools')
            names, offset = [], 0
            while offset is not None:
                part = await search(a, 'tools', offset=offset, limit=2)
                names += [t['name'] for t in part['tools']]
                offset = part['next_offset']
            assert names == [t['name'] for t in all_tools['tools']]
            for conn, owner in [('notes-a', 'person_a'), ('notes-house', 'household')]:
                result = await execute(a, 'notes_whoami', conn, {})
                assert not result.is_error and owner in text_of(result)
            with pytest.raises(MCPError, match='Unknown tool'):
                await execute(a, 'notes_whoami', 'notes-b', {})
            with pytest.raises(MCPError, match='Unknown tool'):
                await execute(a, 'notes_whoami', 'notes-a', {}, variant='b_whoami')
            assert (await execute(a, 'notes_list_notes', 'notes-house', {'folder': 'inbox'})).is_error
            assert (await a.call_tool('gateway_search_tools', {'limit': 0})).is_error
            assert (await a.call_tool('gateway_call_tool', {'tool': 'notes_whoami', 'connection': 'notes-a', 'arguments': {}, 'approved': True})).is_error
            # Previous clients may continue calling their cached names, with the same checks.
            assert 'person_a' in text_of(await a.call_tool('a_whoami', {}))
        calls = [row for row in gw.audit() if row.get('upstream_tool') == 'whoami' and row.get('decision') == 'allow']
        assert {row['connection'] for row in calls} == {'notes-a', 'notes-house'}


async def test_restricted_variants_hide_pins_and_never_let_the_caller_override_them(tmp_path):
    raw = base_config()
    raw['server']['tool_discovery'] = 'search'
    raw['connections'][0]['tools'][-1]['description'] = 'Read the family notes only.'
    raw['connections'][0]['tools'].append({'upstream': 'list_notes', 'name': 'a_inbox', 'pin': {'folder': 'inbox'}})
    raw['policy'].append({'principals': ['household'], 'connection': 'notes-a', 'tools': ['a_inbox'], 'effect': 'allow', 'cross_account': True})
    async with running_gateway(await prepare(tmp_path, raw)) as gw:
        async with agent(gw.url, TOKEN_HOUSE) as client:
            found = await search(client, 'connections', tool='notes_list_notes', query='notes-a')
            variants = found['connections'][0]['variants']
            assert len(variants) == 2
            assert next(v for v in variants if v['id'] == 'a_family_notes')['description'] == 'Read the family notes only.'
            assert all('folder' not in v['inputSchema']['properties'] for v in variants)
            assert (await execute(client, 'notes_list_notes', 'notes-a', {})).is_error
            result = await execute(client, 'notes_list_notes', 'notes-a', {}, variant='a_family_notes')
            assert not result.is_error and 'family' in text_of(result)
            assert (await execute(client, 'notes_list_notes', 'notes-a', {'folder': 'inbox'}, variant='a_family_notes')).is_error


async def test_discovery_updates_without_reloading_and_approvals_bind_connection_and_arguments(tmp_path):
    port = free_port()
    origin = f'http://localhost:{port}'
    raw = approval_config(origin=origin)
    raw['server']['tool_discovery'] = 'search'
    raw['admin'] = {'owner': 'person_a', 'state': 'admin.enc'}
    path = await prepare(tmp_path, raw)
    async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        token = (await change(http, 'clients/create', id='discovery-agent', household='household')).json()['token']
        async with agent(origin + '/mcp', token) as client:
            cached_list = await tool_names(client)
            assert cached_list == CORE
            assert (await search(client, 'tools'))['total'] == (await search(client, 'connections'))['total'] == 0
            for conn in ['notes-a', 'notes-house']:
                reply = await change(http, 'permissions/connection', client='discovery-agent', connection=conn, access='read_write', approver='person_a')
                assert reply.status_code == 200, reply.text
            # No tools/list request here: discovery immediately uses the latest grants.
            found = await search(client, 'tools', query='add_note')
            assert len(found['tools']) == 1 and found['tools'][0]['connection_count'] == 2
            assert all(c['variants'][0]['approval_required'] for c in (await search(client, 'connections', tool='notes_add_note'))['connections'])
            args = {'folder': 'inbox', 'text': 'one exact approved operation'}
            request = await execute(client, 'notes_add_note', 'notes-a', args)
            first = request_id_in(text_of(request))
            assert (await Page(origin, origin).decide('approve', first, key, origin=origin))[0] == 200
            other = await execute(client, 'notes_add_note', 'notes-house', args)
            assert other.is_error and request_id_in(text_of(other)) != first
            changed = await execute(client, 'notes_add_note', 'notes-a', {**args, 'text': 'different content'})
            assert changed.is_error and request_id_in(text_of(changed)) != first
            result = await wait_for_approval(client, first)
            assert result.structured_content['status'] == 'succeeded' and result.content[1].text == 'added'
            assert (await execute(client, 'notes_add_note', 'notes-a', args)).is_error
            for conn in ['notes-a', 'notes-house']:
                assert (await change(http, 'permissions/connection', client='discovery-agent', connection=conn, access='none')).status_code == 200
            assert (await search(client, 'tools'))['total'] == 0
            with pytest.raises(MCPError):
                await execute(client, 'notes_list_notes', 'notes-a', {'folder': 'inbox'})


async def test_watch_works_for_direct_calls_and_keeps_them_private(tmp_path, monkeypatch):
    from test_passkey import defer_dispatch

    resume = defer_dispatch(monkeypatch)
    port = free_port()
    origin = f'http://localhost:{port}'
    raw = approval_config(origin=origin)
    raw['server']['tool_discovery'] = 'search'
    raw['admin'] = {'owner': 'person_a', 'state': 'admin.enc'}
    async with web_gateway(tmp_path, path=await prepare(tmp_path, raw), port=port) as (_gw, http, origin, path):
        await setup(http, origin, path)
        async with agent(origin + '/mcp', TOKEN_A) as client, agent(origin + '/mcp', TOKEN_B) as other:
            reply = await execute(client, 'notes_list_notes', 'notes-a', {'folder': 'inbox'}, background=True)
            info = reply.structured_content
            assert not reply.is_error and info['status'] == 'queued' and 'approval_url' not in info
            request_id = info['request_id']
            assert (await wait_for_approval(client, request_id, 0)).structured_content['status'] == 'queued'
            assert (await Page(origin, origin).view(request_id))[0] == 404
            with pytest.raises(MCPError):
                await wait_for_approval(other, request_id, 0)
            needs_approval = await execute(client, 'notes_add_note', 'notes-a',
                                           {'folder': 'inbox', 'text': 'approval cannot be bypassed'}, background=True)
            assert needs_approval.structured_content['status'] == 'pending'
            assert 'approval_url' in needs_approval.structured_content
            resume.set()
            watched = await wait_for_approval(client, request_id)
            assert watched.structured_content['status'] == 'succeeded'
            assert 'private inbox note of person_a' in watched.content[1].text
            assert 'approval cannot be bypassed' not in watched.content[1].text


async def test_background_call_is_cancelled_if_grant_changes_before_dispatch(tmp_path, monkeypatch):
    from test_passkey import defer_dispatch

    resume = defer_dispatch(monkeypatch)
    port = free_port()
    origin = f'http://localhost:{port}'
    raw = approval_config(origin=origin)
    raw['server']['tool_discovery'] = 'search'
    raw['admin'] = {'owner': 'person_a', 'state': 'admin.enc'}
    async with web_gateway(tmp_path, path=await prepare(tmp_path, raw), port=port) as (_gw, http, origin, path):
        await setup(http, origin, path)
        async with agent(origin + '/mcp', TOKEN_A) as client:
            queued = await execute(client, 'notes_list_notes', 'notes-a', {'folder': 'inbox'}, background=True)
            assert queued.structured_content['status'] == 'queued'
            removed = await change(http, 'permissions/connection', client='agent-a', connection='notes-a', access='none')
            assert removed.status_code == 200, removed.text
            resume.set()
            finished = await wait_for_approval(client, queued.structured_content['request_id'])
            assert finished.structured_content['status'] == 'cancelled'
            assert len(finished.content) == 1
