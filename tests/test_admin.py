"""Web administration against a real gateway, passkeys, and connector processes."""
import json
import os
import sqlite3
from contextlib import asynccontextmanager

import anyio
import httpx2
import pytest

from helpers import TOKEN_A, prepare, running_gateway
from passkey_helpers import Authenticator, approval_config
from service_helpers import free_port

pytestmark = pytest.mark.anyio


@asynccontextmanager
async def web_gateway(tmp_path, *, path=None, port=None):
    port = port or free_port()
    origin = f"http://localhost:{port}"
    if path is None:
        raw = approval_config(origin=origin)
        raw["admin"] = {"owner": "person_a", "state": "admin.enc"}
        path = await prepare(tmp_path, raw)
    async with running_gateway(path, port=port) as gw:
        async with httpx2.AsyncClient(base_url=origin, headers={"Origin": origin}, trust_env=False) as http:
            yield gw, http, origin, path


async def login(http, key, origin, action="login", code=""):
    start = await http.post('/admin/api/auth/begin', json={"action": action, "code": code})
    assert start.status_code == 200, start.text
    ceremony = start.json()
    reply = await http.post('/admin/api/auth/finish', json={"ceremony_id": ceremony["ceremony_id"],
                                                         "response": key.response(ceremony, origin=origin)})
    assert reply.status_code == 200, reply.text
    http.headers['X-CSRF-Token'] = reply.json()['csrf']
    return reply


async def setup(http, origin, path):
    link_file = path.parent / 'admin-setup-link'
    assert os.stat(link_file).st_mode & 0o777 == 0o600
    code = link_file.read_text().strip().split('#setup=')[1]
    key = Authenticator()
    await login(http, key, origin, 'setup', code)
    assert not link_file.exists()
    return key, code


async def state(http):
    reply = await http.get('/admin/api/state')
    assert reply.status_code == 200, reply.text
    return reply.json()


async def change(http, operation, **kwargs):
    current = await state(http)
    return await http.post('/admin/api/' + operation, json={'revision': current['revision'], **kwargs})


async def rpc(origin, token, name='tools/list', params=None):
    async with httpx2.AsyncClient(trust_env=False) as http:
        return await http.post(origin + '/mcp', headers={'Authorization': 'Bearer ' + token,
            'Accept': 'application/json, text/event-stream'}, json={
                'jsonrpc': '2.0', 'id': 1, 'method': name, **({'params': params} if params else {})})


async def test_bootstrap_is_private_single_use_and_origin_bound(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        assert (await http.get('/')).status_code == 200
        public = await http.get('/admin/api/status')
        assert public.json() == {'initialized': False, 'authenticated': False}
        assert 'setup=' not in public.text
        assert (await http.get('/admin/api/state', headers={'Authorization': 'Bearer ' + TOKEN_A})).status_code == 401
        assert (await http.post('/admin/api/auth/begin', json={'action': 'setup', 'code': 'guess'})).status_code == 403
        assert (await http.get('/admin/', headers={'Host': 'attacker.invalid'})).status_code == 403
        code = (path.parent / 'admin-setup-link').read_text().strip().split('#setup=')[1]
        start = (await http.post('/admin/api/auth/begin', json={'action': 'setup', 'code': code})).json()
        key = Authenticator()
        forged = await http.post('/admin/api/auth/finish', json={'ceremony_id': start['ceremony_id'],
            'response': key.response(start, origin='https://attacker.invalid')})
        assert forged.status_code == 403
        assert (await http.post('/admin/api/auth/finish', json={'ceremony_id': start['ceremony_id'], 'response': {}})).status_code == 403
        key, code = await setup(http, origin, path)
        assert (await http.post('/admin/api/auth/begin', json={'action': 'setup', 'code': code})).status_code == 403
        assert (await state(http))['owner'] == 'person_a'
        cookie = http.cookies.get('agw_admin')
        with sqlite3.connect(path.parent / 'approvals.sqlite') as db:
            assert cookie not in str(db.execute('SELECT * FROM admin_sessions').fetchall())
        assert cookie not in gw.audit_text() and code not in gw.audit_text()


async def test_sessions_csrf_logout_and_member_cannot_become_admin(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        assert (await http.post('/admin/api/members/add', json={'id': 'alice', 'revision': 0}, headers={'X-CSRF-Token': ''})).status_code == 403
        assert (await http.post('/admin/api/members/add', json={'id': 'alice', 'revision': 0}, headers={'Origin': 'https://evil.invalid'})).status_code == 403
        assert (await http.post('/admin/api/members/add', content='x' * 256001, headers={'Content-Type': 'application/json'})).status_code == 413
        assert (await change(http, 'members/add', id='alice')).status_code == 200
        link = (await http.post('/admin/api/members/enroll', json={'id': 'alice'})).json()['url']
        member = Authenticator()
        start = (await http.post('/approvals/api/begin', json={'action': 'enroll', 'target': link.split('#')[1]})).json()
        assert (await http.post('/approvals/api/finish', json={'ceremony_id': start['ceremony_id'], 'response': member.response(start, origin=origin)})).status_code == 200
        start = (await http.post('/admin/api/auth/begin', json={'action': 'login'})).json()
        assert (await http.post('/admin/api/auth/finish', json={'ceremony_id': start['ceremony_id'], 'response': member.response(start, origin=origin)})).status_code == 403
        owner_key = next(k['id'] for k in (await state(http))['passkeys'] if k['principal'] == 'person_a')
        assert (await http.post('/admin/api/passkeys/remove', json={'id': owner_key})).status_code == 409
        assert (await http.post('/admin/api/auth/logout', json={})).status_code == 200
        assert (await http.get('/admin/api/state')).status_code == 401
        reply = await login(http, key, origin)
        assert 'HttpOnly' in reply.headers['set-cookie'] and 'SameSite=strict' in reply.headers['set-cookie']
        with sqlite3.connect(path.parent / 'approvals.sqlite') as db:
            db.execute('UPDATE admin_sessions SET expires=0')
        assert (await http.get('/admin/api/state')).status_code == 401


async def test_https_session_uses_host_cookie_and_logout_revokes_copied_cookie(tmp_path):
    origin = 'https://gateway.example.test'
    raw = approval_config(origin=origin)
    raw['admin'] = {'owner': 'person_a', 'state': 'admin.enc'}
    path = await prepare(tmp_path, raw)
    async with running_gateway(path) as gw:
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=gw.app), base_url=origin,
                                     headers={'Origin': origin}) as http:
            code = (tmp_path / 'admin-setup-link').read_text().strip().split('#setup=')[1]
            reply = await login(http, Authenticator(), origin, 'setup', code)
            cookie = reply.headers['set-cookie']
            assert cookie.startswith('__Host-agw_admin=')
            assert all(part in cookie for part in ('Secure', 'HttpOnly', 'SameSite=strict', 'Path=/;'))
            assert 'Domain=' not in cookie
            assert (await http.get('/admin/api/state')).status_code == 200
            assert (await http.post('/admin/api/auth/logout', json={})).status_code == 200
            assert (await http.get('/admin/api/state', headers={'Cookie': cookie.split(';')[0]})).status_code == 401


async def test_live_tokens_permissions_and_restart_persistence(tmp_path):
    port = free_port()
    async with web_gateway(tmp_path, port=port) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        reply = await change(http, 'clients/create', id='new-agent', principal='person_a')
        assert reply.status_code == 200, reply.text
        token = reply.json()['token']
        visible = (await rpc(origin, token)).json()['result']['tools']
        assert 'a_list_notes' in {t['name'] for t in visible}
        assert token not in json.dumps(await state(http)) and token not in gw.audit_text()
        assert token.encode() not in (tmp_path / 'admin.enc').read_bytes()
        invalid = await change(http, 'permissions/save', principal='person_b', connection='notes-a', tool='a_list_notes', effect='allow')
        assert invalid.status_code == 400
        shared = await change(http, 'permissions/save', principal='person_b', connection='notes-a', tool='a_list_notes', effect='allow', cross_account=True)
        assert shared.status_code == 200, shared.text
        rotated = await change(http, 'clients/rotate', id='new-agent')
        newer = rotated.json()['token']
        assert (await rpc(origin, token)).status_code == 401
        assert (await rpc(origin, newer)).status_code == 200
        stale = await http.post('/admin/api/clients/revoke', json={'revision': 0, 'id': 'new-agent'})
        assert stale.status_code == 409
    async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, _):
        assert not (tmp_path / 'admin-setup-link').exists()
        await login(http, key, origin)
        assert any(c['id'] == 'new-agent' for c in (await state(http))['clients'])
        assert (await rpc(origin, newer)).status_code == 200
        assert (await change(http, 'clients/revoke', id='new-agent')).status_code == 200
        assert (await rpc(origin, newer)).status_code == 401


async def test_connector_review_probe_restrictions_and_encrypted_secret(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        bad = await change(http, 'connections/preview', id='work', kind='demo', owner='person_a', command=['sh'])
        assert bad.status_code == 400
        preview = await change(http, 'connections/preview', id='work', kind='demo', owner='person_a')
        assert preview.status_code == 200, preview.text
        draft = preview.json()['draft']
        assert len(preview.json()['definitions']) == 3
        assert (await change(http, 'connections/apply', draft=draft)).status_code == 400
        assert (await change(http, 'connections/apply', draft=draft, reviewed=True)).status_code == 200
        assert (await http.post('/admin/api/connections/test', json={'id': 'work'})).status_code == 200
        visible = (await rpc(origin, TOKEN_A)).json()['result']['tools']
        assert 'work_list' in {t['name'] for t in visible}
        limited = await change(http, 'tools/restrict', connection='work', tool='work_list', pin={'folder':'family'}, allow_values={})
        assert limited.status_code == 200
        reply = (await rpc(origin, TOKEN_A, 'tools/call', {'name':'work_list','arguments':{}})).json()
        assert 'family note kept by person_a' in reply['result']['content'][0]['text']
        bad = await change(http, 'tools/restrict', connection='work', tool='work_list', pin={'unknown':'x'}, allow_values={})
        assert bad.status_code == 400
        # Listing tools is not a mailbox login. Wrong credentials may be staged,
        # but the UI labels account checks separately; secrets are never echoed.
        password = 'very-private-app-password-123456'
        preview = await change(http, 'connections/preview', id='mail', kind='imap', owner='person_a',
                               settings={'username':'fake@example.test'}, credentials={'password':password})
        assert preview.status_code == 200, preview.text
        assert password not in preview.text
        assert (await change(http, 'connections/apply', draft=preview.json()['draft'], reviewed=True)).status_code == 200
        assert password not in json.dumps(await state(http))
        assert password.encode() not in (tmp_path / 'admin.enc').read_bytes()
        assert password not in gw.audit_text()
        assert (await change(http, 'connections/remove', id='mail')).status_code == 200


async def test_setup_race_user_verification_and_session_revocation(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        code = (tmp_path / 'admin-setup-link').read_text().strip().split('#setup=')[1]
        ceremonies = [(await http.post('/admin/api/auth/begin', json={'action':'setup','code':code})).json() for _ in range(3)]
        keys = [Authenticator() for _ in range(3)]
        for i in range(3):
            reply = await http.post('/admin/api/auth/finish', json={'ceremony_id':ceremonies[i]['ceremony_id'],
                'response':keys[i].response(ceremonies[i], origin=origin, verified=i != 0)})
            assert reply.status_code == (200 if i == 1 else 403)
        assert len((await state(http))['passkeys']) == 1
        gw.gateway.approver.forget_passkey(keys[1].id.hex())
        assert (await http.get('/admin/api/state')).status_code == 401


async def test_failed_save_is_atomic_and_configuration_change_invalidates_approvals(tmp_path, monkeypatch):
    from passkey_helpers import Page, request_id_in
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        note = {'folder':'inbox','text':'must not survive a configuration change'}
        response = (await rpc(origin, TOKEN_A, 'tools/call', {'name':'a_add_note','arguments':note})).json()
        request_id = request_id_in(response['result']['content'][0]['text'])
        page = Page(origin, origin)
        assert (await page.decide('approve', request_id, key, origin=origin))[0] == 200
        controller = gw.app.state.admin
        original = controller.store.file.set
        def fail(*args):
            raise OSError('test disk full')
        monkeypatch.setattr(controller.store.file, 'set', fail)
        assert (await change(http, 'clients/create', id='atomic', principal='person_a')).status_code == 500
        assert (await state(http))['revision'] == 0
        assert (await rpc(origin, TOKEN_A)).status_code == 200
        monkeypatch.setattr(controller.store.file, 'set', original)
        assert (await change(http, 'clients/create', id='atomic', principal='person_a')).status_code == 200
        response = (await rpc(origin, TOKEN_A, 'tools/call', {'name':'a_add_note','arguments':note})).json()
        assert response['result']['isError']
        assert request_id_in(response['result']['content'][0]['text']) != request_id
        assert (await page.view(request_id))[1]['status'] == 'cancelled'


async def test_revocation_drains_inflight_calls_and_drafts_are_session_bound(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        token = (await change(http, 'clients/create', id='slow-agent', principal='person_a')).json()['token']
        order = []
        async def running_call():
            answer = await rpc(origin, token, 'tools/call', {'name':'a_slow','arguments':{'seconds':0.25}})
            assert not answer.json()['result'].get('isError')
            order.append('finished')
        async with anyio.create_task_group() as group:
            group.start_soon(running_call)
            with anyio.fail_after(5):
                while not gw.app.state.runtime.active:
                    await anyio.sleep(.005)
            assert (await change(http, 'clients/revoke', id='slow-agent')).status_code == 200
            order.append('revoked')
        assert order == ['finished','revoked']
        assert (await rpc(origin, token)).status_code == 401
        draft = (await change(http, 'connections/preview', id='staged', kind='demo', owner='person_a')).json()['draft']
        async with httpx2.AsyncClient(base_url=origin, headers={'Origin':origin}) as second:
            await login(second, key, origin)
            assert (await change(second, 'connections/apply', draft=draft, reviewed=True)).status_code == 409
        await change(http, 'members/add', id='someone')
        assert (await change(http, 'connections/apply', draft=draft, reviewed=True)).status_code == 409
