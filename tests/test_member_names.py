import sqlite3

import pytest

from helpers import TOKEN_A
from passkey_helpers import request_id_in
from service_helpers import free_port
from test_admin import change, login, rpc, setup, state, web_gateway

pytestmark = pytest.mark.anyio


async def test_rename_preserves_identity_sessions_open_approval_and_restart(tmp_path):
    port = free_port()
    async with web_gateway(tmp_path, port=port) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        old = gw.app.state.runtime.gateway
        before = await state(http)
        note = {'folder': 'inbox', 'text': 'one approved write survives a name change'}
        pending = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'a_add_note', 'arguments': note})).json()
        request_id = request_id_in(pending['result']['content'][0]['text'])
        ceremony = (await http.post('/approvals/api/begin', json={'action': 'approve', 'target': request_id})).json()
        with sqlite3.connect(tmp_path / 'approvals.sqlite') as db:
            credentials = db.execute('SELECT * FROM credentials').fetchall()
            sessions = db.execute('SELECT * FROM admin_sessions').fetchall()
        renamed = await change(http, 'members/rename', id='person_a', name='  Greg 林  ')
        assert renamed.status_code == 200, renamed.text
        after = await state(http)
        assert after['revision'] == before['revision']
        assert after['owner'] == 'person_a'
        assert after['clients'] == before['clients']
        assert after['passkeys'] == before['passkeys']
        assert next(m for m in after['members'] if m['id'] == 'person_a')['name'] == 'Greg 林'
        assert gw.app.state.runtime.gateway is old
        with sqlite3.connect(tmp_path / 'approvals.sqlite') as db:
            assert db.execute('SELECT * FROM credentials').fetchall() == credentials
            assert db.execute('SELECT * FROM admin_sessions').fetchall() == sessions
        view = (await http.get('/approvals/api/request/' + request_id)).json()
        assert view['status'] == 'pending' and view['owner'] == 'person_a'
        assert view['names']['person_a'] == 'Greg 林'
        decision = await http.post('/approvals/api/finish', json={
            'ceremony_id': ceremony['ceremony_id'], 'response': key.response(ceremony, origin=origin)})
        assert decision.status_code == 200, decision.text
        result = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'a_add_note', 'arguments': note})).json()
        assert not result['result'].get('isError', False)
        assert 'Greg 林' not in gw.audit_text()
        assert 'Greg 林'.encode() not in (tmp_path / 'admin.enc').read_bytes()
    async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, path):
        await login(http, key, origin)
        assert next(m for m in (await state(http))['members'] if m['id'] == 'person_a')['name'] == 'Greg 林'
        link = (await http.post('/admin/api/members/enroll', json={'id': 'person_a'})).json()['url']
        begin = (await http.post('/approvals/api/begin', json={'action': 'enroll', 'target': link.split('#')[1]})).json()
        assert begin['options']['publicKey']['user']['displayName'] == 'Greg 林'
        assert begin['options']['publicKey']['user']['name'] == 'Greg 林'


async def test_name_validation_and_failed_write_do_not_change_identity(tmp_path, monkeypatch):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        assert (await http.post('/admin/api/members/rename', json={'id': 'person_a', 'name': 'Greg', 'revision': 0})).status_code == 401
        await setup(http, origin, path)
        before = await state(http)
        for value in ('', '   ', 'x' * 81, 'Greg\nBob', '\u202eGreg', None, 42):
            reply = await change(http, 'members/rename', id='person_a', name=value)
            assert reply.status_code == 400 and reply.json()['error'] == 'invalid_member_name'
        assert (await change(http, 'members/rename', id='unknown', name='Greg')).status_code == 400
        assert (await http.post('/admin/api/members/rename', json={'revision': 0, 'id': 'person_a', 'name': 'Greg'},
                                headers={'X-CSRF-Token': ''})).status_code == 403
        assert (await change(http, 'members/rename', id='person_a', name='Greg', revision=999)).status_code == 409
        def failed_save(_):
            raise OSError('disk unavailable')
        with monkeypatch.context() as patch:
            patch.setattr(gw.app.state.admin.store, 'save', failed_save)
            assert (await change(http, 'members/rename', id='person_a', name='Greg')).status_code == 500
        after = await state(http)
        assert after['members'] == before['members'] and after['passkeys'] == before['passkeys']


async def test_connector_draft_keeps_latest_name_and_member_removal_clears_it(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        draft = await change(http, 'connections/preview', id='new-notes', owner='person_a', kind='demo')
        assert draft.status_code == 200
        assert (await change(http, 'members/rename', id='person_a', name='Greg')).status_code == 200
        assert (await change(http, 'connections/apply', draft=draft.json()['draft'], reviewed=True)).status_code == 200
        assert next(m for m in (await state(http))['members'] if m['id'] == 'person_a')['name'] == 'Greg'
        assert (await change(http, 'members/add', id='alex')).status_code == 200
        assert (await change(http, 'members/rename', id='alex', name='Alex 林')).status_code == 200
        assert (await change(http, 'members/remove', id='alex')).status_code == 200
        assert not any(m['id'] == 'alex' for m in gw.app.state.admin.store.state['config']['members'])
        assert (await change(http, 'members/add', id='alex')).status_code == 200
        assert next(m for m in (await state(http))['members'] if m['id'] == 'alex')['name'] == 'alex'
