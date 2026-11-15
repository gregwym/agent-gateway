"""Sensitive admin changes authorize one request, even with a copied session cookie."""
import httpx2
import pytest

from test_admin import change, login, setup, state, web_gateway

pytestmark = pytest.mark.anyio


async def test_copied_cookie_only_gets_challenges_for_sensitive_changes(tmp_path):
    async with web_gateway(tmp_path) as (_, http, origin, path):
        await setup(http, origin, path)
        before = await state(http)
        headers = {'Origin': origin, 'Cookie': 'agw_admin=' + http.cookies.get('agw_admin')}
        async with httpx2.AsyncClient(base_url=origin, headers=headers, trust_env=False) as copied:
            copied.headers['X-CSRF-Token'] = (await copied.get('/admin/api/status')).json()['csrf']
            for operation, data in (
                ('members/enroll', {'id': 'person_a'}),
                ('clients/create', {'id': 'unknown-agent', 'household': 'household'}),
                ('clients/rotate', {'id': 'agent-a'}),
                ('permissions/connection', {'client': 'agent-a', 'connection': 'notes-a', 'access': 'read_write_direct'}),
                ('permissions/connection', {'client': 'agent-a', 'connection': 'notes-a', 'access': 'custom', 'approver': 'person_b'}),
                ('permissions/save', {'client': 'agent-a', 'connection': 'notes-a', 'tool': 'a_add_note', 'effect': 'allow'}),
                ('tools/restrict', {'connection': 'notes-a', 'tool': 'a_add_note', 'pin': {}, 'allow_values': {}}),
            ):
                body = {'revision': before['revision'], **data}
                reply = await copied.post('/admin/api/' + operation, json=body)
                assert reply.status_code == 403
                assert reply.json()['error'] == 'admin_confirmation_required'
                ceremony = reply.json()['confirmation']
                forged = await copied.post('/admin/api/' + operation, json={**body, 'confirmation': {
                    'ceremony_id': ceremony['ceremony_id'], 'response': {}}})
                assert forged.status_code == 403 and forged.json()['error'] == 'verification_failed'
        after = await state(http)
        for field in ('revision', 'passkeys', 'clients'):
            assert before[field] == after[field]


async def test_admin_passkey_confirmation_binds_exact_operation_payload_session_and_revision(tmp_path):
    async with web_gateway(tmp_path) as (_, http, origin, path):
        key, _ = await setup(http, origin, path)
        body = {'id': 'safe-agent', 'household': 'household', 'revision': (await state(http))['revision']}

        async def sign():
            reply = await http.post('/admin/api/clients/create', json=body)
            ceremony = reply.json()['confirmation']
            return {'ceremony_id': ceremony['ceremony_id'], 'response': key.response(ceremony, origin=origin)}

        proof = await sign()
        request = {**body, 'confirmation': proof}
        changed = await http.post('/admin/api/members/enroll', json=request)
        assert changed.status_code == 409 and changed.json()['error'] == 'admin_confirmation_changed'
        spent = await http.post('/admin/api/clients/create', json=request)
        assert spent.status_code == 409 and spent.json()['error'] == 'admin_confirmation_expired'

        proof = await sign()
        changed = await http.post('/admin/api/clients/create', json={**body, 'id': 'different', 'confirmation': proof})
        assert changed.status_code == 409 and changed.json()['error'] == 'admin_confirmation_changed'

        async with httpx2.AsyncClient(base_url=origin, headers={'Origin': origin}, trust_env=False) as other:
            await login(other, key, origin)
            proof = await sign()
            request = {**body, 'confirmation': proof}
            copied_proof = await other.post('/admin/api/clients/create', json=request)
            assert copied_proof.status_code == 409 and copied_proof.json()['error'] == 'admin_confirmation_expired'
        created = await http.post('/admin/api/clients/create', json=request)
        assert created.status_code == 200 and created.json()['token']
        replay = await http.post('/admin/api/clients/create', json=request)
        assert replay.status_code == 409 and replay.json()['error'] == 'admin_confirmation_expired'

        body.update(id='next-agent', revision=(await state(http))['revision'])
        proof = await sign()
        assert (await change(http, 'members/add', id='new-member')).status_code == 200
        stale = await http.post('/admin/api/clients/create', json={**body, 'confirmation': proof})
        assert stale.status_code == 409 and stale.json()['error'] == 'admin_confirmation_changed'
        assert {'safe-agent', 'next-agent'} & {c['id'] for c in (await state(http))['clients']} == {'safe-agent'}
