"""Google web consent with actual state/PKCE/session handling and a fake provider."""
import json
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest

from agent_gateway.admin_oauth import AUTHORIZE, PROFILE, SCOPE, TOKEN
from agent_gateway.gmail_scopes import MODIFY_SCOPE, ORGANIZE_TOOLS, SCOPES, SEND_SCOPE
from test_admin import change, login, setup, state, web_gateway

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize('failure,expected', [
    ('invalid_client', 'oauth_client_rejected'), ('invalid_grant', 'oauth_code_rejected'),
    ('network', 'oauth_network_failed'), ('timeout', 'oauth_timeout'), ('profile', 'oauth_profile_rejected'),
])
async def test_google_failures_report_the_specific_step_without_provider_text(tmp_path, failure, expected):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        query = await start(http)
        def handle(request):
            if failure == 'network':
                raise httpx2.ConnectError('private-provider-detail')
            if failure == 'timeout':
                raise httpx2.ReadTimeout('private-provider-detail')
            if failure == 'profile' and str(request.url) == TOKEN:
                return httpx2.Response(200, json={'access_token': 'private-access-token', 'scope': SCOPE, 'refresh_token': 'private-refresh'})
            return httpx2.Response(403 if failure == 'profile' else 400,
                                   json={'error': failure, 'error_description': 'private-provider-detail'})
        gw.app.state.admin.google._http = lambda: httpx2.AsyncClient(transport=httpx2.MockTransport(handle), trust_env=False)
        flow = query['state'][0]
        assert (await http.get('/admin/oauth/google/callback', params={'state': flow, 'code': 'fake-code'})).status_code == 303
        response = await http.post('/admin/api/oauth/complete', json={'id': flow})
        assert response.status_code == 400 and response.json()['error'] == expected
        assert 'private-' not in response.text + gw.audit_text()


async def start(http, access='read'):
    reply = await change(http, 'oauth/start', kind='gmail', id='google-mail', owner='person_a',
                         settings={'client_id':'test-web-client', 'gmail_access': access}, credentials={'client_secret':'very-secret-client'})
    assert reply.status_code == 200, reply.text
    url = reply.json()['url']
    assert url.startswith(AUTHORIZE)
    assert 'very-secret-client' not in url
    query = parse_qs(urlsplit(url).query)
    assert set(query['scope'][0].split()) == set(SCOPES[access])
    assert query['access_type'] == ['offline']
    assert query['code_challenge_method'] == ['S256']
    return query


def provider(google, query, *, scope=SCOPE, refresh='google-private-refresh'):
    calls = []
    def handle(request):
        calls.append(request)
        if str(request.url) == TOKEN:
            form = parse_qs(request.content.decode())
            assert form['client_id'] == ['test-web-client']
            assert form['client_secret'] == ['very-secret-client']
            assert form['code'] == ['fake-code']
            assert form['redirect_uri'] == query['redirect_uri']
            import hashlib
            from fido2.utils import websafe_encode
            assert websafe_encode(hashlib.sha256(form['code_verifier'][0].encode()).digest()) == query['code_challenge'][0]
            return httpx2.Response(200, json={'access_token':'fake-access', 'scope':scope, 'refresh_token':refresh})
        assert str(request.url) == PROFILE
        assert request.headers['Authorization'] == 'Bearer fake-access'
        return httpx2.Response(200, json={'emailAddress':'owner@example.test'})
    google._http = lambda: httpx2.AsyncClient(transport=httpx2.MockTransport(handle))
    return calls


async def test_google_consent_is_session_bound_reviewed_and_never_echoes_credentials(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        query = await start(http)
        flow = query['state'][0]
        calls = provider(gw.app.state.admin.google, query)
        # Google redirects cross-site, without the Strict administrator cookie.
        async with httpx2.AsyncClient(base_url=origin) as outsider:
            bad = await outsider.get('/admin/oauth/google/callback', params={'state':'guess','code':'fake-code'})
            assert bad.status_code == 409 and not calls
            returned = await outsider.get('/admin/oauth/google/callback', params={'state':flow,'code':'fake-code'})
            assert returned.status_code == 303 and len(calls) == 2
            assert 'google-private-refresh' not in returned.text + str(returned.headers)
            assert (await outsider.get('/admin/oauth/google/callback', params={'state':flow,'code':'fake-code'})).status_code == 409
        # A second, valid login is still not the session that started this flow.
        async with httpx2.AsyncClient(base_url=origin, headers={'Origin':origin}) as second:
            await login(second, key, origin)
            assert (await second.post('/admin/api/oauth/complete', json={'id':flow})).status_code == 403
        saved = await http.post('/admin/api/oauth/complete', json={'id':flow})
        assert saved.status_code == 200, saved.text
        assert saved.json()['saved'] and saved.json()['google_account'] == 'owner@example.test'
        assert 'google-private-refresh' not in saved.text
        conn = next(c for c in (await state(http))['connections'] if c['id'] == 'google-mail')
        assert conn['mailbox'] == {'email':'owner@example.test'}
        assert 'google-private-refresh' not in json.dumps(await state(http)) + gw.audit_text()
        assert b'google-private-refresh' not in (tmp_path / 'admin.enc').read_bytes()


@pytest.mark.parametrize('scope,refresh,error', [
    (SCOPE + ' https://mail.google.com/', 'refresh', 'gmail_readonly_required'),
    (SCOPE, '', 'oauth_refresh_token_missing'),
])
async def test_google_rejects_extra_permissions_and_missing_refresh(tmp_path, scope, refresh, error):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        query = await start(http)
        provider(gw.app.state.admin.google, query, scope=scope, refresh=refresh)
        flow = query['state'][0]
        assert (await http.get('/admin/oauth/google/callback', params={'state':flow,'code':'fake-code'})).status_code == 303
        result = await http.post('/admin/api/oauth/complete', json={'id':flow})
        assert result.status_code == 400 and result.json()['error'] == error
        assert (await state(http))['revision'] == 0


async def test_google_flow_expires_on_logout_or_config_change(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        query = await start(http)
        calls = provider(gw.app.state.admin.google, query)
        await http.post('/admin/api/auth/logout', json={})
        assert (await http.get('/admin/oauth/google/callback', params={'state':query['state'][0],'code':'fake-code'})).status_code == 401
        assert not calls
        await login(http, key, origin)
        query = await start(http)
        provider(gw.app.state.admin.google, query)
        await change(http, 'members/add', id='new-member')
        await http.get('/admin/oauth/google/callback', params={'state':query['state'][0],'code':'fake-code'})
        assert (await http.post('/admin/api/oauth/complete', json={'id':query['state'][0]})).status_code == 409


async def test_gmail_scope_changes_drop_send_grants_until_explicitly_restored(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)

        async def authorize(access, returned_scope):
            query = await start(http, access)
            provider(gw.app.state.admin.google, query, scope=returned_scope, refresh=f'private-refresh-{access}')
            flow = query['state'][0]
            assert (await http.get('/admin/oauth/google/callback', params={'state': flow, 'code': 'fake-code'})).status_code == 303
            return await http.post('/admin/api/oauth/complete', json={'id': flow})

        async def connection():
            return next(c for c in (await state(http))['connections'] if c['id'] == 'google-mail')

        rejected = await authorize('read_send', SCOPE)
        assert rejected.status_code == 400 and rejected.json()['error'] == 'gmail_scope_mismatch'
        assert (await state(http))['revision'] == 0
        assert (await authorize('read_send', f'{SCOPE} {SEND_SCOPE}')).status_code == 200
        conn = await connection()
        assert conn['settings']['gmail_access'] == 'read_send'
        send = next(t for t in conn['tools'] if t['upstream'] == 'send_message')
        assert send['access'] == 'write' and send['permissions']['agent-a'] == 'deny'

        allowed = await change(http, 'permissions/connection', client='agent-a', connection='google-mail', access='read_write')
        assert allowed.status_code == 200, allowed.text
        conn = await connection()
        assert next(t for t in conn['tools'] if t['upstream'] == 'send_message')['permissions']['agent-a'] == 'approval_required'

        assert (await authorize('read', SCOPE)).status_code == 200
        conn = await connection()
        assert conn['settings']['gmail_access'] == 'read'
        assert all(t['upstream'] != 'send_message' for t in conn['tools'] + conn['available_tools'])
        assert conn['access']['agent-a'] == 'read'

        assert (await authorize('read_send', f'{SEND_SCOPE} {SCOPE}')).status_code == 200
        send = next(t for t in (await connection())['tools'] if t['upstream'] == 'send_message')
        assert send['permissions']['agent-a'] == 'deny'


async def test_gmail_organize_scope_does_not_auto_grant_tools_or_expose_send(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        organize = {name for name, _ in ORGANIZE_TOOLS}

        async def authorize(access):
            query = await start(http, access)
            provider(gw.app.state.admin.google, query, scope=" ".join(SCOPES[access]), refresh=f"fake-refresh-{access}")
            flow = query['state'][0]
            assert (await http.get('/admin/oauth/google/callback', params={'state': flow, 'code': 'fake-code'})).status_code == 303
            saved = await http.post('/admin/api/oauth/complete', json={'id': flow})
            assert saved.status_code == 200, saved.text
            return {t['upstream']: t for t in next(c for c in (await state(http))['connections'] if c['id'] == 'google-mail')['tools']}

        tools = await authorize('read_organize')
        assert SCOPES['read_organize'] == (MODIFY_SCOPE,)
        assert organize <= tools.keys() and 'send_message' not in tools
        assert all(tools[name]['access'] == 'write' and tools[name]['permissions']['agent-a'] == 'deny' for name in organize)
        assert (await change(http, 'permissions/connection', client='agent-a', connection='google-mail', access='read_write')).status_code == 200
        tools = await authorize('read_organize_send')
        assert tools['send_message']['permissions']['agent-a'] == 'deny'
        assert all(tools[name]['permissions']['agent-a'] == 'approval_required' for name in organize)
        tools = await authorize('read_send')
        assert not (organize & tools.keys())
        assert tools['send_message']['permissions']['agent-a'] == 'deny'
        tools = await authorize('read_organize')
        assert 'send_message' not in tools and all(tools[name]['permissions']['agent-a'] == 'deny' for name in organize)
