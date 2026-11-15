"""Remote MCP and OAuth against simulated HTTP services; no external accounts."""
import hashlib
import json
import time
from urllib.parse import parse_qs, urlsplit

import anyio
import httpx2
import pytest
from fido2.utils import websafe_encode

from agent_gateway import upstream
from agent_gateway.oauth import OAuthVault
from test_admin import change, login, setup, state, web_gateway, rpc
from helpers import TOKEN_HOUSE

pytestmark = pytest.mark.anyio
URL = 'https://mcp.example.test/mcp'
ISSUER = 'https://auth.example.test'


class Remote:
    def __init__(self, monkeypatch, mode='oauth', url=URL):
        self.url = url
        self.mode = mode
        self.requests = []
        self.calls = []
        self.tokens = 0
        self.access = 'private-bearer-token'
        self.refresh = None
        self.query = None
        self.fail_token = None
        self.grant_scope = 'notes.read notes.write'
        self.denied = None
        self.cimd = False
        self.extra = False
        self.no_registration = False
        self.issuer = ISSUER
        self.pkce = ['S256']
        monkeypatch.setattr(upstream, 'http_client', lambda **kw: httpx2.AsyncClient(transport=httpx2.MockTransport(self.handle), **kw))

    def handle(self, request):
        self.requests.append(request)
        url = str(request.url)
        if url.startswith('https://mcp.example.test/.well-known/oauth-protected-resource'):
            return httpx2.Response(200, json={'resource': URL, 'authorization_servers': [self.issuer], 'scopes_supported': self.grant_scope.split()})
        if '/.well-known/' in url:
            data = {'issuer': self.issuer, 'authorization_endpoint': self.issuer + '/authorize', 'token_endpoint': self.issuer + '/token',
                    'response_types_supported': ['code'], 'code_challenge_methods_supported': self.pkce,
                    'token_endpoint_auth_methods_supported': ['none', 'client_secret_post', 'client_secret_basic']}
            if self.cimd:
                data['client_id_metadata_document_supported'] = True
            if not self.no_registration:
                data['registration_endpoint'] = self.issuer + '/register'
            return httpx2.Response(200, json=data)
        if url.endswith('/register'):
            data = json.loads(request.content)
            assert data['application_type'] == 'web'
            return httpx2.Response(201, json={**data, 'client_id': 'test-client', 'client_secret': 'private-client-secret', 'token_endpoint_auth_method':'client_secret_post'})
        if url.endswith('/token'):
            form = parse_qs(request.content.decode())
            assert form['resource'] == [URL]
            if self.fail_token:
                return httpx2.Response(400, json={'error': self.fail_token, 'error_description':'private-provider-detail'})
            if form['grant_type'] == ['authorization_code']:
                assert form['code'] == ['fake-code']
                assert form['redirect_uri'] == self.query['redirect_uri']
                assert websafe_encode(hashlib.sha256(form['code_verifier'][0].encode()).digest()) == self.query['code_challenge'][0]
            else:
                assert form['grant_type'] == ['refresh_token']
                assert form['refresh_token'] == [self.refresh]
            self.tokens += 1
            self.access = 'private-access-' + str(self.tokens)
            self.refresh = 'private-refresh-' + str(self.tokens)
            return httpx2.Response(200, json={'access_token':self.access, 'refresh_token':self.refresh,
                                            'token_type':'Bearer', 'expires_in':3600, 'scope':self.grant_scope})
        assert url == self.url, url
        authenticated = self.mode == 'none' or request.headers.get('Authorization') == 'Bearer ' + self.access or (
            self.mode == 'header' and request.headers.get('X-API-Key') == self.access)
        if not authenticated:
            return httpx2.Response(401, headers={'WWW-Authenticate': 'Bearer resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/mcp"'}, json={'error':'unauthorized'})
        if self.denied:
            return httpx2.Response(403, headers={'WWW-Authenticate':'Bearer error="insufficient_scope"'} if self.denied == 'scope' else {})
        if request.method == 'GET':
            return httpx2.Response(405)
        if request.method == 'DELETE':
            return httpx2.Response(200)
        body = json.loads(request.content)
        if 'id' not in body:
            return httpx2.Response(202)
        method = body['method']
        if method == 'initialize':
            result = {'protocolVersion':'2025-11-25','capabilities':{'tools':{}},'serverInfo':{'name':'simulated','version':'1'}}
        elif method == 'tools/list':
            names = ['read.note'] if not body.get('params', {}).get('cursor') else ['write.note'] + (['new.note'] if self.extra else [])
            result = {'tools':[{'name': name, 'description':'A simulated operation', 'inputSchema':{'type':'object','properties':{}},
                               'annotations': {'readOnlyHint': True}} for name in names]}
            if names == ['read.note']:
                result['nextCursor'] = 'page-two'
        elif method == 'tools/call':
            self.calls.append(body['params'])
            result = {'content':[{'type':'text','text':'simulated result ' + self.access}]}
        else:
            result = {}
        return httpx2.Response(200, json={'jsonrpc':'2.0','id':body['id'],'result':result})


class StreamingBody(httpx2.AsyncByteStream):
    def __init__(self, content):
        self.content = content

    async def __aiter__(self):
        yield self.content


class StreamingOAuthRemote(Remote):
    def handle(self, request):
        response = super().handle(request)
        content = response.content
        headers = dict(response.headers)
        if str(request.url) == self.url and response.status_code == 200 and request.method == "POST":
            headers.pop("content-length", None)
            headers["content-type"] = "text/event-stream"
            content = b"event: message\ndata: " + content + b"\n\n"
        return httpx2.Response(response.status_code, headers=headers, stream=StreamingBody(content))


async def remote_preview(http, mode='none', name='remote-notes'):
    return await change(http, 'connections/preview', kind='remote', id=name, owner='person_a',
                        settings={'url':URL, 'auth':mode, 'header':'X-API-Key'},
                        credentials={'token':'private-bearer-token'} if mode in ('bearer','header') else {})


async def consent_start(http, remote, **settings):
    reply = await change(http, 'oauth/mcp/start', kind='remote', id='remote-notes', owner='person_a',
                         settings={'url':URL, 'auth':'oauth', **settings}, credentials={})
    assert reply.status_code == 200, reply.text
    remote.query = parse_qs(urlsplit(reply.json()['url']).query)
    assert remote.query['resource'] == [URL]
    assert remote.query['code_challenge_method'] == ['S256']
    return remote.query


async def consent_complete(http, remote):
    reply = await http.get('/admin/oauth/mcp/callback', params={'state':remote.query['state'][0], 'code':'fake-code'})
    assert reply.status_code == 303, reply.text
    key = parse_qs(urlsplit(reply.headers['location']).query)['mcp_oauth'][0]
    return await http.post('/admin/api/oauth/mcp/complete', json={'id':key})


async def apply(http, response, tools=None):
    assert response.status_code == 200, response.text
    result = response.json()
    return await change(http, 'connections/apply', draft=result['draft'], reviewed=True,
                        tools=tools or [{'upstream': 'read.note', 'access':'read'}, {'upstream':'write.note', 'access':'write'}])


@pytest.mark.parametrize('mode', ['none', 'bearer', 'header'])
async def test_remote_review_classification_and_default_denial(tmp_path, monkeypatch, mode):
    remote = Remote(monkeypatch, mode)
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        preview = await remote_preview(http, mode)
        assert preview.status_code == 200, preview.text
        assert [t['name'] for t in preview.json()['definitions']] == ['read.note', 'write.note']
        assert {t['upstream']: t['access'] for t in preview.json()['tools']} == {
            'read.note': 'read', 'write.note': 'write',  # both carry readOnlyHint
        }
        assert not remote.calls
        assert (await apply(http, preview)).status_code == 200
        conn = next(c for c in (await state(http))['connections'] if c['id'] == 'remote-notes')
        assert conn['access']['shared-agent'] == 'none'
        assert (await change(http, 'connections/test', id=conn['id'])).status_code == 200
        assert not remote.calls  # generic testing never executes a business operation
        assert (await change(http, 'permissions/connection', client='shared-agent', connection=conn['id'], access='read')).status_code == 200
        reply = (await rpc(origin, TOKEN_HOUSE, 'tools/call', {'name':'remote_notes_read_note','arguments':{}})).json()
        assert '[REDACTED]' in reply['result']['content'][0]['text'] if mode != 'none' else not reply['result'].get('isError')
        remote.extra = True
        preview = await change(http, 'connections/review-tools', id=conn['id'])
        assert preview.status_code == 200
        assert {t['upstream']: t['access'] for t in preview.json()['tools']}['new.note'] == 'write'
        assert (await apply(http, preview, [{'upstream':'read.note','access':'write'}, {'upstream':'new.note','access':'read'}])).status_code == 200
        conn = next(c for c in (await state(http))['connections'] if c['id'] == 'remote-notes')
        assert conn['access']['shared-agent'] == 'none'  # reclassification revokes prior grant
        assert {t['upstream'] for t in conn['tools']} == {'read.note', 'new.note'}


async def test_oauth_roundtrip_refresh_restart_scrubbing_and_revoke(tmp_path, monkeypatch):
    remote = StreamingOAuthRemote(monkeypatch)
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        await consent_start(http, remote)
        review = await consent_complete(http, remote)
        assert (await apply(http, review)).status_code == 200
        admin = gw.app.state.admin
        conn = next(c for c in admin.runtime.gateway.cfg.connections if c.id == 'remote-notes')
        ref = conn.oauth_ref
        assert remote.tokens == 1
        assert b'private-access' not in (tmp_path / 'admin.enc.oauth').read_bytes()
        assert 'private-' not in json.dumps(await state(http)) + review.text + gw.audit_text()
        revision = (await state(http))['revision']
        admin.oauth.get(ref)['expires'] = 0
        admin.oauth.save(ref)
        checks = []
        async def check():
            async with upstream.open_client(conn, {}, admin.oauth) as client:
                checks.append(await upstream.list_all_tools(client))
        async with anyio.create_task_group() as group:
            for _ in range(3):
                group.start_soon(check)
        assert len(checks) == 3 and remote.tokens == 2  # rotating refresh used exactly once
        assert (await state(http))['revision'] == revision
        restored = OAuthVault(admin.store.base)
        assert restored.get(ref)['tokens']['refresh_token'] == 'private-refresh-2'
        assert restored.get(ref)['expires'] > time.time()
        async with upstream.open_client(conn, {}, restored) as client:
            await upstream.list_all_tools(client)
        assert remote.tokens == 2  # absolute expiry survives restart
        assert (await change(http, 'permissions/connection', client='shared-agent', connection=conn.id, access='read')).status_code == 200
        renamed = await change(http, 'connections/rename', id=conn.id, name='personal-notes')
        assert renamed.status_code == 200, renamed.text
        conn = admin.runtime.gateway.cfg.connection('personal-notes')
        assert conn.oauth_ref == ref and remote.tokens == 2
        reply = (await rpc(origin, TOKEN_HOUSE, 'tools/call', {'name':'remote_notes_read_note','arguments':{}})).json()
        assert '[REDACTED]' in reply['result']['content'][0]['text']
        revoked = await change(http, 'oauth/revoke', id=conn.id)
        assert revoked.json() == {'local_revoked':True, 'provider':'unsupported'}
        failed = await change(http, 'connections/test', id=conn.id)
        assert failed.status_code == 422 and failed.json()['error'] == 'oauth_reauthorization_required'
        assert not admin.oauth.get(ref)['tokens']
        assert (await change(http, 'connections/remove', id=conn.id)).status_code == 200
        assert ref not in admin.oauth.records and ref not in admin.oauth.file.names()


async def test_oauth_callback_is_single_use_session_bound_and_revision_bound(tmp_path, monkeypatch):
    remote = Remote(monkeypatch)
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        await consent_start(http, remote)
        async with httpx2.AsyncClient(base_url=origin, trust_env=False) as outsider:
            bad = await outsider.get('/admin/oauth/mcp/callback', params={'state':'guess','code':'fake-code'})
            assert bad.status_code == 409 and remote.tokens == 0
            returned = await outsider.get('/admin/oauth/mcp/callback', params={'state':remote.query['state'][0],'code':'fake-code'})
            assert returned.status_code == 303 and remote.tokens == 1
            assert (await outsider.get('/admin/oauth/mcp/callback', params={'state':remote.query['state'][0],'code':'fake-code'})).status_code == 409
        flow = parse_qs(urlsplit(returned.headers['location']).query)['mcp_oauth'][0]
        async with httpx2.AsyncClient(base_url=origin, headers={'Origin':origin}, trust_env=False) as second:
            await login(second, key, origin)
            response = await second.post('/admin/api/oauth/mcp/complete', json={'id':flow})
            assert response.status_code == 403
        review = await http.post('/admin/api/oauth/mcp/complete', json={'id':flow})
        assert review.status_code == 200
        assert (await http.post('/admin/api/oauth/mcp/complete', json={'id':flow})).status_code == 409
        await change(http, 'members/add', id='new-member')
        assert (await apply(http, review)).status_code == 409
        assert not gw.app.state.admin.oauth.persisted
        # A saved change invalidates an unfinished consent before token exchange.
        await consent_start(http, remote)
        await change(http, 'members/add', id='another-member')
        response = await http.get('/admin/oauth/mcp/callback', params={'state':remote.query['state'][0],'code':'fake-code'})
        assert response.status_code == 409 and remote.tokens == 1
        await consent_start(http, remote)
        await http.post('/admin/api/auth/logout', json={})
        response = await http.get('/admin/oauth/mcp/callback', params={'state':remote.query['state'][0],'code':'fake-code'})
        assert response.status_code == 401 and remote.tokens == 1


@pytest.mark.parametrize('failure,expected', [('deny','oauth_declined'), ('invalid_client','oauth_client_rejected'),
                                              ('invalid_grant','oauth_code_rejected'), ('issuer','oauth_callback_invalid')])
async def test_oauth_failures_are_actionable_and_secret_free(tmp_path, monkeypatch, failure, expected):
    remote = Remote(monkeypatch)
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        await consent_start(http, remote)
        params = {'state':remote.query['state'][0], 'code':'fake-code'}
        if failure == 'deny':
            params['error'] = 'access_denied'
        elif failure == 'issuer':
            params['iss'] = 'https://wrong.example.test'
        else:
            remote.fail_token = failure
        returned = await http.get('/admin/oauth/mcp/callback', params=params)
        assert returned.status_code == 303
        flow = parse_qs(urlsplit(returned.headers['location']).query)['mcp_oauth'][0]
        response = await http.post('/admin/api/oauth/mcp/complete', json={'id':flow})
        assert response.status_code == 400 and response.json()['error'] == expected, response.text
        assert not gw.app.state.admin.oauth.records
        assert response.json()["incident"] in gw.audit_text()
        assert 'private-' not in response.text + gw.audit_text()


@pytest.mark.parametrize('case,expected', [('pkce','oauth_pkce_required'), ('registration','oauth_client_registration_required'),
                                          ('issuer','oauth_issuer_changed')])
async def test_oauth_discovery_fails_closed(tmp_path, monkeypatch, case, expected):
    remote = Remote(monkeypatch)
    settings, credentials = {'url':URL, 'auth':'oauth'}, {}
    if case == 'pkce':
        remote.pkce = ['plain']
    if case == 'registration':
        remote.no_registration = True
    if case == 'issuer':
        settings.update(client_id='registered', issuer='https://trusted.example.test', auth_method='client_secret_post')
        credentials['client_secret'] = 'private-registered-secret'
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        response = await change(http, 'oauth/mcp/start', kind='remote', id='remote-notes', owner='person_a',
                                settings=settings, credentials=credentials)
        assert response.status_code == 422 and response.json()['error'] == expected, response.text
        assert remote.tokens == 0
        assert all(b'private-registered-secret' not in r.content for r in remote.requests)


async def test_expired_refresh_is_recoverable_through_reauthorization(tmp_path, monkeypatch):
    remote = Remote(monkeypatch)
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        await consent_start(http, remote)
        assert (await apply(http, await consent_complete(http, remote))).status_code == 200
        admin = gw.app.state.admin
        ref = next(c.oauth_ref for c in admin.runtime.gateway.cfg.connections if c.id == 'remote-notes')
        admin.oauth.get(ref)['expires'] = 0
        remote.fail_token = 'invalid_grant'
        response = await change(http, 'connections/test', id='remote-notes')
        assert response.status_code == 422 and response.json()['error'] == 'oauth_reauthorization_required'
        assert remote.tokens == 1
        # No automatic consent or registration on a failed background refresh.
        registrations = sum(str(r.url).endswith('/register') for r in remote.requests)
        await change(http, 'connections/test', id='remote-notes')
        assert sum(str(r.url).endswith('/register') for r in remote.requests) == registrations
        remote.fail_token = None
        await consent_start(http, remote)
        assert (await apply(http, await consent_complete(http, remote))).status_code == 200
        assert ref not in admin.oauth.records
        assert (await change(http, 'connections/test', id='remote-notes')).status_code == 200


async def test_remote_endpoint_changes_do_not_reuse_credentials(tmp_path, monkeypatch):
    Remote(monkeypatch, 'bearer')
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        assert (await apply(http, await remote_preview(http, 'bearer'))).status_code == 200
        changed = await change(http, 'connections/preview', kind='remote', id='remote-notes', owner='person_a',
                               settings={'url':'https://different.example.test/mcp', 'auth':'bearer'}, credentials={})
        assert changed.status_code == 400 and changed.json()['error'] == 'missing_token'
        for url in ('http://mcp.example.test/mcp', URL+'?token=secret', 'https://user:pass@mcp.example.test/mcp'):
            rejected = await change(http, 'connections/preview', kind='remote', id='new-remote', owner='person_a',
                                    settings={'url':url, 'auth':'none'}, credentials={})
            assert rejected.status_code == 400 and rejected.json()['error'] == 'https_url_required'


async def test_two_remote_accounts_share_tool_names_but_keep_credentials_and_grants_separate(tmp_path, monkeypatch):
    from helpers import TOKEN_A, TOKEN_B
    from agent_gateway import discovery
    from types import SimpleNamespace
    first = Remote(monkeypatch, 'bearer')
    second = Remote(monkeypatch, 'bearer', url='https://other.example.test/mcp')
    second.access = 'private-other-account-key'
    def dispatch(request):
        return (first if str(request.url) == URL else second).handle(request)
    monkeypatch.setattr(upstream, 'http_client', lambda **kw: httpx2.AsyncClient(transport=httpx2.MockTransport(dispatch), **kw))
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        for name, owner, remote, agent in [('remote-one','person_a',first,'agent-a'), ('remote-two','person_b',second,'agent-b')]:
            preview = await change(http, 'connections/preview', kind='remote', id=name, owner=owner,
                                   settings={'url':remote.url,'auth':'bearer','service':'notes-proxy'}, credentials={'token':remote.access})
            assert (await apply(http, preview)).status_code == 200
            assert (await change(http, 'permissions/connection', client=agent, connection=name, access='read')).status_code == 200
        gateway = gw.app.state.admin.runtime.gateway
        a, b = SimpleNamespace(client_id='agent-a',principal='person_a'), SimpleNamespace(client_id='agent-b',principal='person_b')
        discovered = discovery.search_tools(gateway, a, {'connection':'remote-one'})['tools'][0]['name']
        assert discovered == discovery.search_tools(gateway, b, {'connection':'remote-two'})['tools'][0]['name']
        assert {c['connection'] for c in discovery.search_connections(gateway,a,{'tool':discovered})['connections']} == {'remote-one'}
        assert {c['connection'] for c in discovery.search_connections(gateway,b,{'tool':discovered})['connections']} == {'remote-two'}
        for token, allowed, denied in [(TOKEN_A,'remote_one_read_note','remote_two_read_note'),(TOKEN_B,'remote_two_read_note','remote_one_read_note')]:
            ok = (await rpc(origin,token,'tools/call',{'name':allowed,'arguments':{}})).json()['result']
            assert not ok.get('isError')
            failed = await rpc(origin,token,'tools/call',{'name':denied,'arguments':{}})
            assert failed.json().get('error') or failed.json()['result'].get('isError')
        assert len(first.calls) == len(second.calls) == 1
        assert all(r.headers.get('Authorization') != 'Bearer '+second.access for r in first.requests)
        assert all(r.headers.get('Authorization') != 'Bearer '+first.access for r in second.requests)


async def test_removed_oauth_grant_cannot_be_resurrected_by_late_refresh(tmp_path, monkeypatch):
    from agent_gateway.oauth import GrantStorage
    from agent_gateway.passkey import Refused
    from mcp.shared.auth import OAuthToken
    remote = Remote(monkeypatch)
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        await consent_start(http, remote)
        assert (await apply(http, await consent_complete(http, remote))).status_code == 200
        vault = gw.app.state.admin.oauth
        ref = next(iter(vault.persisted))
        storage = GrantStorage(vault, ref)
        assert (await change(http,'connections/remove',id='remote-notes')).status_code == 200
        with pytest.raises(Refused):
            await storage.set_tokens(OAuthToken(access_token='late-private-token', token_type='Bearer'))
        assert ref not in OAuthVault(gw.app.state.admin.store.base).records


async def test_oauth_apply_failure_keeps_existing_config_and_retryable_draft(tmp_path, monkeypatch):
    remote = Remote(monkeypatch)
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        await consent_start(http, remote)
        review = await consent_complete(http, remote)
        admin = gw.app.state.admin
        before = await state(http)
        original = admin.store.save
        def full(_):
            import errno
            raise OSError(errno.ENOSPC, 'private-input')
        monkeypatch.setattr(admin.store, 'save', full)
        failed = await apply(http, review)
        assert failed.status_code == 500 and failed.json()['error'] == 'storage_full'
        assert (await state(http))['connections'] == before['connections']
        assert not admin.oauth.persisted and not admin.oauth.file.names()
        monkeypatch.setattr(admin.store, 'save', original)
        assert (await apply(http, review)).status_code == 200


@pytest.mark.parametrize('method', ['none','client_secret_post','client_secret_basic','cimd'])
async def test_registered_and_url_based_oauth_clients(tmp_path, monkeypatch, method):
    remote = Remote(monkeypatch)
    settings = {'url':URL,'auth':'oauth'}
    credentials = {}
    if method == 'cimd':
        remote.cimd = True
        remote.no_registration = True
        settings['client_metadata_url'] = 'https://client.example.test/oauth.json'
    else:
        settings.update(issuer=ISSUER,client_id='registered-client',auth_method=method)
        if method != 'none':
            credentials['client_secret'] = 'private-registered-secret'
    async with web_gateway(tmp_path) as (gw,http,origin,path):
        await setup(http,origin,path)
        started = await change(http,'oauth/mcp/start',kind='remote',id='remote-notes',owner='person_a',settings=settings,credentials=credentials)
        assert started.status_code == 200, started.text
        remote.query = parse_qs(urlsplit(started.json()['url']).query)
        assert (await apply(http,await consent_complete(http,remote))).status_code == 200
        assert not any(str(r.url).endswith('/register') for r in remote.requests)
        request = next(r for r in remote.requests if str(r.url).endswith('/token'))
        form = parse_qs(request.content.decode())
        if method == 'client_secret_post':
            assert form['client_secret'] == ['private-registered-secret']
        elif method == 'client_secret_basic':
            import base64
            assert base64.b64decode(request.headers['Authorization'].split()[1]).decode() == 'registered-client:private-registered-secret'
            assert 'client_secret' not in form
        else:
            assert 'client_secret' not in form and 'Authorization' not in request.headers
        assert (await change(http,'connections/test',id='remote-notes')).status_code == 200


async def test_oauth_connection_survives_full_gateway_restart(tmp_path,monkeypatch):
    from service_helpers import free_port
    remote = Remote(monkeypatch)
    port = free_port()
    async with web_gateway(tmp_path,port=port) as (gw,http,origin,path):
        key,_ = await setup(http,origin,path)
        await consent_start(http,remote)
        assert (await apply(http,await consent_complete(http,remote))).status_code == 200
        before = (await state(http))['revision']
        vault = gw.app.state.admin.oauth
        ref = next(iter(vault.persisted))
        vault.get(ref)['expires'] = 0
        vault.save(ref)
    async with web_gateway(tmp_path,path=path,port=port) as (gw,http,origin,path):
        await login(http,key,origin)
        assert (await change(http,'connections/test',id='remote-notes')).status_code == 200
        assert remote.tokens == 2 and (await state(http))['revision'] == before


@pytest.mark.parametrize('status', [200,503])
async def test_oauth_revoke_reports_provider_confirmation(tmp_path,monkeypatch,status):
    remote = Remote(monkeypatch)
    async with web_gateway(tmp_path) as (gw,http,origin,path):
        await setup(http,origin,path)
        await consent_start(http,remote)
        assert (await apply(http,await consent_complete(http,remote))).status_code == 200
        vault = gw.app.state.admin.oauth
        ref = next(iter(vault.persisted))
        vault.get(ref)['authorization_metadata']['revocation_endpoint'] = ISSUER+'/revoke'
        revoked = []
        def handler(request):
            assert not vault.get(ref)['tokens']
            revoked.append(parse_qs(request.content.decode()))
            return httpx2.Response(status)
        vault._http = lambda: httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
        reply = await change(http,'oauth/revoke',id='remote-notes')
        assert reply.json() == {'local_revoked': True, 'provider': 'revoked' if status == 200 else 'failed'}
        assert {r['token_type_hint'][0] for r in revoked} == {'access_token','refresh_token'}
        assert not OAuthVault(gw.app.state.admin.store.base).get(ref)['tokens']


@pytest.mark.parametrize('denied', ['resource', 'scope'])
async def test_oauth_distinguishes_resource_denial_from_scope_challenge(tmp_path, monkeypatch, denied):
    remote = Remote(monkeypatch)
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        await consent_start(http, remote)
        assert (await apply(http, await consent_complete(http, remote))).status_code == 200
        remote.denied = denied
        response = await change(http, 'connections/test', id='remote-notes')
        assert response.status_code == 422
        assert response.json()['error'] == ('oauth_scope_rejected' if denied == 'scope' else 'connector_access_denied')
        assert remote.tokens == 1
        if denied == 'resource':
            remote.denied = None
            assert (await change(http, 'connections/test', id='remote-notes')).status_code == 200


@pytest.mark.parametrize('status,expected', [(401,'connector_auth_rejected'),(403,'connector_access_denied'),
                                            (404,'connector_endpoint_missing'),(429,'connector_rate_limited'),(503,'connector_http_error')])
async def test_remote_http_failures_keep_the_original_cause(tmp_path,monkeypatch,status,expected):
    def failure(request):
        return httpx2.Response(status, json={'error_description':'private-provider-detail'})
    monkeypatch.setattr(upstream, 'http_client', lambda **kw: httpx2.AsyncClient(transport=httpx2.MockTransport(failure), **kw))
    async with web_gateway(tmp_path) as (gw,http,origin,path):
        await setup(http,origin,path)
        response = await remote_preview(http,'bearer')
        assert response.status_code == 422 and response.json()['error'] == expected, response.text
        assert 'private-' not in response.text + gw.audit_text()


@pytest.mark.parametrize('name, definition, expected', [
    ('get_issue', {}, 'read'),
    ('list-issues', {}, 'read'),
    ('searchIssues', {}, 'read'),
    ('QueryProjects', {}, 'read'),
    ('get_or_create_issue', {}, 'write'),
    ('search_and_replace', {}, 'write'),
    ('query_sql', {}, 'write'),
    ('query', {'inputSchema': {'properties': {'statement': {}}}}, 'write'),
    ('get_issue', {'annotations': {'readOnlyHint': False}}, 'write'),
    ('list_projects', {'annotations': {'destructiveHint': True}}, 'write'),
    ('custom_action', {'annotations': {'readOnlyHint': True}}, 'write'),
])
def test_suggested_remote_access(name, definition, expected):
    from agent_gateway.admin_remote import suggested_access
    assert suggested_access(name, definition) == expected
