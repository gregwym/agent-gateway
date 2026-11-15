"""Existing mail connections gain reviewed capabilities without gaining permissions."""
import json

import pytest

from helpers import SECRETS, TOKEN_A, prepare
from passkey_helpers import Page, approval_config, request_id_in
from service_helpers import free_port, mail_account
from test_admin import change, rpc, setup, state, web_gateway
from test_connector_mail import mail_connection
from test_imap_operations import extended_connection
from test_smtp import smtp_server

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize('operation', ['connections/preview', 'connections/review-tools'])
async def test_review_extends_existing_mail_and_preserves_original_restrictions(tmp_path, operation, monkeypatch):
    # Non-bundled/externally managed connectors retain the manual review path.
    monkeypatch.setattr('agent_gateway.catalog_sync.bundled_manifest', lambda conn: None)
    with mail_account(tmp_path / 'server', 'account@example.test', 'fake-app-password') as account:
        port = free_port()
        origin = f'http://localhost:{port}'
        raw = approval_config(origin=origin)
        raw['admin'] = {'owner': 'person_a', 'state': 'admin.enc'}
        conn = mail_connection('mail', 'person_a', account, 'mail_password', 'a')
        conn['env'].update(SMTP_HOST='smtp.example.test', SMTP_PORT='587', SMTP_SECURITY='starttls')
        conn['tools'][2]['pin'] = {'mailbox': 'INBOX'}
        old_names = {t['name'] for t in conn['tools']}
        raw['connections'].append(conn)
        raw['policy'].append({'principals': ['person_a'], 'connection': 'mail', 'tools': sorted(old_names), 'effect': 'allow'})
        path = await prepare(tmp_path / 'gateway', raw, secrets={**SECRETS, 'mail_password': account.password})
        async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, path):
            await setup(http, origin, path)
            before = (await rpc(origin, TOKEN_A)).json()['result']['tools']
            original = next(c for c in gw.app.state.admin.runtime.gateway.cfg.connections if c.id == 'mail').model_dump(mode='json')
            current = next(c for c in (await state(http))['connections'] if c['id'] == 'mail')
            assert len(current['available_tools']) == 7
            assert sum(t['access'] == 'write' for t in current['available_tools']) == 5
            refused = await change(http, 'permissions/connection', client='agent-a', connection='mail', access='read_write')
            assert refused.json()['error'] == 'connection_tools_update_required'
            preview = await change(http, operation, id='mail') if operation == 'connections/review-tools' else await change(http, operation, id='mail', kind='imap', owner='person_a',
                                   settings={'username': account.user, 'host': 'localhost', 'port': str(account.front.port),
                                             'smtp_host': 'smtp.example.test', 'smtp_port': '587', 'smtp_security': 'starttls'}, credentials={})
            assert preview.status_code == 200, preview.text
            assert len(preview.json()['definitions']) == 11
            assert (await rpc(origin, TOKEN_A)).json()['result']['tools'] == before  # preview is read-only
            assert (await change(http, 'connections/apply', draft=preview.json()['draft'], reviewed=True)).status_code == 200
            mail = next(c for c in (await state(http))['connections'] if c['id'] == 'mail')
            assert len(mail['tools']) == 11
            assert next(t for t in mail['tools'] if t['upstream'] == 'get_message')['pin'] == {'mailbox': 'INBOX'}
            assert all(t['permissions']['agent-a'] == ('allow' if t['name'] in old_names else 'deny') for t in mail['tools'])
            cfg = next(c for c in gw.app.state.admin.runtime.gateway.cfg.connections if c.id == 'mail')
            if operation == 'connections/review-tools':
                assert {k: v for k, v in cfg.model_dump(mode='json').items() if k != 'tools'} == {k: v for k, v in original.items() if k != 'tools'}
            assert mail['available_tools'] == []
            assert set(cfg.secret_env) == {'IMAP_PASSWORD'}  # SMTP uses the same stored credential
            assert mail['settings']['smtp_host'] == 'smtp.example.test'
            assert (await change(http, 'permissions/connection', client='agent-a', connection='mail', access='read_write')).status_code == 200
            mail = next(c for c in (await state(http))['connections'] if c['id'] == 'mail')
            assert all(t['permissions']['agent-a'] == ('allow' if t['access'] == 'read' else 'approval_required') for t in mail['tools'])


@pytest.mark.parametrize('reject_auth', [False, True])
async def test_one_connection_checks_both_protocols_and_requires_exact_send_approval(tmp_path, reject_auth):
    # Reuse the local TLS certificate for both simulated services.
    with mail_account(tmp_path / 'imap', 'account@example.test', 'fake-app-password') as account:
        with smtp_server(tmp_path / 'smtp', cert_pair=(account.cert, account.cert.parent / 'key.pem'), reject_auth=reject_auth) as (smtp_port, cert, events, messages, _):
            port = free_port()
            origin = f'http://localhost:{port}'
            raw = approval_config(origin=origin)
            raw['admin'] = {'owner': 'person_a', 'state': 'admin.enc'}
            conn = extended_connection(account)
            conn['env'].update(SMTP_HOST='localhost', SMTP_PORT=str(smtp_port), SMTP_SECURITY='starttls')
            raw['connections'].append(conn)
            raw['policy'].append({'principals': ['person_a'], 'connection': conn['id'], 'tools': ['mail_send_message'], 'effect': 'allow'})
            path = await prepare(tmp_path / 'gateway', raw, secrets={**SECRETS, 'mail_password': account.password})
            async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, path):
                key, _ = await setup(http, origin, path)
                tested = await http.post('/admin/api/connections/test', json={'id': conn['id']})
                if reject_auth:
                    assert tested.status_code == 422 and tested.json()['error'] == 'smtp_credentials_rejected'
                    assert 'fake-app-password' not in tested.text and not messages
                    current = next(c for c in (await state(http))['connections'] if c['id'] == conn['id'])
                    assert current['test']['reason'] == 'smtp_credentials_rejected'
                    return
                assert tested.status_code == 200, tested.text
                assert events.count('AUTH') == 1 and not messages and 'LIST' in account.front.commands
                args = {'to': ['ok@example.test'], 'subject': 'approved fake message', 'text': 'simulated content'}
                async def send(arguments):
                    return (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'mail_send_message', 'arguments': arguments})).json()['result']
                # An allow rule from before sending had a separate permission must fail closed.
                pending = await send(args)
                request_id = request_id_in(pending['content'][0]['text'])
                page = Page(origin, origin)
                status, view = await page.view(request_id)
                assert status == 200 and 'approved fake message' in json.dumps(view) and not messages
                approved, detail = await page.decide('approve', request_id, key, origin=origin)
                assert approved == 200, detail
                different = await send({**args, 'to': ['different@example.test']})
                assert request_id_in(different['content'][0]['text']) != request_id
                sent = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'gateway_call_tool',
                                  'arguments': {'request_id': request_id}})).json()['result']
                assert sent['structuredContent']['status'] == 'succeeded'
                outcome = json.loads(sent['content'][1]['text'])
                assert outcome['results'] == [{'recipient': 'ok@example.test', 'status': 'accepted'}]
                assert len(messages) == 1
                repeat = await send(args)
                assert repeat['structuredContent']['request_id'] == request_id and len(messages) == 1

                updated = await change(http, 'permissions/connection', client='agent-a', connection=conn['id'],
                                       access='read_write_direct')
                assert updated.status_code == 200
                mail = next(c for c in (await state(http))['connections'] if c['id'] == conn['id'])
                assert next(t for t in mail['tools'] if t['upstream'] == 'archive_messages')['permissions']['agent-a'] == 'allow'
                still_pending = await send(args)
                assert still_pending['isError'] and len(messages) == 1
                direct = await change(http, 'permissions/connection', client='agent-a', connection=conn['id'],
                                      access='read_write_direct', mail_send='allow')
                assert direct.status_code == 200
                assert not (await send(args)).get('isError') and len(messages) == 2
                await change(http, 'permissions/connection', client='agent-a', connection=conn['id'],
                             access='read_write_direct', mail_send='deny')
                denied = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'mail_send_message', 'arguments': args})).json()
                assert denied['error']['code'] == -32602 and len(messages) == 2
