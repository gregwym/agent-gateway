"""Browser error contracts, using a real local TLS IMAP server and MCP processes."""
import ast
import errno
import json
from pathlib import Path
import re

import pytest

from helpers import prepare
from passkey_helpers import approval_config
from service_helpers import free_port, mail_account
from test_admin import setup, state, web_gateway
from test_connector_mail import mail_connection

pytestmark = pytest.mark.anyio


async def test_imap_check_reports_auth_network_and_schema_failures_without_masking(tmp_path):
    password = 'local-test-app-password'
    with mail_account(tmp_path / 'mail', 'test@icloud.example', password) as mailbox:
        port = free_port()
        raw = approval_config(origin=f'http://localhost:{port}')
        raw['admin'] = {'owner': 'person_a', 'state': 'admin.enc'}
        raw['connections'] = [mail_connection('mail', 'person_a', mailbox, 'mail-secret', 'a')]
        raw['policy'] = []
        path = await prepare(tmp_path / 'gateway', raw, secrets={'mail-secret': 'incorrect-private-password'})
        async with web_gateway(tmp_path, path=path, port=port) as (gw, http, origin, _):
            await setup(http, origin, path)
            gateway = gw.app.state.runtime.gateway
            rejected = await http.post('/admin/api/connections/test', json={'id': 'mail'})
            assert rejected.status_code == 422 and rejected.json()['error'] == 'imap_credentials_rejected'
            assert (await state(http))['connections'][0]['test']['reason'] == 'imap_credentials_rejected'
            assert 'LOGIN' in mailbox.front.commands
            # Verify the next read check clears a failed result once credentials work.
            gateway.secrets['mail-secret'] = password
            passed = await http.post('/admin/api/connections/test', json={'id': 'mail'})
            assert passed.status_code == 200 and (await state(http))['connections'][0]['test']['ok']
            assert 'LIST' in mailbox.front.commands
            conn = gateway.cfg.connections[0]
            certificate = conn.env.pop('SSL_CERT_FILE')
            untrusted = await http.post('/admin/api/connections/test', json={'id': 'mail'})
            assert untrusted.status_code == 422 and untrusted.json()['error'] == 'connector_tls_failed'
            conn.env['SSL_CERT_FILE'] = certificate
            conn.env['IMAP_PORT'] = '1'
            unreachable = await http.post('/admin/api/connections/test', json={'id': 'mail'})
            assert unreachable.status_code == 422 and unreachable.json()['error'] == 'imap_server_unreachable'
            conn.env['IMAP_PORT'] = str(mailbox.front.port)
            # A changed definition is blocked before LOGIN or the probe itself.
            gateway.lock.entries['mail']['list_mailboxes']['sha256'] = '0' * 64
            mailbox.front.commands.clear()
            changed = await http.post('/admin/api/connections/test', json={'id': 'mail'})
            assert changed.status_code == 409 and changed.json()['error'] == 'tool_definitions_changed'
            assert 'LOGIN' not in mailbox.front.commands
            output = rejected.text + passed.text + untrusted.text + unreachable.text + changed.text + json.dumps(await state(http)) + gw.audit_text()
            assert 'incorrect-private-password' not in output and password not in output


@pytest.mark.parametrize('failure,code', [
    (OSError(errno.ENOSPC, 'secret-value'), 'storage_full'),
    (PermissionError(errno.EACCES, 'secret-value'), 'storage_permission_denied'),
    (OSError(errno.EROFS, 'secret-value'), 'storage_readonly'),
    (RuntimeError('secret-value'), 'operation_failed'),
])
async def test_save_failure_has_actionable_code_and_safe_incident(tmp_path, monkeypatch, failure, code):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        before = await state(http)
        def fail(_):
            raise failure
        monkeypatch.setattr(gw.app.state.admin.store, 'save', fail)
        response = await http.post('/admin/api/members/rename', json={
            'revision': before['revision'], 'id': 'person_a', 'name': 'Test'})
        assert response.status_code == 500 and response.json()['error'] == code
        incident = response.json()['incident']
        assert re.fullmatch(r'[a-f0-9]{12}', incident) and incident in gw.audit_text()
        assert 'secret-value' not in response.text + gw.audit_text()
        assert (await state(http))['members'] == before['members']


async def test_known_browser_refusals_have_human_translations():
    root = Path(__file__).resolve().parents[1] / 'agent_gateway'
    for files, script in [(['admin.py', 'admin_auth.py', 'admin_config.py', 'admin_oauth.py', 'admin_remote.py', 'admin_mcp_oauth.py', 'oauth.py'], 'admin.js'),
                          (['passkey.py'], 'approve.js')]:
        translated = set(re.findall(r'^  ([a-z_]+): \[', (root / 'static' / script).read_text(), flags=re.M))
        codes = set()
        for filename in files:
            for node in ast.walk(ast.parse((root / filename).read_text())):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'Refused'
                        and node.args and isinstance(node.args[0], ast.Constant)):
                    codes.add(node.args[0].value)
        assert codes <= translated, codes - translated
