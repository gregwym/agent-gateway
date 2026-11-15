"""Future bundled capability changes reconcile automatically, without data patches."""
import copy
import sys
from types import SimpleNamespace

import pytest

from agent_gateway import catalog_sync
from agent_gateway.admin_config import ManagedStore
from agent_gateway.cli import resolve_secrets
from agent_gateway.config import Config, load_config
from agent_gateway.connectors._base import Tool
from agent_gateway.lock import Lock, definition_of
from agent_gateway.policy import Policy
from helpers import write_config
from passkey_helpers import approval_config


def old_gateway(tmp_path):
    raw = approval_config()
    raw['admin'] = {'owner': 'person_a', 'state': 'admin.enc'}
    old = ['list_mailboxes', 'search_messages', 'get_message', 'get_attachment']
    raw['connections'] = [{'id': 'any_mail', 'service': 'imap-mail', 'account': 'fake', 'owner': 'person_a',
        'transport': 'stdio', 'command': [sys.executable, '-m', 'agent_gateway.connectors.imap_mail'],
        'env': {'IMAP_USERNAME': 'fake@example.test', 'IMAP_HOST': '127.0.0.1', 'IMAP_PORT': '1'},
        'secret_env': {'IMAP_PASSWORD': 'mail_password'},
        'tools': [{'upstream': name, 'name': 'old_' + name} for name in old]}]
    raw['connections'][0]['tools'][2]['pin'] = {'mailbox': 'INBOX'}
    raw['policy'] = [{'principals': ['person_a'], 'connection': 'any_mail', 'tools': ['old_' + n for n in old], 'effect': 'allow'}]
    path = write_config(tmp_path, raw, secrets={'mail_password': 'fake-password'})
    cfg = load_config(path)
    manifest = catalog_sync.bundled_manifest(cfg.connections[0])
    lock = Lock()
    for name in old:
        lock.put('any_mail', manifest[name]['definition'])
    lock.save(cfg.lock_file)
    return SimpleNamespace(cfg=cfg, lock=lock, secrets=resolve_secrets(cfg))


def add_future(manifest, name, access):
    manifest[name] = {'suffix': name, 'access': access,
                      'definition': definition_of(Tool(name, 'A future bundled capability.', lambda _: None, read_only=access == 'read').as_mcp())}


def test_startup_and_two_future_releases_add_tools_without_disk_writes_or_new_grants(tmp_path, monkeypatch):
    gateway = old_gateway(tmp_path)
    old = gateway.cfg
    store = ManagedStore(gateway)
    cfg, lock, values = store.effective(store.state)
    assert not old.admin.state.exists()
    assert len(cfg.connections[0].tools) == 11
    assert len(store.catalog_updates['any_mail']['added']) == 7
    for client in cfg.clients:
        for tool in old.connections[0].tools:
            assert Policy(old).effect(client.subject, tool.name, client.id) == Policy(cfg).effect(client.subject, tool.name, client.id)
    # Simulate an administrator's existing grants before another release.
    saved = store.candidate()
    saved['config']['policy'] = [{'clients': ['agent-a'], 'connection': 'any_mail', 'tools': [t.name for t in cfg.connections[0].tools], 'effect': 'allow'}]
    store.save(saved)
    disk = old.admin.state.read_bytes()
    manifest = copy.deepcopy(catalog_sync.bundled_manifest(cfg.connections[0]))
    add_future(manifest, 'future_read', 'read')
    add_future(manifest, 'future_write', 'write')
    manifest['get_message']['definition']['description'] += ' Improved in a future release.'
    manifest['get_message']['definition']['inputSchema']['properties']['optional_new_field'] = {'type': 'string'}
    monkeypatch.setattr(catalog_sync, 'bundled_manifest', lambda _: manifest)
    upgraded = ManagedStore(gateway)
    future_cfg, future_lock, future_values = upgraded.effective(upgraded.state)
    assert old.admin.state.read_bytes() == disk and values == future_values
    assert len(future_cfg.connections[0].tools) == 13
    assert future_cfg.clients == cfg.clients
    assert future_cfg.connections[0].tools[:11] == cfg.connections[0].tools
    assert Policy(future_cfg).effect('person_a', 'old_get_message', 'agent-a') == 'allow'
    for client in future_cfg.clients:
        for tool in future_cfg.connections[0].tools[11:]:
            assert Policy(future_cfg).effect(client.subject, tool.name, client.id) == 'deny'
    assert catalog_sync.catalog_revision(cfg, lock) != catalog_sync.catalog_revision(future_cfg, future_lock)
    assert ManagedStore(gateway).state == upgraded.state
    upgraded.save(upgraded.state)
    assert ManagedStore(gateway).state == upgraded.state
    add_future(manifest, 'later_read', 'read')
    later = ManagedStore(gateway)
    assert len(later.effective(later.state)[0].connections[0].tools) == 14
    assert len(later.catalog_updates['any_mail']['added']) == 1


def test_breaking_restrictions_are_preserved_and_reconcile_after_ui_edit(tmp_path, monkeypatch):
    gateway = old_gateway(tmp_path)
    store = ManagedStore(gateway)
    store.state['config']['connections'][0]['tools'].append({'upstream': 'get_message', 'name': 'unrestricted_alias'})
    store.save(store.state)
    manifest = copy.deepcopy(catalog_sync.bundled_manifest(gateway.cfg.connections[0]))
    del manifest['get_message']['definition']['inputSchema']['properties']['mailbox']
    monkeypatch.setattr(catalog_sync, 'bundled_manifest', lambda _: manifest)
    changed = ManagedStore(gateway)
    cfg, lock, _ = changed.effective(changed.state)
    assert next(t for t in cfg.connections[0].tools if t.upstream == 'get_message').pin == {'mailbox': 'INBOX'}
    assert lock.get('any_mail', 'get_message') == gateway.lock.get('any_mail', 'get_message')
    assert {'tool': 'old_get_message', 'reason': 'pin_unknown_argument'} in changed.catalog_updates['any_mail']['issues']
    candidate = changed.candidate()
    next(t for t in candidate['config']['connections'][0]['tools'] if t['upstream'] == 'get_message')['pin'] = {}
    fixed, report = changed.reconcile(candidate)
    assert report['any_mail']['issues'] == []
    assert changed.effective(fixed)[1].get('any_mail', 'get_message')['definition'] == manifest['get_message']['definition']


def test_read_to_write_and_removed_capabilities_cannot_inherit_grants(tmp_path, monkeypatch):
    gateway = old_gateway(tmp_path)
    store = ManagedStore(gateway)
    store.save(store.state)
    manifest = copy.deepcopy(catalog_sync.bundled_manifest(gateway.cfg.connections[0]))
    manifest['get_message']['access'] = 'write'
    manifest['get_message']['definition']['annotations']['readOnlyHint'] = False
    del manifest['search_messages']
    monkeypatch.setattr(catalog_sync, 'bundled_manifest', lambda _: manifest)
    changed = ManagedStore(gateway)
    cfg, _, _ = changed.effective(changed.state)
    assert Policy(cfg).effect('person_a', 'old_get_message', 'agent-a') == 'deny'
    assert Policy(cfg).effect('person_a', 'old_search_messages', 'agent-a') == 'deny'
    assert next(t for t in cfg.connections[0].tools if t.name == 'old_get_message').access == 'write'
    assert Policy(cfg).effect('person_a', 'old_get_attachment', 'agent-a') == 'allow'


@pytest.mark.parametrize('module,kind,env', [
    ('agent_gateway.connectors.imap_mail', 'imap', {}),
    ('agent_gateway.connectors.gmail', 'gmail', {}),
    ('agent_gateway.connectors.caldav_calendar', 'caldav', {'CALDAV_TIMEZONE': 'America/Los_Angeles'}),
    ('agent_gateway.demo_connector', 'demo', {}),
])
def test_all_bundled_factories_produce_local_definitions(tmp_path, module, kind, env):
    gateway = old_gateway(tmp_path)
    conn = gateway.cfg.connections[0].model_copy(update={'command': [sys.executable, '-m', module], 'env': env})
    assert catalog_sync.bundled_kind(conn) == kind
    manifest = catalog_sync.bundled_manifest(conn)
    assert manifest and all(entry['definition']['name'] == name for name, entry in manifest.items())


def test_arbitrary_commands_and_remote_helpers_are_never_auto_trusted(tmp_path):
    conn = old_gateway(tmp_path).cfg.connections[0]
    for changed in [conn.model_copy(update={'command': ['wrapper', '-m', 'agent_gateway.connectors.imap_mail']}),
                    conn.model_copy(update={'command': [sys.executable, '-c', 'agent_gateway.connectors.imap_mail']}),
                    conn.model_copy(update={'transport': 'http', 'url': 'https://example.test/mcp'}),
                    conn.model_copy(update={'env': {**conn.env, 'PYTHONPATH': '/untrusted'}})]:
        assert catalog_sync.bundled_manifest(changed) is None


def test_generated_names_do_not_collide_or_reassign_old_authorizations(tmp_path):
    gateway = old_gateway(tmp_path)
    raw = gateway.cfg.model_dump(mode='json')
    second = copy.deepcopy(raw['connections'][0])
    second.update(id='any-mail', account='second')
    for tool in second['tools']:
        tool['name'] = 'second_' + tool['name']
    raw['connections'].append(second)
    cfg = Config.model_validate(raw)
    before = Lock(copy.deepcopy(gateway.lock.entries))
    before.entries['any-mail'] = copy.deepcopy(before.entries['any_mail'])
    after, _, _, _ = catalog_sync.sync_catalog(cfg, before)
    names = [t.name for c in after.connections for t in c.tools]
    assert len(names) == len(set(names)) == 22
    assert all(Policy(after).effect('person_a', t.name, 'agent-a') == 'deny' for t in after.connections[1].tools)
