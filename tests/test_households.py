"""Household ownership is independent of per-Agent access and human approval."""
import copy
import json

import pytest
from pydantic import ValidationError

from agent_gateway.admin_config import ManagedStore
from agent_gateway.audit import Audit
from agent_gateway.cli import resolve_secrets
from agent_gateway.config import Config, load_config
from agent_gateway.credentials import EncryptedFileStore
from agent_gateway.lock import Lock
from agent_gateway.policy import Policy
from agent_gateway.server import Gateway
from helpers import TOKEN_A, TOKEN_HOUSE, base_config, prepare
from passkey_helpers import Page, approval_config, request_id_in
from test_admin import change, rpc, setup, state, web_gateway

pytestmark = pytest.mark.anyio


async def test_legacy_migration_preserves_every_effect_and_token_without_startup_writes(tmp_path):
    raw = approval_config()
    raw['admin'] = {'owner': 'person_a', 'state': 'admin.enc'}
    raw['policy'].append({'principals': ['person_a'], 'connection': 'notes-a',
                          'tools': ['a_get_note'], 'effect': 'deny'})
    raw['clients'].append({**raw['clients'][0], 'id': 'another-agent', 'token_sha256': '7' * 64})
    path = await prepare(tmp_path, raw)
    cfg = load_config(path)
    old_state = {'revision': 7, 'config': {}, 'secrets': {}, 'locks': {}, 'display_names': {'person_a': 'Greg 林'}}
    disk = EncryptedFileStore(cfg.admin.state, cfg.secrets.key_file)
    disk.set('state', json.dumps(old_state))
    before = cfg.admin.state.read_bytes()
    gateway = Gateway(cfg, Lock.load(cfg.lock_file), resolve_secrets(cfg), Audit(None))
    store = ManagedStore(gateway)
    migrated, _, _ = store.effective(store.state)
    assert cfg.admin.state.read_bytes() == before
    assert store.state['revision'] == 7 and store.state['schema'] == 2
    assert 'display_names' not in store.state
    assert migrated.name_of('person_a') == 'Greg 林'
    assert {m.household for m in migrated.members} == {'household'}
    assert [(c.id, c.subject, c.token_sha256) for c in migrated.clients] == [(c.id, c.subject, c.token_sha256) for c in cfg.clients]
    old_policy, new_policy = Policy(cfg), Policy(migrated)
    for c in cfg.clients:
        for conn in cfg.connections:
            assert cfg.approvers_of(conn) == migrated.approvers_of(conn)
            for tool in conn.tools:
                assert old_policy.effect(c.subject, tool.name, c.id) == new_policy.effect(c.subject, tool.name, c.id)
    store.rename('person_a', 'Greg')
    restarted = ManagedStore(gateway)
    assert restarted.name_of('person_a') == 'Greg'
    assert restarted.state == store.state
    assert 'display_names' not in json.loads(disk.get('state'))
    # A host file can also start directly in the household format, with no web overrides.
    modern_base = migrated.model_copy(update={'admin': migrated.admin.model_copy(update={'state': tmp_path / 'modern.enc'})})
    fresh = ManagedStore(Gateway(modern_base, Lock.load(cfg.lock_file), resolve_secrets(cfg), Audit(None)))
    assert fresh.name_of('person_a') == 'Greg 林'
    fresh.rename('person_a', 'Greg from YAML')
    assert fresh.effective(fresh.candidate())[0].name_of('person_a') == 'Greg from YAML'


async def test_agents_in_one_household_never_inherit_each_others_grants(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        key, _ = await setup(http, origin, path)
        tokens = {}
        for name in ('one', 'two'):
            response = await change(http, 'clients/create', id=name, household='household')
            assert response.status_code == 200, response.text
            tokens[name] = response.json()['token']
            assert {t['name'] for t in (await rpc(origin, tokens[name])).json()['result']['tools']} == {'gateway_call_tool'}
        grant = await change(http, 'permissions/save', client='one', connection='notes-a', tool='a_list_notes', effect='allow')
        assert grant.status_code == 200, grant.text
        assert {t['name'] for t in (await rpc(origin, tokens['one'])).json()['result']['tools']} == {'a_list_notes', 'gateway_call_tool'}
        assert {t['name'] for t in (await rpc(origin, tokens['two'])).json()['result']['tools']} == {'gateway_call_tool'}
        denied = (await rpc(origin, tokens['two'], 'tools/call', {'name': 'a_list_notes', 'arguments': {}})).json()
        assert denied['error']['code'] == -32602
        # A household Agent can request a personal tool, but only its owner approves.
        assert (await change(http, 'permissions/save', client='one', connection='notes-a', tool='a_add_note', effect='approval_required')).status_code == 200
        arguments = {'folder': 'inbox', 'text': 'owner approved for a household Agent'}
        pending = (await rpc(origin, tokens['one'], 'tools/call', {'name': 'a_add_note', 'arguments': arguments})).json()
        request_id = request_id_in(pending['result']['content'][0]['text'])
        page = Page(origin, origin)
        view = (await page.view(request_id))[1]
        assert view['client'] == 'one' and view['owner'] == 'person_a' and view['approvers'] == ['person_a']
        assert (await page.decide('approve', request_id, key, origin=origin))[0] == 200
        result = (await rpc(origin, tokens['one'], 'tools/call', {'name': 'gateway_call_tool',
                                                               'arguments': {'request_id': request_id}})).json()
        assert result['result']['structuredContent']['status'] == 'succeeded'
        assert (await change(http, 'clients/revoke', id='one')).status_code == 200
        assert (await rpc(origin, tokens['one'])).status_code == 401
        recreated = await change(http, 'clients/create', id='one', household='household')
        assert {t['name'] for t in (await rpc(origin, recreated.json()['token'])).json()['result']['tools']} == {'gateway_call_tool'}
        # A real name can contain spaces/Unicode; IDs never appear as another name.
        response = await change(http, 'members/add', name='Alex 林', household='household')
        assert response.status_code == 200
        member = next(m for m in (await state(http))['members'] if m['name'] == 'Alex 林')
        assert member['household'] == 'household' and member['id'].startswith('member_')
        assert (await change(http, 'members/rename', id=member['id'], name='person_a')).status_code == 400
        assert (await change(http, 'members/add', name='Fake shared', shared=True)).json()['error'] == 'shared_identity_removed'


def test_household_relationships_bound_grants_and_shared_approvers():
    raw = base_config()
    raw.pop('principals'); raw.pop('shared')
    raw['households'] = [{'id': 'household', 'name': 'Home'}, {'id': 'other', 'name': 'Other'}]
    raw['members'] = [{'id': 'person_a', 'name': 'Greg', 'household': 'household'},
                      {'id': 'person_b', 'name': 'Alex', 'household': 'other'}]
    for client in raw['clients']:
        client['household'] = 'other' if client['principal'] == 'person_b' else 'household'
    raw['policy'] = [{'clients': ['agent-a'], 'connection': 'notes-a', 'tools': ['a_list_notes'], 'effect': 'allow'}]
    cfg = Config.model_validate(raw)
    assert cfg.approvers_of(cfg.connection('notes-house')) == ('person_a',)
    assert cfg.approvers_of(cfg.connection('notes-b')) == ('person_b',)
    for update in ({'principals': ['household'], 'clients': []}, {'clients': ['agent-b']}, {'clients': ['missing']}):
        invalid = copy.deepcopy(raw)
        invalid['policy'][0].update(update)
        with pytest.raises(ValidationError):
            Config.model_validate(invalid)
    invalid = copy.deepcopy(raw)
    invalid['clients'][0]['household'] = 'other'
    with pytest.raises(ValidationError):
        Config.model_validate(invalid)
    invalid = copy.deepcopy(raw)
    invalid['connections'][0]['approver'] = 'person_b'
    with pytest.raises(ValidationError):
        Config.model_validate(invalid)
