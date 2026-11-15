"""An old four-tool mail connection upgrades directly from its permission card."""
import sys

import pytest

from helpers import SECRETS, TOKEN_A, prepare
from passkey_helpers import approval_config
from service_helpers import free_port
from test_admin import rpc
from test_admin_feedback_browser import admin_page, playwright

pytestmark = [pytest.mark.anyio, pytest.mark.browser]


@pytest.mark.parametrize('locale', ['en-US', 'zh-CN'])
async def test_legacy_mail_card_explains_and_reviews_new_write_tools(tmp_path, locale):
    def t(en, zh):
        return zh if locale == 'zh-CN' else en
    port = free_port()
    origin = f'http://localhost:{port}'
    raw = approval_config(origin=origin)
    raw['admin'] = {'owner': 'person_a', 'state': 'admin.enc'}
    old = ['list_mailboxes', 'search_messages', 'get_message', 'get_attachment']
    raw['connections'].append({'id': 'mail', 'service': 'imap-mail', 'account': 'fake', 'owner': 'person_a', 'transport': 'stdio',
        'command': [sys.executable, '-m', 'agent_gateway.connectors.imap_mail'],
        'env': {'IMAP_HOST': '127.0.0.1', 'IMAP_PORT': '1', 'IMAP_USERNAME': 'fake@example.test'},
        'secret_env': {'IMAP_PASSWORD': 'mail_password'},
        'tools': [{'name': 'mail_' + n, 'upstream': n} for n in old]})
    raw['policy'].append({'principals': ['person_a'], 'connection': 'mail', 'tools': ['mail_' + n for n in old], 'effect': 'allow'})
    path = await prepare(tmp_path, raw, secrets={**SECRETS, 'mail_password': 'fake-password'})
    async with admin_page(tmp_path, locale, path=path, port=port) as (page, origin):
        await page.get_by_role('button', name=t('Permissions', '权限'), exact=True).click()
        card = page.locator('.permission-card[data-connection=mail]')
        await playwright.expect(card).to_contain_text(t('older tool list', '仍使用旧工具列表'))
        await playwright.expect(card).not_to_contain_text(t('only provides read operations', '不支持写入'))
        assert await card.locator('select[name=connection_access] option[value=read_write]').count() == 0
        before = (await rpc(origin, TOKEN_A)).json()['result']['tools']
        await card.get_by_role('button', name=t('Review new tools', '审阅新工具'), exact=True).click()
        review = page.get_by_role('dialog')
        await playwright.expect(review.get_by_role('heading', name='send_message', exact=True)).to_have_count(1)
        assert (await rpc(origin, TOKEN_A)).json()['result']['tools'] == before
        await review.get_by_role('checkbox', name=t('I reviewed these definitions and permissions.', '我已审阅这些工具定义和权限。'), exact=True).check()
        await review.get_by_role('button', name=t('Apply connector', '应用连接器'), exact=True).click()
        await playwright.expect(review).to_have_count(0)
        await playwright.expect(card.get_by_role('button', name=t('Review new tools', '审阅新工具'), exact=True)).to_have_count(0)
        assert await card.locator('select[name=connection_access] option[value=read_write]').count() == 1
        assert (await rpc(origin, TOKEN_A)).json()['result']['tools'] == before
        await card.get_by_label(t('Connection access', '连接权限'), exact=True).select_option('read_write')
        await card.get_by_role('button', name=t('Save connection access', '保存连接权限'), exact=True).click()
        await playwright.expect(card.get_by_label(t('Connection access', '连接权限'), exact=True)).to_have_value('read_write')
        tools = (await rpc(origin, TOKEN_A)).json()['result']['tools']
        assert 'mail_send' in {tool['name'] for tool in tools}
        await page.reload()
        await page.get_by_role('button', name=t('Permissions', '权限'), exact=True).click()
        await playwright.expect(card.get_by_label(t('Connection access', '连接权限'), exact=True)).to_have_value('read_write')
        await playwright.expect(card.get_by_label(t('Write approval', '写入审批'), exact=True)).to_have_value('approval_required')
