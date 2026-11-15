"""The common permission flow uses connection cards, with tool details collapsed."""
import os
from pathlib import Path

import pytest

from helpers import TOKEN_A
from passkey_helpers import request_id_in
from test_admin import rpc
from test_admin_feedback_browser import admin_page, playwright

pytestmark = [pytest.mark.anyio, pytest.mark.browser]


@pytest.mark.parametrize('locale', ['en-US', 'zh-CN'])
async def test_agent_rename_simple_permissions_and_household_approval(tmp_path, locale):
    def t(en, zh):
        return zh if locale == 'zh-CN' else en
    async with admin_page(tmp_path, locale) as (page, origin):
        before = (await rpc(origin, TOKEN_A)).json()['result']['tools']
        await page.get_by_role('button', name=t('Agents', 'Agent 接入'), exact=True).click()
        agent = page.get_by_role('row').filter(has=page.get_by_text('agent-a', exact=True))
        fingerprint = await agent.locator('.token-fingerprint').inner_text()
        await agent.get_by_role('button', name=t('Rename', '改名'), exact=True).click()
        await page.get_by_label(t('Agent name', 'Agent 名称'), exact=True).fill('agent-b')
        await page.get_by_role('button', name=t('Save name', '保存名称'), exact=True).click()
        await playwright.expect(page.get_by_role('dialog').get_by_role('alert')).to_contain_text(t('already exists', '已存在'))
        await page.get_by_label(t('Agent name', 'Agent 名称'), exact=True).fill('openclaw')
        await page.get_by_role('button', name=t('Save name', '保存名称'), exact=True).click()
        agent = page.get_by_role('row').filter(has=page.get_by_text('openclaw', exact=True))
        await playwright.expect(agent).to_be_visible()
        assert await agent.locator('.token-fingerprint').inner_text() == fingerprint
        assert (await rpc(origin, TOKEN_A)).json()['result']['tools'] == before
        await agent.get_by_role('button', name=t('Configure permissions', '配置权限'), exact=True).click()
        await playwright.expect(page.get_by_label('Agent', exact=True)).to_have_value('openclaw')
        card = page.locator('.permission-card[data-connection=notes-a]')
        assert not await card.locator('details').evaluate('(node) => node.open')
        await card.get_by_label(t('Connection access', '连接权限'), exact=True).select_option('read')
        await card.get_by_role('button', name=t('Save connection access', '保存连接权限'), exact=True).click()
        await playwright.expect(card.get_by_label(t('Connection access', '连接权限'), exact=True)).to_have_value('read')
        listed = {tool['name'] for tool in (await rpc(origin, TOKEN_A)).json()['result']['tools']}
        assert 'a_list_notes' in listed and 'a_add_note' not in listed
        await card.get_by_label(t('Connection access', '连接权限'), exact=True).select_option('read_write')
        await card.get_by_label(t('Write approval', '写入审批'), exact=True).select_option('allow')
        await playwright.expect(card.get_by_label(t('Who can approve?', '由谁审批？'), exact=True)).to_be_hidden()
        await card.get_by_role('button', name=t('Save connection access', '保存连接权限'), exact=True).click()
        await playwright.expect(card.get_by_label(t('Write approval', '写入审批'), exact=True)).to_have_value('allow')
        direct = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'a_add_note', 'arguments': {'folder': 'inbox', 'text': 'direct write from browser preset'}})).json()
        assert not direct['result'].get('isError')
        await card.get_by_label(t('Read approval', '读取审批'), exact=True).select_option('approval_required')
        await card.get_by_role('button', name=t('Save connection access', '保存连接权限'), exact=True).click()
        await playwright.expect(card.get_by_label(t('Read approval', '读取审批'), exact=True)).to_have_value('approval_required')
        assert await page.evaluate("state.connections.find(c => c.id === 'notes-a').access[subject]") == 'read_approval_write_direct'
        gated = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'a_list_notes', 'arguments': {'folder': 'inbox'}})).json()
        assert request_id_in(gated['result']['content'][0]['text'])
        await card.get_by_label(t('Write approval', '写入审批'), exact=True).select_option('approval_required')
        await card.get_by_role('button', name=t('Save connection access', '保存连接权限'), exact=True).click()
        await playwright.expect(card.get_by_label(t('Write approval', '写入审批'), exact=True)).to_have_value('approval_required')
        assert await page.evaluate("state.connections.find(c => c.id === 'notes-a').access[subject]") == 'read_write_approval'
        await card.get_by_label(t('Read approval', '读取审批'), exact=True).select_option('allow')
        await card.get_by_label(t('Connection access', '连接权限'), exact=True).select_option('read_write')
        await card.get_by_label(t('Write approval', '写入审批'), exact=True).select_option('approval_required')
        await card.get_by_label(t('Who can approve?', '由谁审批？'), exact=True).select_option('person_b')
        await playwright.expect(card).to_contain_text(t('No selected approver has a passkey', '所选审批人尚未注册通行密钥'))
        await card.get_by_role('button', name=t('Save connection access', '保存连接权限'), exact=True).click()
        await playwright.expect(card.get_by_label(t('Who can approve?', '由谁审批？'), exact=True)).to_have_value('person_b')
        await playwright.expect(card).to_contain_text(t('Account owner: person_a', '账号归属：person_a'))
        await card.get_by_label(t('Who can approve?', '由谁审批？'), exact=True).select_option('household')
        await card.get_by_role('button', name=t('Save connection access', '保存连接权限'), exact=True).click()
        await playwright.expect(card.get_by_label(t('Who can approve?', '由谁审批？'), exact=True)).to_have_value('household')
        assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        if directory := os.environ.get('AGW_TEST_ARTIFACTS'):
            Path(directory).mkdir(parents=True, exist_ok=True)
            await card.scroll_into_view_if_needed()
            await page.screenshot(path=str(Path(directory) / f'connection-access-{locale}.png'))
        args = {'folder': 'inbox', 'text': 'approved using the connection card'}
        pending = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'a_add_note', 'arguments': args})).json()
        request_id = request_id_in(pending['result']['content'][0]['text'])
        await page.goto(origin + '/approvals/r/' + request_id)
        await playwright.expect(page.locator('dl')).to_contain_text('openclaw')
        await page.get_by_role('button', name=t('Approve with passkey', '用通行密钥批准'), exact=True).click()
        await playwright.expect(page.locator('h1')).to_have_text(t('Approved', '已批准'))
        assert not (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'a_add_note', 'arguments': args})).json()['result'].get('isError')
        # An IMAP connector lists read capabilities only; never offer a fictitious write mode.
        await page.goto(origin + '/admin/')
        await page.get_by_role('button', name=t('Permissions', '权限'), exact=True).click()
        await page.evaluate("""async () => {
          const preview = await api('connections/preview', {revision:state.revision, id:'mail', kind:'imap', owner:state.owner,
            settings:{username:'fake@example.test',host:'127.0.0.1',port:'1'},credentials:{password:'fake-browser-password'}});
          await mutate('connections/apply', {draft:preview.draft,reviewed:true});
        }""")
        mail = page.locator('.permission-card[data-connection=mail]')
        await playwright.expect(mail).to_contain_text(t('only provides read operations', '只提供读取操作'))
        assert await mail.locator('select[name=connection_access] option[value=read_write]').count() == 0
        assert await mail.locator('select[name=connection_access] option[value=read_write_direct]').count() == 0
        await mail.get_by_label(t('Connection access', '连接权限'), exact=True).select_option('read')
        await mail.get_by_role('button', name=t('Save connection access', '保存连接权限'), exact=True).click()
        await playwright.expect(mail.get_by_label(t('Connection access', '连接权限'), exact=True)).to_have_value('read')
        await mail.get_by_label(t('Read approval', '读取审批'), exact=True).select_option('approval_required')
        await mail.get_by_label(t('Who can approve?', '由谁审批？'), exact=True).select_option('household')
        await mail.get_by_role('button', name=t('Save connection access', '保存连接权限'), exact=True).click()
        await playwright.expect(mail.get_by_label(t('Read approval', '读取审批'), exact=True)).to_have_value('approval_required')
        await playwright.expect(mail.get_by_label(t('Write approval', '写入审批'), exact=True)).to_be_hidden()
        mailbox_read = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'mail_mailboxes', 'arguments': {}})).json()
        assert request_id_in(mailbox_read['result']['content'][0]['text'])
        await page.reload()
        await page.get_by_role('button', name=t('Permissions', '权限'), exact=True).click()
        mail = page.locator('.permission-card[data-connection=mail]')
        await playwright.expect(mail.get_by_label(t('Connection access', '连接权限'), exact=True)).to_have_value('read')
        await playwright.expect(mail.get_by_label(t('Read approval', '读取审批'), exact=True)).to_have_value('approval_required')
        await playwright.expect(mail.get_by_label(t('Who can approve?', '由谁审批？'), exact=True)).to_have_value('household')
