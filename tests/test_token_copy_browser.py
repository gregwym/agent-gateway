"""Clipboard-bound values authenticate; tests use an isolated in-memory clipboard."""
import hashlib

import pytest

from test_admin import rpc
from test_admin_feedback_browser import admin_page, playwright

pytestmark = [pytest.mark.anyio, pytest.mark.browser]


@pytest.mark.parametrize('locale', ['en-US', 'zh-CN'])
async def test_copy_check_and_rotate_token_with_clipboard_failure(tmp_path, locale):
    def t(en, zh):
        return zh if locale == 'zh-CN' else en
    async with admin_page(tmp_path, locale) as (page, origin):
        await page.evaluate("Object.defineProperty(navigator, 'clipboard', {configurable:true, value:{writeText:async value => { window.copiedToken=value; }}})")
        await page.get_by_role('button', name=t('Agents', 'Agent 接入'), exact=True).click()
        await page.get_by_role('button', name=t('Create agent token', '创建 Agent Token'), exact=True).click()
        await page.get_by_label(t('Agent name', 'Agent 名称'), exact=True).fill('copy-test')
        await page.get_by_role('button', name=t('Create token', '创建 Token'), exact=True).click()
        token = await page.get_by_label(t('Agent token', 'Agent Token'), exact=True).input_value()
        fingerprint = hashlib.sha256(token.encode()).hexdigest()[:12]
        await playwright.expect(page.get_by_role('dialog').locator('.token-fingerprint')).to_contain_text(fingerprint)
        await page.get_by_role('button', name=t('Copy', '复制'), exact=True).click()
        copied = await page.evaluate('window.copiedToken')
        assert copied == token and (await rpc(origin, copied)).status_code == 200
        await page.get_by_role('button', name=t('Close', '关闭'), exact=True).click()
        row = page.get_by_role('row').filter(has_text='copy-test')
        await playwright.expect(row).to_contain_text(fingerprint)
        await row.get_by_role('button', name=t('Check token', '核对 Token'), exact=True).click()
        requests = []
        page.on('request', lambda request: requests.append(request.post_data or ''))
        for value, message in [(token, t('Check codes match.', '核对码一致。')),
                               ('Bearer ' + token + ' ', t('extra whitespace or a Bearer prefix', '多余空白或 Bearer 前缀')),
                               ('agw_different-value', t('Check codes differ.', '核对码不同'))]:
            field = page.get_by_label(t('Token to check', '待核对的 Token'), exact=True)
            await field.fill(value)
            await page.get_by_role('button', name=t('Compare check code', '比较核对码'), exact=True).click()
            await playwright.expect(page.locator('.token-check-result')).to_contain_text(message)
            await playwright.expect(field).to_have_value('')
        assert not any(token in body for body in requests)
        await page.get_by_role('button', name=t('Close', '关闭'), exact=True).click()
        await row.get_by_role('button', name=t('Rotate token', '轮换 Token'), exact=True).click()
        await page.get_by_role('button', name=t('Confirm', '确认'), exact=True).click()
        new = await page.get_by_label(t('Agent token', 'Agent Token'), exact=True).input_value()
        await page.evaluate("() => { navigator.clipboard.writeText=async () => { throw new DOMException('denied','NotAllowedError'); }; }")
        await page.get_by_role('button', name=t('Copy', '复制'), exact=True).click()
        await playwright.expect(page.get_by_role('dialog').get_by_role('alert')).to_contain_text(t('clipboard access', '剪贴板'))
        assert await page.get_by_label(t('Agent token', 'Agent Token'), exact=True).evaluate('(node) => document.activeElement===node && node.selectionStart===0 && node.selectionEnd===node.value.length')
        assert await page.get_by_role('dialog').locator('.dialog-notice').count() == 0
        await page.evaluate("() => { navigator.clipboard.writeText=async value => { window.copiedToken=value; }; }")
        await page.get_by_role('button', name=t('Copy', '复制'), exact=True).click()
        assert await page.evaluate('window.copiedToken') == new
        assert (await rpc(origin, new)).status_code == 200 and (await rpc(origin, token)).status_code == 401
