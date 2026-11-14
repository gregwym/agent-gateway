from contextlib import asynccontextmanager
import os
from pathlib import Path

import anyio
import pytest

from helpers import TOKEN_A
from passkey_helpers import request_id_in
from test_admin import rpc, web_gateway

playwright = pytest.importorskip('playwright.async_api')
pytestmark = [pytest.mark.anyio, pytest.mark.browser]


@asynccontextmanager
async def admin_page(tmp_path, locale):
    async with web_gateway(tmp_path) as (gateway, http, origin, config):
        async with playwright.async_playwright() as driver:
            browser = await driver.chromium.launch()
            try:
                context = await browser.new_context(locale=locale, viewport={'width': 390 if locale == 'zh-CN' else 1280, 'height': 900})
                page = await context.new_page()
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                cdp = await context.new_cdp_session(page)
                await cdp.send('WebAuthn.enable')
                await cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {
                    'protocol': 'ctap2', 'transport': 'internal', 'hasResidentKey': True,
                    'hasUserVerification': True, 'isUserVerified': True, 'automaticPresenceSimulation': True}})
                await page.goto((tmp_path / 'admin-setup-link').read_text().strip())
                await page.get_by_role('button', name='创建管理员通行密钥' if locale == 'zh-CN' else 'Create administrator passkey', exact=True).click()
                await playwright.expect(page.locator('.profile-name')).to_be_visible()
                yield page, origin
                assert not errors
            finally:
                await browser.close()


@pytest.mark.parametrize('locale', ['en-US', 'zh-CN'])
async def test_rename_and_imap_preview_feedback_in_the_open_dialog(tmp_path, locale):
    def t(en, zh):
        return zh if locale == 'zh-CN' else en
    async with admin_page(tmp_path, locale) as (page, origin):
        label = 'Greg <b>林</b>'
        await page.locator('.profile-name').click()
        await page.get_by_label(t('Display name', '显示名称'), exact=True).fill(label)
        await page.get_by_role('button', name=t('Save name', '保存名称'), exact=True).click()
        await playwright.expect(page.locator('.profile-name')).to_have_text(label)
        assert await page.locator('.profile-name b').count() == 0
        await page.reload()
        await playwright.expect(page.locator('.profile-name')).to_have_text(label)
        assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        if directory := os.environ.get('AGW_TEST_ARTIFACTS'):
            Path(directory).mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=str(Path(directory) / f'member-name-{locale}.png'))
        pending = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'a_add_note', 'arguments': {'folder': 'inbox', 'text': 'name UI test'}})).json()
        request_id = request_id_in(pending['result']['content'][0]['text'])
        await page.goto(origin + '/approvals/r/' + request_id)
        await playwright.expect(page.locator('dl')).to_contain_text(label + ' (person_a)')
        assert await page.locator('dl b').count() == 0
        await page.goto(origin + '/admin/')
        await page.get_by_role('button', name=t('Connectors', '连接器'), exact=True).click()
        await page.get_by_role('button', name=t('Add connector', '添加连接器'), exact=True).click()
        box = page.get_by_role('dialog')
        await page.get_by_label(t('Service', '服务'), exact=True).select_option('imap')
        name = page.get_by_label(t('Connector name', '连接器名称'), exact=True)
        await name.fill('iCloud Mail')
        preview = page.get_by_role('button', name=t('Preview tools', '预览工具'), exact=True)
        await preview.click()
        await playwright.expect(box.get_by_role('alert')).to_contain_text(t('lowercase letter', '小写字母'))
        await name.fill('icloud-mail')
        await page.get_by_label(t('Account email / username', '账号邮箱 / 用户名'), exact=True).fill('fake@example.test')
        await preview.click()
        error = box.get_by_role('alert')
        await playwright.expect(error).to_contain_text(t('Enter the app-specific password.', '请填写 App 专用密码。'))
        assert await error.evaluate('(node) => { const r = node.getBoundingClientRect(); return document.elementFromPoint(r.x+r.width/2, r.y+r.height/2) === node; }')
        if directory := os.environ.get('AGW_TEST_ARTIFACTS'):
            Path(directory).mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=str(Path(directory) / f'imap-preview-error-{locale}.png'))
        password = page.get_by_label(t('App-specific password', 'App 专用密码'), exact=True)
        await password.fill('fake-app-password-for-preview')
        async def offline(route):
            await route.abort('connectionfailed')
        await page.route('**/admin/api/connections/preview', offline)
        await preview.click()
        await playwright.expect(error).to_contain_text(t('Could not reach the gateway.', '无法连接网关'))
        await playwright.expect(password).to_have_value('fake-app-password-for-preview')
        await page.unroute('**/admin/api/connections/preview', offline)
        release = anyio.Event()
        async def delayed(route):
            await release.wait()
            await route.continue_()
        await page.route('**/admin/api/connections/preview', delayed)
        try:
            await preview.click()
            loading = page.get_by_role('button', name=t('Reading tool definitions…', '正在读取工具定义…'), exact=True)
            await playwright.expect(loading).to_be_disabled()
        finally:
            release.set()
        await playwright.expect(page.get_by_role('heading', name=t('Review tool definitions', '审阅工具定义'), exact=True)).to_be_visible()
        await playwright.expect(page.get_by_role('heading', name='list_mailboxes', exact=True)).to_be_visible()
        if directory := os.environ.get('AGW_TEST_ARTIFACTS'):
            await page.screenshot(path=str(Path(directory) / f'imap-preview-review-{locale}.png'))
