"""Chromium uses the real admin UI; OAuth provider and MCP are simulated."""
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, urlencode

import pytest
from test_admin import web_gateway
from test_admin_remote import Remote, URL

playwright = pytest.importorskip('playwright.async_api')
pytestmark = [pytest.mark.anyio, pytest.mark.browser]


@pytest.mark.parametrize('locale', ['en-US','zh-CN'])
async def test_browser_remote_oauth_review_errors_and_revoke(tmp_path, monkeypatch, locale):
    remote = Remote(monkeypatch)
    def t(en, zh):
        return zh if locale == 'zh-CN' else en
    async with web_gateway(tmp_path) as (gw, http, origin, config):
        async with playwright.async_playwright() as driver:
            browser = await driver.chromium.launch()
            try:
                context = await browser.new_context(locale=locale, viewport={'width':390 if locale == 'zh-CN' else 1280,'height':900})
                page = await context.new_page()
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                cdp = await context.new_cdp_session(page)
                await cdp.send('WebAuthn.enable')
                await cdp.send('WebAuthn.addVirtualAuthenticator', {'options':{'protocol':'ctap2','transport':'internal',
                    'hasResidentKey':True,'hasUserVerification':True,'isUserVerified':True,'automaticPresenceSimulation':True}})
                async def authorize(route):
                    remote.query = parse_qs(urlsplit(route.request.url).query)
                    callback = remote.query['redirect_uri'][0] + '?' + urlencode({'state':remote.query['state'][0], 'code':'fake-code'})
                    await route.fulfill(status=302, headers={'Location': callback})
                await page.route('https://auth.example.test/authorize?*', authorize)
                await page.goto((tmp_path / 'admin-setup-link').read_text().strip())
                await page.get_by_role('button', name=t('Create administrator passkey','创建管理员通行密钥'), exact=True).click()
                await page.get_by_role('link', name=t('Connectors','连接器'), exact=True).click()
                await page.get_by_role('button', name=t('Add connector','添加连接器'), exact=True).click()
                await page.get_by_label(t('Service','服务'), exact=True).select_option('remote')
                await page.get_by_label(t('Connector name','连接器名称'), exact=True).fill('browser-remote')
                await page.get_by_label(t('MCP endpoint URL','MCP 接口地址'), exact=True).fill(URL)
                issuer = page.get_by_label('Issuer', exact=True)
                advanced = page.get_by_text(t('Advanced OAuth settings', 'OAuth 高级设置'), exact=True)
                await playwright.expect(issuer).to_be_hidden()
                await advanced.click()
                await playwright.expect(issuer).to_be_visible()
                await advanced.click()
                await playwright.expect(issuer).to_be_hidden()
                await page.get_by_role('button', name=t('Preview tools','预览工具'), exact=True).click()
                await playwright.expect(page.get_by_role('heading', name=t('Review tool definitions','审阅工具定义'), exact=True)).to_be_visible()
                assert page.url == origin + '/admin/connections'
                access = t('Operation type: ', '操作类型：')
                await playwright.expect(page.get_by_label(access+'read.note', exact=True)).to_have_value('read')
                await playwright.expect(page.get_by_label(access+'write.note', exact=True)).to_have_value('write')
                await page.get_by_label('write.note', exact=True).uncheck()
                if directory := os.environ.get('AGW_TEST_ARTIFACTS'):
                    output = Path(directory); output.mkdir(parents=True, exist_ok=True)
                    await page.screenshot(path=str(output / f'remote-oauth-review-{locale}.png'), full_page=True)
                await page.get_by_label(t('I reviewed these definitions and permissions.','我已审阅这些工具定义和权限。'), exact=True).check()
                await page.get_by_role('button', name=t('Apply connector','应用连接器'), exact=True).click()
                card = page.locator('tr[data-connection=browser-remote]')
                await playwright.expect(card).to_be_visible()
                await card.get_by_role('button', name=t('Edit settings', '编辑设置'), exact=True).click()
                await page.get_by_role('button', name=t('Save connector', '保存连接器'), exact=True).click()
                await playwright.expect(page.get_by_role('dialog')).to_have_count(0)
                assert remote.tokens == 1
                await card.get_by_role('button', name=t('Details', '详情'), exact=True).click()
                details = page.get_by_role('dialog', name='browser-remote')
                await details.get_by_role('button', name=t('Test connection','验证连接'), exact=True).click()
                await playwright.expect(card).to_contain_text(t('MCP check passed','MCP 验证通过'))
                assert not remote.calls
                assert 'private-' not in await page.locator('body').inner_text()
                await details.get_by_role('button', name=t('Revoke authorization','撤销授权'), exact=True).click()
                await page.get_by_role('button', name=t('Confirm','确认'), exact=True).click()
                await playwright.expect(card).to_contain_text(t('OAuth authorization is missing, expired, or revoked.', 'OAuth 授权缺失、过期或已撤销'))
                await card.get_by_role('button', name=t('Details', '详情'), exact=True).click()
                details = page.get_by_role('dialog', name='browser-remote')
                await details.get_by_role('button', name=t('Test connection','验证连接'), exact=True).click()
                await playwright.expect(details).to_contain_text(t('MCP check failed','MCP 验证失败'))
                assert not errors
                assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            finally:
                await browser.close()
