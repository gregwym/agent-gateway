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
                await page.get_by_role('button', name=t('Connectors','连接器'), exact=True).click()
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
                assert 'mcp_oauth=' not in page.url
                await page.get_by_label(t('Operation type: ','操作类型：')+'read.note', exact=True).select_option('read')
                await page.get_by_label('write.note', exact=True).uncheck()
                if directory := os.environ.get('AGW_TEST_ARTIFACTS'):
                    output = Path(directory); output.mkdir(parents=True, exist_ok=True)
                    await page.screenshot(path=str(output / f'remote-oauth-review-{locale}.png'), full_page=True)
                await page.get_by_label(t('I reviewed these definitions and permissions.','我已审阅这些工具定义和权限。'), exact=True).check()
                await page.get_by_role('button', name=t('Apply connector','应用连接器'), exact=True).click()
                card = page.locator('.card').filter(has=page.get_by_role('heading', name='browser-remote', exact=True))
                await playwright.expect(card).to_be_visible()
                await card.get_by_role('button', name=t('Test connection','验证连接'), exact=True).click()
                await playwright.expect(card).to_contain_text(t('MCP initialization and tools verified','MCP 初始化和工具验证通过'))
                assert not remote.calls
                assert 'private-' not in await page.locator('body').inner_text()
                await card.get_by_role('button', name=t('Revoke authorization','撤销授权'), exact=True).click()
                await page.get_by_role('button', name=t('Confirm','确认'), exact=True).click()
                await playwright.expect(card).to_contain_text(t('OAuth authorization is missing, expired, or revoked.', 'OAuth 授权缺失、过期或已撤销'))
                await card.get_by_role('button', name=t('Test connection','验证连接'), exact=True).click()
                await playwright.expect(card).to_contain_text(t('MCP check failed','MCP 验证失败'))
                assert not errors
                assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            finally:
                await browser.close()
