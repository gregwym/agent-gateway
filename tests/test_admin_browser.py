"""Real Chromium onboarding and administration, using disposable virtual passkeys."""
import os
from pathlib import Path

import pytest

from helpers import TOKEN_HOUSE
from test_admin import rpc, web_gateway

playwright = pytest.importorskip('playwright.async_api')
pytestmark = [pytest.mark.anyio, pytest.mark.browser]


@pytest.mark.parametrize('locale', ['en-US', 'zh-CN'])
async def test_browser_setup_members_agents_connector_review_permissions_and_login(tmp_path, locale):
    zh = locale == 'zh-CN'
    def t(en, cn):
        return cn if zh else en
    async with web_gateway(tmp_path) as (gw, http, origin, config):
        async with playwright.async_playwright() as driver:
            browser = await driver.chromium.launch()
            try:
                context = await browser.new_context(locale=locale, viewport={'width':390 if zh else 1280,'height':900})
                page = await context.new_page()
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                cdp = await context.new_cdp_session(page)
                await cdp.send('WebAuthn.enable')
                await cdp.send('WebAuthn.addVirtualAuthenticator', {'options':{
                    'protocol':'ctap2','transport':'internal','hasResidentKey':True,
                    'hasUserVerification':True,'isUserVerified':True,'automaticPresenceSimulation':True}})
                link = (tmp_path / 'admin-setup-link').read_text().strip()
                await page.goto(link)
                await page.get_by_role('button', name=t('Create administrator passkey','创建管理员通行密钥'), exact=True).click()
                await playwright.expect(page.get_by_role('heading', name=t('One gateway. Clear boundaries.','一个网关，清晰的权限。'))).to_be_visible()
                assert '#' not in page.url
                assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                if directory := os.environ.get('AGW_TEST_ARTIFACTS'):
                    output = Path(directory); output.mkdir(parents=True, exist_ok=True)
                    await page.screenshot(path=str(output / f'admin-overview-{locale}.png'), full_page=True)

                await page.get_by_role('button', name=t('Members','家庭成员'), exact=True).click()
                await page.get_by_role('button', name=t('Add member','添加成员'), exact=True).click()
                await page.get_by_label(t('Identity name','身份名称'), exact=True).fill('alex')
                await page.get_by_role('button', name=t('Add','添加'), exact=True).click()
                await playwright.expect(page.get_by_role('heading', name='alex', exact=True)).to_be_visible()

                await page.get_by_role('button', name=t('Agents','Agent 接入'), exact=True).click()
                await page.get_by_role('button', name=t('Create agent token','创建 Agent Token'), exact=True).click()
                await page.get_by_label(t('Agent name','Agent 名称'), exact=True).fill('browser-agent')
                await page.get_by_label(t('Identity','身份'), exact=True).select_option('person_b')
                await page.get_by_role('button', name=t('Create token','创建 Token'), exact=True).click()
                token = await page.get_by_label(t('Agent token','Agent Token'), exact=True).input_value()
                assert token.startswith('agw_')
                names = {tool['name'] for tool in (await rpc(origin, token)).json()['result']['tools']}
                assert 'b_list_notes' in names and 'a_list_notes' not in names
                await page.get_by_role('button', name=t('Close','关闭'), exact=True).click()
                assert token not in await page.locator('body').inner_text()
                await page.get_by_role('row').filter(has_text='browser-agent').get_by_role('button', name=t('Revoke','撤销'), exact=True).click()
                await page.get_by_role('button', name=t('Confirm','确认'), exact=True).click()
                await playwright.expect(page.get_by_role('row').filter(has_text='browser-agent')).to_have_count(0)
                assert (await rpc(origin, token)).status_code == 401

                await page.get_by_role('button', name=t('Connectors','连接器'), exact=True).click()
                await page.get_by_role('button', name=t('Add connector','添加连接器'), exact=True).click()
                await page.get_by_label(t('Connector name','连接器名称'), exact=True).fill('browser-notes')
                await page.get_by_role('button', name=t('Preview tools','预览工具'), exact=True).click()
                apply = page.get_by_role('button', name=t('Apply connector','应用连接器'), exact=True)
                await playwright.expect(apply).to_be_disabled()
                await page.get_by_label(t('I reviewed these definitions and permissions.','我已审阅这些工具定义和权限。'), exact=True).check()
                await apply.click()
                connector = page.locator('.card').filter(has=page.get_by_role('heading', name='browser-notes', exact=True))
                await playwright.expect(connector).to_be_visible()
                await connector.get_by_role('button', name=t('Test connection','验证连接'), exact=True).click()
                await playwright.expect(connector).to_contain_text(t('Read check passed','读取验证通过'))

                await page.get_by_role('button', name=t('Permissions','权限'), exact=True).click()
                await page.get_by_label(t('Inspect as','以此身份检查'), exact=True).select_option('household')
                row = page.get_by_role('row').filter(has_text='browser_notes_list')
                await row.get_by_label(t('Effect','权限效果'), exact=True).select_option('allow')
                await row.get_by_label(t('Explicitly share access to this other account','明确允许访问另一人的账号'), exact=True).check()
                await row.get_by_role('button', name=t('Save access','保存权限'), exact=True).click()
                await playwright.expect(row.get_by_label(t('Effect','权限效果'), exact=True)).to_have_value('allow')
                await row.get_by_role('button', name=t('Argument limits','参数限制'), exact=True).click()
                await page.get_by_label(t('Fixed arguments (JSON object)','固定参数（JSON 对象）'), exact=True).fill('{"folder":"family"}')
                await page.get_by_role('button', name=t('Save restrictions','保存限制'), exact=True).click()
                await playwright.expect(page.get_by_role('dialog')).to_have_count(0)
                reply = (await rpc(origin, TOKEN_HOUSE, 'tools/call', {'name':'browser_notes_list','arguments':{}})).json()
                assert 'family note kept by person_a' in reply['result']['content'][0]['text']
                assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                if directory := os.environ.get('AGW_TEST_ARTIFACTS'):
                    await page.screenshot(path=str(Path(directory) / f'admin-permissions-{locale}.png'), full_page=True)
                    if zh:
                        await row.scroll_into_view_if_needed()
                        await page.screenshot(path=str(Path(directory) / 'admin-permissions-mobile-detail.png'))
                bounds = await row.get_by_role('button', name=t('Save access','保存权限'), exact=True).bounding_box()
                assert bounds['x'] >= 0 and bounds['x'] + bounds['width'] <= page.viewport_size['width']
                await page.get_by_role('button', name=t('Sign out','退出'), exact=True).click()
                await page.get_by_role('button', name=t('Sign in with passkey','用通行密钥登录'), exact=True).click()
                await playwright.expect(page.get_by_role('button', name=t('Sign out','退出'), exact=True)).to_be_visible()
                assert not errors
            finally:
                await browser.close()
