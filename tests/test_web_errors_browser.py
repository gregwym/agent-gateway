import os
from pathlib import Path

import pytest

from test_admin_feedback_browser import admin_page, playwright

pytestmark = [pytest.mark.anyio, pytest.mark.browser]


@pytest.mark.parametrize('locale', ['en-US', 'zh-CN'])
async def test_connection_failure_stays_on_card_and_other_errors_stay_on_page(tmp_path, locale):
    def t(en, zh):
        return zh if locale == 'zh-CN' else en
    async with admin_page(tmp_path, locale) as (page, origin):
        failed = False
        async def state(route):
            response = await route.fetch()
            body = await response.json()
            if failed:
                body['connections'][0]['test'] = {'ok': False, 'reason': 'imap_credentials_rejected', 'at': 1}
            await route.fulfill(response=response, json=body)
        async def reject(route):
            nonlocal failed
            failed = True
            await route.fulfill(status=422, json={'error': 'imap_credentials_rejected'})
        await page.route('**/admin/api/state', state)
        await page.route('**/admin/api/connections/test', reject)
        await page.get_by_role('link', name=t('Connectors', '连接器'), exact=True).click()
        card = page.locator('tbody tr[data-connection]').first
        await card.get_by_role('button', name=t('Details', '详情'), exact=True).click()
        details = page.get_by_role('dialog')
        await details.get_by_role('button', name=t('Test connection', '验证连接'), exact=True).click()
        await playwright.expect(card.get_by_role('alert')).to_contain_text(t('rejected the username or password', '拒绝了用户名或密码'))
        await playwright.expect(card).to_contain_text(t('Read check failed', '读取验证失败'))
        await page.reload()
        await page.get_by_role('link', name=t('Connectors', '连接器'), exact=True).click()
        await playwright.expect(card.get_by_role('alert')).to_be_visible()
        if directory := os.environ.get('AGW_TEST_ARTIFACTS'):
            Path(directory).mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=str(Path(directory) / f'connection-error-{locale}.png'))
        # An HTML proxy error must not be misreported as a network failure or shown as markup.
        async def invalid_response(route):
            await route.fulfill(status=502, content_type='text/html', body='<h1>private-upstream-debug</h1>')
        await page.unroute('**/admin/api/connections/test', reject)
        await page.route('**/admin/api/connections/test', invalid_response)
        await card.get_by_role('button', name=t('Details', '详情'), exact=True).click()
        await details.get_by_role('button', name=t('Test connection', '验证连接'), exact=True).click()
        await playwright.expect(details.locator('.operation-error')).to_contain_text('HTTP 502')
        await details.get_by_role('button', name=t('Close', '关闭'), exact=True).click()
        assert 'private-upstream-debug' not in await page.locator('body').inner_text()
        # Name save errors are visible in the open dialog and include a traceable ID.
        await page.locator('.profile-name').click()
        async def disk_full(route):
            await route.fulfill(status=500, json={'error': 'storage_full', 'incident': 'abcdef012345'})
        await page.route('**/admin/api/members/rename', disk_full)
        await page.get_by_role('button', name=t('Save name', '保存名称'), exact=True).click()
        error = page.get_by_role('dialog').get_by_role('alert')
        await playwright.expect(error).to_contain_text(t('disk is full', '磁盘已满'))
        await playwright.expect(error).to_contain_text('abcdef012345')
        # Invalid OAuth navigation still renders a useful page, with the code removed from the address bar.
        response = await page.goto(origin + '/admin/oauth/google/callback?state=expired&code=private-oauth-code')
        assert response.status == 409
        await playwright.expect(page.locator('main > .operation-error')).to_contain_text(t('OAuth authorization expired', 'OAuth 授权已过期'))
        await playwright.expect(page).to_have_url(origin + '/admin/')
        assert 'private-oauth-code' not in await page.locator('body').inner_text()
