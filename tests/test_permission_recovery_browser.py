"""A committed save with a lost HTTP response is reconciled, never replayed."""
import pytest

from test_admin_feedback_browser import admin_page, playwright

pytestmark = [pytest.mark.anyio, pytest.mark.browser]


@pytest.mark.parametrize('failure', ['lost_response', 'refresh_failed', 'not_sent'])
async def test_permission_save_reports_actual_status_without_repeating_post(tmp_path, failure):
    async with admin_page(tmp_path, 'zh-CN') as (page, origin):
        await page.get_by_role('button', name='权限', exact=True).click()
        card = page.locator('.permission-card[data-connection=notes-a]')
        before = await page.evaluate('state.revision')
        await page.evaluate('''failure => {
          const original = window.fetch;
          window.savePosts = 0;
          let failRefresh = false;
          window.fetch = async (url, options) => {
            if (String(url).endsWith('/permissions/connection')) {
              window.savePosts++;
              if (failure === 'not_sent') throw new TypeError('simulated network loss');
              const response = await original(url, options);
              if (failure === 'lost_response') throw new DOMException('simulated lost response', 'AbortError');
              failRefresh = true;
              return response;
            }
            if (failRefresh && String(url).endsWith('/state')) {
              failRefresh = false;
              throw new TypeError('simulated refresh failure');
            }
            return original(url, options);
          };
        }''', failure)
        await card.get_by_label('连接权限', exact=True).select_option('read')
        await card.get_by_role('button', name='保存连接权限', exact=True).click()
        if failure == 'lost_response':
            await playwright.expect(page.locator('#notice')).to_contain_text('连接权限已更新')
            assert await page.evaluate('state.revision') == before + 1
            await playwright.expect(card.get_by_label('连接权限', exact=True)).to_have_value('read')
        elif failure == 'refresh_failed':
            await playwright.expect(page.get_by_role('alert')).to_contain_text('权限已保存')
            await playwright.expect(page.get_by_role('alert')).to_contain_text('无需重复提交')
        else:
            await playwright.expect(page.get_by_role('alert')).to_contain_text('尚未确认所选权限已保存')
            assert await page.evaluate('state.revision') == before
        assert await page.evaluate('window.savePosts') == 1
        await page.reload()
        await playwright.expect(page.locator('.profile-name')).to_be_visible()
        assert await page.evaluate('state.revision') == before + (failure != 'not_sent')
