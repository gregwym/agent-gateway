"""Gmail setup chooses the Google grant separately from Agent access."""
import json
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx2
import pytest

from agent_gateway.admin_oauth import PROFILE, TOKEN, GoogleConsent
from agent_gateway.gmail_scopes import SCOPE, SEND_SCOPE
from test_admin_feedback_browser import admin_page, playwright

pytestmark = [pytest.mark.anyio, pytest.mark.browser]


@pytest.mark.parametrize('locale', ['en-US', 'zh-CN'])
async def test_gmail_setup_import_scope_and_mail_preset(tmp_path, locale, monkeypatch):
    def t(en, zh):
        return zh if locale == 'zh-CN' else en

    def google(request):
        if str(request.url) == TOKEN:
            assert parse_qs(request.content.decode())['client_secret'] == ['fake-client-secret']
            return httpx2.Response(200, json={'access_token': 'fake-access-token',
                                             'refresh_token': 'fake-refresh-token',
                                             'scope': f'{SCOPE} {SEND_SCOPE}'})
        assert str(request.url) == PROFILE
        return httpx2.Response(200, json={'emailAddress': 'fake@example.test'})

    monkeypatch.setattr(GoogleConsent, '_http', lambda self: httpx2.AsyncClient(transport=httpx2.MockTransport(google)))
    async with admin_page(tmp_path, locale) as (page, origin):
        await page.goto(origin + '/admin/connections')
        add = page.get_by_role('button', name=t('Add connector', '添加连接器'), exact=True)
        await add.click()
        box = page.get_by_role('dialog')
        service = box.get_by_label(t('Service', '服务'), exact=True)
        await service.select_option('imap')
        await box.get_by_label(t('Mail provider', '邮箱服务商'), exact=True).select_option('gmail')
        for name, expected in [('host', 'imap.gmail.com'), ('port', '993'), ('smtp_host', 'smtp.gmail.com'), ('smtp_port', '587'), ('smtp_security', 'starttls')]:
            await playwright.expect(box.locator(f'[name={name}]')).to_have_value(expected)
        await service.select_option('gmail')
        await box.get_by_label(t('Connector name', '连接器名称'), exact=True).fill('gmail-browser')
        scope = box.get_by_label(t('Google permissions', 'Google 权限'), exact=True)
        await playwright.expect(scope).to_have_value('read')
        await playwright.expect(box.locator('input[name=refresh_token]')).to_be_hidden()
        await playwright.expect(box.locator('input[name=client_secret]')).to_be_hidden()
        upload = box.get_by_label(t('Google OAuth client JSON', 'Google OAuth 客户端 JSON'), exact=True)

        async def import_json(data):
            await upload.set_input_files({'name': 'google-client.json', 'mimeType': 'application/json',
                                          'buffer': json.dumps(data).encode()})

        await import_json({'installed': {'client_id': 'desktop', 'client_secret': 'x'}})
        await playwright.expect(box.get_by_role('alert')).to_contain_text(t('Desktop app', '桌面应用'))
        await import_json({'web': {'client_id': 'test-web-client', 'client_secret': 'fake-client-secret',
                                   'token_uri': 'https://untrusted.invalid/token'}})
        await playwright.expect(box.get_by_role('status')).to_contain_text(t('OAuth client loaded', '已导入 OAuth 客户端'))
        await scope.select_option('read_send')

        async def consent(route):
            query = parse_qs(urlsplit(route.request.url).query)
            assert set(query['scope'][0].split()) == {SCOPE, SEND_SCOPE}
            assert query['client_id'] == ['test-web-client']
            assert 'fake-client-secret' not in route.request.url
            callback = query['redirect_uri'][0] + '?' + urlencode({'state': query['state'][0], 'code': 'fake-code'})
            await route.fulfill(status=302, headers={'Location': callback})

        await page.route('https://accounts.google.com/o/oauth2/v2/auth?**', consent)
        await box.get_by_role('button', name=t('Authorize with Google', '通过 Google 授权'), exact=True).click()
        row = page.locator('tr[data-connection=gmail-browser]')
        await playwright.expect(row).to_contain_text('fake@example.test')
        assert page.url == origin + '/admin/connections'
        assert 'fake-refresh-token' not in await page.locator('body').inner_text()
        await row.get_by_role('button', name=t('Edit settings', '编辑设置'), exact=True).click()
        await playwright.expect(scope).to_have_value('read_send')
