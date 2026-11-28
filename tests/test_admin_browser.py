"""Real Chromium onboarding and administration, using disposable virtual passkeys."""
import json
import os
import sys
from pathlib import Path

import pytest

from agent_gateway import __version__
from agent_gateway.credentials import EncryptedFileStore
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
                version = page.locator('#gateway-version')
                await playwright.expect(version).to_have_text(f'v{__version__}')
                await playwright.expect(version).to_be_visible()
                assert page.url == origin + '/admin/'
                assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                if directory := os.environ.get('AGW_TEST_ARTIFACTS'):
                    output = Path(directory); output.mkdir(parents=True, exist_ok=True)
                    await page.screenshot(path=str(output / f'admin-overview-{locale}.png'), full_page=True)

                await page.get_by_role('link', name=t('Members','群组成员'), exact=True).click()
                assert page.url == origin + '/admin/members'
                await playwright.expect(page.get_by_role('heading', name=t('Group members', '群组成员'), exact=True)).to_be_visible()
                await playwright.expect(page.get_by_role('button', name=t('Rename group', '修改群组名称'), exact=True)).to_be_visible()
                await page.get_by_role('button', name=t('Add member','添加成员'), exact=True).click()
                await page.get_by_label(t('Name','名字'), exact=True).fill('alex')
                await page.get_by_role('button', name=t('Add','添加'), exact=True).click()
                next_step = page.get_by_role('dialog', name=t('Member added: alex', '已添加成员：alex'), exact=True)
                await next_step.get_by_role('button', name=t('Close', '关闭'), exact=True).click()
                await playwright.expect(page.get_by_role('heading', name='alex', exact=True)).to_be_visible()

                await page.get_by_role('link', name=t('Agents','Agent 接入'), exact=True).click()
                assert page.url == origin + '/admin/agents'
                await page.get_by_role('button', name=t('Create agent token','创建 Agent Token'), exact=True).click()
                await page.get_by_label(t('Agent name','Agent 名称'), exact=True).fill('browser-agent')
                await page.get_by_label(t('Group','所属群组'), exact=True).select_option('household')
                await page.get_by_role('button', name=t('Create token','创建 Token'), exact=True).click()
                token = await page.get_by_label(t('Agent token','Agent Token'), exact=True).input_value()
                assert token.startswith('agw_')
                names = {tool['name'] for tool in (await rpc(origin, token)).json()['result']['tools']}
                assert names == {'gateway_call_tool'}
                await page.get_by_role('button', name=t('Close','关闭'), exact=True).click()
                assert token not in await page.locator('body').inner_text()
                await page.get_by_role('row').filter(has_text='browser-agent').get_by_role('button', name=t('Revoke','撤销'), exact=True).click()
                await page.get_by_role('button', name=t('Confirm','确认'), exact=True).click()
                await playwright.expect(page.get_by_role('row').filter(has_text='browser-agent')).to_have_count(0)
                assert (await rpc(origin, token)).status_code == 401

                gw.gateway.audit.write('tool_call', client='agent-a', connection='notes-a',
                                       tool='a_list_notes', decision='allow', reason='ok')
                gw.gateway.audit.write('tool_call', client='agent-a', connection='notes-a',
                                       tool='a_list_notes', decision='allow', is_error=True)
                await page.get_by_role('link', name=t('Audit history', '审计历史'), exact=True).click()
                assert page.url == origin + '/admin/audit'
                await playwright.expect(page.get_by_role('heading', name=t('Audit history', '审计历史'))).to_be_visible()
                await playwright.expect(page.get_by_role('row').filter(has_text='a_list_notes')).to_have_count(2)
                await page.get_by_label(t('Agent ID', 'Agent 标识'), exact=True).fill('agent-a')
                await page.get_by_label(t('Connector ID', '连接器标识'), exact=True).fill('notes-a')
                await page.get_by_label(t('Result', '结果'), exact=True).select_option('error')
                await page.get_by_role('button', name=t('Apply filters', '应用筛选')).click()
                events = page.locator('tbody tr')
                await playwright.expect(events).to_have_count(1)
                await playwright.expect(events.first).to_contain_text(t('Error', '错误'))
                await playwright.expect(events.first).to_contain_text('a_list_notes')
                assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')

                await page.get_by_role('link', name=t('Settings', '设置'), exact=True).click()
                await page.get_by_role('button', name=t('Add OAuth client', '添加 OAuth 客户端'), exact=True).click()
                client_form = page.get_by_role('dialog', name=t('Add system OAuth client', '添加系统 OAuth 客户端'))
                await client_form.get_by_label(t('Connector name', '连接器名称')).fill('system-mcp')
                await client_form.get_by_label('Issuer').fill('https://auth.example.test')
                await client_form.get_by_label('OAuth client ID').fill('browser-test-id')
                await client_form.get_by_label(t('OAuth client secret', 'OAuth 客户端密钥')).fill('synthetic-browser-secret')
                await client_form.get_by_role('button', name=t('Save OAuth client', '保存 OAuth 客户端')).click()
                await playwright.expect(page.get_by_text('system-mcp · https://auth.example.test')).to_be_visible()
                assert 'synthetic-browser-secret' not in await page.locator('body').inner_text()

                await page.get_by_role('link', name=t('Connectors','连接器'), exact=True).click()
                await page.get_by_role('button', name=t('Add connector','添加连接器'), exact=True).click()
                await page.get_by_label(t('System OAuth client', '系统 OAuth 客户端')).select_option('system-mcp')
                await playwright.expect(page.get_by_text(t('Advanced OAuth settings', 'OAuth 高级设置'))).not_to_be_visible()
                service = page.get_by_label(t('Service', '服务'), exact=True)
                await playwright.expect(service).to_have_value('remote')
                assert await service.locator('option').last.get_attribute('value') == 'demo'
                if not zh:
                    await service.select_option('web')
                    await page.get_by_label('Website', exact=True).select_option('weee-orders')
                    await playwright.expect(page.get_by_role('button', name='Sign in to website', exact=True)).not_to_be_visible()
                    await page.get_by_text('Advanced: import a session file', exact=True).click()
                    await page.get_by_label('Connector name', exact=True).fill('browser-weee')
                    await page.get_by_label('Browser session JSON', exact=True).set_input_files({
                        'name': 'weee-session.json', 'mimeType': 'application/json',
                        'buffer': b'[{"domain":"www.weee.com","name":"auth","value":"fake-browser-session"}]'})
                    await page.get_by_role('button', name='Import session', exact=True).click()
                    await playwright.expect(page.locator('tr[data-connection=browser-weee]')).to_contain_text("Session saved")
                    await page.get_by_role('button', name='Add connector', exact=True).click()
                await service.select_option('demo')
                await page.get_by_label(t('Connector name','连接器名称'), exact=True).fill('browser-notes')
                await page.get_by_role('button', name=t('Save connector','保存连接器'), exact=True).click()
                connector = page.locator('tr[data-connection=browser-notes]')
                await playwright.expect(connector).to_be_visible()
                await connector.get_by_role('button', name=t('Details', '详情'), exact=True).click()
                details = page.get_by_role('dialog', name='browser-notes')
                await details.get_by_role('button', name=t('Test connection','验证连接'), exact=True).click()
                await details.get_by_role('button', name=t('Close', '关闭'), exact=True).click()
                # The check waits for the new connector process to start; on CI's macOS runners that can take longer than 5 s.
                await playwright.expect(connector).to_contain_text(t('Read check passed','读取验证通过'), timeout=20_000)

                await page.get_by_role('link', name=t('Permissions','权限'), exact=True).click()
                assert page.url == origin + '/admin/permissions'
                await page.get_by_label(t('Agent','Agent'), exact=True).select_option('shared-agent')
                await page.locator('tr[data-connection=browser-notes]').get_by_role('button', name=t('Edit access', '编辑权限'), exact=True).click()
                card = page.get_by_role('dialog', name=t('Permissions: browser-notes', '权限：browser-notes'), exact=True)
                await card.locator('summary').click()
                row = card.get_by_role('row').filter(has_text='browser_notes_list')
                await row.get_by_label(t('Effect','权限效果'), exact=True).select_option('allow')
                await row.get_by_role('button', name=t('Save access','保存权限'), exact=True).click()
                await playwright.expect(row.get_by_label(t('Effect','权限效果'), exact=True)).to_have_value('allow')
                await row.get_by_role('button', name=t('Argument limits','参数限制'), exact=True).click()
                await page.get_by_label(t('Fixed arguments (JSON object)','固定参数（JSON 对象）'), exact=True).fill('{"folder":"family"}')
                await page.get_by_role('button', name=t('Save restrictions','保存限制'), exact=True).click()
                await playwright.expect(page.get_by_role('dialog', name=t('Argument limits','参数限制'), exact=True)).to_have_count(0)
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
                await card.get_by_role('button', name=t('Close', '关闭'), exact=True).click()
                await page.get_by_role('link', name=t('Connectors','连接器'), exact=True).click()
                await connector.get_by_role('button', name=t('Details', '详情'), exact=True).click()
                await details.get_by_role('button', name=t('Rename','改名'), exact=True).click()
                await page.get_by_label(t('Connector name','连接器名称'), exact=True).fill('renamed-notes')
                await page.get_by_role('button', name=t('Save name','保存名称'), exact=True).click()
                await playwright.expect(page.locator('tr[data-connection=renamed-notes]')).to_be_visible()
                await playwright.expect(connector).to_have_count(0)
                renamed = page.locator('tr[data-connection=renamed-notes]')
                assert page.url == origin + '/admin/connections'
                await page.reload()
                await playwright.expect(renamed).to_be_visible()
                await playwright.expect(page.locator('nav a[aria-current=page]')).to_have_attribute('href', '/admin/connections')
                await page.go_back()
                assert page.url == origin + '/admin/permissions'
                await playwright.expect(page.get_by_role('heading', name=t('Inspect permissions', '检查权限'))).to_be_visible()
                await page.go_forward()
                assert page.url == origin + '/admin/connections'
                await playwright.expect(renamed).to_be_visible()
                await page.get_by_role('button', name=t('Sign out','退出'), exact=True).click()
                await page.get_by_role('button', name=t('Sign in with passkey','用通行密钥登录'), exact=True).click()
                await playwright.expect(page.get_by_role('button', name=t('Sign out','退出'), exact=True)).to_be_visible()
                assert page.url == origin + '/admin/connections'
                await playwright.expect(renamed).to_be_visible()
                await playwright.expect(version).to_be_visible()
                if not zh:
                    await playwright.expect(page.locator('tr[data-connection=gateway_config]')).to_be_visible()
                    await page.get_by_role('link', name='Permissions', exact=True).click()
                    await page.get_by_label('Agent', exact=True).select_option('shared-agent')
                    await page.locator('tr[data-connection=gateway_config]').get_by_role('button', name='Edit access').click()
                    config_card = page.get_by_role('dialog', name='Permissions: gateway_config', exact=True)
                    await config_card.locator('summary').click()
                    provision = config_card.get_by_role('row').filter(has_text='gateway_config_provision')
                    await provision.get_by_label('Effect', exact=True).select_option('allow')
                    async with page.expect_response(lambda response: response.url.endswith('/permissions/save') and response.ok):
                        await provision.get_by_role('button', name='Save access', exact=True).click()
                    await config_card.get_by_role('button', name='Close', exact=True).click()
                    reply = await rpc(origin, TOKEN_HOUSE, 'tools/call', {'name':'gateway_config_provision',
                        'arguments':{'kind':'http_mcp', 'id':'browser-proposal',
                                     'url':'https://example.test/mcp', 'auth':'none'}})
                    assert json.loads(reply.json()['result']['content'][0]['text'])['status'] == 'pending'
                    await page.get_by_role('link', name='Connectors', exact=True).click()
                    pending = page.get_by_role('heading', name='Provisioning requests', exact=True)
                    await playwright.expect(pending).to_be_visible()
                    await page.get_by_role('button', name='Review', exact=True).click()
                    await playwright.expect(page.get_by_label('MCP endpoint URL', exact=True)).to_have_value('https://example.test/mcp')
                    await page.get_by_role('dialog', name='Add connector', exact=True).get_by_role('button', name='Close', exact=True).click()
                    await page.get_by_role('button', name='Reject', exact=True).click()
                    await playwright.expect(pending).not_to_be_visible()
                assert not errors
            finally:
                await browser.close()


async def test_amazon_session_file_create_and_rotate(tmp_path):
    directory = tmp_path / 'plugins'
    directory.mkdir()
    slot = 'ORDERS_SESSION_SECRET'
    (directory / 'amazon-orders.json').write_text(json.dumps({
        'id': 'amazon-orders', 'label': 'Amazon Orders', 'kind': 'stdio',
        'command': [sys.executable, '-m', 'agent_gateway.demo_connector'],
        'env': {'DEMO_API_KEY': 'synthetic-test-credential'},
        'credentials': {slot: 'Amazon session file'},
    }))

    def session(value):
        return json.dumps([{'name': 'session', 'value': value, 'domain': '.amazon.com', 'path': '/'}])

    def select_file(contents):
        return {'name': 'amazon-session.json', 'mimeType': 'application/json', 'buffer': contents.encode()}

    async with web_gateway(tmp_path) as (gw, _, _, _), playwright.async_playwright() as driver:
        browser = await driver.chromium.launch()
        try:
            page = await browser.new_page(locale='en-US')
            cdp = await page.context.new_cdp_session(page)
            await cdp.send('WebAuthn.enable')
            await cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {
                'protocol': 'ctap2', 'transport': 'internal', 'hasResidentKey': True,
                'hasUserVerification': True, 'isUserVerified': True, 'automaticPresenceSimulation': True,
            }})
            store_file = gw.cfg.admin.state
            store = EncryptedFileStore(store_file, gw.cfg.secrets.key_file)

            def saved_session():
                saved = json.loads(store.get('state'))
                connector = next(item for item in saved['config']['connections'] if item['id'] == 'orders')
                return saved['secrets'][connector['secret_env'][slot]]

            first = session('synthetic-amazon-session-first')
            updated = session('synthetic-amazon-session-updated')
            await page.goto((tmp_path / 'admin-setup-link').read_text().strip())
            await page.get_by_role('button', name='Create administrator passkey').click()
            await page.get_by_role('link', name='Connectors', exact=True).click()
            await page.get_by_role('button', name='Add connector', exact=True).click()
            await page.get_by_label('Service', exact=True).select_option('local')
            await page.get_by_label('Installed connector', exact=True).select_option('amazon-orders')
            await page.get_by_label('Connector name', exact=True).fill('orders')
            picker = page.get_by_label('Browser session JSON', exact=True)
            await playwright.expect(picker).to_have_attribute('type', 'file')
            await picker.set_input_files(select_file(first))
            async with page.expect_response(
                lambda response: response.url.endswith('/connections/preview') and response.status == 200
            ) as preview:
                await page.get_by_role('button', name='Preview tools', exact=True).click()
            review = page.get_by_role('dialog', name='Review tool definitions')
            await playwright.expect(review).to_be_visible()
            assert not store_file.exists()
            await review.get_by_role('checkbox', name='I reviewed these definitions and permissions.').check()
            await review.get_by_role('button', name='Apply connector').click()
            connection = page.locator('tr[data-connection=orders]')
            await playwright.expect(connection).to_be_visible()
            assert saved_session() == first

            await page.get_by_role('link', name='Permissions', exact=True).click()
            await page.get_by_label('Agent', exact=True).select_option('agent-a')
            await connection.get_by_role('button', name='Edit access', exact=True).click()
            permissions = page.get_by_role('dialog', name='Permissions: orders')
            await permissions.get_by_label('Connection access', exact=True).select_option('read')
            async with page.expect_response(
                lambda response: response.url.endswith('/permissions/connection') and response.status == 200
            ):
                await permissions.get_by_role('button', name='Save connection access').click()
            await permissions.get_by_role('button', name='Close', exact=True).click()
            await page.get_by_role('link', name='Connectors', exact=True).click()
            original_policy = json.loads(store.get('state'))['config']['policy']
            assert any(rule.get('connection') == 'orders' for rule in original_policy)

            async def edit():
                await connection.get_by_role('button', name='Edit settings', exact=True).click()
                return page.get_by_role('dialog', name='Edit connector')

            editor = await edit()
            save = editor.get_by_role('button', name='Save connector', exact=True)
            await picker.set_input_files(select_file('invalid-synthetic-session-json'))
            await save.click()
            await playwright.expect(editor.get_by_role('alert')).to_contain_text('Select a browser session JSON file')
            assert saved_session() == first
            await picker.set_input_files([])
            await save.click()
            await playwright.expect(editor).to_have_count(0)
            assert saved_session() == first

            editor = await edit()
            await picker.set_input_files(select_file(updated))
            async with page.expect_response(
                lambda response: response.url.endswith('/connections/save') and response.status == 200
            ) as rotation:
                await editor.get_by_role('button', name='Save connector', exact=True).click()
            await playwright.expect(editor).to_have_count(0)
            assert saved_session() == updated
            assert json.loads(store.get('state'))['config']['policy'] == original_policy
            public = (await page.locator('body').inner_text() + gw.audit_text()
                      + await (await preview.value).text() + await (await rotation.value).text())
            for marker in ('synthetic-amazon-session-first', 'synthetic-amazon-session-updated', 'invalid-synthetic-session-json'):
                assert marker not in public
                assert marker.encode() not in store_file.read_bytes()
        finally:
            await browser.close()
