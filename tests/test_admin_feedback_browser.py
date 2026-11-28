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
async def admin_page(tmp_path, locale, *, mobile=False, **gateway_options):
    async with web_gateway(tmp_path, **gateway_options) as (gateway, http, origin, config):
        async with playwright.async_playwright() as driver:
            browser = await driver.chromium.launch()
            try:
                screen = driver.devices['iPhone 15'] if mobile else {'viewport': {'width': 390 if locale == 'zh-CN' else 1280, 'height': 900}}
                context = await browser.new_context(locale=locale, **screen)
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


async def open_permission(page, connection, t):
    row = page.locator(f'tr[data-connection="{connection}"]')
    await row.get_by_role('button', name=t('Edit access', '编辑权限'), exact=True).click()
    return page.get_by_role('dialog', name=t('Permissions: ', '权限：') + connection, exact=True)


@pytest.mark.parametrize('locale', ['en-US', 'zh-CN'])
async def test_rename_and_imap_preview_feedback_in_the_open_dialog(tmp_path, locale):
    def t(en, zh):
        return zh if locale == 'zh-CN' else en
    async with admin_page(tmp_path, locale) as (page, origin):
        label = 'Greg <b>林</b>'
        await page.locator('.profile-name').click()
        await page.get_by_label(t('Name', '名字'), exact=True).fill(label)
        await page.get_by_role('button', name=t('Save name', '保存名称'), exact=True).click()
        await playwright.expect(page.locator('.profile-name')).to_have_text(label)
        assert await page.locator('.profile-name b').count() == 0
        await page.reload()
        await playwright.expect(page.locator('.profile-name')).to_have_text(label)
        assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        assert await page.get_by_role('button', name=t('Sign out', '退出'), exact=True).evaluate('(node) => node.getBoundingClientRect().height < 50')
        if directory := os.environ.get('AGW_TEST_ARTIFACTS'):
            Path(directory).mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=str(Path(directory) / f'member-name-{locale}.png'))
        pending = (await rpc(origin, TOKEN_A, 'tools/call', {'name': 'a_add_note', 'arguments': {'folder': 'inbox', 'text': 'name UI test'}})).json()
        request_id = request_id_in(pending['result']['content'][0]['text'])
        await page.goto(origin + '/approvals/r/' + request_id)
        await playwright.expect(page.locator('dl')).to_contain_text(label)
        assert await page.locator('dl b').count() == 0
        await page.goto(origin + '/admin/')
        await page.get_by_role('link', name=t('Connectors', '连接器'), exact=True).click()
        await page.get_by_role('button', name=t('Add connector', '添加连接器'), exact=True).click()
        box = page.get_by_role('dialog')
        await page.get_by_label(t('Service', '服务'), exact=True).select_option('imap')
        await playwright.expect(box.get_by_role('button', name=t('Search MCP Registry', '搜索 MCP Registry'), exact=True)).to_have_count(0)
        assert await box.locator('input[type=password]').count() == 1
        await playwright.expect(box.locator('input[name=smtp_host]')).to_have_value('smtp.mail.me.com')
        await playwright.expect(box.locator('input[name=smtp_port]')).to_have_value('587')
        security = box.locator('select[name=smtp_security]')
        await playwright.expect(security).to_have_value('starttls')
        assert (await security.bounding_box())['height'] == (await box.locator('input[name=smtp_host]').bounding_box())['height']
        name = page.get_by_label(t('Connector name', '连接器名称'), exact=True)
        await name.fill('iCloud Mail')
        preview = page.get_by_role('button', name=t('Save connector', '保存连接器'), exact=True)
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
        await page.route('**/admin/api/connections/save', offline)
        await preview.click()
        await playwright.expect(error).to_contain_text(t('Could not reach the gateway.', '无法连接网关'))
        await playwright.expect(password).to_have_value('fake-app-password-for-preview')
        await page.unroute('**/admin/api/connections/save', offline)
        release = anyio.Event()
        async def delayed(route):
            await release.wait()
            await route.continue_()
        await page.route('**/admin/api/connections/save', delayed)
        try:
            await preview.click()
            loading = page.get_by_role('button', name=t('Saving…', '正在保存…'), exact=True)
            await playwright.expect(loading).to_be_disabled()
        finally:
            release.set()
        card = page.locator('tr[data-connection=icloud-mail]')
        await playwright.expect(card).to_be_visible()
        await card.get_by_role('button', name=t('Edit settings', '编辑设置'), exact=True).click()
        await page.get_by_text(t('Mailbox addresses', '邮箱地址与别名'), exact=True).click()
        await page.get_by_label(t('Email aliases', '邮箱别名'), exact=True).fill('alias@example.test')
        await preview.click()
        await playwright.expect(page.get_by_role('dialog')).to_have_count(0)
        info = page.locator('main .info-tip')
        explanation = info.get_by_text(t('Credentials are encrypted.', '凭据加密保存。'), exact=False)
        await playwright.expect(explanation).to_be_hidden()
        await info.locator('summary').click()
        await playwright.expect(explanation).to_be_visible()
        await info.locator('summary').click()
        search = page.get_by_role('searchbox', name=t('Filter connectors', '筛选连接器'))
        await search.fill('no-matching-connector')
        await playwright.expect(card).to_be_hidden()
        await playwright.expect(page.get_by_text(t('No matching connectors.', '没有匹配的连接器。'))).to_be_visible()
        await search.fill('alias@example.test')
        await playwright.expect(page.locator('tbody tr:visible')).to_have_count(1)
        await card.get_by_role('button', name=t('Details', '详情'), exact=True).click()
        details = page.get_by_role('dialog', name='icloud-mail')
        await playwright.expect(details).to_contain_text('alias@example.test')


@pytest.mark.parametrize("auth", ["bearer", "oauth"])
async def test_prepared_proposals_review_in_browser_without_credential_fields(tmp_path, monkeypatch, auth):
    import hashlib
    import json
    import secrets
    import sys
    from urllib.parse import parse_qs, urlencode, urlsplit

    from helpers import TOKEN_HOUSE, prepare
    from passkey_helpers import approval_config
    from service_helpers import free_port
    from test_admin_remote import ISSUER, Remote, URL

    port = free_port()
    raw = approval_config(origin=f"http://localhost:{port}")
    raw["admin"] = {"owner": "person_a", "state": "admin.enc"}
    raw["server"]["tool_discovery"] = "search"
    path = await prepare(tmp_path, raw)
    remote = Remote(monkeypatch, mode=auth)
    remote.no_registration = True
    remote.grant_scope = "notes.read"
    async with admin_page(tmp_path, 'en-US', path=path, port=port) as (page, origin):
        await page.evaluate("""() => mutate('permissions/connection', {
          client: 'shared-agent', connection: 'gateway_config', access: 'read_write_direct'
        })""")

        confirmations = []
        operations = {"oauth-clients/save", "oauth/mcp/start", "connections/preview", "connections/apply"}

        def remember_confirmation(request):
            operation = urlsplit(request.url).path.removeprefix("/admin/api/")
            if request.method == "POST" and operation in operations and "confirmation" in request.post_data_json:
                confirmations.append(operation)

        page.on("request", remember_confirmation)

        async def prepare_request(config, credentials=None):
            args = {"prepared": True, **config}
            if credentials is not None:
                token = "agw_intake_" + secrets.token_urlsafe(32)
                args["intake_sha256"] = hashlib.sha256(token.encode()).hexdigest()
            response = await rpc(origin, TOKEN_HOUSE, "tools/call", {"name": "gateway_call_tool", "arguments": {
                "connection": "gateway_config", "tool": "gateway_config_provision",
                "idempotency_key": config["id"], "arguments": args,
            }})
            proposal = json.loads(response.json()["result"]["content"][0]["text"])
            await page.goto(origin + "/admin/connections")
            card = page.get_by_role('heading', name='Provisioning requests').locator('..')
            row = card.locator('.row').filter(has_text=config["id"])
            if credentials is not None:
                await playwright.expect(row.get_by_text('Waiting for credentials')).to_be_visible()
                stage = await anyio.run_process(
                    [sys.executable, "-m", "agent_gateway.cli", "stage", origin, proposal["id"], "--intake-token-stdin"],
                    input=(token + "\n" + json.dumps(credentials)).encode(),
                    env={key: value for key, value in os.environ.items() if key != "AGW_AGENT_TOKEN"},
                )
                assert json.loads(stage.stdout)["proposal"] == proposal["id"]
                assert all(private.encode() not in stage.stdout for private in (token, *credentials.values()))
            await page.goto(proposal["review_url"])
            dialog = page.locator('dialog[open]').last
            await playwright.expect(dialog).to_be_visible()
            await playwright.expect(dialog.locator('input')).to_have_count(0)
            return row, dialog

        client, client_review = await prepare_request(
            {"kind": "oauth_client", "id": "browser-oauth", "issuer": ISSUER},
            {"client_id": "browser-synthetic-client", "client_secret": "browser-client-secret"},
        )
        await playwright.expect(client_review.get_by_text('OAuth client ID: browser-synthetic-client')).to_be_visible()
        await client_review.get_by_role('button', name='Approve and save').click()
        await playwright.expect(client).to_have_count(0)
        assert not remote.requests

        config = {"kind": "http_mcp", "id": "browser-remote", "url": URL, "auth": auth,
                  "grants": [{"client": "shared-agent", "tool": "read.note", "access": "read"}]}
        credentials = {"token": remote.access} if auth == "bearer" else None
        if auth == "oauth":
            async def accept_consent(route):
                remote.query = parse_qs(urlsplit(route.request.url).query)
                callback, = remote.query["redirect_uri"]
                query = urlencode({"state": remote.query["state"][0], "code": "fake-code"})
                await route.fulfill(status=302, headers={"Location": callback + "?" + query})

            await page.route(ISSUER + "/authorize?*", accept_consent)
            config.update(oauth_client="browser-oauth", scope="notes.read")
        connection, connector_review = await prepare_request(config, credentials)
        await playwright.expect(connector_review.get_by_text('shared-agent · read.note · Read')).to_be_visible()
        button = "Start OAuth authorization" if auth == "oauth" else "Approve and load tools"
        await connector_review.get_by_role('button', name=button).click()
        tools = page.get_by_role('dialog', name='Review tool definitions')
        await playwright.expect(tools.get_by_text('shared-agent · read.note · Read')).to_be_visible()
        await tools.get_by_role('checkbox', name='I reviewed these definitions and permissions.').check()
        await tools.get_by_role('button', name='Apply connector').click()
        await playwright.expect(connection).to_have_count(0)
        await playwright.expect(page.locator('tr[data-connection="browser-remote"]')).to_be_visible()
        review = "oauth/mcp/start" if auth == "oauth" else "connections/preview"
        assert confirmations == ["oauth-clients/save", review, "connections/apply"]
