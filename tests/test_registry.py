"""Search public MCP metadata from the admin console, then preview a selected endpoint."""
import httpx2
import pytest

from agent_gateway import registry
from test_admin import setup, state, web_gateway

pytestmark = pytest.mark.anyio


def entry(name, *remotes, status='active', title=None):
    return {'server': {'name': name, 'title': title, 'remotes': [
        {'type': transport, 'url': url} for transport, url in remotes]},
        '_meta': {registry.OFFICIAL: {'status': status}}}


def mock_registry(monkeypatch, handler):
    monkeypatch.setattr(registry, '_http', lambda: httpx2.AsyncClient(transport=httpx2.MockTransport(handler)))


async def test_registry_search_requires_admin_and_only_returns_compatible_endpoints(tmp_path, monkeypatch):
    calls = []
    def handler(request):
        calls.append(request)
        assert str(request.url).split('?')[0] == registry.URL
        assert request.method == 'GET'
        assert 'authorization' not in request.headers and 'cookie' not in request.headers
        assert request.url.params['version'] == 'latest'
        assert request.url.params['search'] == 'sample'
        if request.url.params.get('cursor'):
            assert request.url.params['cursor'] == 'next-page'
            return httpx2.Response(200, json={'metadata': {}, 'servers': []})
        return httpx2.Response(200, json={'metadata': {'nextCursor': 'next-page'}, 'servers': [
            entry('net.todoist/mcp', ('streamable-http', 'https://ai.todoist.net/mcp'), title='Todoist'),
            entry('com.example/sample', ('streamable-http', 'https://sample.example.test/mcp'),
                  ('streamable-http', 'https://sample.example.test/{region}/mcp'),
                  ('streamable-http', 'https://sample.example.test/mcp?token=private'),
                  ('streamable-http', 'http://sample.example.test/mcp'),
                  ('sse', 'https://sample.example.test/sse')),
            entry('com.example/old-sample', ('streamable-http', 'https://old.example.test/mcp'), status='deprecated'),
            entry('com.example/local-sample'),
        ]})
    mock_registry(monkeypatch, handler)
    async with web_gateway(tmp_path) as (_, http, origin, path):
        before_login = await http.post('/admin/api/registry/search', json={'query': 'sample'})
        assert before_login.status_code == 401
        await setup(http, origin, path)
        before = await state(http)
        no_csrf = await http.post('/admin/api/registry/search', json={'query': 'sample'}, headers={'X-CSRF-Token': ''})
        assert no_csrf.status_code == 403 and not calls
        short = await http.post('/admin/api/registry/search', json={'query': 'ab'})
        assert short.status_code == 400 and not calls
        response = await http.post('/admin/api/registry/search', json={'query': '  sample  '})
        assert response.status_code == 200
        result = response.json()
        assert result['next_cursor'] == 'next-page'
        assert [(item['url'], item['auth']) for item in result['results']] == [
            ('https://ai.todoist.net/mcp', 'oauth'), ('https://sample.example.test/mcp', None)]
        next_page = await http.post('/admin/api/registry/search', json={'query': 'sample', 'cursor': result['next_cursor']})
        assert next_page.json() == {'next_cursor': None, 'results': []}
        after = await state(http)
        assert after['revision'] == before['revision'] and after['connections'] == before['connections']
        assert len(calls) == 2


@pytest.mark.browser
async def test_registry_selection_prefills_remote_mcp_without_saving(tmp_path, monkeypatch):
    from test_admin_feedback_browser import admin_page, playwright

    def handler(request):
        return httpx2.Response(200, json={'metadata': {}, 'servers': [
            entry('net.todoist/mcp', ('streamable-http', 'https://ai.todoist.net/mcp'), title='Todoist')]})
    mock_registry(monkeypatch, handler)
    async with admin_page(tmp_path, 'en-US') as (page, _):
        await page.get_by_role('link', name='Connectors', exact=True).click()
        await page.get_by_role('button', name='Add connector', exact=True).click()
        await page.get_by_role('button', name='Search MCP Registry', exact=True).click()
        await page.get_by_label('Service name', exact=True).fill('todoist')
        await page.get_by_role('button', name='Search', exact=True).click()
        await playwright.expect(page.get_by_text('net.todoist/mcp', exact=True)).to_be_visible()
        await page.get_by_role('button', name='Use endpoint', exact=True).click()
        await playwright.expect(page.get_by_label('Service', exact=True)).to_have_value('remote')
        await playwright.expect(page.get_by_label('MCP endpoint URL', exact=True)).to_have_value('https://ai.todoist.net/mcp')
        await playwright.expect(page.get_by_label('Authentication', exact=True)).to_have_value('oauth')
        await playwright.expect(page.get_by_role('heading', name='Review tool definitions')).to_have_count(0)
