"""Opt-in acceptance of the actual image with disposable Docker volumes.

Run through `python scripts/acceptance.py --docker`. No real accounts, secrets,
existing containers or deployment volumes are used.
"""

import json
import os
import subprocess
import uuid
from contextlib import contextmanager
from pathlib import Path

import anyio
import httpx2
import pytest
import yaml
from helpers import TOKEN_A, TOKEN_B, TOKEN_HOUSE, agent, text_of, tool_names
from mcp import MCPError
from passkey_helpers import wait_for_approval, Authenticator, Page, request_id_in
from test_admin import admin_post

from agent_gateway.auth import hash_token

pytestmark = [pytest.mark.anyio, pytest.mark.docker,
              pytest.mark.skipif(not os.environ.get("AGW_TEST_IMAGE"), reason="run scripts/acceptance.py --docker")]


def docker(*args, input=None, check=True):
    done = subprocess.run(["docker", *args], input=input, capture_output=True, text=True, timeout=120)
    if check and done.returncode:
        raise AssertionError(f"docker {args[0]} failed: {done.stderr[:2000]}")
    return done.stdout.strip()


@contextmanager
def deployed(*, admin=False):
    image = os.environ["AGW_TEST_IMAGE"]
    name = "agw-acceptance-" + uuid.uuid4().hex[:12]
    volumes = {part: f"{name}-{part}" for part in ("config", "key", "secrets", "state")}
    mounts = [arg for part, volume in volumes.items() for arg in ("-v", f"{volume}:/{part}")]
    try:
        for volume in volumes.values():
            docker("volume", "create", volume)
        docker("run", "--rm", "--network", "none", "--user", "0:0", *mounts, "--entrypoint", "python", image,
               "-c", "import os; [os.chown('/'+p,10001,10001) for p in ('config','key','secrets','state')]")
        config = yaml.safe_load((Path(__file__).resolve().parent.parent / "deploy/gateway.example.yaml").read_text())
        tokens = {"person_a": TOKEN_A, "person_b": TOKEN_B, "household": TOKEN_HOUSE}
        for client in config["clients"]:
            client["token_sha256"] = hash_token(tokens[client["principal"]])
        config["approvals"]["origin"] = "http://localhost"
        if admin:
            config['admin'] = {'owner':'person_a','state':'../state/admin.enc'}
        seed = """
import json, os, sys
from pathlib import Path
from agent_gateway.credentials import EncryptedFileStore
os.umask(0o077)
Path('/config/gateway.yaml').write_text(json.dumps(json.load(sys.stdin)))
EncryptedFileStore.create_key(Path('/key/master.key'))
store=EncryptedFileStore(Path('/secrets/secrets.enc'),Path('/key/master.key'))
for name in ('notes_key_a','notes_key_b','notes_key_house'):
    store.set(name,'fake-container-secret-'+name)
"""
        docker("run", "--rm", "-i", "--network", "none", *mounts, "--entrypoint", "python", image, "-c", seed,
               input=json.dumps(config))
        docker("run", "--rm", "--network", "none", *mounts, image, "lock", "--write")
        docker("run", "--rm", "--network", "none", *mounts, image, "check")
        protected = [arg for part, volume in volumes.items()
                     for arg in ("-v", f"{volume}:/{part}" + ("" if part == "state" else ":ro"))]
        docker("run", "-d", "--name", name, "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--tmpfs", "/tmp", "-p", "127.0.0.1::8080", *protected, image)
        port = docker("port", name, "8080/tcp").rsplit(":", 1)[1]
        yield name, image, mounts, f"http://127.0.0.1:{port}"
    finally:
        docker("rm", "-f", name, check=False)
        for volume in volumes.values():
            docker("volume", "rm", volume, check=False)


async def healthy(base):
    async with httpx2.AsyncClient(trust_env=False, timeout=2) as http:
        with anyio.fail_after(30):
            while True:
                try:
                    if (await http.get(f"{base}/healthz")).status_code == 200:
                        return
                except httpx2.TransportError:
                    pass
                await anyio.sleep(0.1)


async def test_hardened_image_identity_restart_approval_and_connector_recovery():
    with deployed() as (name, image, mounts, base):
        await healthy(base)
        metadata = json.loads(docker("inspect", name))[0]
        assert metadata["Config"]["User"] == "10001:10001"
        assert metadata["HostConfig"]["ReadonlyRootfs"]
        assert "ALL" in metadata["HostConfig"]["CapDrop"]
        assert {mount["Destination"]: mount["RW"] for mount in metadata["Mounts"]} == {
            "/config": False, "/key": False, "/secrets": False, "/state": True,
        }
        probe = """
import os
from pathlib import Path
assert os.getuid()==10001
status=Path('/proc/self/status').read_text()
assert int(next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:')),16)==0
for directory in ('/config','/key','/secrets'):
    try:
        Path(directory,'write-probe').write_text('test')
    except OSError:
        pass
    else:
        raise AssertionError(directory+' is writable')
p=Path('/state/write-probe'); p.write_text('test'); p.unlink()
"""
        docker("exec", name, "python", "-c", probe)
        async with httpx2.AsyncClient(trust_env=False) as http:
            assert (await http.post(f"{base}/mcp", json={})).status_code == 401
        url = f"{base}/mcp"
        async with agent(url, TOKEN_A) as a, agent(url, TOKEN_B) as b, agent(url, TOKEN_HOUSE) as shared:
            assert await tool_names(a) == await tool_names(b) == await tool_names(shared) == {'gateway_search_tools', 'gateway_search_connections', 'gateway_call_tool'}
            assert 'notes_list_notes' in text_of(await a.call_tool('gateway_search_tools', {}))
            for other in (b, shared):
                restricted = json.loads(text_of(await other.call_tool('gateway_search_connections', {'tool': 'notes_list_notes', 'query': 'notes-a'})))
                variants = restricted['connections'][0]['variants']
                assert len(variants) == 1 and variants[0]['id'] == 'a_family_notes'
                assert 'folder' not in variants[0]['inputSchema']['properties']
                assert (await other.call_tool('gateway_call_tool', {'idempotency_key': 'list-notes', 'tool': 'notes_list_notes', 'connection': 'notes-a', 'arguments': {'folder': 'inbox'}})).is_error
            with pytest.raises(MCPError):
                await b.call_tool("a_notes_list", {})
            assert not (await a.call_tool("a_notes_list", {"folder": "inbox"})).is_error

        enrollment = docker("run", "--rm", "--network", "none", *mounts, image, "approval", "enroll", "person_a")
        link = next(line.strip() for line in enrollment.splitlines() if "/approvals/enroll#" in line)
        page, key = Page(base), Authenticator()
        status, ceremony = await page.begin("enroll", link.split("#", 1)[1])
        assert status == 200
        assert (await page.finish(ceremony, key.response(ceremony)))[0] == 200
        note = {"folder": "inbox", "text": "container-test-private-note"}
        async with agent(url, TOKEN_A) as a:
            request_id = request_id_in(text_of(await a.call_tool("a_notes_add", note)))
        assert (await page.decide("approve", request_id, key))[0] == 200

        async with agent(url, TOKEN_A) as a:
            assert (await wait_for_approval(a, request_id)).structured_content["status"] == "succeeded"
            assert text_of(await a.call_tool("a_notes_list", {"folder": "inbox"})).count(note["text"]) == 1

        # The execution outcome survives a restart, without replaying the write.
        docker("restart", name)
        # Docker may allocate a new host port when an ephemeral published port restarts.
        port = docker("port", name, "8080/tcp").rsplit(":", 1)[1]
        base, url = f"http://127.0.0.1:{port}", f"http://127.0.0.1:{port}/mcp"
        page = Page(base)
        await healthy(base)
        assert (await page.view(request_id))[1]["status"] == "used"
        async with agent(url, TOKEN_A) as a:
            recovered = await wait_for_approval(a, request_id)
            assert recovered.structured_content["status"] == "succeeded"
            assert "no longer available" in text_of(recovered)
            assert (await a.call_tool("a_notes_add", note)).structured_content["idempotency_key"] == request_id
            assert note["text"] not in text_of(await a.call_tool("a_notes_list", {"folder": "inbox"}))
            kill = """
import os, signal
from pathlib import Path
for p in Path('/proc').iterdir():
    if not p.name.isdigit(): continue
    try:
        args=(p/'cmdline').read_bytes().split(b'\\0')
        if b'examples/demo_connector.py' in args and b'DEMO_ACCOUNT=person_a' in (p/'environ').read_bytes().split(b'\\0'):
            os.kill(int(p.name),signal.SIGKILL)
            break
    except (FileNotFoundError,ProcessLookupError): pass
else: raise AssertionError('demo connector was not running')
"""
            docker("exec", name, "python", "-c", kill)
            with anyio.fail_after(30):
                while (await a.call_tool("a_notes_list", {"folder": "inbox"})).is_error:
                    await anyio.sleep(0.2)
        audit = docker("exec", name, "cat", "/state/audit/audit.jsonl")
        for private in (TOKEN_A, TOKEN_B, TOKEN_HOUSE, note["text"], "fake-container-secret-"):
            assert private not in audit
        assert '"event":"approval_decided"' in audit


async def test_web_onboarding_in_readonly_container_and_state_survives_restart():
    with deployed(admin=True) as (name, image, mounts, base):
        await healthy(base)
        link = docker('exec', name, 'cat', '/state/admin-setup-link')
        key = Authenticator()
        headers = {'Host':'localhost','Origin':'http://localhost'}
        async with httpx2.AsyncClient(base_url=base, headers=headers, trust_env=False) as http:
            ceremony = (await http.post('/admin/api/auth/begin', json={'action':'setup','code':link.split('#setup=')[1]})).json()
            registered = await http.post('/admin/api/auth/finish', json={'ceremony_id':ceremony['ceremony_id'], 'response':key.response(ceremony)})
            assert registered.status_code == 200, registered.text
            csrf = registered.json()['csrf']
            http.headers['X-CSRF-Token'] = csrf
            http.test_passkey = key, 'http://localhost'
            renamed = await http.post('/admin/api/members/rename', json={'revision':0,'id':'person_a','name':'Container owner'})
            assert renamed.status_code == 200, renamed.text
            created = await admin_post(http, 'clients/create', json={'revision':0,'id':'web-agent','household':'household'})
            assert created.status_code == 200, created.text
            token = created.json()['token']
            preview = await admin_post(http, 'connections/preview', json={'revision':1,'id':'web-notes','owner':'person_a','kind':'demo'})
            assert preview.status_code == 200, preview.text
            applied = await admin_post(http, 'connections/apply', json={'revision':1,'draft':preview.json()['draft'],'reviewed':True})
            assert applied.status_code == 200, applied.text
            async with agent(base + '/mcp', token, Host='localhost') as client:
                assert await tool_names(client) == {"gateway_search_tools", "gateway_search_connections", "gateway_call_tool"}
                assert json.loads(text_of(await client.call_tool('gateway_search_tools', {})))['total'] == 0
            granted = await admin_post(http, 'permissions/save', json={'revision':2,'client':'web-agent',
                'connection':'web-notes','tool':'web_notes_list','effect':'allow'})
            assert granted.status_code == 200, granted.text
            cookies = http.cookies
        docker('restart', name)
        port = docker('port', name, '8080/tcp').rsplit(':',1)[1]
        base = f'http://127.0.0.1:{port}'
        await healthy(base)
        async with httpx2.AsyncClient(base_url=base, headers=headers, cookies=cookies, trust_env=False) as http:
            saved = await http.get('/admin/api/state')
            assert saved.status_code == 200, saved.text
            assert saved.json()['revision'] == 3
            assert next(m for m in saved.json()['members'] if m['id']=='person_a')['name'] == 'Container owner'
            assert any(c['id']=='web-notes' for c in saved.json()['connections'])
            assert token not in saved.text
        async with agent(base + '/mcp', token, Host='localhost') as client:
            assert 'notes_list_notes' in text_of(await client.call_tool('gateway_search_tools', {}))
            result = await client.call_tool('gateway_call_tool', {'idempotency_key': 'list-web-notes', 'tool': 'notes_list_notes', 'connection': 'web-notes', 'arguments': {'folder':'inbox'}})
            assert not result.is_error and 'person_a' in text_of(result)
        check = "from pathlib import Path; assert not Path('/state/admin-setup-link').exists(); assert Path('/state/admin.enc').stat().st_mode & 0o777 == 0o600"
        docker('exec', name, 'python', '-c', check)
        metadata = json.loads(docker('inspect', name))[0]
        assert metadata['HostConfig']['ReadonlyRootfs']
        assert not next(m for m in metadata['Mounts'] if m['Destination']=='/config')['RW']


async def test_isolated_browser_container_starts_and_renders_without_network():
    image = os.environ["AGW_TEST_BROWSER_IMAGE"]
    name = "agw-browser-acceptance-" + uuid.uuid4().hex[:12]
    try:
        docker("run", "-d", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:size=384m,mode=1777",
               "--init", "--memory", "768m", "--pids-limit", "256", "-v", f"{name}:/browser", image)
        metadata = json.loads(docker("inspect", name))[0]
        assert metadata["HostConfig"]["NetworkMode"] == "none"
        assert [mount["Destination"] for mount in metadata["Mounts"]] == ["/browser"]
        probe = """
import base64, time
import httpx2
http = httpx2.Client(transport=httpx2.HTTPTransport(uds='/browser/control.sock'), timeout=25)
for _ in range(75):
    try:
        http.post('http://browser/health').raise_for_status()
        break
    except httpx2.TransportError:
        time.sleep(.2)
else:
    raise AssertionError('Browser control socket was not ready')
ident='0123456789abcdef01234567'
def call(op, **kw):
    r=http.post('http://browser/'+op,json=dict(id=ident,**kw))
    return r.raise_for_status().json()
# Match the display settings that the Gateway sends to the worker. This
# in-memory page needs no network connection or login account.
viewport = {'width': 420, 'height': 620}
assert call('start', url='data:text/html,<h1>Simulated login</h1>', viewport=viewport,
            touch=False, user_agent=None, expires=time.time()+50) == viewport
assert base64.b64decode(call('frame')['image']).startswith(b'\\xff\\xd8')
assert call('close') == {}
"""
        docker("exec", name, "python", "-c", probe)
    finally:
        docker("rm", "-f", name, check=False)
        docker("volume", "rm", name, check=False)


async def test_sidecar_container_runs_connectors_without_gateway_data():
    image = os.environ["AGW_TEST_IMAGE"]
    name = "agw-sidecar-acceptance-" + uuid.uuid4().hex[:12]
    sockets = "/sidecars/acceptance"
    mount = ["-v", f"{name}:{sockets}"]
    hardened = ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp"]
    try:
        docker("volume", "create", name)
        docker("run", "--rm", "--network", "none", "--user", "0:0", *mount, "--entrypoint", "python", image,
               "-c", f"import os; os.chown({sockets!r}, 10001, 10001); os.chmod({sockets!r}, 0o700)")
        docker("run", "-d", "--name", name, "--network", "none", *hardened, "--init", *mount,
               "-e", "HOME=/sidecar-home", "-e", "SIDECAR_PRIVATE=sidecar-only",
               "--entrypoint", "python", image, "-m", "agent_gateway.sidecar", f"{sockets}/control.sock")
        metadata = json.loads(docker("inspect", name))[0]
        assert metadata["Config"]["User"] == "10001:10001"
        assert [mount["Destination"] for mount in metadata["Mounts"]] == [sockets]
        docker("exec", name, "python", "-c",
               "import os; assert not any(os.path.exists(p) for p in ('/config', '/secrets', '/key', '/state'))")
        # The gateway's end, in a second container of the same image.
        probe = """
import os, sys, time
import anyio
from agent_gateway.config import ConnectionCfg
from agent_gateway.upstream import open_client
for _ in range(75):
    if os.path.exists(sys.argv[1]):
        break
    time.sleep(.2)
conn = ConnectionCfg(id='notes', service='notes', account='person_a', owner='person_a', transport='stdio',
                     command=[sys.executable, '-m', 'agent_gateway.demo_connector'], env={'DEMO_ACCOUNT': 'person_a'},
                     secret_env={'DEMO_API_KEY': 'notes_key'}, socket=sys.argv[1], tools=[])
async def main():
    async with open_client(conn, {'notes_key': 'fake-sidecar-secret'}) as client:
        print((await client.call_tool('debug_dump', {})).content[0].text)
anyio.run(main)
"""
        dump = docker("run", "--rm", "--network", "none", *hardened, *mount, "--entrypoint", "python", image,
                      "-c", probe, f"{sockets}/control.sock")
        # It ran in the sidecar, with the sidecar's minimal environment and this connection's credential.
        assert "HOME=/sidecar-home" in dump and "DEMO_API_KEY=fake-sidecar-secret" in dump
        assert "SIDECAR_PRIVATE" not in dump
        # Closing the connection stopped the connector; only the sidecar is left.
        with anyio.fail_after(10):
            while "demo_connector" in docker("top", name):
                await anyio.sleep(0.2)
    finally:
        docker("rm", "-f", name, check=False)
        docker("volume", "rm", name, check=False)


async def test_amazon_orders_sidecar_without_a_session_reports_it_and_does_not_sign_in():
    image = os.environ["AGW_TEST_IMAGE"]
    name = "agw-amazon-acceptance-" + uuid.uuid4().hex[:12]
    sockets, state = f"{name}-sockets", f"{name}-state"
    mount = ["-v", f"{sockets}:/sidecars/amazon-orders"]
    hardened = ["--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--tmpfs", "/tmp"]
    try:
        # No chown: the image creates both mount points for UID 10001, and a new volume takes that over.
        docker("run", "-d", "--name", name, *hardened, "--init", *mount, "-v", f"{state}:/var/lib/amazon-orders",
               "--entrypoint", "python", image, "-m", "agent_gateway.sidecar", "/sidecars/amazon-orders/control.sock")
        # The gateway's end: the manifest that comes with the image, an empty cookie array as the session.
        probe = """
import json, time
import anyio
from agent_gateway.config import ConnectionCfg
from agent_gateway.plugins import connector_plugins
from agent_gateway.upstream import list_all_tools, open_client
for _ in range(75):
    if 'amazon-orders' in connector_plugins(None):
        break
    time.sleep(.2)
plugin = connector_plugins(None)['amazon-orders']
command, env = plugin.connection()
conn = ConnectionCfg(id='amazon', service='amazon-orders', account='person_a', owner='person_a', transport='stdio',
                     command=command, env=env, secret_env={'ORDERS_SESSION_SECRET': 'session'}, socket=plugin.socket,
                     tools=[], timeout_seconds=30)
async def main():
    async with open_client(conn, {'session': '[]'}) as client:
        tools = await list_all_tools(client)
        calls = {name: await client.call_tool(name, {}) for name in ('check_session', 'get_orders')}
    print(json.dumps({'read_only': [t.name for t in tools if t.annotations and t.annotations.read_only_hint],
                      **{name: [r.is_error, r.content[0].text] for name, r in calls.items()}}))
anyio.run(main)
"""
        with anyio.fail_after(60):
            result = json.loads(docker("run", "--rm", *hardened, *mount, "--entrypoint", "python", image, "-c", probe))
        assert {"check_session", "get_orders", "get_order", "get_tracking"} <= set(result["read_only"])
        assert result["check_session"][0] is False and json.loads(result["check_session"][1])["signed_in"] is False
        # Without the network, an attempt to sign in or to read Amazon would fail differently.
        assert result["get_orders"][0] is True and "There's no saved Amazon session." in result["get_orders"][1]
        # The credential became the MCP's cookie file, readable by the sidecar's user only.
        assert docker("exec", name, "stat", "-c", "%a %u", "/var/lib/amazon-orders/cookies.json") == "600 10001"
        assert docker("exec", name, "cat", "/var/lib/amazon-orders/cookies.json") == "[]"
    finally:
        docker("rm", "-f", name, check=False)
        docker("volume", "rm", sockets, state, check=False)
