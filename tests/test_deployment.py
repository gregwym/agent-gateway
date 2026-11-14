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
from passkey_helpers import Authenticator, Page, request_id_in

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
            assert "a_notes_list" in await tool_names(a)
            assert "a_notes_list" not in await tool_names(b)
            assert "a_notes_list" not in await tool_names(shared)
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

        # The approval store survives a real process/container restart.
        docker("restart", name)
        # Docker may allocate a new host port when an ephemeral published port restarts.
        port = docker("port", name, "8080/tcp").rsplit(":", 1)[1]
        base, url = f"http://127.0.0.1:{port}", f"http://127.0.0.1:{port}/mcp"
        page = Page(base)
        await healthy(base)
        assert (await page.view(request_id))[1]["status"] == "approved"
        async with agent(url, TOKEN_A) as a:
            assert not (await a.call_tool("a_notes_add", note)).is_error
            assert (await a.call_tool("a_notes_add", note)).is_error
            assert text_of(await a.call_tool("a_notes_list", {"folder": "inbox"})).count(note["text"]) == 1
            assert (await page.view(request_id))[1]["status"] == "used"
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
            renamed = await http.post('/admin/api/members/rename', json={'revision':0,'id':'person_a','display_name':'Container owner'})
            assert renamed.status_code == 200, renamed.text
            created = await http.post('/admin/api/clients/create', json={'revision':0,'id':'web-agent','principal':'person_a'})
            assert created.status_code == 200, created.text
            token = created.json()['token']
            preview = await http.post('/admin/api/connections/preview', json={'revision':1,'id':'web-notes','owner':'person_a','kind':'demo'})
            assert preview.status_code == 200, preview.text
            applied = await http.post('/admin/api/connections/apply', json={'revision':1,'draft':preview.json()['draft'],'reviewed':True})
            assert applied.status_code == 200, applied.text
            cookies = http.cookies
        docker('restart', name)
        port = docker('port', name, '8080/tcp').rsplit(':',1)[1]
        base = f'http://127.0.0.1:{port}'
        await healthy(base)
        async with httpx2.AsyncClient(base_url=base, headers=headers, cookies=cookies, trust_env=False) as http:
            saved = await http.get('/admin/api/state')
            assert saved.status_code == 200, saved.text
            assert saved.json()['revision'] == 2
            assert next(m for m in saved.json()['members'] if m['id']=='person_a')['display_name'] == 'Container owner'
            assert any(c['id']=='web-notes' for c in saved.json()['connections'])
            assert token not in saved.text
        async with agent(base + '/mcp', token, Host='localhost') as client:
            assert 'web_notes_list' in await tool_names(client)
            result = await client.call_tool('web_notes_list', {'folder':'inbox'})
            assert not result.is_error and 'person_a' in text_of(result)
        check = "from pathlib import Path; assert not Path('/state/admin-setup-link').exists(); assert Path('/state/admin.enc').stat().st_mode & 0o777 == 0o600"
        docker('exec', name, 'python', '-c', check)
        metadata = json.loads(docker('inspect', name))[0]
        assert metadata['HostConfig']['ReadonlyRootfs']
        assert not next(m for m in metadata['Mounts'] if m['Destination']=='/config')['RW']
