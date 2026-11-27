"""Stdio connectors in a sidecar: the gateway runs them over a Unix socket, not as its own children."""
import json
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

import anyio
import pytest
from helpers import TOKEN_A, agent, base_config, prepare, running_gateway, text_of
from test_admin import change, rpc, setup, state, web_gateway

from agent_gateway.config import ConnectionCfg
from agent_gateway.plugins import IMAGE_PLUGINS_ENV, MANIFEST_ENV, Plugin, connector_plugins
from agent_gateway.upstream import open_client

pytestmark = pytest.mark.anyio


@pytest.fixture
def socket_dir():
    # macOS Unix sockets have a short path limit.
    with TemporaryDirectory(prefix="agws-", dir="/tmp") as directory:
        yield Path(directory)


@contextmanager
def running_sidecar(path, log=None, **env):
    path.unlink(missing_ok=True)
    process = subprocess.Popen([sys.executable, "-m", "agent_gateway.sidecar", str(path)],
                               env={**os.environ, **env}, stderr=log)
    try:
        deadline = time.monotonic() + 15
        while not path.exists():
            assert process.poll() is None and time.monotonic() < deadline, "the sidecar did not start"
            time.sleep(0.02)
        yield process
    finally:
        process.terminate()
        process.wait(10)


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


async def test_image_sidecar_connector_review_call_and_stop(tmp_path, socket_dir, monkeypatch):
    socket = socket_dir / "control.sock"
    started = tmp_path / "started"
    secret = "private-sidecar-credential"
    # The demo connector, after recording its process and the process that started it.
    record = ("import os, sys; open(sys.argv[1], 'w').write(f'{os.getpid()} {os.getppid()}'); "
              "os.execv(sys.executable, [sys.executable, '-m', 'agent_gateway.demo_connector'])")
    image = tmp_path / "image-plugins"
    image.mkdir()
    (image / "notes-sidecar.json").write_text(json.dumps({
        "id": "notes-sidecar", "label": "Sidecar notes", "kind": "stdio", "socket": str(socket),
        "command": [sys.executable, "-c", record, str(started)], "credentials": {"DEMO_API_KEY": "Notes key"},
    }))
    monkeypatch.setenv(IMAGE_PLUGINS_ENV, str(image))
    assert "notes-sidecar" not in connector_plugins(None)  # offered only where its sidecar runs
    body = {"id": "notes-sidecar", "owner": "person_a", "kind": "local",
            "settings": {"plugin": "notes-sidecar"}, "credentials": {"DEMO_API_KEY": secret}}
    with running_sidecar(socket) as sidecar:
        async with web_gateway(tmp_path) as (gw, http, origin, path):
            await setup(http, origin, path)
            public = [p for p in (await state(http))["plugins"] if p["kind"] != "web"]
            assert public == [{"id": "notes-sidecar", "label": "Sidecar notes", "kind": "stdio",
                               "credentials": {"DEMO_API_KEY": "Notes key"}}]
            preview = await change(http, "connections/preview", **body)
            assert preview.status_code == 200, preview.text
            review = preview.json()
            applied = await change(http, "connections/apply", draft=review["draft"], reviewed=True, tools=review["tools"])
            assert applied.status_code == 200, applied.text
            granted = await change(http, "permissions/connection", client="agent-a", connection="notes-sidecar", access="read")
            assert granted.status_code == 200, granted.text
            conn = next(c for c in (await state(http))["connections"] if c["id"] == "notes-sidecar")
            tool = next(t for t in conn["tools"] if t["access"] == "read")
            result = (await rpc(origin, TOKEN_A, "tools/call", {"name": tool["name"], "arguments": {"folder": "inbox"}})).json()
            assert not result.get("error") and not result["result"].get("isError"), result
            assert secret not in str(result) + gw.audit_text()
            # The connector is the sidecar's child, not the gateway's.
            pid, parent = map(int, started.read_text().split())
            assert parent == sidecar.pid != os.getpid()
            assert alive(pid)
        # The gateway closed its connection, so the sidecar stopped the connector.
        with anyio.fail_after(10):
            while alive(pid):
                await anyio.sleep(0.05)
        assert sidecar.poll() is None


async def test_sidecar_connector_gets_only_its_connection_environment(socket_dir):
    socket = socket_dir / "control.sock"
    conn = ConnectionCfg(id="notes", service="notes", account="person_a", owner="person_a", transport="stdio",
                         command=[sys.executable, "-m", "agent_gateway.demo_connector"],
                         env={"DEMO_ACCOUNT": "person_a"}, secret_env={"DEMO_API_KEY": "notes_key"},
                         socket=str(socket), tools=[])
    with running_sidecar(socket, HOME="/sidecar-home", SIDECAR_PRIVATE="sidecar-only-value"):
        async with open_client(conn, {"notes_key": "sidecar-test-key"}) as client:
            dump = text_of(await client.call_tool("debug_dump", {}))
    assert "DEMO_API_KEY=sidecar-test-key" in dump and "DEMO_ACCOUNT=person_a" in dump
    # The minimal environment of a stdio connector, taken from the sidecar and nothing more.
    assert "HOME=/sidecar-home" in dump and "SIDECAR_PRIVATE" not in dump


async def test_sidecar_log_leaves_out_a_connector_line_it_cannot_parse(tmp_path, socket_dir):
    socket = socket_dir / "control.sock"
    secret = "sidecar-log-credential"
    # The connector prints its credential on stdout before speaking MCP.
    noisy = ("import os, sys; print('not json', os.environ['DEMO_API_KEY'], flush=True); "
             "os.execv(sys.executable, [sys.executable, '-m', 'agent_gateway.demo_connector'])")
    conn = ConnectionCfg(id="notes", service="notes", account="person_a", owner="person_a", transport="stdio",
                         command=[sys.executable, "-c", noisy], secret_env={"DEMO_API_KEY": "notes_key"},
                         socket=str(socket), tools=[])
    log_path = tmp_path / "sidecar.log"
    with log_path.open("w") as log, running_sidecar(socket, log):
        async with open_client(conn, {"notes_key": secret}) as client:
            assert "account=" in text_of(await client.call_tool("whoami", {}))
    log = log_path.read_text()
    assert "Failed to parse JSONRPC message" in log and secret not in log


def test_cli_manifest_without_a_socket_reads_in_a_release_without_sidecars():
    plugin = Plugin(id="fixture", label="Fixture", kind="cli", command=[sys.executable, "-c", "print(1)"],
                    tools={"get_value": {"description": "Read a fixture", "access": "read"}})
    _, env = plugin.connection()
    # The connection keeps this manifest; 0.20.0 rejects any field it does not know.
    assert "socket" not in json.loads(env[MANIFEST_ENV])


async def test_gateway_reconnects_after_the_sidecar_restarts(tmp_path, socket_dir):
    socket = socket_dir / "control.sock"
    raw = base_config()
    raw["connections"][0]["socket"] = str(socket)
    with running_sidecar(socket) as first:
        path = await prepare(tmp_path, raw)
        async with running_gateway(path) as gw, agent(gw.url, TOKEN_A) as a:
            assert "account=person_a" in text_of(await a.call_tool("a_whoami", {}))
            first.terminate()
            first.wait(10)
            stopped = await a.call_tool("a_whoami", {})
            assert stopped.is_error and text_of(stopped) == "The upstream service is currently unavailable."
            with running_sidecar(socket):
                with anyio.fail_after(20):
                    while (result := await a.call_tool("a_whoami", {})).is_error:
                        await anyio.sleep(0.2)
            assert "account=person_a" in text_of(result)
