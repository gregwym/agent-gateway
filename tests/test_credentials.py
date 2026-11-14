"""Agents never see upstream credentials: not in results, listings, errors or logs."""

from __future__ import annotations

import json
import os
import sys

import httpx2
import pytest
from helpers import (
    CONNECTOR,
    SECRETS,
    TOKEN_A,
    TOKEN_B,
    agent,
    base_config,
    prepare,
    running_gateway,
    text_of,
    write_config,
)

from agent_gateway.config import load_config
from agent_gateway.credentials import REDACTED, EncryptedFileStore, Scrubber, SecretStoreError
from agent_gateway.upstream import open_client

pytestmark = pytest.mark.anyio


async def test_a_connector_that_echoes_its_credential_is_scrubbed(tmp_path):
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            dump = text_of(await a.call_tool("a_debug_dump", {}))
        assert "DEMO_ACCOUNT=person_a" in dump  # the tool really ran and really dumped
        assert f"DEMO_API_KEY={REDACTED}" in dump
        for value in SECRETS.values():
            assert value not in dump


async def test_a_connector_gets_only_its_own_credential_and_a_minimal_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("AGW_TEST_CANARY", "gateway-process-env-value")
    cfg = load_config(await prepare(tmp_path))
    async with running_gateway(tmp_path / "gateway.yaml") as gw:
        assert set(gw.gateway.upstreams["notes-a"]._secrets) == {"notes_key_a"}
        assert set(gw.gateway.upstreams["notes-b"]._secrets) == {"notes_key_b"}
    # Straight to the connector, bypassing the gateway's scrubbing, to see its real environment.
    async with open_client(cfg.connection("notes-a"), {"notes_key_a": SECRETS["notes_key_a"]}) as client:
        raw = text_of(await client.call_tool("debug_dump", {}))
    assert SECRETS["notes_key_a"] in raw
    assert SECRETS["notes_key_b"] not in raw and SECRETS["notes_key_house"] not in raw
    assert "gateway-process-env-value" not in raw


async def test_listings_errors_and_audit_log_hold_no_secrets_or_content(tmp_path):
    async with running_gateway(await prepare(tmp_path)) as gw:
        headers = {"Accept": "application/json, text/event-stream", "Authorization": f"Bearer {TOKEN_A}"}
        async with httpx2.AsyncClient(headers=headers) as http:
            listing = (await http.post(gw.url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).text
            unauthenticated = (await http.post(gw.url, json={}, headers={"Authorization": "Bearer nope"})).text
        async with agent(gw.url, TOKEN_A) as a:
            await a.call_tool("a_list_notes", {"folder": "inbox"})
            await a.call_tool("a_get_note", {"id": "zebra-crossing-unique-argument"})
            await a.call_tool("a_debug_dump", {})
        audit = gw.audit_text()

    for blob in (listing, unauthenticated, audit):
        for value in SECRETS.values():
            assert value not in blob
        assert TOKEN_A not in blob and TOKEN_B not in blob
        assert CONNECTOR not in blob and "DEMO_API_KEY" not in blob and "master.key" not in blob
    # The audit log has the shape of the call, not its content.
    assert "zebra-crossing-unique-argument" not in audit
    assert "private inbox note" not in audit
    record = next(e for e in gw.audit() if e.get("tool") == "a_get_note")
    assert record["arg_keys"] == ["id"] and record["principal"] == "person_a" and record["account"] == "person_a"
    assert set(record) <= {
        "ts", "event", "client", "principal", "tool", "connection", "service", "account",
        "upstream_tool", "decision", "reason", "duration_ms", "result_bytes", "is_error", "arg_keys", "remote",
    }  # fmt: skip
    assert record["remote"] == "127.0.0.1"


async def test_an_upstream_that_cannot_start_fails_without_revealing_how_it_is_launched(tmp_path):
    path = await prepare(tmp_path)  # lock the real definitions first
    raw = base_config()
    raw["connections"][0]["command"] = ["/nonexistent/dir/secret-binary-name", "--password=hunter2-in-argv"]
    write_config(tmp_path, raw)
    async with running_gateway(path) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            result = await a.call_tool("a_whoami", {})
            assert result.is_error
            message = text_of(result)
            assert message == "The upstream service is currently unavailable."
        # The failure of one account's upstream does not touch another's.
        async with agent(gw.url, TOKEN_B) as b:
            assert "account=person_b" in text_of(await b.call_tool("b_whoami", {}))
        audit = gw.audit_text()
        assert "hunter2" not in audit and "secret-binary-name" not in audit
        assert any(e.get("reason") == "upstream_unavailable" for e in gw.audit())


async def test_oversized_results_are_refused_not_truncated(tmp_path):
    raw = base_config()
    raw["server"] = {"max_result_bytes": 2000}
    raw["connections"][0]["env"]["DEMO_PADDING"] = "x" * 5000
    async with running_gateway(await prepare(tmp_path, raw)) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            result = await a.call_tool("a_debug_dump", {})
            assert result.is_error and "too large" in text_of(result)
            assert not (await a.call_tool("a_whoami", {})).is_error


# -- the secret store ---------------------------------------------------------------


def test_secret_store_round_trip_and_ciphertext(tmp_path):
    key = tmp_path / "k" / "master.key"
    EncryptedFileStore.create_key(key)
    assert (key.stat().st_mode & 0o777) == 0o600
    store = EncryptedFileStore(tmp_path / "secrets.enc", key)
    store.set("imap_password", "correct horse battery staple")
    store.set("other", "second-value-123")
    assert store.names() == ["imap_password", "other"]
    assert EncryptedFileStore(tmp_path / "secrets.enc", key).get("imap_password") == "correct horse battery staple"
    on_disk = (tmp_path / "secrets.enc").read_bytes()
    assert b"correct horse" not in on_disk and b"imap_password" not in on_disk
    assert ((tmp_path / "secrets.enc").stat().st_mode & 0o777) == 0o600
    store.delete("other")
    assert store.names() == ["imap_password"]
    with pytest.raises(SecretStoreError):
        store.get("other")
    with pytest.raises(SecretStoreError):
        store.set("empty", "")


def test_secret_store_refuses_wrong_key_loose_permissions_and_key_overwrite(tmp_path):
    key = tmp_path / "master.key"
    EncryptedFileStore.create_key(key)
    EncryptedFileStore(tmp_path / "secrets.enc", key).set("name", "value-123456")

    other = tmp_path / "other.key"
    EncryptedFileStore.create_key(other)
    with pytest.raises(SecretStoreError) as wrong:
        EncryptedFileStore(tmp_path / "secrets.enc", other).get("name")
    assert "value-123456" not in str(wrong.value)

    with pytest.raises(FileExistsError):
        EncryptedFileStore.create_key(key)

    os.chmod(key, 0o644)
    with pytest.raises(SecretStoreError):
        EncryptedFileStore(tmp_path / "secrets.enc", key)


def test_scrubber_reaches_into_structures():
    scrub = Scrubber(["super-secret-token", "short"])
    data = {"a": ["x super-secret-token y", {"super-secret-token": 1}], "n": 5}
    assert json.dumps(scrub.data(data)).count("super-secret-token") == 0
    assert scrub.text("short stays: too short to be a credential") .startswith("short")


def test_secrets_given_on_the_command_line_are_not_supported(tmp_path, monkeypatch, capsys):
    """`agw secret set` reads the value from stdin, never from argv."""
    import io

    from agent_gateway.cli import main

    path = write_config(tmp_path, base_config(), secrets={})
    monkeypatch.setattr(sys, "stdin", io.StringIO("typed-in-value-98765\n"))
    assert main(["secret", "-c", str(path), "set", "notes_key_a"]) == 0
    assert "typed-in-value-98765" not in capsys.readouterr().out
    assert EncryptedFileStore(tmp_path / "secrets.enc", tmp_path / "master.key").get("notes_key_a") == "typed-in-value-98765"
    with pytest.raises(SystemExit):
        main(["secret", "-c", str(path), "set", "notes_key_a", "value-on-argv"])
