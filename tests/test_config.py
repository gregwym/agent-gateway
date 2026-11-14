"""Configuration: a typo must fail loudly, never widen access."""

from __future__ import annotations

import copy

import pytest
from helpers import TOKEN_A, base_config, prepare, write_config

from agent_gateway.auth import hash_token
from agent_gateway.cli import main
from agent_gateway.config import ConfigError, load_config
from agent_gateway.policy import Policy

pytestmark = pytest.mark.anyio


def rejected(tmp_path, change) -> str:
    raw = base_config()
    change(raw)
    rejected.count = getattr(rejected, "count", 0) + 1
    with pytest.raises(ConfigError) as error:
        load_config(write_config(tmp_path / f"case{rejected.count}", raw))
    return str(error.value)


def test_unknown_keys_are_rejected_everywhere(tmp_path):
    rejected(tmp_path, lambda raw: raw.update(admin_api=True))
    rejected(tmp_path, lambda raw: raw["connections"][0].update(passthrough=True))
    rejected(tmp_path, lambda raw: raw["connections"][0]["tools"][0].update(alow_values={"folder": ["family"]}))
    rejected(tmp_path, lambda raw: raw["policy"][0].update(tool="a_whoami"))
    rejected(tmp_path, lambda raw: raw["clients"][0].update(admin=True))
    rejected(tmp_path, lambda raw: raw["server"].update(debug=True) if "server" in raw else raw.update(server={"debug": True}))


def test_there_are_no_wildcards(tmp_path):
    assert "is not a tool of connection" in rejected(tmp_path, lambda raw: raw["policy"][0].update(tools=["*"]))
    assert "is not a tool of connection" in rejected(tmp_path, lambda raw: raw["policy"][0].update(tools=["a_*"]))
    assert "unknown principal" in rejected(tmp_path, lambda raw: raw["policy"][0].update(principals=["*"]))
    assert "unknown connection" in rejected(tmp_path, lambda raw: raw["policy"][0].update(connection="*"))
    rejected(tmp_path, lambda raw: raw["policy"][0].update(tools=[]))
    rejected(tmp_path, lambda raw: raw["policy"][0].update(principals=[]))


def test_references_must_resolve(tmp_path):
    assert "unknown principal" in rejected(tmp_path, lambda raw: raw["clients"][0].update(principal="person_c"))
    assert "unknown owner" in rejected(tmp_path, lambda raw: raw["connections"][0].update(owner="person_c"))
    assert "unknown principal" in rejected(tmp_path, lambda raw: raw.update(shared=["everyone"]))
    # person_b's tool listed under person_a's connection: caught, not silently granted.
    message = rejected(tmp_path, lambda raw: raw["policy"][0].update(tools=["b_list_notes"]))
    assert "is not a tool of connection notes-a" in message


def test_one_token_cannot_be_two_identities(tmp_path):
    def same_token(raw):
        raw["clients"][1]["token_sha256"] = raw["clients"][0]["token_sha256"]

    message = rejected(tmp_path, same_token)
    assert "duplicate client token" in message and hash_token(TOKEN_A) not in message
    rejected(tmp_path, lambda raw: raw["clients"][0].update(token_sha256=TOKEN_A))  # a raw token is not a hash
    rejected(tmp_path, lambda raw: raw["clients"][1].update(id="agent-a"))


def test_granting_another_persons_account_needs_an_explicit_flag(tmp_path):
    def grant_b_access_to_a(raw):
        raw["policy"].append(
            {"principals": ["person_b"], "connection": "notes-a", "tools": ["a_list_notes"], "effect": "allow"}
        )

    assert "set cross_account: true" in rejected(tmp_path, grant_b_access_to_a)

    def add_b_to_a_rule(raw):  # the copy-paste version of the same mistake
        raw["policy"][0]["principals"].append("person_b")

    assert "set cross_account: true" in rejected(tmp_path, add_b_to_a_rule)

    explicit = base_config()
    grant_b_access_to_a(explicit)
    explicit["policy"][-1]["cross_account"] = True
    policy = Policy(load_config(write_config(tmp_path / "explicit", explicit)))
    assert policy.effect("person_b", "a_list_notes") == "allow"
    assert policy.effect("person_b", "a_get_note") == "deny"  # only what was named

    # Denying needs no flag, and the household account is declared shared, so no flag there either.
    denied = base_config()
    denied["policy"].append(
        {"principals": ["person_b"], "connection": "notes-a", "tools": ["a_list_notes"], "effect": "deny"}
    )
    load_config(write_config(tmp_path / "denied", denied))


def test_policy_defaults_to_deny_and_the_strictest_rule_wins(tmp_path):
    raw = base_config()
    raw["policy"] += [
        {"principals": ["person_a"], "connection": "notes-a", "tools": ["a_get_note"], "effect": "deny"},
        {"principals": ["person_a"], "connection": "notes-a", "tools": ["a_whoami"], "effect": "approval_required"},
        {"principals": ["person_a"], "connection": "notes-a", "tools": ["a_add_note"], "effect": "allow"},
    ]
    policy = Policy(load_config(write_config(tmp_path, raw)))
    assert policy.effect("person_a", "a_list_notes") == "allow"
    assert policy.effect("person_a", "a_get_note") == "deny"  # allow + deny
    assert policy.effect("person_a", "a_whoami") == "approval_required"  # allow + approval_required
    assert policy.effect("person_a", "a_add_note") == "approval_required"  # a later allow does not loosen it
    assert policy.effect("person_a", "a_family_notes") == "deny"  # configured, granted to someone else only
    assert policy.effect("person_b", "a_list_notes") == "deny"
    assert policy.effect("person_a", "no_such_tool") == "deny"
    assert policy.effect("nobody", "a_list_notes") == "deny"

    empty = base_config()
    empty["policy"] = []
    nothing = Policy(load_config(write_config(tmp_path / "empty", empty)))
    assert all(
        nothing.effect(principal, tool["name"]) == "deny"
        for principal in empty["principals"]
        for conn in empty["connections"]
        for tool in conn["tools"]
    )


def test_tool_and_connection_shapes(tmp_path):
    def pin_and_allow(raw):
        raw["connections"][0]["tools"][-1]["allow_values"] = {"folder": ["family"]}

    assert "both pin and allow_values" in rejected(tmp_path, pin_and_allow)
    rejected(tmp_path, lambda raw: raw["connections"][2]["tools"][0].update(allow_values={"folder": []}))
    rejected(tmp_path, lambda raw: raw["connections"][0].update(url="https://example.com/mcp"))
    rejected(tmp_path, lambda raw: raw["connections"][0].update(command=[]))
    rejected(tmp_path, lambda raw: raw["connections"][0].update(transport="sse"))
    rejected(tmp_path, lambda raw: raw["connections"][0]["tools"][0].update(name="notes.list"))
    # Two connections for the same account of the same service would blur whose data a tool reads.
    rejected(tmp_path, lambda raw: raw["connections"][1].update(account="person_a"))
    # Secrets are referenced by name; without a store there is nowhere to read them from.
    assert "no `secrets:` store" in rejected(tmp_path, lambda raw: raw.pop("secrets"))


def test_errors_name_the_place_not_the_value(tmp_path):
    message = rejected(tmp_path, lambda raw: raw["connections"][0].update(password="hunter2-plaintext"))
    assert "connections.0.password" in message and "hunter2" not in message

    message = rejected(tmp_path, lambda raw: raw["connections"][0].update(secret_env={"DEMO_API_KEY": ["hunter2-plaintext"]}))
    assert "hunter2" not in message

    def url_with_password(raw):
        raw["connections"][0] = {
            "id": "notes-a", "service": "notes", "account": "person_a", "owner": "person_a", "transport": "http",
            "url": "https://admin:s3cr3t-in-url@example.com/mcp", "tools": raw["connections"][0]["tools"],
        }  # fmt: skip

    message = rejected(tmp_path, url_with_password)
    assert "secret store" in message and "s3cr3t" not in message


def test_paths_are_relative_to_the_config_file(tmp_path, monkeypatch):
    path = write_config(tmp_path / "etc", base_config())
    monkeypatch.chdir(tmp_path)
    cfg = load_config(path)
    assert cfg.audit.path == tmp_path / "etc" / "audit" / "audit.jsonl"
    assert cfg.secrets.key_file == tmp_path / "etc" / "master.key"
    assert cfg.lock_file == tmp_path / "etc" / "tools.lock.json"
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.yaml")
    (tmp_path / "list.yaml").write_text("- not\n- a mapping\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path / "list.yaml")


async def test_check_prints_the_access_table(tmp_path, capsys):
    path = await prepare(tmp_path)
    capsys.readouterr()
    assert main(["check", "-c", str(path)]) == 0
    out = capsys.readouterr().out
    assert "agent-a" in out and "-> person_a" in out
    household = out.split("\n  household\n", 1)[1]
    assert "a_family_notes" in household and "account of person_a" in household and "pinned: folder" in household
    assert "a_list_notes" not in household and "b_list_notes" not in household
    assert "approval_required" in out and "never runs: no `approvals:` section" in out
    assert "restricted: folder" in out and out.rstrip().endswith("OK")
    assert hash_token(TOKEN_A) not in out and "upstream-key" not in out


async def test_check_fails_when_tools_are_unlocked_or_secrets_missing(tmp_path, capsys):
    unlocked = await prepare(tmp_path / "unlocked", lock=False)
    assert main(["check", "-c", str(unlocked)]) == 1
    captured = capsys.readouterr()
    assert "NOT SERVED (not_locked)" in captured.out and "will not be served" in captured.err

    raw = copy.deepcopy(base_config())
    path = write_config(tmp_path / "nosecret", raw, secrets={"notes_key_a": "value-aaaaaaaa"})
    assert main(["check", "-c", str(path)]) == 1
    captured = capsys.readouterr()
    assert "secrets missing from the store: notes_key_b, notes_key_house" in captured.err
    assert "value-aaaaaaaa" not in captured.out + captured.err

    broken = tmp_path / "broken.yaml"
    broken.write_text("principals: [person_a]\n")
    assert main(["check", "-c", str(broken)]) == 2


def test_token_command_prints_a_token_and_its_hash(capsys):
    assert main(["token"]) == 0
    lines = [line.strip() for line in capsys.readouterr().out.splitlines()]
    token = next(line for line in lines if line.startswith("agw_"))
    assert len(token) > 40 and hash_token(token) in lines


@pytest.mark.parametrize("name", ["gateway.example.yaml", "gateway.household.example.yaml"])
def test_the_shipped_examples_are_rejected_as_they_are_and_valid_once_filled_in(tmp_path, name):
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "deploy" / name).read_text(encoding="utf-8")
    target = tmp_path / "config" / "gateway.yaml"
    target.parent.mkdir()
    target.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):  # placeholder token hashes
        load_config(target)
    for index in range(text.count("PASTE_HASH_FROM_agw_token")):
        text = text.replace("PASTE_HASH_FROM_agw_token", hash_token(f"agw_example-token-{index}-{'x' * 32}"), 1)
    target.write_text(text, encoding="utf-8")
    cfg = load_config(target)
    assert {client.principal for client in cfg.clients} == {"person_a", "person_b", "household"}
    policy, names = Policy(cfg), [tool.name for connection in cfg.connections for tool in connection.tools]
    reach = {who: {name for name in names if policy.effect(who, name) != "deny"} for who in cfg.principals}
    assert reach["household"] and reach["household"] < set(names)  # the shared agent gets something, never everything
    assert not any("_mail_" in name or "_gmail_" in name for name in reach["household"])
    assert not reach["person_a"] & {name for name in names if name.startswith("b_")}


def test_the_household_example_names_tools_the_connectors_really_have(tmp_path):
    """A wrong upstream name in the example would only show up at `agw lock`, on someone's real setup."""
    from pathlib import Path

    import yaml

    from agent_gateway.connectors import caldav_calendar, gmail, imap_mail, reminders_eventkit

    from types import SimpleNamespace
    from zoneinfo import ZoneInfo

    tools = {
        "agent_gateway.connectors.imap_mail": imap_mail.build_tools(None, 1, 1),
        "agent_gateway.connectors.caldav_calendar": caldav_calendar.build_tools(SimpleNamespace(zone=ZoneInfo("UTC"))),
        "agent_gateway.connectors.gmail": gmail.build_tools(None, 1, 1),
    }
    offered = {module: {tool.name: tool for tool in found} for module, found in tools.items()}
    raw = yaml.safe_load((Path(__file__).resolve().parent.parent / "deploy" / "gateway.household.example.yaml").read_text(encoding="utf-8"))
    assert len(raw["connections"]) == 6
    for connection in raw["connections"]:
        module = connection["command"][-1]
        assert connection["command"][:2] == ["python", "-m"] and module in offered, connection["id"]
        for tool in connection["tools"]:
            assert tool["upstream"] in offered[module], tool["name"]
            assert set(tool.get("pin", {})) <= set(offered[module][tool["upstream"]].properties), tool["name"]  # real arguments

    # The Reminders helper is a gateway of its own; what it exposes is what the main gateway's example asks it for.
    deploy = Path(__file__).resolve().parent.parent / "deploy"
    target = tmp_path / "gateway.yaml"
    helper_text = (deploy / "reminders-helper.example.yaml").read_text(encoding="utf-8")
    target.write_text(helper_text.replace("PASTE_HASH_FROM_agw_token", hash_token("agw_example-token-" + "x" * 32)), encoding="utf-8")
    helper = load_config(target)
    (connection,) = helper.connections
    assert connection.command == ["python", "-m", "agent_gateway.connectors.reminders_eventkit"]
    assert {tool.upstream for tool in connection.tools} == {t.name for t in reminders_eventkit.build_tools(None)}
    assert helper.secrets is None
    assert not connection.secret_env and [client.principal for client in helper.clients] == ["person_a"]
    lines = (deploy / "gateway.household.example.yaml").read_text(encoding="utf-8").splitlines()
    block = lines[lines.index("  # - id: reminders-a") :]
    block = block[: next(i for i, line in enumerate(block) if not line.startswith("  # "))]
    (main_side,) = yaml.safe_load("\n".join(line.replace("  # ", "", 1) for line in block))
    assert main_side["transport"] == "http" and main_side["bearer_secret"] == "reminders_helper_token_a"
    assert {tool["upstream"] for tool in main_side["tools"]} == {tool.name for tool in connection.tools}
