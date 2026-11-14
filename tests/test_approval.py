"""`approval_required` in the gateway core: the default refuses, and the hook is narrow.

Without an `approvals:` section nothing that needs approval ever runs. The
hook itself is tested with a test double: it is asked on every call, with the
caller's identity and the exact arguments. The real approver (passkeys) is
tested in test_passkey.py.
"""

from __future__ import annotations

import pytest
from helpers import TOKEN_A, TOKEN_B, agent, base_config, prepare, running_gateway, text_of, tool_names, write_config
from mcp import MCPError

from agent_gateway.approval import ApprovalDecision, ApprovalRequest, arguments_digest
from agent_gateway.config import ConfigError, load_config

pytestmark = pytest.mark.anyio

NOT_EXECUTED = "This action needs human approval and was not executed."


async def test_approval_required_tools_never_run_without_an_approval_channel(tmp_path):
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            assert "a_add_note" in await tool_names(a)  # visible, so the agent can explain what it would do
            for _ in range(3):  # asking again changes nothing
                result = await a.call_tool("a_add_note", {"folder": "family", "text": "written-without-approval"})
                assert result.is_error and text_of(result) == NOT_EXECUTED
            # The model cannot approve its own call.
            for claim in ({"approved": True}, {"approval_id": "abc"}, {"confirm": "yes"}, {"_approved_by": "person_a"}):
                result = await a.call_tool("a_add_note", {"folder": "family", "text": "written-without-approval", **claim})
                assert result.is_error
            # Nothing reached the upstream.
            assert "written-without-approval" not in text_of(await a.call_tool("a_list_notes", {"folder": "family"}))
        # ...and it is still not person_b's tool at all.
        async with agent(gw.url, TOKEN_B) as b:
            with pytest.raises(MCPError):
                await b.call_tool("a_add_note", {"folder": "family", "text": "x"})
        attempts = [e for e in gw.audit() if e.get("tool") == "a_add_note" and e["principal"] == "person_a"]
        assert {e["decision"] for e in attempts} == {"deny"}
        assert {e["reason"] for e in attempts} == {"approval:no_approval_channel", "invalid_arguments"}


class OneShotApprover:
    """Test double: approves one exact argument digest, once."""

    def __init__(self, digest: str) -> None:
        self.digest = digest
        self.used = False
        self.requests: list[ApprovalRequest] = []

    async def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        self.requests.append(request)
        if request.arguments_sha256 != self.digest:
            return ApprovalDecision(False, "arguments_differ")
        if self.used:
            return ApprovalDecision(False, "already_used")
        self.used = True
        return ApprovalDecision(True, "test")

    async def finished(self, approval_id: str, outcome: str) -> None:
        raise AssertionError("no approval id was given, so there is nothing to report on")


async def test_the_hook_binds_a_decision_to_caller_and_exact_arguments(tmp_path):
    approved = {"folder": "family", "text": "buy milk"}
    approver = OneShotApprover(arguments_digest(approved))
    async with running_gateway(await prepare(tmp_path), approver=approver) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            # Same tool, different arguments: not what was approved.
            changed = await a.call_tool("a_add_note", {"folder": "family", "text": "buy milk and wire $5000"})
            assert changed.is_error and text_of(changed) == NOT_EXECUTED
            other_folder = await a.call_tool("a_add_note", {"folder": "inbox", "text": "buy milk"})
            assert other_folder.is_error

            assert text_of(await a.call_tool("a_add_note", approved)) == "added"
            # Replay: the gateway asks again on every call and keeps no approval of its own.
            replay = await a.call_tool("a_add_note", approved)
            assert replay.is_error and text_of(replay) == NOT_EXECUTED

            notes = text_of(await a.call_tool("a_list_notes", {"folder": "family"}))
            assert notes.count("buy milk") == 1 and "wire" not in notes

        assert len(approver.requests) == 4
        assert len({r.id for r in approver.requests}) == 4
        for request in approver.requests:
            # Who is asking comes from the token, like everything else.
            assert (request.principal, request.client_id) == ("person_a", "agent-a")
            assert (request.connection, request.account, request.upstream_tool) == ("notes-a", "person_a", "add_note")
            assert request.expires_at > request.created_at
        reasons = [e["reason"] for e in gw.audit() if e.get("tool") == "a_add_note"]
        assert reasons == ["approval:arguments_differ", "approval:arguments_differ", "approved", "approval:already_used"]


async def test_arguments_are_checked_before_anyone_is_asked_to_approve(tmp_path):
    approver = OneShotApprover("never-matches")
    async with running_gateway(await prepare(tmp_path), approver=approver) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            assert (await a.call_tool("a_add_note", {"folder": "family"})).is_error  # `text` missing
            assert (await a.call_tool("a_add_note", {"folder": "family", "text": "x", "extra": 1})).is_error
    assert approver.requests == []


def test_digest_is_stable_and_sensitive():
    assert arguments_digest({"a": 1, "b": [1, 2]}) == arguments_digest({"b": [1, 2], "a": 1})
    assert arguments_digest({"a": 1}) != arguments_digest({"a": "1"})
    assert arguments_digest({"a": 1}) != arguments_digest({"a": 1, "b": None})
    assert arguments_digest({"to": "a@example.com"}) != arguments_digest({"to": "a@example.com "})


def test_no_configuration_turns_approval_off_or_picks_an_approver(tmp_path):
    for index, extra in enumerate(
        (
            {"approval": {"mode": "auto"}},
            {"approver": "allow_all"},
            {"auto_approve": True},
        )
    ):
        with pytest.raises(ConfigError):
            load_config(write_config(tmp_path / str(index), {**base_config(), **extra}))
    raw = base_config()
    raw["policy"][1]["effect"] = "approved"
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path / "effect", raw))
    raw = base_config()
    raw["policy"][1]["auto_approve"] = True
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path / "rule", raw))
