"""Passkey approval, end to end: a real gateway, a real connector, a software passkey.

The passkey is simulated (see passkey_helpers.py); everything that checks it is
production code. What is NOT covered here: a real browser and a real
authenticator talking to the page (approve.js) over https.
"""

from __future__ import annotations

import json
import sqlite3

import anyio
import httpx2
import pytest
from helpers import TOKEN_A, TOKEN_B, TOKEN_HOUSE, agent, prepare, running_gateway, text_of, write_config
from passkey_helpers import ORIGIN, TOKEN_A2, Authenticator, Page, approval_config, request_id_in

from agent_gateway import passkey
from agent_gateway.approval import NOT_EXECUTED
from agent_gateway.cli import main as agw
from agent_gateway.config import ConfigError, load_config

pytestmark = pytest.mark.anyio

NOTE = {"folder": "family", "text": "buy milk"}


async def notes(client, folder="family") -> str:
    return text_of(await client.call_tool("a_list_notes", {"folder": folder}))


async def test_a_call_runs_once_after_its_owner_approves_it(tmp_path):
    async with running_gateway(await prepare(tmp_path, approval_config())) as gw:
        page = Page(gw.base)
        key_a = await page.enroll(gw.gateway, "person_a")
        async with agent(gw.url, TOKEN_A) as a:
            first = await a.call_tool("a_add_note", NOTE)
            assert first.is_error and text_of(first).startswith(NOT_EXECUTED)
            assert "person_a" in text_of(first) and "same arguments" in text_of(first)
            request_id = request_id_in(text_of(first))
            assert f"{ORIGIN}/approvals/r/{request_id}" in text_of(first)
            # Asking again does not create a second request and does not run anything.
            again = await a.call_tool("a_add_note", NOTE)
            assert again.is_error and request_id_in(text_of(again)) == request_id
            assert "buy milk" not in await notes(a)

            # What the person deciding sees: who asks, which account, the exact content.
            status, shown = await page.view(request_id)
            assert status == 200 and shown["status"] == "pending"
            assert (shown["client"], shown["principal"]) == ("agent-a", "person_a")
            assert (shown["service"], shown["account"], shown["owner"]) == ("notes", "person_a", "person_a")
            assert (shown["tool"], shown["upstream_tool"]) == ("a_add_note", "add_note")
            assert shown["arguments"] == NOTE and shown["approvers"] == ["person_a"]

            status, result = await page.decide("approve", request_id, key_a)
            assert status == 200 and result["request"]["status"] == "approved"
            assert result["request"]["decided_by"] == "person_a"

            assert text_of(await a.call_tool("a_add_note", NOTE)) == "added"
            # The approval is spent: the same call again is a new request for a new decision.
            replay = await a.call_tool("a_add_note", NOTE)
            assert replay.is_error and request_id_in(text_of(replay)) != request_id
            assert (await notes(a)).count("buy milk") == 1

        status, shown = await page.view(request_id)
        assert (shown["status"], shown["outcome"], shown["arguments"]) == ("used", "ok", None)  # content erased after use

        events = [(e["event"], e.get("decision"), e.get("reason")) for e in gw.audit() if e.get("approval") == request_id]
        assert events == [
            ("approval_requested", None, None),
            ("tool_call", "deny", "approval:requested"),
            ("tool_call", "deny", "approval:pending"),
            ("approval_decided", "approve", None),
            ("tool_call", "allow", "approved"),
        ]
        decided = next(e for e in gw.audit() if e["event"] == "approval_decided")
        assert (decided["approver"], decided["tool"], decided["account"]) == ("person_a", "a_add_note", "person_a")
        assert "buy milk" not in gw.audit_text()  # the audit log never holds argument values


async def test_an_approval_is_only_for_the_exact_arguments_and_the_client_that_asked(tmp_path):
    async with running_gateway(await prepare(tmp_path, approval_config())) as gw:
        page = Page(gw.base)
        key_a = await page.enroll(gw.gateway, "person_a")
        async with agent(gw.url, TOKEN_A) as a, agent(gw.url, TOKEN_A2) as a2:
            request_id = request_id_in(text_of(await a.call_tool("a_add_note", NOTE)))
            assert (await page.decide("approve", request_id, key_a))[0] == 200

            for changed in (
                {"folder": "family", "text": "buy milk and wire $5000"},
                {"folder": "inbox", "text": "buy milk"},
                {"folder": "family", "text": "buy milk "},
            ):
                other = await a.call_tool("a_add_note", changed)
                assert other.is_error and request_id_in(text_of(other)) != request_id
            # Another client of the same person cannot spend it either.
            other = await a2.call_tool("a_add_note", NOTE)
            assert other.is_error and request_id_in(text_of(other)) != request_id
            assert "buy milk" not in await notes(a)

            assert text_of(await a.call_tool("a_add_note", NOTE)) == "added"  # still there for the call it was for
            assert (await notes(a)).count("buy milk") == 1 and "wire" not in await notes(a)


async def test_only_the_account_owner_can_decide_and_only_with_user_verification(tmp_path):
    async with running_gateway(await prepare(tmp_path, approval_config())) as gw:
        page = Page(gw.base)
        key_a = await page.enroll(gw.gateway, "person_a")
        key_b = await page.enroll(gw.gateway, "person_b")
        stranger = Authenticator()
        async with agent(gw.url, TOKEN_A) as a:
            request_id = request_id_in(text_of(await a.call_tool("a_add_note", NOTE)))

            status, ceremony = await page.begin("approve", request_id)
            offered = {c["id"] for c in ceremony["options"]["publicKey"]["allowCredentials"]}
            assert len(offered) == 1  # only person_a's passkey is even asked for
            # person_b's passkey, an unknown passkey, the wrong website, no user verification: all refused.
            for authenticator, how in (
                (key_b, {}),
                (stranger, {}),
                (key_a, {"origin": "https://evil.example"}),
                (key_a, {"verified": False}),
            ):
                status, result = await page.decide("approve", request_id, authenticator, **how)
                assert (status, result) == (403, {"error": "verification_failed"})
            assert (await page.view(request_id))[1]["status"] == "pending"
            assert (await a.call_tool("a_add_note", NOTE)).is_error
            assert "buy milk" not in await notes(a)

            assert (await page.decide("approve", request_id, key_a))[0] == 200
            assert text_of(await a.call_tool("a_add_note", NOTE)) == "added"


async def test_either_person_can_decide_for_a_shared_account(tmp_path):
    async with running_gateway(await prepare(tmp_path, approval_config())) as gw:
        page = Page(gw.base)
        await page.enroll(gw.gateway, "person_a")
        key_b = await page.enroll(gw.gateway, "person_b")
        async with agent(gw.url, TOKEN_HOUSE) as shared:
            asked = await shared.call_tool("house_add_note", NOTE)
            request_id = request_id_in(text_of(asked))
            assert "person_a or person_b" in text_of(asked)
            assert (await page.view(request_id))[1]["approvers"] == ["person_a", "person_b"]
            status, result = await page.decide("approve", request_id, key_b)
            assert status == 200 and result["request"]["decided_by"] == "person_b"
            assert text_of(await shared.call_tool("house_add_note", NOTE)) == "added"
        async with agent(gw.url, TOKEN_B) as b:
            # Same tool and arguments from another client: its own request, not the spent one.
            assert request_id_in(text_of(await b.call_tool("house_add_note", NOTE))) != request_id


async def test_declined_and_withdrawn_requests_never_run(tmp_path):
    async with running_gateway(await prepare(tmp_path, approval_config())) as gw:
        page = Page(gw.base)
        key_a = await page.enroll(gw.gateway, "person_a")
        async with agent(gw.url, TOKEN_A) as a:
            declined = request_id_in(text_of(await a.call_tool("a_add_note", NOTE)))
            status, result = await page.decide("deny", declined, key_a)
            assert status == 200 and result["request"]["status"] == "denied" and result["request"]["arguments"] is None
            told = await a.call_tool("a_add_note", NOTE)
            assert told.is_error and "declined" in text_of(told) and "/approvals/" not in text_of(told)
            assert (await page.decide("approve", declined, key_a)) == (403, {"error": "stale_request"})

            # Approved, then withdrawn with a passkey before the agent used it.
            other = {"folder": "family", "text": "second thoughts"}
            withdrawn = request_id_in(text_of(await a.call_tool("a_add_note", other)))
            assert (await page.decide("approve", withdrawn, key_a))[0] == 200
            status, result = await page.decide("cancel", withdrawn, key_a)
            assert status == 200 and result["request"]["status"] == "cancelled"
            after = await a.call_tool("a_add_note", other)
            assert after.is_error and request_id_in(text_of(after)) != withdrawn

            listing = await notes(a)
            assert "buy milk" not in listing and "second thoughts" not in listing
        decisions = [e["decision"] for e in gw.audit() if e["event"] == "approval_decided"]
        assert decisions == ["deny", "approve", "cancel"]


async def test_requests_and_approvals_expire(tmp_path, monkeypatch):
    clock = [1_800_000_000]
    monkeypatch.setattr(passkey, "_now", lambda: clock[0])
    raw = approval_config(request_ttl_seconds=600, grant_ttl_seconds=120)
    async with running_gateway(await prepare(tmp_path, raw)) as gw:
        page = Page(gw.base)
        key_a = await page.enroll(gw.gateway, "person_a")
        async with agent(gw.url, TOKEN_A) as a:
            # Nobody decided in time.
            stale = request_id_in(text_of(await a.call_tool("a_add_note", NOTE)))
            clock[0] += 601
            assert (await page.decide("approve", stale, key_a)) == (403, {"error": "stale_request"})
            assert (await page.view(stale))[1]["status"] == "expired"

            # Approved, but the agent came back too late.
            late = request_id_in(text_of(await a.call_tool("a_add_note", NOTE)))
            assert late != stale
            assert (await page.decide("approve", late, key_a))[0] == 200
            clock[0] += 121
            after = await a.call_tool("a_add_note", NOTE)
            assert after.is_error and request_id_in(text_of(after)) not in (stale, late)
            assert (await page.view(late))[1]["status"] == "expired"

            # A passkey prompt left open for too long is worthless.
            fresh = request_id_in(text_of(after))
            status, ceremony = await page.begin("approve", fresh)
            clock[0] += 121
            assert (await page.finish(ceremony, key_a.response(ceremony))) == (403, {"error": "expired_ceremony"})
            assert "buy milk" not in await notes(a)


async def test_a_passkey_answer_cannot_be_replayed_or_moved_to_another_request(tmp_path):
    async with running_gateway(await prepare(tmp_path, approval_config())) as gw:
        page = Page(gw.base)
        key_a = await page.enroll(gw.gateway, "person_a")
        async with agent(gw.url, TOKEN_A) as a:
            small = request_id_in(text_of(await a.call_tool("a_add_note", NOTE)))
            big = request_id_in(text_of(await a.call_tool("a_add_note", {"folder": "family", "text": "wire $5000"})))

            status, ceremony = await page.begin("approve", small)
            answer = key_a.response(ceremony)
            assert (await page.finish(ceremony, answer))[0] == 200
            # The same answer again, for the same ceremony: gone.
            assert (await page.finish(ceremony, answer)) == (403, {"error": "expired_ceremony"})
            # The same answer presented for the other request's ceremony: wrong challenge.
            status, other = await page.begin("approve", big)
            assert (await page.finish(other, answer)) == (403, {"error": "verification_failed"})
            assert (await page.view(big))[1]["status"] == "pending"

            # A cloned authenticator shows itself by a signature counter that does not advance.
            key_a.counter -= 2
            assert (await page.decide("approve", big, key_a)) == (403, {"error": "verification_failed"})

            assert text_of(await a.call_tool("a_add_note", NOTE)) == "added"
            assert "wire" not in await notes(a)


async def test_a_decision_is_void_if_the_request_changed_while_the_prompt_was_open(tmp_path):
    async with running_gateway(await prepare(tmp_path, approval_config())) as gw:
        page = Page(gw.base)
        key_a = await page.enroll(gw.gateway, "person_a")
        async with agent(gw.url, TOKEN_A) as a:
            request_id = request_id_in(text_of(await a.call_tool("a_add_note", NOTE)))
            status, ceremony = await page.begin("approve", request_id)
            # Someone with access to the host rewrites the stored request before the passkey answers.
            db = sqlite3.connect(gw.cfg.approvals.store)
            db.execute("UPDATE requests SET arguments=? WHERE id=?", (json.dumps({"folder": "family", "text": "wire $5000"}), request_id))
            db.commit()
            db.close()
            assert (await page.finish(ceremony, key_a.response(ceremony))) == (403, {"error": "stale_request"})
            assert (await page.view(request_id))[1]["status"] == "pending"

            # The same, but the attacker also swaps the stored challenge state for one that was
            # issued for the original content: what is signed no longer matches what is stored.
            status, ceremony = await page.begin("approve", request_id)  # issued for "wire $5000"
            db = sqlite3.connect(gw.cfg.approvals.store)
            db.execute("UPDATE requests SET arguments=? WHERE id=?", (json.dumps(NOTE), request_id))
            db.commit()
            db.close()
            assert (await page.finish(ceremony, key_a.response(ceremony))) == (403, {"error": "stale_request"})

            # Opening prompt after prompt for one request only closes that request's older prompts.
            ceremonies = [(await page.begin("approve", request_id))[1] for _ in range(5)]
            assert (await page.finish(ceremonies[0], key_a.response(ceremonies[0]))) == (403, {"error": "expired_ceremony"})
            assert (await page.finish(ceremonies[1], key_a.response(ceremonies[1]))) == (403, {"error": "expired_ceremony"})

            gw.gateway.approver.cancel(request_id)  # what `agw approval cancel` does
            assert (await page.decide("approve", request_id, key_a)) == (403, {"error": "stale_request"})
            assert "milk" not in await notes(a) and "wire" not in await notes(a)


async def test_two_simultaneous_calls_cannot_both_spend_one_approval(tmp_path):
    async with running_gateway(await prepare(tmp_path, approval_config())) as gw:
        page = Page(gw.base)
        key_a = await page.enroll(gw.gateway, "person_a")
        async with agent(gw.url, TOKEN_A) as a:
            request_id = request_id_in(text_of(await a.call_tool("a_add_note", NOTE)))
            assert (await page.decide("approve", request_id, key_a))[0] == 200
            results = []

            async def call() -> None:
                async with agent(gw.url, TOKEN_A) as client:
                    results.append(await client.call_tool("a_add_note", NOTE))

            async with anyio.create_task_group() as tg:
                for _ in range(6):
                    tg.start_soon(call)
            assert sorted(bool(r.is_error) for r in results) == [False, True, True, True, True, True]
            assert (await notes(a)).count("buy milk") == 1


async def test_an_approval_is_spent_even_when_the_upstream_fails(tmp_path):
    raw = approval_config()
    raw["policy"][0]["tools"].remove("a_crash")
    raw["policy"].append({"principals": ["person_a"], "connection": "notes-a", "tools": ["a_crash"], "effect": "approval_required"})
    async with running_gateway(await prepare(tmp_path, raw)) as gw:
        page = Page(gw.base)
        key_a = await page.enroll(gw.gateway, "person_a")
        async with agent(gw.url, TOKEN_A) as a:
            request_id = request_id_in(text_of(await a.call_tool("a_crash", {})))
            assert (await page.decide("approve", request_id, key_a))[0] == 200
            failed = await a.call_tool("a_crash", {})
            assert failed.is_error and text_of(failed) == "The upstream service is currently unavailable."
            status, shown = await page.view(request_id)
            assert (shown["status"], shown["outcome"]) == ("used", "upstream_unavailable")
            # No automatic retry of something that may have happened: it needs a new decision.
            await gw.connected("notes-a")
            again = await a.call_tool("a_crash", {})
            assert again.is_error and request_id_in(text_of(again)) != request_id


async def test_nothing_waits_when_nobody_could_decide_and_requests_are_bounded(tmp_path):
    async with running_gateway(await prepare(tmp_path, approval_config())) as gw:
        page = Page(gw.base)
        async with agent(gw.url, TOKEN_A) as a:
            # No passkey registered for person_a: the tool behaves as if there were no approval page.
            nobody = await a.call_tool("a_add_note", NOTE)
            assert nobody.is_error and text_of(nobody) == NOT_EXECUTED
            assert gw.gateway.approver.requests() == []

            await page.enroll(gw.gateway, "person_a")
            ids = {request_id_in(text_of(await a.call_tool("a_add_note", {"folder": "family", "text": f"n{i}"}))) for i in range(5)}
            assert len(ids) == 5
            flood = await a.call_tool("a_add_note", {"folder": "family", "text": "one too many"})
            assert flood.is_error and "/approvals/" not in text_of(flood) and "Too many" in text_of(flood)
            assert len(gw.gateway.approver.requests()) == 5
        reasons = {e["reason"] for e in gw.audit() if e["event"] == "tool_call"}
        assert {"approval:no_approver_enrolled", "approval:requested", "approval:too_many_pending"} <= reasons


async def test_enrollment_links_work_once_and_only_from_the_approval_page(tmp_path):
    async with running_gateway(await prepare(tmp_path, approval_config())) as gw:
        page = Page(gw.base)
        code = gw.gateway.approver.new_enrollment("person_a").split("#", 1)[1]
        assert (await page.begin("enroll", "not-a-code")) == (403, {"error": "invalid_enrollment_code"})

        # Posts that do not come from the page itself are refused before anything is looked at.
        for origin in ("https://evil.example", "http://localhost:9999", "null"):
            assert (await Page(gw.base, origin).begin("enroll", code)) == (403, {"error": "wrong_origin"})
        async with httpx2.AsyncClient(base_url=gw.base) as http:
            no_origin = await http.post("/approvals/api/begin", json={"action": "enroll", "target": code})
            assert no_origin.status_code == 403
            form = await http.post("/approvals/api/begin", data={"action": "enroll"}, headers={"Origin": ORIGIN})
            assert form.status_code == 400
            assert (await http.get("/approvals/api/begin")).status_code == 405

        first = Authenticator()
        status, ceremony = await page.begin("enroll", code)
        second_status, second = await page.begin("enroll", code)  # two prompts open on the same link
        assert (await page.finish(ceremony, first.response(ceremony)))[0] == 200
        late = Authenticator()
        assert (await page.finish(second, late.response(second))) == (403, {"error": "invalid_enrollment_code"})
        assert (await page.begin("enroll", code)) == (403, {"error": "invalid_enrollment_code"})

        keys = gw.gateway.approver.passkeys()
        assert [k["principal"] for k in keys] == ["person_a"] and keys[0]["id"] == first.id.hex()
        assert any(e["event"] == "passkey_enrolled" and e["approver"] == "person_a" for e in gw.audit())
        assert code not in gw.audit_text()


async def test_the_page_is_static_and_treats_agent_text_as_text(tmp_path):
    hostile = {"folder": "family", "text": "<img src=x onerror=alert(1)><script>fetch('/approvals/api/begin')</script>"}
    async with running_gateway(await prepare(tmp_path, approval_config())) as gw:
        page = Page(gw.base)
        await page.enroll(gw.gateway, "person_a")
        async with agent(gw.url, TOKEN_A) as a:
            request_id = request_id_in(text_of(await a.call_tool("a_add_note", hostile)))
        async with httpx2.AsyncClient(base_url=gw.base) as http:
            shell = await http.get(f"/approvals/r/{request_id}")
            assert shell.status_code == 200 and shell.headers["content-type"].startswith("text/html")
            assert shell.text == (await http.get("/approvals/enroll")).text  # one fixed page; nothing is rendered into it
            assert "onerror" not in shell.text and request_id not in shell.text
            csp = shell.headers["content-security-policy"]
            assert "default-src 'none'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
            assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
            data = await http.get(f"/approvals/api/request/{request_id}")
            assert data.headers["content-type"] == "application/json" and data.headers["x-content-type-options"] == "nosniff"
            assert data.json()["arguments"] == hostile
            script = (await http.get("/approvals/approve.js")).text
            for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
                assert sink not in script
            assert (await http.get("/approvals/api/request/does-not-exist")).status_code == 404
            for path in ("/approvals", "/approvals/", "/approvals/api/requests", "/approvals/r", "/approvals/static/../passkey.py"):
                assert (await http.get(path)).status_code == 404, path


async def test_without_an_approvals_section_there_is_no_page(tmp_path):
    async with running_gateway(await prepare(tmp_path)) as gw:
        async with httpx2.AsyncClient(base_url=gw.base) as http:
            for path in ("/approvals/enroll", "/approvals/r/abc", "/approvals/approve.js", "/approvals/api/request/abc"):
                assert (await http.get(path)).status_code == 404, path
            assert (await http.post("/approvals/api/begin", json={}, headers={"Origin": ORIGIN})).status_code == 404


def test_the_approvals_section_cannot_approve_anything_by_itself(tmp_path):
    good = approval_config()
    assert load_config(write_config(tmp_path / "ok", good)).approvals.rp_id == "localhost"
    for index, extra in enumerate(
        (
            {"auto_approve": True},
            {"mode": "auto"},
            {"approver": "allow_all"},
            {"trusted_clients": ["agent-a"]},
            {"origin": "http://gateway.example.ts.net"},  # passkeys need https
            {"origin": "https://gateway.example.ts.net/approvals"},
            {"origin": "gateway.example.ts.net"},
            {"request_ttl_seconds": 0},
            {"grant_ttl_seconds": 86_400},
        )
    ):
        with pytest.raises(ConfigError):
            load_config(write_config(tmp_path / str(index), approval_config(**extra)))


async def test_admin_commands(tmp_path, capsys):
    path = await prepare(tmp_path, approval_config())
    config = ["-c", str(path)]
    assert agw(["approval", *config, "enroll", "household"]) == 2  # a shared identity is not a person
    assert agw(["approval", *config, "enroll", "nobody"]) == 2
    capsys.readouterr()
    assert agw(["approval", *config, "enroll", "person_a"]) == 0
    link = next(line.strip() for line in capsys.readouterr().out.splitlines() if "/approvals/enroll#" in line)
    assert link.startswith(f"{ORIGIN}/approvals/enroll#")

    async with running_gateway(path) as gw:
        page = Page(gw.base)
        key_a = Authenticator()
        assert (await page.decide("enroll", link.split("#", 1)[1], key_a))[0] == 200
        async with agent(gw.url, TOKEN_A) as a:
            request_id = request_id_in(text_of(await a.call_tool("a_add_note", NOTE)))

            assert agw(["approval", *config, "passkeys"]) == 0
            assert key_a.id.hex()[:16] in capsys.readouterr().out
            assert agw(["approval", *config, "requests"]) == 0
            listed = capsys.readouterr().out
            assert request_id in listed and "pending" in listed and "buy milk" not in listed
            assert agw(["approval", *config, "cancel", request_id]) == 0
            assert agw(["approval", *config, "cancel", request_id]) == 2
            assert (await page.decide("approve", request_id, key_a)) == (403, {"error": "stale_request"})

            assert agw(["approval", *config, "forget", key_a.id.hex()[:16]]) == 0
            assert agw(["approval", *config, "forget", key_a.id.hex()[:16]]) == 2
            # With the passkey gone nobody can decide, so nothing waits.
            assert text_of(await a.call_tool("a_add_note", NOTE)) == NOT_EXECUTED

    assert agw(["check", *config]) == 0
    assert "each call needs a passkey approval by person_a" in capsys.readouterr().out
