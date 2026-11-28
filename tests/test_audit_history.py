"""Read-only audit history through the actual administrator HTTP interface."""
import json

import pytest

from agent_gateway import audit_history
from helpers import TOKEN_A
from test_admin import setup, web_gateway

pytestmark = pytest.mark.anyio
API = "/admin/api/audit"


def record(instant, **overrides):
    return dict(
        ts=f"2026-11-{instant}:00.000+00:00", event="tool_call", client="agent-a",
        connection="notes-a", tool="a_list_notes", decision="allow",
    ) | overrides


async def test_audit_history_filters_rotated_rows_and_projects_only_safe_fields(tmp_path):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        assert (await http.get("/admin/audit")).status_code == 200
        assert (await http.post(API, json={})).status_code == 401
        assert (await http.post(API, json={}, headers={"Authorization": "Bearer " + TOKEN_A})).status_code == 401
        await setup(http, origin, path)
        assert (await http.get(API)).status_code == 404
        assert (await http.post(API, json={}, headers={"X-CSRF-Token": ""})).status_code == 403
        assert (await http.post(API, json={}, headers={"Origin": "https://example.test"})).status_code == 403
        assert (await http.post(API, json={}, headers={"Host": "example.test"})).status_code == 403
        assert (await http.post(API, json={"path": "other"})).status_code == 400
        audit = gw.cfg.audit.path
        rotated = audit.with_name(audit.name + ".2026-11-25")
        newest = record(
            "26T13:01", is_error=True, reason="secret-reason", approval="secret-approval",
            request_id="secret-request", remote="127.0.0.8", arguments="secret-arguments",
            account="private@example.test", detail="secret-detail", tool="secret_tool",
        )
        earlier = record("25T17:30", decision="deny", reason="policy_deny")
        pending = record("25T17:31", decision="deny", reason="approval:requested")
        unrelated = record("26T09:00", client="agent-b", connection="notes-b", decision="deny")
        audit.write_text("\n".join(map(json.dumps, [newest, unrelated])) + '\n{"ts":"unfinished"', encoding="utf-8")
        rotated.write_text("\n".join(map(json.dumps, [earlier, pending])) + "\n", encoding="utf-8")
        outside = tmp_path / "foreign-log"
        outside.write_text(json.dumps(record("28T00:00")) + "\n", encoding="utf-8")
        audit.with_name(audit.name + ".2026-11-27").symlink_to(outside)
        audit.with_name(audit.name + ".junk").write_bytes(outside.read_bytes())

        reply = await http.post(API, json={})
        assert reply.status_code == 200
        assert reply.headers["cache-control"] == "no-store"
        assert "secret" not in reply.text and "@example.test" not in reply.text and "127.0.0.8" not in reply.text
        data = reply.json()
        assert set(data) == {"items", "truncated"}
        assert data["truncated"] is False
        rows = data["items"]
        assert [row["ts"] for row in rows] == [entry["ts"] for entry in (newest, unrelated, pending, earlier)]
        assert rows[0] == {
            "ts": newest["ts"], "event": "tool_call", "client": "agent-a", "connection": "notes-a",
            "result": "error", "reason": None, "tool": None,
        }
        assert rows[-2]["result"] == "pending"
        assert rows[-1]["tool"] == "a_list_notes"
        assert rows[-1]["reason"] == "policy_deny"
        reply = await http.post(API, json={"client": "agent-a", "connection": "notes-a", "result": "deny"})
        assert reply.json() == {"items": [rows[-1]], "truncated": False}
        assert (await http.post(API, json={"client": "no-match"})).json() == {"items": [], "truncated": False}
        assert (await http.post("/admin/api/auth/logout", json={})).status_code == 200
        assert (await http.post(API, json={})).status_code == 401


async def test_audit_history_reports_bounds_through_http(tmp_path, monkeypatch):
    async with web_gateway(tmp_path) as (gw, http, origin, path):
        await setup(http, origin, path)
        audit = gw.cfg.audit.path
        audit.write_bytes(b"")
        assert (await http.post(API, json={})).json() == {"items": [], "truncated": False}
        first = json.dumps(record("26T13:00", client="agent-b")) + "\n"
        recent = json.dumps(record("26T13:01")) + "\n"
        audit.write_text(first + recent * 2, encoding="utf-8")
        monkeypatch.setattr(audit_history, "MAX_ROWS", 1)
        assert len((await http.post(API, json={})).json()["items"]) == 1
        assert (await http.post(API, json={})).json()["truncated"] is True
        monkeypatch.setattr(audit_history, "MAX_BYTES", len(recent) + 8)
        reply = await http.post(API, json={"client": "agent-b"})
        assert reply.json() == {"items": [], "truncated": True}
