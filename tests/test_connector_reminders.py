"""The Reminders connector, as far as it can be tested without a person at the Mac.

The objects below stand in for EventKit's: they answer the same method names with the
same kinds of values. What this shows is that the connector's own logic is right given
those answers. It does not show that EventKit answers this way on a real Mac, and no
test here reads real reminders or asks macOS for permission.
"""

from __future__ import annotations

import subprocess
import sys

import pytest
from agent_gateway.connectors import reminders_eventkit as module
from agent_gateway.connectors._base import ConnectorError
from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client

UNSET = 9223372036854775807  # NSDateComponentUndefined


class When:
    def __init__(self, stamp: float) -> None:
        self.stamp = stamp

    def timeIntervalSince1970(self) -> float:  # noqa: N802
        return self.stamp


class Zone:
    def name(self) -> str:
        return "America/Vancouver"


class Due:
    def __init__(self, year=UNSET, month=UNSET, day=UNSET, hour=UNSET, minute=UNSET, zone=None) -> None:
        self._parts, self._zone = {"year": year, "month": month, "day": day, "hour": hour, "minute": minute}, zone

    def __getattr__(self, name: str):
        return lambda: self._parts[name]

    def timeZone(self):  # noqa: N802
        return self._zone


class ListOf:
    def __init__(self, identifier: str, title: str) -> None:
        self._identifier, self._title = identifier, title

    def calendarIdentifier(self) -> str:  # noqa: N802
        return self._identifier

    def title(self) -> str:
        return self._title


class Link:
    def absoluteString(self) -> str:  # noqa: N802
        return "https://example.com/tickets"


class Reminder:
    def __init__(self, identifier, title, in_list, *, due=None, done_at=None, priority=0, notes=None, link=None) -> None:
        self._values = {
            "calendarItemIdentifier": identifier, "title": title, "calendar": in_list, "dueDateComponents": due,
            "isCompleted": done_at is not None, "completionDate": done_at, "priority": priority, "notes": notes, "URL": link,
            "hasRecurrenceRules": False, "creationDate": When(1_793_000_000), "lastModifiedDate": When(1_793_000_500),
        }  # fmt: skip

    def __getattr__(self, name: str):
        return lambda: self._values[name]


FAMILY, WORK = ListOf("list-1", "Family"), ListOf("list-2", "Work")
ITEMS = [
    Reminder("r1", "Buy milk", FAMILY, due=Due(2026, 11, 20)),
    Reminder("r2", "Call the dentist", FAMILY, due=Due(2026, 11, 18, 9, 30, Zone()), priority=1, notes="Ask about Friday.", link=Link()),
    Reminder("r3", "No date", WORK, priority=5),
    Reminder("r4", "Renew passport", WORK, done_at=When(1_794_000_000)),
    Reminder("r5", "Old chore", FAMILY, done_at=When(1_793_500_000)),
]


class Source:
    def lists(self):
        return [FAMILY, WORK]

    def reminders(self, list_id, completed):
        if list_id not in (None, "list-1", "list-2"):
            raise ConnectorError("No such list.")
        return [r for r in ITEMS if r.isCompleted() == completed and list_id in (None, r.calendar().calendarIdentifier())]

    def reminder(self, reminder_id):
        for item in ITEMS:
            if item.calendarItemIdentifier() == reminder_id:
                return item
        raise ConnectorError("No such reminder.")


def test_lists_reminders_and_details_from_eventkit_shaped_objects():
    tools = {tool.name: tool.handler for tool in module.build_tools(Source())}
    assert tools["list_lists"]({}) == [{"list": "list-1", "name": "Family"}, {"list": "list-2", "name": "Work"}]

    listing = tools["list_reminders"]({})
    assert listing["found"] == 3 and [r["id"] for r in listing["reminders"]] == ["r2", "r1", "r3"]  # soonest first, undated last
    dentist, milk, undated = listing["reminders"]
    assert dentist == {"id": "r2", "list": "Family", "title": "Call the dentist", "completed": False,
                       "due": "2026-11-18T09:30", "due_timezone": "America/Vancouver", "priority": "high"}  # fmt: skip
    assert milk["due"] == "2026-11-20" and "due_timezone" not in milk and "priority" not in milk
    assert "due" not in undated and undated["priority"] == "medium" and "notes" not in dentist

    assert [r["id"] for r in tools["list_reminders"]({"list": "list-2"})["reminders"]] == ["r3"]
    assert [r["id"] for r in tools["list_reminders"]({"limit": 1})["reminders"]] == ["r2"]
    finished = tools["list_reminders"]({"completed": True})["reminders"]
    assert [r["id"] for r in finished] == ["r4", "r5"] and finished[0]["completed_at"] == "2026-11-06T21:20:00+00:00"

    full = tools["get_reminder"]({"id": "r2"})
    assert (full["notes"], full["url"], full["repeats"]) == ("Ask about Friday.", "https://example.com/tickets", False)
    assert full["created"] == "2026-10-26T07:33:20+00:00"
    for call, arguments in (("get_reminder", {"id": "nope"}), ("list_reminders", {"list": "someone-elses"})):
        with pytest.raises(ConnectorError):
            tools[call](arguments)


def test_the_tools_take_no_account_and_offer_no_write():
    tools = module.build_tools(Source())
    assert {tool.name for tool in tools} == {"list_lists", "list_reminders", "get_reminder"}
    for tool in tools:
        assert tool.schema["additionalProperties"] is False
        assert not {"account", "user", "apple_id", "source"} & set(tool.properties)
    # The module names no EventKit method that saves, removes or commits.
    source = open(module.__file__, encoding="utf-8").read()
    for write in ("saveReminder", "removeReminder", "saveCalendar", "removeCalendar", "commit_", "setCompleted", "setTitle"):
        assert write not in source, write


def test_without_eventkit_the_connector_says_so_and_stops():
    blocked = "import sys; sys.modules['EventKit'] = None; from agent_gateway.connectors.reminders_eventkit import main; main()"
    done = subprocess.run([sys.executable, "-c", blocked], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    assert done.returncode != 0 and "EventKit is not available" in done.stderr


@pytest.mark.anyio
async def test_without_the_macos_grant_nothing_is_read_and_nothing_is_asked():
    kit = pytest.importorskip("EventKit")
    status = kit.EKEventStore.authorizationStatusForEntityType_(kit.EKEntityTypeReminder)
    if status == kit.EKAuthorizationStatusFullAccess:
        pytest.skip("this process has access to real reminders; a test must not read them")
    params = StdioServerParameters(command=sys.executable, args=["-m", "agent_gateway.connectors.reminders_eventkit"])
    async with Client(stdio_client(params), cache=None) as client:
        assert {tool.name for tool in (await client.list_tools()).tools} == {"list_lists", "list_reminders", "get_reminder"}
        for tool, arguments in (("list_lists", {}), ("list_reminders", {}), ("get_reminder", {"id": "x"})):
            refused = await client.call_tool(tool, arguments)
            assert refused.is_error and "has not granted" in refused.content[0].text
    # Still not asked: the status is what it was.
    assert kit.EKEventStore.authorizationStatusForEntityType_(kit.EKEntityTypeReminder) == status
