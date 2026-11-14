"""The CalDAV calendar connector behind the gateway, against a real CalDAV server.

The server is Radicale on localhost. What these tests cannot show is how iCloud's
CalDAV server behaves; that needs a real account (see docs/design.md).
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
from zoneinfo import ZoneInfo

import caldav
import pytest
from helpers import TOKEN_A, TOKEN_B, TOKEN_HOUSE, agent, base_config, prepare, running_gateway, text_of, tool_names
from mcp import Client, MCPError, StdioServerParameters
from mcp.client.stdio import stdio_client
from service_helpers import CalendarServer, calendar_server

pytestmark = pytest.mark.anyio

PASSWORD_A = "app-specific-CAL-AAAA-aaaa-bbbb"
PASSWORD_B = "app-specific-CAL-BBBB-cccc-dddd"
LA = ZoneInfo("America/Los_Angeles")
TOOLS = ["list_calendars", "list_events", "get_event", "check_conflicts"]
SECRETS = {"cal_a": PASSWORD_A, "cal_b": PASSWORD_B}

DENTIST = """BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//test//EN
BEGIN:VEVENT
UID:dentist-1
DTSTAMP:20261101T000000Z
DTSTART;TZID=America/Los_Angeles:20261116T090000
DTEND;TZID=America/Los_Angeles:20261116T100000
SUMMARY:Dentist
LOCATION:12 Main St
DESCRIPTION:Bring the insurance card.
ORGANIZER;CN=Front Desk:mailto:desk@dentist.example
ATTENDEE;CN=Person A;PARTSTAT=ACCEPTED:mailto:person.a@icloud.example
END:VEVENT
END:VCALENDAR
"""


def populate(server: CalendarServer) -> None:
    a = caldav.DAVClient(url=server.url, username="person.a@icloud.example", password=PASSWORD_A, enable_rfc6764=False).principal()
    home, family = a.make_calendar(name="Home", cal_id="home"), a.make_calendar(name="Family", cal_id="family")
    home.add_event(DENTIST)
    home.add_event(dtstart=dt.datetime(2026, 11, 2, 18, 0, tzinfo=LA), dtend=dt.datetime(2026, 11, 2, 19, 0, tzinfo=LA),
                   summary="Yoga", rrule={"FREQ": "WEEKLY", "COUNT": 10}, uid="yoga-1")  # fmt: skip
    home.add_event(dtstart=dt.datetime(2026, 11, 18, 12, 0, tzinfo=LA), dtend=dt.datetime(2026, 11, 18, 13, 0, tzinfo=LA),
                   summary="Lunch (called off)", status="CANCELLED", uid="lunch-1")  # fmt: skip
    family.add_event(dtstart=dt.date(2026, 11, 17), dtend=dt.date(2026, 11, 18), summary="School holiday",
                     transp="TRANSPARENT", uid="holiday-1")  # fmt: skip
    family.add_event(dtstart=dt.datetime(2026, 11, 19, 17, 0, tzinfo=dt.timezone.utc), dtend=dt.datetime(2026, 11, 19, 18, 0, tzinfo=dt.timezone.utc),
                     summary="Parents' evening", uid="parents-1")  # fmt: skip
    b = caldav.DAVClient(url=server.url, username="person.b@icloud.example", password=PASSWORD_B, enable_rfc6764=False).principal()
    b.make_calendar(name="Private", cal_id="private").add_event(
        dtstart=dt.datetime(2026, 11, 16, 9, 0, tzinfo=LA), dtend=dt.datetime(2026, 11, 16, 9, 30, tzinfo=LA),
        summary="B's job interview", uid="interview-1")  # fmt: skip


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    users = {"person.a@icloud.example": PASSWORD_A, "person.b@icloud.example": PASSWORD_B}
    with calendar_server(tmp_path_factory.mktemp("caldav"), users) as running:
        populate(running)
        yield running


def calendar_connection(conn_id: str, owner: str, url: str, username: str, secret: str, tools: list[dict]) -> dict:
    return {
        "id": conn_id,
        "service": "icloud-calendar",
        "account": owner,
        "owner": owner,
        "transport": "stdio",
        "command": [sys.executable, "-m", "agent_gateway.connectors.caldav_calendar"],
        "env": {"CALDAV_URL": url, "CALDAV_USERNAME": username, "CALDAV_TIMEZONE": "America/Los_Angeles"},
        "secret_env": {"CALDAV_PASSWORD": secret},
        "timeout_seconds": 30,
        "tools": tools,
    }


def config(url: str) -> dict:
    raw = base_config()
    raw["connections"] = [
        calendar_connection(
            "cal-a", "person_a", url, "person.a@icloud.example", "cal_a",
            [{"upstream": t, "name": f"a_cal_{t}"} for t in TOOLS]
            # The household may see one calendar of person_a's account, and nothing else of it.
            + [{"upstream": "list_events", "name": "family_events", "pin": {"calendar": "family"}},
               {"upstream": "check_conflicts", "name": "family_conflicts", "allow_values": {"calendar": ["family"]}}],
        ),  # fmt: skip
        calendar_connection("cal-b", "person_b", url, "person.b@icloud.example", "cal_b", [{"upstream": t, "name": f"b_cal_{t}"} for t in TOOLS]),
    ]
    raw["policy"] = [
        {"principals": ["person_a"], "connection": "cal-a", "tools": [f"a_cal_{t}" for t in TOOLS], "effect": "allow"},
        {"principals": ["person_b"], "connection": "cal-b", "tools": [f"b_cal_{t}" for t in TOOLS], "effect": "allow"},
        {"principals": ["household"], "connection": "cal-a", "tools": ["family_events", "family_conflicts"],
         "effect": "allow", "cross_account": True},  # fmt: skip
    ]
    return raw


async def ask(client, tool: str, **arguments):
    result = await client.call_tool(tool, arguments)
    assert not result.is_error, text_of(result)
    return json.loads(text_of(result))


async def test_calendars_events_and_conflicts(server, tmp_path):
    async with running_gateway(await prepare(tmp_path, config(server.url), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            assert await ask(a, "a_cal_list_calendars") == [{"calendar": "home", "name": "Home"}, {"calendar": "family", "name": "Family"}]

            week = await ask(a, "a_cal_list_events", start="2026-11-15", end="2026-11-22")
            assert (week["start"], week["end"]) == ("2026-11-15T00:00:00-08:00", "2026-11-22T00:00:00-08:00")
            assert [(e["summary"], e["start"], e["end"]) for e in week["events"]] == [
                ("Dentist", "2026-11-16T09:00:00-08:00", "2026-11-16T10:00:00-08:00"),
                ("Yoga", "2026-11-16T18:00:00-08:00", "2026-11-16T19:00:00-08:00"),
                ("School holiday", "2026-11-17", "2026-11-18"),
                ("Lunch (called off)", "2026-11-18T12:00:00-08:00", "2026-11-18T13:00:00-08:00"),
                ("Parents' evening", "2026-11-19T09:00:00-08:00", "2026-11-19T10:00:00-08:00"),  # stored in UTC, shown in local time
            ]
            dentist, yoga, holiday = week["events"][0], week["events"][1], week["events"][2]
            assert (dentist["calendar"], dentist["uid"], dentist["location"], dentist["recurring"]) == ("home", "dentist-1", "12 Main St", False)
            assert yoga["recurring"] and holiday["all_day"] and not holiday["busy"]
            assert "description" not in dentist  # a listing carries no notes

            # A repeating event appears once per occurrence in the range.
            month = await ask(a, "a_cal_list_events", start="2026-11-01", end="2026-12-01", calendar="home")
            assert [e["start"][:10] for e in month["events"] if e["summary"] == "Yoga"] == ["2026-11-02", "2026-11-09", "2026-11-16", "2026-11-23", "2026-11-30"]
            assert {e["calendar"] for e in month["events"]} == {"home"}
            assert (await ask(a, "a_cal_list_events", start="2026-11-01", end="2026-12-01", limit=2))["found"] == 9

            # One event in full, named by what the listing showed for it.
            full = await ask(a, "a_cal_get_event", calendar="home", uid="dentist-1", start=dentist["start"])
            assert full["description"] == "Bring the insurance card." and full["organizer"] == {"name": "Front Desk", "address": "desk@dentist.example"}
            assert full["attendees"] == [{"name": "Person A", "address": "person.a@icloud.example", "response": "ACCEPTED"}]
            assert (full["start"], full["end"]) == (dentist["start"], dentist["end"])
            # For a repeating event that is the occurrence asked for, not the first one of the series.
            later = await ask(a, "a_cal_get_event", calendar="home", uid="yoga-1", start="2026-11-23T18:00:00-08:00")
            assert (later["start"], later["end"], later["recurring"]) == ("2026-11-23T18:00:00-08:00", "2026-11-23T19:00:00-08:00", True)
            # The start may be given in another offset or, for an all-day event, as its date.
            assert (await ask(a, "a_cal_get_event", calendar="home", uid="yoga-1", start="2026-11-24T02:00:00Z"))["start"] == later["start"]
            day = await ask(a, "a_cal_get_event", calendar="family", uid=holiday["uid"], start=holiday["start"])
            assert (day["summary"], day["start"], day["all_day"]) == ("School holiday", "2026-11-17", True)

            # Times without an offset are local time; with an offset they are what they say.
            busy = await ask(a, "a_cal_check_conflicts", start="2026-11-16T09:30", end="2026-11-16T09:45")
            assert not busy["free"] and [e["summary"] for e in busy["conflicts"]] == ["Dentist"]
            assert not (await ask(a, "a_cal_check_conflicts", start="2026-11-16T17:30:00Z", end="2026-11-16T17:45:00Z"))["free"]
            assert (await ask(a, "a_cal_check_conflicts", start="2026-11-16T10:00", end="2026-11-16T11:00"))["free"]  # back to back
            # An all-day event marked as free time and a cancelled event are not conflicts.
            assert (await ask(a, "a_cal_check_conflicts", start="2026-11-17T10:00", end="2026-11-17T11:00"))["free"]
            assert (await ask(a, "a_cal_check_conflicts", start="2026-11-18T12:00", end="2026-11-18T13:00"))["free"]
            assert (await ask(a, "a_cal_check_conflicts", start="2026-11-16T09:30", end="2026-11-16T09:45", calendar="family"))["free"]

            for tool, arguments, message in (
                ("a_cal_list_events", {"start": "2026-11-15", "end": "2026-11-22", "calendar": "nope"}, "No such calendar."),
                ("a_cal_get_event", {"calendar": "home", "uid": "nope", "start": "2026-11-16T09:00"}, "No such event at that time."),
                ("a_cal_get_event", {"calendar": "home", "uid": "dentist-1", "start": "2026-12-25"}, "No such event at that time."),
                ("a_cal_get_event", {"calendar": "family", "uid": "dentist-1", "start": "2026-11-16T09:00"}, "No such event at that time."),
                ("a_cal_get_event", {"calendar": "nope", "uid": "dentist-1", "start": "2026-11-16T09:00"}, "No such calendar."),
                ("a_cal_list_events", {"start": "2026-11-22", "end": "2026-11-15"}, "`end` must be after `start`."),
                ("a_cal_list_events", {"start": "2026-01-01", "end": "2028-01-01"}, "The range is too long: one year at most."),
            ):
                failed = await a.call_tool(tool, arguments)
                assert failed.is_error and text_of(failed) == message, tool


async def test_people_and_the_household_see_only_what_is_theirs(server, tmp_path):
    async with running_gateway(await prepare(tmp_path, config(server.url), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as a, agent(gw.url, TOKEN_B) as b, agent(gw.url, TOKEN_HOUSE) as shared:
            assert await tool_names(b) == {f"b_cal_{t}" for t in TOOLS}
            assert await ask(b, "b_cal_list_calendars") == [{"calendar": "private", "name": "Private"}]
            mine = await ask(b, "b_cal_list_events", start="2026-11-15", end="2026-11-22")
            assert [e["summary"] for e in mine["events"]] == ["B's job interview"]
            theirs = json.dumps(await ask(a, "a_cal_list_events", start="2026-11-15", end="2026-11-22"))
            assert "interview" not in theirs
            # Naming the other person's calendar or account gets nowhere.
            assert text_of(await b.call_tool("b_cal_list_events", {"start": "2026-11-15", "end": "2026-11-22", "calendar": "home"})) == "No such calendar."
            assert (await b.call_tool("b_cal_list_events", {"start": "2026-11-15", "end": "2026-11-22", "account": "person_a"})).is_error
            with pytest.raises(MCPError):
                await b.call_tool("a_cal_list_events", {"start": "2026-11-15", "end": "2026-11-22"})

            # The shared agent: the family calendar of person_a's account, and only that.
            assert await tool_names(shared) == {"family_events", "family_conflicts"}
            family = await ask(shared, "family_events", start="2026-11-15", end="2026-11-22")
            assert [e["summary"] for e in family["events"]] == ["School holiday", "Parents' evening"]
            assert (await shared.call_tool("family_events", {"start": "2026-11-15", "end": "2026-11-22", "calendar": "home"})).is_error
            assert not (await ask(shared, "family_conflicts", start="2026-11-19T09:15", end="2026-11-19T09:30", calendar="family"))["free"]
            for arguments in ({"calendar": "home"}, {}):  # another calendar, or all of them by leaving it out
                refused = await shared.call_tool("family_conflicts", {"start": "2026-11-16T09:30", "end": "2026-11-16T09:45", **arguments})
                assert refused.is_error and "Dentist" not in text_of(refused)
            for tool in ("a_cal_list_events", "a_cal_get_event", "a_cal_list_calendars"):
                with pytest.raises(MCPError):
                    await shared.call_tool(tool, {"calendar": "home", "uid": "dentist-1", "start": "2026-11-16T09:00"})

        log = gw.audit_text()
        for private in ("Dentist", "interview", "insurance", PASSWORD_A, PASSWORD_B, "icloud.example"):
            assert private not in log, private


async def test_only_reads_reach_the_server(server, tmp_path):
    mark = server.mark()
    async with running_gateway(await prepare(tmp_path, config(server.url), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            await ask(a, "a_cal_list_calendars")
            await ask(a, "a_cal_list_events", start="2026-11-01", end="2026-12-01")
            await ask(a, "a_cal_get_event", calendar="home", uid="yoga-1", start="2026-11-16T18:00")
            await ask(a, "a_cal_check_conflicts", start="2026-11-16T09:30", end="2026-11-16T09:45")
    sent = server.requests(mark)
    assert sent and set(sent) <= {"PROPFIND", "REPORT", "OPTIONS"}, sent


async def test_a_refused_password_and_an_unreachable_server(server, tmp_path):
    wrong = {"cal_a": "app-specific-CAL-REVOKED", "cal_b": PASSWORD_B}
    async with running_gateway(await prepare(tmp_path / "wrong", config(server.url), secrets=wrong)) as gw:
        async with agent(gw.url, TOKEN_A) as a, agent(gw.url, TOKEN_B) as b:
            first = await a.call_tool("a_cal_list_calendars", {})
            assert first.is_error and "rejected this account's credentials" in text_of(first) and "REVOKED" not in text_of(first)
            mark = server.mark()
            for _ in range(3):
                again = await a.call_tool("a_cal_list_events", {"start": "2026-11-15", "end": "2026-11-22"})
                assert again.is_error and "rejected this account's credentials" in text_of(again)
            assert server.requests(mark) == []  # a refused password is not presented again and again
            assert [e["summary"] for e in (await ask(b, "b_cal_list_events", start="2026-11-15", end="2026-11-22"))["events"]] == ["B's job interview"]
        assert "REVOKED" not in gw.audit_text()

    async with running_gateway(await prepare(tmp_path / "dead", config("http://127.0.0.1:1"), secrets=SECRETS)) as gw:
        async with agent(gw.url, TOKEN_A) as a:
            failed = await a.call_tool("a_cal_list_calendars", {})
            assert failed.is_error and text_of(failed) == "The calendar server could not be reached."


async def test_the_connector_checks_its_own_input_and_settings(server):
    env = {"CALDAV_URL": server.url, "CALDAV_USERNAME": "person.a@icloud.example", "CALDAV_PASSWORD": PASSWORD_A}
    params = StdioServerParameters(command=sys.executable, args=["-m", "agent_gateway.connectors.caldav_calendar"], env=env)
    mark = server.mark()
    async with Client(stdio_client(params), cache=None) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        assert set(tools) == set(TOOLS)
        for tool in tools.values():
            assert tool.annotations.read_only_hint and tool.input_schema["additionalProperties"] is False
            assert not {"account", "user", "username", "password", "url"} & set(tool.input_schema["properties"])
        for tool, arguments in (
            ("list_events", {"start": "2026-11-15", "end": "tomorrow"}),
            ("list_events", {"start": "2026-11-15"}),
            ("list_events", {"start": "2026-11-15", "end": "2026-11-22", "calendar": "home\r\nX: y"}),
            ("list_events", {"start": "2026-11-15", "end": "2026-11-22", "url": "http://elsewhere.example"}),
            ("get_event", {"calendar": "home", "uid": "a\nb", "start": "2026-11-16"}),
            ("get_event", {"calendar": "home", "uid": "dentist-1"}),
            ("get_event", {"calendar": "home", "uid": "dentist-1", "start": "next monday"}),
            ("get_event", {"calendar": "../../person.b@icloud.example/private", "uid": "interview-1", "start": "2026-11-18"}),
        ):
            assert (await client.call_tool(tool, arguments)).is_error, arguments
        # Without CALDAV_TIMEZONE, times are UTC.
        utc = json.loads(text_of(await client.call_tool("list_events", {"start": "2026-11-16", "end": "2026-11-17", "calendar": "home"})))
        assert [e["start"] for e in utc["events"]] == ["2026-11-16T17:00:00+00:00"]
    assert set(server.requests(mark)) <= {"PROPFIND", "REPORT", "OPTIONS"}

    for bad, message in (
        ({"CALDAV_URL": "http://caldav.example.com"}, "CALDAV_URL must be https"),
        ({"CALDAV_URL": "https://user:pw@caldav.example.com"}, "must not contain credentials"),
        ({"CALDAV_TIMEZONE": "Mars/Olympus"}, "not a known time zone"),
        ({"CALDAV_PASSWORD": ""}, "CALDAV_PASSWORD is not set"),
    ):
        done = subprocess.run(
            [sys.executable, "-m", "agent_gateway.connectors.caldav_calendar"], env={**env, **bad, "PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
        )  # fmt: skip
        assert done.returncode != 0 and message in done.stderr, bad
        assert PASSWORD_A not in done.stderr
