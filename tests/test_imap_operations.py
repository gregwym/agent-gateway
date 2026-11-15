"""Simulated-account acceptance: real IMAP over TLS plus injected protocol failures."""
import imaplib
import json
from contextlib import contextmanager

import pytest
from imapclient import IMAPClient

from agent_gateway.connectors import _imap_ops
from agent_gateway.connectors._base import ConnectorError
from agent_gateway.connectors.imap_mail import Mailbox, build_tools
from helpers import TOKEN_A, agent, base_config, prepare, running_gateway, text_of
from service_helpers import mail_account
from test_connector_mail import fill, mail_connection, message


@contextmanager
def direct(account):
    with IMAPClient("127.0.0.1", account.plain_port, ssl=False) as client:
        client.login(account.user, account.password)
        yield client


def extended_connection(account):
    conn = mail_connection("mail-a", "person_a", account, "mail_password", "a")
    names = [t.name for t in build_tools(None, 40_000_000, 5_000_000)]
    conn["tools"] = [{"upstream": n, "name": "mail_" + n} for n in names]
    return conn


@pytest.mark.anyio
async def test_complete_snapshot_and_bulk_read_preserve_unread_over_tls(tmp_path):
    with mail_account(tmp_path / "server", "test@example.test", "fake-mail-password") as account:
        fill(account, *(message(f"batch {n:03}", "a@example.test", account.user, f"body {n}\n" * 20) for n in range(127)))
        raw = base_config()
        conn = extended_connection(account)
        raw["connections"] = [conn]
        raw["policy"] = [{"principals": ["person_a"], "connection": conn["id"], "tools": [t["name"] for t in conn["tools"]], "effect": "allow"}]
        async with running_gateway(await prepare(tmp_path / "gateway", raw, secrets={"mail_password": account.password})) as gw:
            async with agent(gw.url, TOKEN_A) as client:
                async def call(name, **args):
                    value = await client.call_tool("mail_" + name, args)
                    assert not value.is_error, text_of(value)
                    return json.loads(text_of(value))

                with direct(account) as inspect:
                    inspect.select_folder("INBOX")
                    original = set(inspect.search(["SUBJECT", "batch"]))
                first = await call("list_messages", subject="batch", unseen=True, limit=19)
                assert first["matched"] == 127
                validity = first["uidvalidity"]
                seen = [r["uid"] for r in first["results"]]
                # Incoming mail, flag changes and removals between pages must not
                # shift offsets or silently drop originally matching UIDs.
                gone, changed = sorted(original)[:2]
                fill(account, message("batch new arrival", "a@example.test", account.user, "new"))
                with direct(account) as inspect:
                    inspect.select_folder("INBOX")
                    inspect.add_flags([changed], [b"\\Seen"])
                    inspect.add_flags([gone], [b"\\Deleted"])
                    inspect.uid_expunge([gone])
                results, page = list(first["results"]), first
                while page["next_cursor"]:
                    page = await call("list_messages", cursor=page["next_cursor"], limit=23)
                    seen += [r["uid"] for r in page["results"]]
                    results += page["results"]
                assert len(seen) == len(set(seen)) == 127 and set(seen) == original
                assert [r["uid"] for r in results if r["status"] == "error"] == [gone]
                assert changed in seen
                selected = seen[:49] + [gone]
                read = await call("get_messages", uidvalidity=validity, uids=selected, max_chars=7)
                assert read["succeeded"] == 49 and read["failed"] == 1
                assert all(r["message"]["truncated"] and r["message"]["next_offset"] == 7 for r in read["results"] if r["status"] == "success")
                with direct(account) as inspect:
                    inspect.select_folder("INBOX", readonly=True)
                    flags = inspect.fetch(list(original - {gone}), ["FLAGS"])
                    assert {uid for uid, value in flags.items() if b"\\Seen" in value[b"FLAGS"]} == {changed}
                fresh = await call("list_messages", subject="batch", limit=100)
                assert fresh["matched"] == 127  # 127 original - one removed + one arrival
                bad = await call("get_messages", uidvalidity=validity + 1, uids=selected[:2])
                assert all(r["error"]["code"] == "imap_uidvalidity_changed" for r in bad["results"])


@pytest.mark.anyio
async def test_real_batch_states_moves_archive_trash_and_per_uid_results(tmp_path):
    with mail_account(tmp_path / "server", "test@example.test", "fake-mail-password") as account:
        fill(account, *(message(f"organize {n}", "a@example.test", account.user, "content") for n in range(7)))
        with direct(account) as inspect:
            inspect.create_folder("Archive")
            inspect.create_folder("Sorted")
            inspect.create_folder("Writable Trash")  # pymap's demo Trash is intentionally read-only
        raw = base_config()
        conn = extended_connection(account)
        raw["connections"] = [conn]
        raw["policy"] = [{"principals": ["person_a"], "connection": conn["id"], "tools": [t["name"] for t in conn["tools"]], "effect": "allow"}]
        async with running_gateway(await prepare(tmp_path / "gateway", raw, secrets={"mail_password": account.password})) as gw:
            async with agent(gw.url, TOKEN_A) as client:
                async def call(name, **args):
                    response = await client.call_tool("mail_" + name, args)
                    assert not response.is_error, text_of(response)
                    return json.loads(text_of(response))
                listing = await call("list_messages", subject="organize")
                uids = [r["uid"] for r in listing["results"]]
                base = {"uidvalidity": listing["uidvalidity"]}
                with direct(account) as inspect:
                    inspect.select_folder("INBOX")
                    inspect.add_flags([uids[0]], [b"\\Answered"])
                    inspect.add_flags([uids[-1]], [b"\\Deleted"])
                for read, starred in ((True, True), (False, False)):
                    value = await call("set_message_state", **base, uids=uids[:2] + [999999], read=read, starred=starred)
                    assert (value["succeeded"], value["failed"]) == (2, 1)
                    assert value["results"][-1]["error"]["code"] == "imap_message_missing"
                    flags = value["results"][0]["flags"]
                    assert ("\\Seen" in flags) == read and ("\\Flagged" in flags) == starred and "\\Answered" in flags
                bad = await call("move_messages", **base, uids=uids[:2], destination="missing")
                assert all(r["status"] == "not_attempted" and r["error"]["code"] == "imap_destination_missing" for r in bad["results"])
                readonly = await call("trash_messages", **base, uids=[uids[0]], destination="Trash")
                assert readonly["results"][0]["error"]["code"] == "imap_mailbox_readonly"
                moves = [("move_messages", uids[:2], "Sorted"), ("archive_messages", uids[2:4], "Archive"), ("trash_messages", uids[4:6], "Writable Trash")]
                for tool, selected, destination in moves:
                    value = await call(tool, **base, uids=selected + [999999], destination=destination)
                    assert (value["succeeded"], value["failed"]) == (2, 1), value
                    with direct(account) as inspect:
                        inspect.select_folder(destination, readonly=True)
                        assert len(inspect.search(["SUBJECT", "organize"])) == 2
                with direct(account) as inspect:
                    inspect.select_folder("INBOX", readonly=True)
                    assert set(inspect.search(["SUBJECT", "organize"])) == {uids[-1]}
                    assert b"\\Deleted" in inspect.fetch([uids[-1]], ["FLAGS"])[uids[-1]][b"FLAGS"]


class FakeIMAP:
    """Protocol fault injection; full happy paths above use an actual TLS server."""
    def __init__(self, *, move=True, uidplus=True):
        self.validity = 17
        self.data = {i: {"flags": {b"\\Answered"}, "raw": message(str(i), "a@test", "b@test", "hello").as_bytes()} for i in range(1, 6)}
        self.capabilities = {k for k, present in (("MOVE", move), ("UIDPLUS", uidplus)) if present}
        self.events, self.destinations = [], []
        self.fail, self.special = None, True

    def select_folder(self, mailbox, readonly=False):
        self.events.append(("select", readonly))
        return {b"UIDVALIDITY": self.validity}

    def search(self, criteria, charset=None):
        return list(self.data)

    def fetch(self, uids, fields):
        self.events.append(("fetch", tuple(uids), fields))
        return {uid: {b"FLAGS": tuple(self.data[uid]["flags"]), b"RFC822.SIZE": self.data[uid].get("size", len(self.data[uid]["raw"])),
                      b"BODY[]": self.data[uid]["raw"], b"BODY[HEADER.FIELDS (SUBJECT)]": self.data[uid]["raw"]} for uid in uids if uid in self.data}

    def list_folders(self):
        return [((), b"/", "INBOX"), ((b"\\Archive",) if self.special else (), b"/", "存档"), ((b"\\Trash",) if self.special else (), b"/", "废纸篓")]

    def has_capability(self, name):
        return name in self.capabilities

    def add_flags(self, uids, flags):
        self.events.append(("add", tuple(uids), tuple(flags)))
        for uid in uids:
            self.data[uid]["flags"].update(flags)
        if self.fail == "add":
            raise imaplib.IMAP4.abort("connection lost after STORE")

    def remove_flags(self, uids, flags):
        for uid in uids:
            self.data[uid]["flags"].difference_update(flags)

    def copy(self, uids, destination):
        self.events.append(("copy", tuple(uids)))
        self.destinations += [(uid, destination) for uid in uids]
        if self.fail == "copy":
            raise imaplib.IMAP4.abort("connection lost after COPY")

    def move(self, uids, destination):
        self.copy(uids, destination)
        for uid in uids:
            del self.data[uid]

    def uid_expunge(self, uids):
        self.events.append(("uid_expunge", tuple(uids)))
        for uid in uids:
            del self.data[uid]

    def shutdown(self):
        self.events.append(("shutdown",))

    def socket(self):
        return self

    def gettimeout(self):
        return 30

    def settimeout(self, timeout):
        pass


def tools_for(client, limit=40000000):
    mail = Mailbox("unused", 993, "unused", "unused")
    mail._client = client
    return {t.name: t.handler for t in build_tools(mail, limit, 5000000)}


@pytest.mark.anyio
async def test_gateway_limits_imap_folders_and_blocks_implicit_archive_destination(tmp_path):
    with mail_account(tmp_path / "server", "limited@example.test", "fake-mail-password") as account:
        fill(account, message("Inbox only", "a@example.test", account.user, "synthetic"))
        with direct(account) as inspect:
            inspect.create_folder("Private")
        raw = base_config()
        conn = extended_connection(account)
        conn["mailbox_access"] = {"agent-a": ["INBOX"]}
        raw["connections"] = [conn]
        raw["policy"] = [{"principals": ["person_a"], "connection": conn["id"], "tools": [t["name"] for t in conn["tools"]], "effect": "allow"}]
        async with running_gateway(await prepare(tmp_path / "gateway", raw, secrets={"mail_password": account.password})) as gw:
            async with agent(gw.url, TOKEN_A) as client:
                folders = await client.call_tool("mail_list_mailboxes", {})
                assert not folders.is_error, text_of(folders)
                assert [folder["name"] for folder in json.loads(text_of(folders))] == ["INBOX"]
                listing = json.loads(text_of(await client.call_tool("mail_list_messages", {"mailbox": "inbox"})))
                uid = listing["results"][0]["uid"]
                for tool, arguments in (
                    ("get_attachment", {"mailbox": "Private", "uid": uid, "index": 0}),
                    ("move_messages", {"destination": "Private", "uids": [uid], "uidvalidity": listing["uidvalidity"]}),
                    ("list_mailboxes", {"_gateway_mail_scope": ["Private"]}),
                ):
                    assert (await client.call_tool("mail_" + tool, arguments)).is_error
        # An implicit special-use destination is also checked by the connector.
        from agent_gateway.connectors._mail_scope import ARGUMENT
        fake = FakeIMAP()
        result = tools_for(fake)["archive_messages"]({"uidvalidity": 17, "uids": [1], ARGUMENT: frozenset({"INBOX"})})
        assert result["results"][0]["error"]["code"] == "mail_scope_denied"
        assert not fake.destinations


def test_cursor_tampering_restart_expiry_and_uidvalidity_fail_closed(monkeypatch):
    fake = FakeIMAP()
    tools = tools_for(fake)
    first = tools["list_messages"]({"limit": 2})
    token = first["next_cursor"]
    for cursor in (token[:-1] + ("0" if token[-1] != "0" else "1"), "nonsense"):
        with pytest.raises(ConnectorError, match="invalid, expired"):
            tools["list_messages"]({"cursor": cursor})
    with pytest.raises(ConnectorError, match="only cursor"):
        tools["list_messages"]({"cursor": token, "mailbox": "elsewhere"})
    with pytest.raises(ConnectorError, match="invalid, expired"):
        tools_for(fake)["list_messages"]({"cursor": token})
    fake.validity += 1
    with pytest.raises(ConnectorError, match="UIDVALIDITY changed"):
        tools["list_messages"]({"cursor": token})
    monkeypatch.setattr(_imap_ops.time, "time", lambda: first["snapshot_expires_at"] + 1)
    with pytest.raises(ConnectorError, match="invalid, expired"):
        tools["list_messages"]({"cursor": token})
    assert all(event[1] is True for event in fake.events if event[0] == "select")


def test_bulk_fetches_are_batched_peek_bounded_and_report_mixed_failures(monkeypatch):
    fake = FakeIMAP()
    fake.data[2]["size"] = 9999
    fake.data[3]["size"] = -1
    monkeypatch.setattr(_imap_ops, "BATCH_BYTES", len(fake.data[1]["raw"]) + 1)
    result = tools_for(fake, limit=1000)["get_messages"]({"uidvalidity": 17, "uids": [1, 2, 3, 4, 99]})
    assert [r["error"]["code"] for r in result["results"][1:]] == ["imap_message_too_large", "imap_size_missing", "imap_batch_too_large", "imap_message_missing"]
    fetches = [e for e in fake.events if e[0] == "fetch"]
    assert len(fetches) == 2 and fetches[-1][2] == ["BODY.PEEK[]"]
    assert all(b"\\Seen" not in d["flags"] for d in fake.data.values())


@pytest.mark.parametrize("operation, destination", [("archive_messages", "存档"), ("trash_messages", "废纸篓")])
def test_special_folders_and_uidplus_fallback_never_expunge_unrelated(operation, destination):
    fake = FakeIMAP(move=False)
    fake.data[5]["flags"].add(b"\\Deleted")
    value = tools_for(fake)[operation]({"uidvalidity": 17, "uids": [1, 2, 99]})
    assert value["destination"] == destination and (value["succeeded"], value["failed"]) == (2, 1)
    assert fake.destinations == [(1, destination), (2, destination)]
    assert 5 in fake.data and b"\\Deleted" in fake.data[5]["flags"]
    assert [e for e in fake.events if e[0] == "uid_expunge"] == [("uid_expunge", (1,)), ("uid_expunge", (2,))]


@pytest.mark.parametrize("fail", ["copy", "add"])
def test_disconnect_is_not_replayed_and_preserves_every_uid_outcome(fail):
    fake = FakeIMAP(move=False)
    fake.fail = fail
    value = tools_for(fake)["move_messages"]({"uidvalidity": 17, "uids": [1, 2, 3], "destination": "存档"})
    assert [r["status"] for r in value["results"]] == ["unknown", "not_attempted", "not_attempted"]
    assert fake.destinations == [(1, "存档")]  # exactly one COPY; no reconnect/replay
    assert set(fake.data) == {1, 2, 3, 4, 5}
    assert value["results"][0]["completed_steps"] == ([] if fail == "copy" else ["copy"])


def test_missing_special_folder_unsupported_move_and_stale_uids_do_not_mutate():
    for setup, args, code in [
        (lambda f: setattr(f, "special", False), {}, "imap_special_folder_missing"),
        (lambda f: f.capabilities.clear(), {}, "imap_move_unsupported"),
        (lambda f: None, {"uidvalidity": 18}, "imap_uidvalidity_changed"),
    ]:
        fake = FakeIMAP()
        setup(fake)
        value = tools_for(fake)["archive_messages"]({"uidvalidity": 17, "uids": [1, 2], **args})
        assert all(r["status"] == "not_attempted" and r["error"]["code"] == code for r in value["results"])
        assert fake.destinations == [] and not any(e[0] == "add" for e in fake.events)


def test_completed_listings_release_capacity_and_active_listings_never_silently_evict(monkeypatch):
    monkeypatch.setattr(_imap_ops, "MAX_SNAPSHOTS", 1)
    tools = tools_for(FakeIMAP())
    page = tools["list_messages"]({"limit": 1})
    with pytest.raises(ConnectorError, match="Too many active"):
        tools["list_messages"]({})
    tools["list_messages"]({"cursor": page["next_cursor"]})
    assert tools["list_messages"]({})["matched"] == 5


def test_response_budget_reports_every_uid_instead_of_losing_entire_batch(monkeypatch):
    monkeypatch.setattr(_imap_ops, "RESPONSE_BYTES", 900)
    value = tools_for(FakeIMAP())["get_messages"]({"uidvalidity": 17, "uids": [1, 2, 3, 4, 5]})
    assert [r["uid"] for r in value["results"]] == [1, 2, 3, 4, 5]
    assert value["succeeded"] >= 1 and value["failed"] >= 1
    assert all(r["error"]["code"] == "imap_response_too_large" for r in value["results"] if r["status"] == "error")


def test_write_time_budget_returns_unattempted_rows(monkeypatch):
    ticks = iter([0, 1, 16, 17])
    monkeypatch.setattr(_imap_ops.time, "monotonic", lambda: next(ticks))
    fake = FakeIMAP()
    value = tools_for(fake)["set_message_state"]({"uidvalidity": 17, "uids": [1, 2, 3], "read": True})
    assert [r["status"] for r in value["results"]] == ["success", "not_attempted", "not_attempted"]
    assert b"\\Seen" in fake.data[1]["flags"] and all(b"\\Seen" not in fake.data[i]["flags"] for i in [2, 3])
