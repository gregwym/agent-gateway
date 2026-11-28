"""`agw`: run the gateway and do the few admin tasks it needs.

    agw serve  -c gateway.yaml [--host H] [--port P]   run the gateway
    agw check  -c gateway.yaml          validate the config and print who can call what
    agw lock   -c gateway.yaml [--write]  review / record upstream tool definitions
    agw token                           mint a client token and its hash
    agw secret -c gateway.yaml init|set NAME|rm NAME|list
    agw approval -c gateway.yaml enroll PERSON|passkeys|forget ID|requests|cancel ID

All of these are run by a human on the gateway host. None is reachable over the network.
"""

from __future__ import annotations

import argparse
import difflib
import getpass
import json
import logging
import os
import sys
import time
from typing import Any
from urllib.parse import urlsplit

import anyio

from .audit import Audit
from .auth import hash_token, new_token
from .config import Config, ConfigError, load_config
from .credentials import EncryptedFileStore, SecretStoreError
from .lock import Lock, LockError, definition_of, digest_of
from .policy import Policy
from .server import SERVE_OPTIONS, Gateway, build_app
from .upstream import _class_name, list_all_tools, open_client


def _store(cfg: Config) -> EncryptedFileStore:
    if cfg.secrets is None:
        raise ConfigError("no `secrets:` store is configured")
    return EncryptedFileStore(cfg.secrets.path, cfg.secrets.key_file)


def resolve_secrets(cfg: Config) -> dict[str, str]:
    """Every secret the configuration references, or an error naming the missing ones."""
    wanted = sorted(cfg.secret_names())
    if not wanted:
        return {}
    store = _store(cfg)
    available = set(store.names())
    missing = [name for name in wanted if name not in available]
    if missing:
        raise SecretStoreError(f"secrets missing from the store: {', '.join(missing)} (add with `agw secret set`)")
    return {name: store.get(name) for name in wanted}


# -- serve ------------------------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config(args.config)
    gateway = Gateway(cfg, Lock.load(cfg.lock_file), resolve_secrets(cfg), Audit(cfg.audit.path, cfg.audit.retention_days))
    app = build_app(gateway)
    gateway = app.state.runtime.gateway
    unusable = {name: route.problem for name, route in gateway.routes.items() if route.problem}
    for name, problem in unusable.items():
        logging.getLogger("agent_gateway").warning("tool %s is not served: %s", name, problem)
    gateway.audit.write("startup", detail=f"tools={len(gateway.routes)} unusable={len(unusable)}")
    uvicorn.run(
        app,
        host=args.host or cfg.server.host,
        port=args.port or cfg.server.port,
        log_level="info",
        **SERVE_OPTIONS,
    )
    return 0


# -- check ------------------------------------------------------------------------


def cmd_check(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    lock = Lock.load(cfg.lock_file)
    # Built without secrets: this only inspects routes, it never connects.
    gateway = Gateway(cfg, lock, {name: "" for name in cfg.secret_names()}, Audit(None))
    web_mail_targets = {}
    if cfg.admin:
        from . import mail_webhooks
        from .admin_config import ManagedStore
        gateway.secrets = resolve_secrets(cfg)
        store = ManagedStore(gateway)
        cfg, lock, values = store.effective(store.state)
        web_mail_targets = mail_webhooks.runtime_targets(store.state, cfg)
        gateway = Gateway(cfg, lock, values, Audit(None), web_mail_targets=web_mail_targets)
    else:
        from .catalog_sync import sync_catalog
        cfg, lock, _, _ = sync_catalog(cfg, lock)
        gateway = Gateway(cfg, lock, gateway.secrets, Audit(None))
    from .web_profiles import is_website
    policy = Policy(cfg)
    problems: list[str] = []

    print("Clients")
    for client in cfg.clients:
        print(f"  {client.id:<28} -> {cfg.name_of(client.household or client.subject)}")

    print("\nAccess (default: deny)")
    subjects = [(c.id, c.subject) for c in cfg.clients] if cfg.households else [(None, p) for p in cfg.principals]
    for client_id, principal in subjects:
        print(f"  {client_id or principal}")
        rows = 0
        for name, route in gateway.routes.items():
            effect = policy.effect(principal, name, client_id)
            if effect == "deny":
                continue
            rows += 1
            notes = []
            if route.conn.owner != principal:
                notes.append(f"account of {route.conn.owner}")
            if route.tool.pin:
                notes.append("pinned: " + ", ".join(sorted(route.tool.pin)))
            if route.tool.allow_values:
                notes.append("restricted: " + ", ".join(sorted(route.tool.allow_values)))
            if route.problem:
                notes.append(f"NOT SERVED ({route.problem})")
            if is_website(route.conn):
                notes.extend(f"{kind}: {policy.effect(principal, name, client_id, operation=kind)}" for kind in ("read", "write"))
                effect = "per request"
            elif effect == "approval_required":
                if cfg.approvals is None:
                    notes.append("never runs: no `approvals:` section")
                else:
                    notes.append("each call needs a passkey approval by " + " or ".join(cfg.approvers_of(route.conn)))
            target = f"{route.conn.service}/{route.conn.account}:{route.tool.upstream}"
            print(f"    {effect:<17} {name:<32} {target}" + (f"  [{'; '.join(notes)}]" if notes else ""))
        if not rows:
            print("    (nothing)")

    granted = {name for name in gateway.routes for client_id, p in subjects if policy.effect(p, name, client_id) != "deny"}
    print()
    for name, route in gateway.routes.items():
        if name not in granted:
            print(f"note: tool {name} is configured but no rule grants it to anyone")
        if route.problem:
            hint = " (run `agw lock`)" if route.problem == "not_locked" else ""
            problems.append(f"tool {name} will not be served: {route.problem}{hint}")
    for event in cfg.mail_events:
        if event.connection in web_mail_targets:
            continue
        if event.connection in gateway.unused_mail_events:
            problems.append(f"mail_events {event.connection}: no bundled Gmail or IMAP connection has this id")
        else:
            print(f"new-mail events: {event.connection} -> {urlsplit(event.url).hostname} (type {event.type})")
    for connection, targets in web_mail_targets.items():
        for target in targets.values():
            print(f"new-mail events: {connection} -> {urlsplit(target['url']).hostname} (type {target['event_type']})")
    try:
        if not cfg.admin:
            resolve_secrets(cfg)
    except (SecretStoreError, ConfigError) as exc:
        problems.append(str(exc))

    for problem in problems:
        print(f"problem: {problem}", file=sys.stderr)
    print("OK" if not problems else f"{len(problems)} problem(s)")
    return 0 if not problems else 1


# -- lock -------------------------------------------------------------------------


def _pretty(definition: dict[str, Any] | None) -> list[str]:
    return [] if definition is None else json.dumps(definition, indent=2, sort_keys=True, ensure_ascii=False).splitlines()


async def _lock(cfg: Config, write: bool, only: str | None) -> int:
    lock = Lock.load(cfg.lock_file)
    secrets = resolve_secrets(cfg)
    changes = failures = 0
    for conn in cfg.connections:
        if only and conn.id != only:
            continue
        print(f"== {conn.id} ({conn.service}/{conn.account})")
        try:
            with anyio.fail_after(60):
                async with open_client(conn, {n: secrets[n] for n in conn.secret_names()}) as client:
                    live = {tool.name: definition_of(tool) for tool in await list_all_tools(client)}
        except Exception as exc:
            failures += 1
            print(f"   could not connect ({_class_name(exc)}); lock entries left untouched")
            continue
        wanted = sorted({tool.upstream for tool in conn.tools})
        for name in wanted:
            old = lock.get(conn.id, name)
            new = live.get(name)
            if new is None:
                failures += 1
                print(f"   MISSING   {name}: the upstream does not offer this tool")
            elif old is None or old["sha256"] != digest_of(new):
                changes += 1
                print(f"   {'NEW' if old is None else 'CHANGED':<9} {name}")
                before = _pretty(old["definition"] if old else None)
                for line in difflib.unified_diff(before, _pretty(new), "locked", "upstream", lineterm="", n=2):
                    print(f"      {line}")
                if write:
                    lock.put(conn.id, new)
            else:
                print(f"   unchanged {name}")
        extra = sorted(set(live) - set(wanted))
        if extra:
            print(f"   not exposed (not in the config): {', '.join(extra)}")
    if write and changes:
        lock.save(cfg.lock_file)
        print(f"\nwrote {cfg.lock_file}; restart the gateway to serve the new definitions")
    elif changes:
        print("\nRead the definitions above: descriptions are text your agents will obey.")
        print("Re-run with --write to accept them.")
    else:
        print("\nnothing to update")
    return 1 if failures else 0


def cmd_lock(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    return anyio.run(_lock, cfg, args.write, args.connection)


# -- token / secret -----------------------------------------------------------------


def cmd_token(args: argparse.Namespace) -> int:
    token = new_token()
    print("Token (give it to the client; it is not stored anywhere and cannot be shown again):")
    print(f"  {token}")
    print("Hash (put it in the config as clients[].token_sha256):")
    print(f"  {hash_token(token)}")
    return 0


def cmd_secret(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if cfg.secrets is None:
        raise ConfigError("no `secrets:` store is configured")
    if args.action == "init":
        EncryptedFileStore.create_key(cfg.secrets.key_file)
        print(f"created {cfg.secrets.key_file}")
        print("Copy this key into your password manager now. Without it the secret store cannot be read.")
        return 0
    store = _store(cfg)
    if args.action == "list":
        for name in store.names():
            print(name)
        return 0
    if not args.name:
        raise ConfigError(f"`agw secret {args.action}` needs a NAME")
    if args.action == "set":
        # Never from argv: command lines end up in shell history and `ps`.
        value = getpass.getpass(f"value for {args.name}: ") if sys.stdin.isatty() else sys.stdin.readline()
        store.set(args.name, value.strip("\r\n"))
        print(f"stored {args.name}")
    else:
        store.delete(args.name)
        print(f"removed {args.name}")
    return 0


# -- approval ---------------------------------------------------------------------


def _ago(stamp: int | None) -> str:
    return "-" if not stamp else time.strftime("%Y-%m-%d %H:%M", time.localtime(stamp))


def cmd_approval(args: argparse.Namespace) -> int:
    from .passkey import PasskeyApprover, Refused

    cfg = load_config(args.config)
    if cfg.admin:
        from .admin_config import ManagedStore
        base = Gateway(cfg, Lock.load(cfg.lock_file), resolve_secrets(cfg), Audit(None))
        store = ManagedStore(base)
        cfg, _, _ = store.effective(store.state)
    if cfg.approvals is None:
        raise ConfigError("no `approvals:` section is configured")
    approver = PasskeyApprover(cfg.approvals, Audit(cfg.audit.path, cfg.audit.retention_days), cfg.audit.retention_days)
    approver.name_of = cfg.name_of
    try:
        if args.action == "passkeys":
            for key in approver.passkeys():
                print(f"{key['id'][:16]}  {key['principal']:<20} registered {_ago(key['created'])}")
            return 0
        if args.action == "requests":
            for row in approver.requests():
                who = f"{row['client']} ({row['principal']})"
                decided = f" by {row['decided_by']}" if row["decided_by"] else ""
                result = f" -> {row['outcome']}" if row["outcome"] else ""
                print(f"{row['id']}  {row['status'] + decided + result:<28} {_ago(row['created'])}  {row['tool']}  {who}")
            return 0
        if not args.name:
            raise ConfigError(f"`agw approval {args.action}` needs an argument")
        if args.action == "enroll":
            people = [p for p in cfg.principals if p not in cfg.shared]
            if args.name not in people:
                raise ConfigError(f"{args.name!r} is not a person in this config (choose from: {', '.join(people)})")
            print(f"Open this link on the device that holds {args.name}'s passkeys (valid for 15 minutes, works once):")
            print(f"  {approver.new_enrollment(args.name)}")
            print("Whoever opens it first becomes an approver for that person's accounts. Send it over a private channel.")
        elif args.action == "forget":
            print(f"removed a passkey of {approver.forget_passkey(args.name)}")
        else:
            approver.cancel(args.name)
            print("cancelled")
        return 0
    except Refused as refused:
        print(f"error: {refused.code}", file=sys.stderr)
        return 2


def cmd_admin(args: argparse.Namespace) -> int:
    from .admin_auth import AdminAuth
    from .passkey import PasskeyApprover, Refused
    cfg = load_config(args.config)
    if not cfg.admin:
        raise ConfigError("web administration is not enabled")
    approver = PasskeyApprover(cfg.approvals, Audit(cfg.audit.path, cfg.audit.retention_days))
    try:
        print(AdminAuth(cfg, approver).setup_link(rotate=args.rotate))
        return 0
    except Refused as exc:
        print(f"error: {exc.code}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agw", description="Personal / family MCP gateway")
    sub = parser.add_subparsers(dest="command", required=True)

    def with_config(name: str, help_text: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("-c", "--config", default=os.environ.get("AGW_CONFIG", "gateway.yaml"))
        return p

    p_serve = with_config("serve", "run the gateway")
    # For containers: bind inside the container's own network namespace, publish one address outside.
    p_serve.add_argument("--host", help="listen address (default: server.host from the config)")
    p_serve.add_argument("--port", type=int, help="listen port (default: server.port from the config)")
    p_serve.set_defaults(func=cmd_serve)
    with_config("check", "validate the config and print the access table").set_defaults(func=cmd_check)
    p_lock = with_config("lock", "compare upstream tool definitions with the lock file")
    p_lock.add_argument("--write", action="store_true", help="accept the definitions shown and write the lock file")
    p_lock.add_argument("--connection", help="only this connection id")
    p_lock.set_defaults(func=cmd_lock)
    sub.add_parser("token", help="mint a client token").set_defaults(func=cmd_token)
    p_secret = with_config("secret", "manage upstream credentials")
    p_secret.add_argument("action", choices=["init", "set", "rm", "list"])
    p_secret.add_argument("name", nargs="?")
    p_secret.set_defaults(func=cmd_secret)
    p_approval = with_config("approval", "manage passkeys and approval requests")
    p_approval.add_argument("action", choices=["enroll", "passkeys", "forget", "requests", "cancel"])
    p_approval.add_argument("name", nargs="?", help="a person (enroll), a passkey id (forget) or a request id (cancel)")
    p_approval.set_defaults(func=cmd_approval)
    p_admin = with_config("admin", "get the private first-run web setup link")
    p_admin.add_argument("action", choices=["setup"])
    p_admin.add_argument("--rotate", action="store_true", help="invalidate the previous setup link")
    p_admin.set_defaults(func=cmd_admin)

    args = parser.parse_args(argv)
    os.umask(0o077)  # whatever these commands write (lock file, secret store, audit log) is owner-only
    try:
        return args.func(args)
    except (ConfigError, SecretStoreError, LockError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileExistsError:
        print("error: the key file already exists; refusing to overwrite it", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
