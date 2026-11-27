"""Gateway configuration tools. Only the administrator can apply a proposal."""
import json
import re
import secrets
import time

import anyio
from mcp_types import Tool, ToolAnnotations

from ._base import result, string, text
from ..config import NAME
from ..credentials import EncryptedFileStore
from ..oauth import https_url, requested_scope
from ..passkey import Refused

READ, PROPOSE = "read", "provision"
ALIAS = string("Configuration name.", 32, NAME)
KINDS = {"oauth_client", "http_mcp"}


def definitions():
    fields = {
        "kind": {"enum": sorted(KINDS), "description": "Type of configuration to provision."},
        "id": ALIAS,
        "issuer": string("Authorization server issuer, for an OAuth client.", 500),
        "url": string("HTTPS Streamable HTTP MCP endpoint.", 1000),
        "service": ALIAS,
        "auth": {"enum": ["none", "oauth", "bearer", "header"]},
        "oauth_client": ALIAS,
        "scope": string("Space-separated OAuth scopes for this connection.", 500),
    }
    return [
        Tool(name=READ,
             description="Read gateway configuration, including available OAuth client references, permitted remote MCP connections and your provisioning requests.",
             input_schema={"type": "object", "additionalProperties": False},
             annotations=ToolAnnotations(read_only_hint=True)),
        Tool(name=PROPOSE,
             description="Propose a gateway configuration for administrator review, either an OAuth client or a remote MCP connector. Do not supply credentials.",
             input_schema={"type": "object", "properties": fields, "required": ["kind", "id"], "additionalProperties": False},
             annotations=ToolAnnotations(read_only_hint=False)),
    ]


class Provisioning:
    def __init__(self, controller):
        self.controller = controller
        cfg = controller.store.base
        path = cfg.admin.state
        self.file = EncryptedFileStore(path.with_name(path.name + ".proposals"), cfg.secrets.key_file)

    def rows(self):
        if "proposals" not in self.file.names():
            return []
        now = time.time()
        return [row for row in json.loads(self.file.get("proposals")) if row["expires_at"] > now]

    def status(self, row):
        if row.get("rejected"):
            return "rejected"
        args = row["config"]
        if args["kind"] == "oauth_client":
            saved = self.controller.oauth.clients().get(args["id"])
            if saved is not None:
                return "applied" if saved["issuer"] == args["issuer"] else "conflict"
        for conn in self.controller.runtime.gateway.cfg.connections:
            if args["kind"] == "http_mcp" and conn.id == args["id"]:
                settings = self.controller.connection_settings(conn)
                scope = requested_scope(args["url"], args.get("scope")) if args["auth"] == "oauth" else None
                expected = args | {"scope": scope or ""}
                return "applied" if all(settings.get(key, "") == expected.get(key, "")
                                        for key in ("url", "auth", "service", "scope", "oauth_client")) else "conflict"
        gateway = self.controller.runtime.gateway
        client = next((c for c in gateway.cfg.clients if c.id == row["client"] and c.token_sha256 == row["token"]), None)
        if not client or not any(
            route.tool.upstream == PROPOSE and isinstance(gateway.upstreams[route.conn.id], ConfigConnection)
            and gateway.policy.effect(client.subject, route.tool.name, client.id) != "deny"
            for route in gateway.routes.values()
        ):
            return "stale"
        return "pending"

    def view(self, row):
        return {key: row[key] for key in ("id", "client", "config", "expires_at")} | {
            "status": self.status(row), "review_url": self.controller.store.base.approvals.origin + "/admin/connections"
        }

    def visible(self, client):
        return [self.view(row) for row in self.rows()
                if row["client"] == client.id and row["token"] == client.token_sha256]

    def read(self, gateway, client):
        connections = [{"id": conn.id} | {key: value for key, value in self.controller.connection_settings(conn).items()
                                         if key in ("service", "auth", "oauth_client")}
                       for conn in gateway.cfg.connections if conn.transport == "http" and any(
                           gateway.policy.effect(client.subject, tool.name, client.id) != "deny" for tool in conn.tools)]
        return {"oauth_clients": self.controller.oauth.list_clients(), "http_mcp_connections": connections,
                "proposals": self.visible(client)}

    def validate(self, gateway, arguments):
        args = dict(arguments)
        kind = args["kind"]
        if kind == "oauth_client":
            if set(args) != {"kind", "id", "issuer"}:
                raise Refused("invalid_proposal", 400)
            https_url(args["issuer"])
        else:
            if not {"url", "auth"} <= args.keys() or "issuer" in args or (
                    args["auth"] != "oauth" and {"oauth_client", "scope"} & args.keys()):
                raise Refused("invalid_proposal", 400)
            https_url(args["url"])
            args.setdefault("service", "remote-mcp")
            if args.get("oauth_client") and args["oauth_client"] not in self.controller.oauth.clients():
                raise Refused("oauth_client_unavailable", 409)
        if not re.fullmatch(NAME, args["id"]) or gateway.scrubber.data(args) != args or any(
                re.search(r"\bagw_[a-zA-Z0-9_-]{43}\b", field) for field in args.values()):
            raise Refused("invalid_proposal", 400)
        return args

    def submit(self, gateway, client, args):
        rows = self.rows()
        own = [row for row in rows if row["client"] == client.id and row["token"] == client.token_sha256]
        for row in own:
            if row["config"] == args:
                return self.view(row)
        if len(rows) >= 50 or len(own) >= 10:
            raise Refused("proposal_limit", 409)
        row = {"id": secrets.token_hex(16), "client": client.id, "token": client.token_sha256,
               "config": args, "expires_at": int(time.time()) + 86400}
        if self.status(row) != "pending":
            raise Refused("configuration_already_exists", 409)
        self.file.set("proposals", json.dumps([*rows, row]))
        gateway.audit.write("configuration_proposed", client=client.id, detail=row["id"])
        return self.view(row)

    def require(self, identifier, rows=None):
        rows = self.rows() if rows is None else rows
        row = next((row for row in rows if row["id"] == identifier), None)
        if row is None or self.status(row) != "pending":
            raise Refused("proposal_not_pending", 409)
        return row

    def match(self, identifier, operation, body):
        args = self.require(identifier)["config"]
        if operation == "oauth-clients/save":
            if args["kind"] == "oauth_client" and all(body.get(key) == args[key] for key in ("id", "issuer")):
                return
        elif operation in ("connections/preview", "oauth/mcp/start") and args["kind"] == "http_mcp":
            settings = body.get("settings", {})
            keys = ("url", "auth", "service", "scope", "oauth_client")
            if (isinstance(settings, dict) and body.get("kind") == "remote" and body.get("id") == args["id"]
                    and all(settings.get(key, "") == args.get(key, "") for key in keys)):
                return
        raise Refused("proposal_changed", 409)

    def reject(self, identifier):
        rows = self.rows()
        row = self.require(identifier, rows)
        row["rejected"] = True
        self.file.set("proposals", json.dumps(rows))
        self.controller.runtime.gateway.audit.write("configuration_proposal_rejected",
                                                    principal=self.controller.auth.owner, detail=identifier)


class ConfigConnection:
    def __init__(self, conn, provisioning):
        self.conn, self.provisioning = conn, provisioning
        self._client = self if provisioning is not None else None
        self.blocked = {} if provisioning is not None else {tool.upstream: "admin_required" for tool in conn.tools}

    async def run(self):
        await anyio.sleep_forever()

    def prepare(self, gateway, client_id, name, args):
        if name == PROPOSE:
            args = self.provisioning.validate(gateway, args)
        return {**args, "_calling_agent": client_id}

    async def call(self, name, arguments):
        gateway = self.provisioning.controller.runtime.gateway
        client = next(c for c in gateway.cfg.clients if c.id == arguments["_calling_agent"])
        try:
            if name == READ:
                value = self.provisioning.read(gateway, client)
            elif name == PROPOSE:
                value = self.provisioning.submit(gateway, client, {k: v for k, v in arguments.items() if k != "_calling_agent"})
            else:
                return text("Unknown tool.", is_error=True)
        except Refused as exc:
            return text("The gateway rejected the configuration request.", is_error=True, code=exc.code)
        return result(value)
