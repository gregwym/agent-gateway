"""Gateway configuration tools. Only the administrator can apply a proposal."""
import hmac
import json
import re
import secrets
import time

import anyio
from mcp_types import Tool, ToolAnnotations

from ._base import result, string, text
from ..auth import hash_token
from ..config import NAME
from ..credentials import EncryptedFileStore
from ..oauth import https_url, requested_scope, system_client_details
from ..passkey import Refused

READ, PROPOSE = "read", "provision"
ALIAS = string("Configuration name.", 32, NAME)
KINDS = {"oauth_client", "http_mcp"}
GRANT_EFFECT = {"read": "allow", "write": "approval_required", "write_direct": "allow"}
SETTING_KEYS = ("url", "auth", "service", "scope", "oauth_client", "header")
INTAKE_TTL = 900


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
        "prepared": {"type": "boolean", "description": "Use the no-entry approval flow."},
        "owner": ALIAS,
        "header": string("Credential header name for header authentication.", 64),
        "grants": {"type": "array", "maxItems": 20, "items": {
            "type": "object", "additionalProperties": False, "required": ["client", "tool", "access"],
            "properties": {"client": ALIAS, "tool": string("Exact upstream tool name.", 200),
                           "access": {"enum": list(GRANT_EFFECT)}},
        }},
    }
    return [
        Tool(name=READ,
             description="Read gateway configuration, including available OAuth client references, permitted remote MCP connections and your provisioning requests.",
             input_schema={"type": "object", "additionalProperties": False},
             annotations=ToolAnnotations(read_only_hint=True)),
        Tool(name=PROPOSE,
             description="Propose a gateway configuration for administrator review, either an OAuth client or a remote MCP connector. Set prepared to true for approval without manual entry. Do not include credentials in this tool.",
             input_schema={"type": "object", "properties": fields, "required": ["kind", "id"], "additionalProperties": False},
             annotations=ToolAnnotations(read_only_hint=False)),
    ]


class Provisioning:
    def __init__(self, controller):
        self.controller = controller
        cfg = controller.store.base
        path = cfg.admin.state
        self.file = EncryptedFileStore(path.with_name(path.name + ".proposals"), cfg.secrets.key_file)
        self.prepared = EncryptedFileStore(path.with_name(path.name + ".prepared"), cfg.secrets.key_file)
        self.intake = EncryptedFileStore(path.with_name(path.name + ".staged"), cfg.secrets.key_file)

    @staticmethod
    def stored_rows(store):
        if "proposals" not in store.names():
            return []
        now = time.time()
        return [row for row in json.loads(store.get("proposals")) if row["expires_at"] > now]

    def rows(self):
        return self.stored_rows(self.file) + self.stored_rows(self.prepared)

    def save_row(self, row):
        store = self.prepared if row["config"].get("prepared") else self.file
        rows = [saved for saved in self.stored_rows(store) if saved["id"] != row["id"]]
        store.set("proposals", json.dumps([*rows, row]))

    def status(self, row):
        if row.get("rejected"):
            return "rejected"
        args = row["config"]
        receipt = self.controller.store.state.get("provisioning_receipts", {}).get(row["id"])
        prepared = args.get("prepared")
        if args["kind"] == "oauth_client":
            saved = self.controller.oauth.clients().get(args["id"])
            if saved is not None:
                return "applied" if saved["issuer"] == args["issuer"] and (not prepared or receipt) else "conflict"
        for conn in self.controller.runtime.gateway.cfg.connections:
            if args["kind"] == "http_mcp" and conn.id == args["id"]:
                settings = self.controller.connection_settings(conn)
                scope = requested_scope(args["url"], args.get("scope")) if args["auth"] == "oauth" else None
                expected = args | {"scope": scope or ""}
                matches = all(settings.get(key, "") == expected.get(key, "")
                              for key in SETTING_KEYS if key != "header" or "header" in args)
                if prepared:
                    matches = matches and receipt and conn.owner == args["owner"] and self.grants_applied(conn, args)
                return "applied" if matches else "conflict"
        if receipt:
            return "conflict"
        gateway = self.controller.runtime.gateway
        client = next((c for c in gateway.cfg.clients if c.id == row["client"] and c.token_sha256 == row["token"]), None)
        if not client or not any(
            route.tool.upstream == PROPOSE and isinstance(gateway.upstreams[route.conn.id], ConfigConnection)
            and gateway.policy.effect(client.subject, route.tool.name, client.id) != "deny"
            for route in gateway.routes.values()
        ):
            return "stale"
        return "pending"

    def view(self, row, *, admin=False):
        status = self.status(row)
        view = {key: row[key] for key in ("id", "client", "config", "expires_at")} | {
            "status": status, "review_url": self.controller.store.base.approvals.origin + "/admin/connections"
        }
        if row["config"].get("prepared"):
            view["review_url"] += "?proposal=" + row["id"]
            if status == "pending" and row.get("last_error"):
                view["last_error"] = row["last_error"]
            required = self.needs_credentials(row)
            view["credentials_required"] = required
            if required and status == "pending":
                record = self.intake_record(row["id"])
                if record and "version" in record:
                    view["staged_version"] = record["version"]
                    view["staged_expires_at"] = record["expires_at"]
                    if admin and row["config"]["kind"] == "oauth_client":
                        view["staged_client_id"] = record["value"]["client_id"]
                        view["staged_auth_method"] = record["value"]["auth_method"]
                view["intake_url"] = self.controller.store.base.approvals.origin + "/admin/intake/" + row["id"]
        return view

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

    def validate(self, gateway, client_id, arguments):
        args = dict(arguments)
        prepared = args.pop("prepared", False)
        if args["kind"] == "oauth_client":
            if set(args) != {"kind", "id", "issuer"}:
                raise Refused("invalid_proposal", 400)
            https_url(args["issuer"])
        else:
            if not {"url", "auth"} <= args.keys() or "issuer" in args or (
                    args["auth"] != "oauth" and {"oauth_client", "scope"} & args.keys()):
                raise Refused("invalid_proposal", 400)
            if not prepared and {"owner", "header", "grants"} & args.keys():
                raise Refused("invalid_proposal", 400)
            https_url(args["url"])
            args.setdefault("service", "remote-mcp")
            if args.get("oauth_client") and args["oauth_client"] not in self.controller.oauth.clients():
                raise Refused("oauth_client_unavailable", 409)
            if prepared:
                args.setdefault("owner", self.controller.auth.owner)
                args.setdefault("grants", [])
                self.validate_permissions(gateway.cfg, client_id, args)
                if ("header" in args) != (args["auth"] == "header"):
                    raise Refused("invalid_credential_header", 400)
                if args["auth"] == "header":
                    from ..admin_remote import validate_credential_header
                    validate_credential_header(args["header"])
        if (not re.fullmatch(NAME, args["id"]) or gateway.scrubber.data(args) != args
                or re.search(r"\bagw_(?:intake_)?[a-zA-Z0-9_-]{43}\b", json.dumps(args))):
            raise Refused("invalid_proposal", 400)
        return args | ({"prepared": True} if prepared else {})

    @staticmethod
    def validate_permissions(cfg, client_id, args):
        clients = {client.id: client for client in cfg.clients}
        owner = args["owner"]
        if owner not in cfg.principals or client_id not in clients:
            raise Refused("unknown_member", 400)
        household = cfg.household_of(owner)
        if clients[client_id].household != household:
            raise Refused("outside_household", 400)
        seen = set()
        for grant in args["grants"]:
            target = clients.get(grant["client"])
            if target is None:
                raise Refused("unknown_agent", 400)
            if target.household != household:
                raise Refused("outside_household", 400)
            key = target.id, grant["tool"]
            if key in seen:
                raise Refused("invalid_proposal", 400)
            seen.add(key)

    def grants_applied(self, conn, args):
        gateway = self.controller.runtime.gateway
        clients = {client.id: client for client in gateway.cfg.clients}
        tools = {tool.upstream: tool for tool in conn.tools}
        return all(
            (client := clients.get(grant["client"])) and (tool := tools.get(grant["tool"]))
            and tool.access == ("read" if grant["access"] == "read" else "write")
            and gateway.policy.effect(client.subject, tool.name, client.id) == GRANT_EFFECT[grant["access"]]
            for grant in args["grants"]
        )

    def mark_applied(self, row, state):
        now = time.time()
        state["provisioning_receipts"] = {
            key: expires for key, expires in state.get("provisioning_receipts", {}).items() if expires > now
        } | {row["id"]: row["expires_at"]}

    def record_error(self, identifier, reason):
        rows = self.rows()
        row = next((row for row in rows if row["id"] == identifier), None)
        if row and row["config"].get("prepared"):
            row["last_error"] = reason
            self.save_row(row)

    def apply_grants(self, row, draft):
        args = row["config"]
        cfg, _, _ = self.controller.store.effective(draft["state"])
        self.validate_permissions(cfg, row["client"], args)
        conn = next(c for c in cfg.connections if c.id == draft["connection"])
        tools = {tool.upstream: tool for tool in conn.tools}
        for grant in args["grants"]:
            mode = grant["access"]
            tool = tools.get(grant["tool"])
            if not tool or tool.access != ("read" if mode == "read" else "write"):
                raise Refused("proposal_tool_grant_changed", 409)
            draft["state"]["config"]["policy"].append({
                "connection": conn.id, "clients": [grant["client"]], "tools": [tool.name],
                "effect": GRANT_EFFECT[mode],
            })

    @staticmethod
    def needs_credentials(row):
        args = row["config"]
        return args["kind"] == "oauth_client" or args.get("auth") in ("bearer", "header")

    def intake_record(self, identifier):
        if identifier not in self.intake.names():
            return None
        record = json.loads(self.intake.get(identifier))
        return record if record["expires_at"] > time.time() else None

    def issue_intake(self, row, caller):
        if row["client"] != caller.client_id or not hmac.compare_digest(row["token"], caller.token_sha256):
            raise Refused("not_found", 404)
        if not row["config"].get("prepared") or not self.needs_credentials(row):
            raise Refused("proposal_without_credentials", 409)
        record = self.intake_record(row["id"])
        if record and "version" in record:
            raise Refused("proposal_credentials_already_staged", 409)
        token = "agw_intake_" + secrets.token_urlsafe(32)
        expires = min(int(time.time()) + INTAKE_TTL, row["expires_at"])
        self.intake.set(row["id"], json.dumps({"hash": hash_token(token), "expires_at": expires}))
        return {"token": token, "expires_at": expires}

    def stage(self, row, token, body):
        identifier, args = row["id"], row["config"]
        record = self.intake_record(identifier)
        if not record or not hmac.compare_digest(record.get("hash", ""), hash_token(token)):
            raise Refused("invalid_intake_token", 401)
        if args["kind"] == "oauth_client":
            if set(body) - {"client_id", "client_secret", "auth_method"}:
                raise Refused("oauth_client_settings_invalid", 400)
            _, details = system_client_details(body | {"id": args["id"], "issuer": args["issuer"]})
            value = {key: details[key] for key in ("client_id", "client_secret", "auth_method")}
        else:
            if set(body) != {"token"} or not isinstance(body["token"], str) or not 1 <= len(body["token"]) <= 4096:
                raise Refused("invalid_remote_token", 400)
            from ..admin_remote import validate_remote_token
            validate_remote_token(body["token"])
            value = body
        if any(v.startswith("agw_") for v in value.values()):
            raise Refused("invalid_argument", 400)
        version = secrets.token_hex(16)
        self.intake.set(identifier, json.dumps({"expires_at": record["expires_at"], "version": version, "value": value}))
        self.controller.runtime.gateway.audit.write("configuration_credentials_staged", detail=identifier)
        return {"version": version, "expires_at": record["expires_at"]}

    def staged(self, row, version):
        record = self.intake_record(row["id"])
        if not record or "version" not in record or record["version"] != version:
            raise Refused("proposal_credentials_changed", 409)
        return record["value"]

    def discard_intake(self, identifier):
        if identifier in self.intake.names():
            self.intake.delete(identifier)

    def finish_intake(self, identifier):
        try:
            self.discard_intake(identifier)
        except Exception:
            self.controller.runtime.gateway.audit.write("provisioning_cleanup_failed", reason="storage_unavailable")

    def prune_intake(self):
        identifiers = self.intake.names()
        if not identifiers:
            return
        pending = {row["id"] for row in self.rows() if self.status(row) == "pending"}
        for identifier in identifiers:
            if identifier not in pending or not self.intake_record(identifier):
                self.discard_intake(identifier)

    def prepared_body(self, row, operation, body):
        args = row["config"]
        if set(body) - {"revision", "staged_version"}:
            raise Refused("proposal_changed", 409)
        credentials = self.staged(row, body.pop("staged_version", None)) if self.needs_credentials(row) else {}
        if args["kind"] == "oauth_client" and operation == "oauth-clients/save":
            return body | {key: args[key] for key in ("id", "issuer")} | credentials
        expected = "oauth/mcp/start" if args.get("auth") == "oauth" else "connections/preview"
        if args["kind"] != "http_mcp" or expected != operation:
            raise Refused("proposal_changed", 409)
        self.validate_permissions(self.controller.runtime.gateway.cfg, row["client"], args)
        return body | {"kind": "remote", "id": args["id"], "owner": args["owner"], "credentials": credentials,
                       "settings": {key: args[key] for key in SETTING_KEYS if key in args}}

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
        self.save_row(row)
        gateway.audit.write("configuration_proposed", client=client.id, detail=row["id"])
        return self.view(row)

    def require(self, identifier):
        row = next((row for row in self.rows() if row["id"] == identifier), None)
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
        row = self.require(identifier)
        row["rejected"] = True
        self.save_row(row)
        self.finish_intake(identifier)
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
            args = self.provisioning.validate(gateway, client_id, args)
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
