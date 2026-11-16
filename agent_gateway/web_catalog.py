"""Externally authored API descriptions and proposals for administrator review."""
import json
import re
import secrets
import time
from difflib import unified_diff
from urllib.parse import urlencode, urlsplit

from graphql import GraphQLError, build_schema, print_type, validate_schema

from .config import MAX_WEB_POST_READS, WebPostRead
from .credentials import EncryptedFileStore
from .passkey import Refused
from .web_profiles import WebProfile, connection_origins, is_website

MAX_DOCUMENT = 192_000
KEEP_REVISIONS = 5
METHODS = {"get", "head", "options", "post", "put", "patch", "delete", "trace"}
FORMAT_OPENAPI = "openapi"
FORMAT_GRAPHQL = "graphql"
GET_DESCRIPTION = "web_get_api_description"
PUBLISH_DESCRIPTION = "web_publish_api_description"
PROPOSE_POST_READS = "web_propose_post_reads"
POST_READ_TTL = 24 * 3600
MAX_POST_READ_PROPOSAL = 16
DESCRIPTIONS = {
    GET_DESCRIPTION: ("Read the latest or a historical API description for this website connection.",
                      {"type": "object", "properties": {"revision": {"type": "integer", "minimum": 1}}, "additionalProperties": False}),
    PUBLISH_DESCRIPTION: ("Publish a complete OpenAPI 3.1 JSON document or GraphQL SDL for this website. "
        "Only its assigned maintainer may publish. Read the latest revision first; publishing cannot change website access or approvals. "
        "Use only schema information and synthetic examples; exclude account data, cookies and tokens.",
        {"type": "object", "required": ["base_revision", "format", "document"], "additionalProperties": False,
         "properties": {"base_revision": {"type": "integer", "minimum": 0},
                        "format": {"enum": ["openapi", "graphql"]},
                        "document": {"oneOf": [{"type": "object"}, {"type": "string"}]}}}),
    PROPOSE_POST_READS: (
        "Propose treating specific HTTP POST endpoints as reads. Only the assigned maintainer may propose. "
        "Use literal paths on approved origins, and only if every request to that endpoint is read-only. "
        "The result contains an administrator review URL. Access changes only after Passkey approval. "
        "Check gateway_search_connections for active post_read_endpoints.",
        {"type": "object", "required": ["endpoints", "reason"], "additionalProperties": False,
         "properties": {"endpoints": {"type": "array", "minItems": 1, "maxItems": MAX_POST_READ_PROPOSAL,
                                     "uniqueItems": True, "items": {
             "type": "object", "required": ["origin", "path"], "additionalProperties": False,
             "properties": {"origin": {"type": "string", "maxLength": 255},
                            "path": {"type": "string", "maxLength": 512}}}},
                        "reason": {"type": "string", "minLength": 1, "maxLength": 500}}}),
}


def public_origin(url):
    try:
        parts = urlsplit(url)
        return WebProfile(origin=f"{parts.scheme}://{parts.netloc}").origin
    except (TypeError, ValueError):
        return None


def document_info(fmt, document):
    """Check the supported document structure without resolving any external resources."""
    if fmt not in (FORMAT_OPENAPI, FORMAT_GRAPHQL):
        raise Refused("website_catalog_format", 400)
    if fmt == FORMAT_OPENAPI and not isinstance(document, dict) or fmt == FORMAT_GRAPHQL and not isinstance(document, str):
        raise Refused("website_catalog_invalid", 400)
    try:
        encoded = json.dumps(document, ensure_ascii=False, allow_nan=False).encode()
    except (UnicodeError, RecursionError, ValueError):
        raise Refused("website_catalog_invalid", 400) from None
    if len(encoded) > MAX_DOCUMENT:
        raise Refused("website_catalog_too_large", 413)
    if re.search(rb"\bagw_[a-zA-Z0-9_-]{43}\b", encoded):
        raise Refused("website_catalog_contains_token", 400)
    if fmt == FORMAT_GRAPHQL:
        try:
            schema = build_schema(document)
            if validate_schema(schema):
                raise ValueError()
        except (GraphQLError, TypeError, ValueError, RecursionError):
            raise Refused("website_catalog_invalid", 400) from None
        return {name: print_type(typ) for name, typ in schema.type_map.items() if not name.startswith("__")}, []

    version, info, paths = document.get("openapi"), document.get("info"), document.get("paths", {})
    if (not isinstance(version, str) or not re.fullmatch(r"3\.1\.[0-9]+", version)
            or not isinstance(info, dict) or any(not isinstance(info.get(k), str) or not info[k].strip() for k in ("title", "version"))
            or not isinstance(paths, dict)):
        raise Refused("website_catalog_invalid", 400)
    nodes, origins, operations = [(document, 0)], set(), []
    while nodes:
        node, depth = nodes.pop()
        if depth > 48:
            raise Refused("website_catalog_invalid", 400)
        if isinstance(node, dict):
            nodes.extend((value, depth + 1) for value in node.values())
        elif isinstance(node, list):
            nodes.extend((value, depth + 1) for value in node)
    def add_origins(obj):
        if isinstance(obj.get("servers"), list):
            origins.update(origin for server in obj["servers"] if isinstance(server, dict)
                           and isinstance(server.get("url"), str) and "{" not in server["url"]
                           and (origin := public_origin(server["url"])))

    add_origins(document)
    for path, item in paths.items():
        if path.startswith("x-"):
            continue
        if not path.startswith("/") or not isinstance(item, dict):
            raise Refused("website_catalog_invalid", 400)
        add_origins(item)
        for method in METHODS & item.keys():
            if not isinstance(item[method], dict):
                raise Refused("website_catalog_invalid", 400)
            add_origins(item[method])
            operations.append(f"{method.upper()} {path}")
    return sorted(operations), sorted(origins)


def summary(previous, revision):
    before = previous["document"].get("paths", {}) if previous and previous["format"] == FORMAT_OPENAPI else {}
    after = revision["document"].get("paths", {}) if revision["format"] == FORMAT_OPENAPI else {}
    old, new = set(previous["operations"] if previous else []), set(revision["operations"])
    changed = []
    other = False
    if previous and previous["format"] == revision["format"] == FORMAT_OPENAPI:
        for operation in sorted(old & new):
            method, path = operation.split(" ", 1)
            if before[path][method.lower()] != after[path][method.lower()]:
                changed.append(operation)

        def other_fields(doc):
            return ({key: value for key, value in doc.items() if key != "paths"},
                    {path: {k: v for k, v in item.items() if k not in METHODS}
                     for path, item in doc.get("paths", {}).items() if isinstance(item, dict)
                     and (set(item) - METHODS)})

        other = other_fields(previous["document"]) != other_fields(revision["document"])
    elif previous and previous["format"] == revision["format"] == FORMAT_GRAPHQL:
        changed = [name for name in sorted(old & new) if previous["operations"][name] != revision["operations"][name]]
        other = not changed and old == new  # e.g. directives or custom schema root mappings.
    elif previous:
        other = True
    return {"added": sorted(new - old), "removed": sorted(old - new), "changed": changed, "other": other}


class WebsiteCatalogs:
    def __init__(self, admin):
        self.admin = admin
        cfg = admin.store.base
        self.directory = cfg.admin.state.with_name(cfg.admin.state.name + ".web-catalogs")
        self.key_file = cfg.secrets.key_file

    def binding(self, connection):
        return self.admin.store.state.get("website_catalogs", {}).get(connection)

    def records(self, binding):
        if not binding:
            return []
        path = self.directory / binding["ref"]
        return json.loads(EncryptedFileStore(path, self.key_file).get("revisions")) if path.is_file() else []

    @staticmethod
    def eligible(gw, client, conn):
        return client.household == gw.cfg.household_of(conn.owner) and any(
            gw.policy.effect(client.subject, tool.name, client.id, operation=mode) != "deny"
            for tool in conn.tools for mode in ("read", "write"))

    @staticmethod
    def can_propose(gw, client, conn):
        return any(tool.upstream == "http_request"
                   and gw.policy.effect(client.subject, tool.name, client.id, operation="read") != "deny"
                   for tool in conn.tools)

    def metadata(self, conn, client=None, gateway=None):
        binding = self.binding(conn.id)
        can_publish = bool(binding and client and binding.get("writer") == client.id)
        return {"read_tool": GET_DESCRIPTION, "can_publish": can_publish,
                **({"publish_tool": PUBLISH_DESCRIPTION} if can_publish else {}),
                **({"propose_post_reads_tool": PROPOSE_POST_READS}
                   if can_publish and self.can_propose(gateway, client, conn) else {})}

    def view(self, conn, version=None):
        binding = self.binding(conn.id)
        records = self.records(binding)
        current = next((record for record in records if version is None or record["revision"] == version), None)
        if version is not None and current is None:
            raise Refused("website_catalog_revision_missing", 404)
        previous = next((r for r in records if current and r["revision"] == current["revision"] - 1), None)

        def lines(record):
            doc = record["document"]
            return (doc if isinstance(doc, str) else json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False)).splitlines()

        diff = None
        if previous and current:
            before, after = lines(previous), lines(current)
            if len(before) + len(after) <= 3_000:
                patch = "\n".join(unified_diff(before, after, fromfile=str(previous["revision"]),
                                              tofile=str(current["revision"]), lineterm=""))
                if len(patch) <= 75_000:
                    diff = patch
        return {"writer": binding.get("writer") if binding else None,
                "current": ({k: v for k, v in current.items() if k != "operations"} if current else None),
                "diff": diff, "history": [{k: record[k] for k in ("revision", "format", "agent", "published_at")}
                                          for record in records]}

    def connection(self, gateway, client, name, tool):
        conn = next((c for c in gateway.cfg.connections if c.id == name and is_website(c)), None)
        if conn is None or not self.eligible(gateway, client, conn):
            return None
        if tool in (PUBLISH_DESCRIPTION, PROPOSE_POST_READS):
            if (self.binding(conn.id) or {}).get("writer") != client.id:
                return None
            if tool == PROPOSE_POST_READS and not self.can_propose(gateway, client, conn):
                return None
        return conn

    def get_description(self, conn, version=None):
        records = self.records(self.binding(conn.id))
        record = next((r for r in records if version is None or r["revision"] == version), None)
        if version is not None and record is None:
            raise Refused("website_catalog_revision_missing", 404)
        return ({k: record[k] for k in ("revision", "format", "document")} if record else
                {"revision": 0, "format": None, "document": None})

    def check_publication(self, body):
        if (not isinstance(body, dict) or set(body) != {"format", "document", "base_revision"}
                or type(body["base_revision"]) is not int or body["base_revision"] < 0):
            raise Refused("website_catalog_invalid", 400)
        info = document_info(body["format"], body["document"])
        gw = self.admin.runtime.gateway
        if gw.scrubber.data(body["document"]) != body["document"]:
            raise Refused("website_catalog_contains_token", 400)
        return info

    def publish(self, conn, binding, client_id, body):
        operations, origins = self.check_publication(body)
        records = self.records(binding)
        previous = records[0] if records else None
        current = previous["revision"] if previous else 0
        if body["base_revision"] != current:
            return {"error": "catalog_revision_conflict", "current_revision": current}
        if previous and all(body[k] == previous[k] for k in ("document", "format")):
            return {"revision": current, "changes": {"added": [], "removed": [], "changed": [], "other": False}}
        record = {"revision": body["base_revision"] + 1, "format": body["format"], "document": body["document"],
                  "origins": origins, "operations": operations, "agent": client_id, "published_at": int(time.time())}
        record["changes"] = summary(previous, record)
        file = EncryptedFileStore(self.directory / binding["ref"], self.key_file)
        file.set("revisions", json.dumps([record, *records][:KEEP_REVISIONS], ensure_ascii=False))
        self.admin.runtime.gateway.audit.write("website_catalog_published", client=client_id, connection=conn.id,
                                               revision=record["revision"])
        return {"revision": record["revision"], "changes": record["changes"]}

    def check_post_reads(self, conn, body):
        try:
            endpoints = sorted((WebPostRead.model_validate(item).model_dump() for item in body["endpoints"]),
                               key=lambda item: (item["origin"], item["path"]))
            reason = body["reason"].strip()
            if (not reason or any(ord(c) < 32 or ord(c) == 127 for c in reason)
                    or not all(row["origin"] in connection_origins(conn) for row in endpoints)):
                raise ValueError()
            serialized = json.dumps(body, ensure_ascii=False)
            serialized.encode("utf-8")
        except ValueError:
            raise Refused("web_post_read_invalid", 400) from None
        if (re.search(r"\bagw_[a-zA-Z0-9_-]{43}\b", serialized)
                or self.admin.runtime.gateway.scrubber.data(body) != body):
            raise Refused("website_catalog_contains_token", 400)
        return endpoints, reason

    def _proposal_file(self, conn):
        binding = self.binding(conn.id)
        return self.directory / (binding["ref"] + ".post-reads") if binding else None

    def save_post_read_proposal(self, conn, proposal):
        EncryptedFileStore(self._proposal_file(conn), self.key_file).set("proposal", json.dumps(proposal))

    def post_read_proposal(self, conn, proposal_id=None):
        path = self._proposal_file(conn)
        proposal = (json.loads(EncryptedFileStore(path, self.key_file).get("proposal"))
                    if path and path.is_file() else None)
        if proposal_id is not None and (not proposal or proposal["id"] != proposal_id):
            raise Refused("web_post_read_proposal_missing", 404)
        if not proposal:
            return None
        active = [rule.model_dump() for rule in conn.web_post_reads]
        gateway = self.admin.runtime.gateway
        if proposal.get("rejected"):
            status = "rejected"
        elif all(row in active for row in proposal["endpoints"]):
            status = "approved"
        elif proposal["revision"] != gateway.configuration_revision or proposal["expires_at"] <= time.time():
            status = "stale"
        else:
            status = "pending_admin_review"
        return {**proposal, "status": status}

    def propose_post_reads(self, conn, client_id, body):
        endpoints, reason = self.check_post_reads(conn, body)
        active = [rule.model_dump() for rule in conn.web_post_reads]
        endpoints = [row for row in endpoints if row not in active]
        if not endpoints:
            return {"status": "already_active"}
        if len(active) + len(endpoints) > MAX_WEB_POST_READS:
            raise Refused("web_post_read_limit", 409)
        gateway = self.admin.runtime.gateway
        existing = self.post_read_proposal(conn)
        if existing and existing["status"] == "pending_admin_review":
            if existing["endpoints"] != endpoints or existing["agent"] != client_id:
                raise Refused("web_post_read_pending", 409)
            proposal = existing
        else:
            proposal = {"id": secrets.token_hex(16), "agent": client_id, "endpoints": endpoints,
                        "reason": reason, "revision": gateway.configuration_revision,
                        "expires_at": int(time.time()) + POST_READ_TTL}
            self.save_post_read_proposal(conn, proposal)
            gateway.audit.write("website_post_reads_proposed", client=client_id, connection=conn.id,
                                proposal=proposal["id"], count=len(endpoints))
        query = urlencode({"review_post_reads": conn.id, "proposal": proposal["id"]})
        return {"status": "pending_admin_review", "proposal_id": proposal["id"], "expires_at": proposal["expires_at"],
                "review_url": gateway.cfg.approvals.origin + "/admin/connections?" + query}

    def prune(self):
        active = {binding["ref"] for binding in self.admin.store.state.get("website_catalogs", {}).values()}
        if self.directory.exists():
            for path in self.directory.iterdir():
                if (match := re.fullmatch(r"([a-f0-9]{32})(?:\.post-reads)?", path.name)) and match[1] not in active:
                    path.unlink(missing_ok=True)

    def set_writer(self, state, connection, writer):
        bindings = state.setdefault("website_catalogs", {})
        if connection not in bindings:
            if writer is None:
                return
            bindings[connection] = {"ref": secrets.token_hex(16)}
        bindings[connection]["writer"] = writer
