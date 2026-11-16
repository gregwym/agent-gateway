"""Externally authored website API descriptions. These never change request policy."""
import json
import re
import secrets
import time
from difflib import unified_diff
from urllib.parse import urlsplit

from graphql import GraphQLError, build_schema, print_type, validate_schema

from .credentials import EncryptedFileStore
from .passkey import Refused
from .web_profiles import WebProfile, is_website

MAX_DOCUMENT = 192_000
KEEP_REVISIONS = 5
METHODS = {"get", "head", "options", "post", "put", "patch", "delete", "trace"}
FORMAT_OPENAPI = "openapi"
FORMAT_GRAPHQL = "graphql"
GET_DESCRIPTION = "web_get_api_description"
PUBLISH_DESCRIPTION = "web_publish_api_description"
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

    def metadata(self, conn, client_id=None):
        binding = self.binding(conn.id)
        can_publish = bool(binding and client_id and binding.get("writer") == client_id)
        return {"read_tool": GET_DESCRIPTION, "can_publish": can_publish,
                **({"publish_tool": PUBLISH_DESCRIPTION} if can_publish else {})}

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
        if tool == PUBLISH_DESCRIPTION and not self.metadata(conn, client.id)["can_publish"]:
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

    def prune(self):
        active = {binding["ref"] for binding in self.admin.store.state.get("website_catalogs", {}).values()}
        if self.directory.exists():
            for path in self.directory.iterdir():
                if re.fullmatch(r"[a-f0-9]{32}", path.name) and path.name not in active:
                    path.unlink(missing_ok=True)

    def set_writer(self, state, connection, writer):
        bindings = state.setdefault("website_catalogs", {})
        if connection not in bindings:
            if writer is None:
                return
            bindings[connection] = {"ref": secrets.token_hex(16)}
        bindings[connection]["writer"] = writer
