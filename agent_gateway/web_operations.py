"""HTTP method defaults and endpoint matching shared by policy and execution."""
import re
from posixpath import normpath
from urllib.parse import unquote

READ_METHODS = ("GET", "HEAD", "OPTIONS")
HTTP_METHODS = (*READ_METHODS, "POST", "PUT", "PATCH", "DELETE")


def _write_path(target):
    # Write restrictions cover common aliases that servers may normalize.
    # Ambiguous encodings fail closed when there is a matching method/origin.
    path = target.split("?", 1)[0]
    for _ in range(4):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    if re.search(r"%[0-9a-fA-F]{2}|[\x00-\x20\x7f\ufffd]", path):
        return None
    path = re.split(r"[?#]", path.replace("\\", "/"), maxsplit=1)[0]
    return normpath("/" + "/".join(part.split(";", 1)[0] for part in path.split("/")).lstrip("/")).casefold()


def operation_access(rules, origin, method, target, default, *, allow_read_override):
    applicable = [rule for rule in rules if rule.origin == origin and
                  (rule.method == method or (method == "HEAD" and rule.method == "GET" and rule.access == "write"))]
    writes = [rule for rule in applicable if rule.access == "write"]
    if writes:
        path = _write_path(target)
        if path is None or any(_write_path(rule.path) == path for rule in writes):
            return "write"
    if allow_read_override and any(rule.method == method and rule.access == "read" and rule.path == target
                                   for rule in applicable):
        return "read"
    return default
