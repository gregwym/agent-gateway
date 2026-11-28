"""Administrator-managed OpenBot mail notification destinations."""

import re
from uuid import uuid4

from .catalog_sync import bundled_kind
from .passkey import Refused


_OPENBOT_URL = re.compile(r"https://signal\.openbot\.run/v1/webhooks/[A-Za-z0-9_-]{1,128}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def mailboxes(cfg):
    return {conn.id for conn in cfg.connections if bundled_kind(conn) in ("gmail", "imap")}


def view(state, cfg):
    return {
        "mailboxes": sorted(mailboxes(cfg)),
        "host_managed": sorted({event.connection for event in cfg.mail_events} - set(state.get("web_mail_takeovers", ()))),
        "targets": [{"id": key, "label": target["label"], "url": target["url"], "event_type": target["event_type"],
                     "connections": sorted(target["bindings"])}
                    for key, target in state.get("mail_webhooks", {}).items()],
    }


def runtime_targets(state, cfg):
    eligible = mailboxes(cfg)
    result = {key: {} for key in state.get("web_mail_takeovers", ()) if key in eligible}
    for target in state.get("mail_webhooks", {}).values():
        for connection, binding in target["bindings"].items():
            if connection in eligible:
                result.setdefault(connection, {})[binding] = {
                    "url": target["url"], "event_type": target["event_type"], "secret": target["secret"],
                }
    return result


def stage(state, cfg, body):
    if body.keys() != {"revision", "id", "label", "url", "event_type", "secret", "connections", "take_over"}:
        raise Refused("mail_webhook_invalid", 400)
    key, label, url, event_type, secret = (body[field] for field in ("id", "label", "url", "event_type", "secret"))
    connections = body["connections"]
    if (not all(isinstance(value, str) for value in (key, label, url, event_type, secret))
            or not 1 <= len(label) <= 100 or _CONTROL.search(label)
            or not 1 <= len(event_type) <= 200 or _CONTROL.search(event_type)
            or len(secret) > 4096 or _CONTROL.search(secret)
            or not _OPENBOT_URL.fullmatch(url)
            or not isinstance(connections, list) or not all(isinstance(value, str) for value in connections)
            or len(connections) != len(set(connections)) or not set(connections) <= mailboxes(cfg)
            or type(body["take_over"]) is not bool):
        raise Refused("mail_webhook_invalid", 400)

    targets = state.setdefault("mail_webhooks", {})
    previous = targets.get(key)
    if (key and previous is None) or (not key and (len(targets) >= 32 or not connections)):
        raise Refused("mail_webhook_invalid", 400)
    if any(other_key != key and target["url"] == url for other_key, target in targets.items()):
        raise Refused("mail_webhook_duplicate", 409)
    if any(sum(connection in target["bindings"] for other_key, target in targets.items() if other_key != key) >= 8
           for connection in connections):
        raise Refused("mail_webhook_limit", 400)

    same_url = previous is not None and previous["url"] == url
    if not secret and not same_url:
        raise Refused("mail_webhook_secret_required", 400)
    hosted = {event.connection for event in cfg.mail_events}
    takeovers = set(state.get("web_mail_takeovers", ()))
    conflicts = (set(connections) & hosted) - takeovers
    if conflicts and not body["take_over"]:
        raise Refused("mail_webhook_takeover_required", 409)
    state["web_mail_takeovers"] = sorted(takeovers | conflicts)

    bindings = previous["bindings"] if same_url else {}
    key = key or uuid4().hex
    targets[key] = {"label": label, "url": url, "event_type": event_type,
                    "secret": secret or previous["secret"],
                    "bindings": {connection: bindings.get(connection) or uuid4().hex for connection in connections}}
    return key
