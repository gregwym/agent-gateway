"""Website origin and sign-in presets; request paths belong to the Agent."""
from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from .plugins import ManifestModel

SESSION_ENV = "AGW_WEB_SESSION"
PROFILE_ENV = "AGW_WEB_PROFILE"
ORIGINS_ENV = "AGW_WEB_API_ORIGINS"
CUSTOM_PROFILE = "custom-website"
WEB_TOOLS = ("http_request", "graphql_request")


class WebProfile(ManifestModel):
    origin: str = Field(max_length=255)
    experimental: bool = False

    @classmethod
    def saved(cls, raw):
        # Stored profiles may include the retired order definitions. Keep the
        # serialized profile in place: it keys the existing encrypted session.
        profile = json.loads(raw)
        if isinstance(profile, dict):
            profile.pop("actions", None)
            profile.pop("probe", None)
        return cls.model_validate(profile)

    @model_validator(mode="after")
    def _check(self):
        parts = urlsplit(self.origin)
        host = parts.hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("Web profiles require a DNS name")
        if (parts.scheme != "https" or parts.netloc != host or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host) or "." not in host or ".." in host
                or host.endswith((".local", ".localhost", ".internal")) or
                parts.path or parts.query or parts.fragment or self.origin != f"https://{host}"):
            raise ValueError("Web profiles require a public HTTPS origin")
        return self


def is_website(conn):
    return bool(conn.plugin and PROFILE_ENV in conn.env)


def bundled_profiles():
    return {
        "amazon-us": ("Amazon US · experimental", WebProfile(origin="https://www.amazon.com", experimental=True)),
        "weee-orders": ("Weee! · experimental", WebProfile(origin="https://www.weee.com", experimental=True)),
    }


def website_origin(value):
    if not isinstance(value, str):
        raise ValueError("Expected a website URL")
    return WebProfile(origin=value.strip().rstrip("/")).origin


def api_origins(raw):
    values = json.loads(raw)
    if not isinstance(values, list) or len(values) > 8:
        raise ValueError("Choose no more than eight API origins")
    return list(dict.fromkeys(website_origin(value) for value in values))


def connection_origins(conn):
    profile = WebProfile.saved(conn.env[PROFILE_ENV])
    return [profile.origin, *(origin for origin in api_origins(conn.env.get(ORIGINS_ENV, "[]")) if origin != profile.origin)]
