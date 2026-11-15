"""Host-defined, read-only HTTP operations. Agents never supply a URL."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from .config import NAME
from .plugins import ManifestModel

SESSION_ENV = "AGW_WEB_SESSION"
PROFILE_ENV = "AGW_WEB_PROFILE"
PARAM = r"[a-zA-Z][a-zA-Z0-9_-]{0,63}"
WEEE_ORIGIN = "https://www.weee.com"
WEEE_ORDER_PATH = "/en/account/my_orders"
# Weee uses the site_lang session cookie to canonicalize the same read page.
# These are runtime aliases so previously installed profiles need no changes.
WEEE_ORDER_ALIASES = frozenset({WEEE_ORDER_PATH, "/zh/account/my_orders", "/account/my_orders"})


def read_redirect_paths(origin, path):
    if origin == WEEE_ORIGIN and path in WEEE_ORDER_ALIASES:
        return WEEE_ORDER_ALIASES
    return frozenset()


class ReadAction(ManifestModel):
    description: str = Field(min_length=1, max_length=500)
    path: str = Field(min_length=1, max_length=512, pattern=r"^/(?:[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)*/?)?$")
    query: dict[str, str] = Field(default_factory=dict, max_length=12)
    # Tool argument -> parameter name. Values are identifiers, never raw query or paths.
    parameters: dict[str, str] = Field(default_factory=dict, max_length=12)
    required: list[str] = Field(default_factory=list, max_length=12)
    format: str = Field(default="html", pattern=r"^(html|json)$")
    expect: list[str] = Field(default_factory=list, max_length=12)
    reject: list[str] = Field(default_factory=list, max_length=12)
    json_fields: list[str] = Field(default_factory=list, max_length=24)

    @model_validator(mode="after")
    def _check(self):
        if (any(part in (".", "..") for part in self.path.split("/"))
                or any(not re.fullmatch(PARAM, x) for x in (*self.query, *self.parameters, *self.parameters.values()))
                or set(self.required) - self.parameters.keys()
                or len(set(self.parameters.values())) != len(self.parameters)
                or self.query.keys() & self.parameters.values()
                or any(not 1 <= len(x) <= 256 for x in (*self.query.values(), *self.expect, *self.reject, *self.json_fields))
                or (self.format == "html" and not self.expect)
                or (self.format == "json" and not self.json_fields)):
            raise ValueError("invalid Web read operation")
        return self


class WebProfile(ManifestModel):
    origin: str = Field(max_length=255)
    probe: str
    actions: dict[str, ReadAction] = Field(min_length=1, max_length=24)
    experimental: bool = False

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
        if (self.probe not in self.actions or self.actions[self.probe].required
                or any(not re.fullmatch(NAME, x) for x in self.actions)):
            raise ValueError("invalid Web profile probe or tool name")
        return self


def bundled_profiles():
    """Retail site page profiles for evaluation; authenticated behavior is unverified."""
    return {
        "amazon-us": ("Amazon US · experimental", WebProfile(
            origin="https://www.amazon.com", probe="list_orders", experimental=True, actions={
                "list_orders": ReadAction(
                    description="Read the Amazon US order history page. Use start_index for a later page.",
                    path="/your-orders/orders", parameters={"start_index": "startIndex"},
                    expect=['id="ordersContainer"', 'class="order-card'],
                    reject=["<title>Amazon Sign-In", "<title>Robot Check"]),
                "get_order": ReadAction(
                    description="Read an Amazon US order by its order ID.", path="/gp/your-account/order-details",
                    parameters={"order_id": "orderID"}, required=["order_id"],
                    expect=['id="orderDetails"', 'id="orderDetailsContainer"'],
                    reject=["<title>Amazon Sign-In", "<title>Robot Check"]),
            })),
        "weee-orders": ("Weee! · experimental", WebProfile(
            origin=WEEE_ORIGIN, probe="list_orders", experimental=True, actions={
                "list_orders": ReadAction(description="Read the Weee! My Orders page.",
                                          path=WEEE_ORDER_PATH,
                                          expect=['class="order-list', 'class="order-card', 'data-testid="order-list"']),
            })),
    }
