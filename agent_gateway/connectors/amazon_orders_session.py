"""Validate an exported Amazon US session before it is written or saved."""
import json
import time

from ..web_profiles import bundled_profiles
from .web import import_session

AMAZON_ORDERS = "amazon-orders"
AMAZON_US_PROFILE = bundled_profiles()["amazon-us"][1]
ORDERS_SESSION_SECRET = "ORDERS_SESSION_SECRET"


def import_amazon_orders_session(raw):
    if not raw.lstrip().startswith("["):
        raise ValueError("expected a cookie array")
    filtered = import_session(raw, AMAZON_US_PROFILE, allow_quoted_values=True)
    now = time.time()
    if not any(cookie["name"] == "x-main" and cookie["path"] == "/"
               and cookie["domain"] in (".amazon.com", "www.amazon.com")
               and (cookie["expires"] == -1 or cookie["expires"] > now)
               for cookie in json.loads(filtered)):
        raise ValueError("missing Amazon US sign-in cookie")
    return filtered
