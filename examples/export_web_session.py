"""Capture cookies from a fresh local browser for a Gateway Website connection."""
import argparse
import os
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

from agent_gateway.connectors.web import import_session
from agent_gateway.web_profiles import bundled_profiles


def main():
    profiles = bundled_profiles()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("site", choices=profiles)
    parser.add_argument("output", type=Path, help="New file, written with owner-only permissions")
    args = parser.parse_args()
    profile = profiles[args.site][1]
    host = urlsplit(profile.origin).hostname
    with sync_playwright() as driver:
        browser = driver.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()
        page.goto(profile.origin, wait_until="domcontentloaded", timeout=30000)
        input(f"Sign in to {host}, then press Enter here. ")
        import json
        cookies = [cookie for cookie in context.cookies()
                   if cookie["domain"] == host or (cookie["domain"].startswith(".") and host.endswith(cookie["domain"]))]
        try:
            raw = import_session(json.dumps(cookies), profile)
        except ValueError:
            parser.exit(1, f"No usable cookies for {host}. Finish signing in before exporting.\n")
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as file:
            file.write(raw)
    print(f"Upload {args.output} to your Gateway Website connector, then remove the local file.")


if __name__ == "__main__":
    main()
