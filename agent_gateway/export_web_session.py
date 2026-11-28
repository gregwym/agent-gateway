"""Capture one site's cookies after you sign in with your own Chrome, for an Agent Gateway connector.

Sign-in happens in a normal Chrome window with a new temporary profile: no automation
or debugging switches, so the site sees an ordinary browser. After you quit that
window, the same profile is reopened headless only to read the site's cookies, then
deleted. Your everyday Chrome profile is never read.

Sites such as Amazon run risk checks that can reject sign-in from automated or headless
browsers, so the Gateway's remote login window may fail there.
"""
import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from agent_gateway.connectors.amazon_orders_session import AMAZON_ORDERS, AMAZON_US_PROFILE, import_amazon_orders_session
from agent_gateway.connectors.web import import_session
from agent_gateway.web_profiles import bundled_profiles

CHROME_PATHS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser",
)
# Same storage settings in both runs, so the second run can read what the first wrote,
# without using the login keychain.
COMMON = ("--no-first-run", "--no-default-browser-check", "--disable-sync", "--use-mock-keychain",
          "--password-store=basic")


def find_chrome(explicit):
    for path in ([explicit] if explicit else CHROME_PATHS):
        if path and os.access(path, os.X_OK):
            return path
    return None


def sign_in(chrome, profile_dir, url):
    """Open an ordinary Chrome window and wait until the user quits it."""
    process = subprocess.Popen([chrome, f"--user-data-dir={profile_dir}", *COMMON, url],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return process.wait()
    except KeyboardInterrupt:
        process.terminate()
        process.wait(timeout=10)
        raise


def debugging_port(profile_dir, process, timeout=20):
    # Chrome writes the port it chose to this file; port 0 avoids a fixed, guessable port.
    marker = Path(profile_dir) / "DevToolsActivePort"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Chrome exited before it was ready. Make sure the sign-in window is closed.")
        if marker.exists() and (lines := marker.read_text().splitlines()):
            return int(lines[0])
        time.sleep(0.2)
    raise RuntimeError("Chrome did not open its local debugging port.")


def saved_cookies(chrome, profile_dir):
    """Reopen the closed profile headless and read its cookies over a local-only debugging port."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError("Install the agent-gateway session-export extra to export a session.") from error
    (Path(profile_dir) / "DevToolsActivePort").unlink(missing_ok=True)
    process = subprocess.Popen(
        [chrome, f"--user-data-dir={profile_dir}", *COMMON, "--headless=new",
         "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0", "about:blank"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        port = debugging_port(profile_dir, process)
        with sync_playwright() as driver:
            browser = driver.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
            try:
                return browser.contexts[0].cookies()
            finally:
                browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


def main():
    profiles = bundled_profiles()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("site", choices=(*profiles, AMAZON_ORDERS))
    parser.add_argument("output", type=Path, help="New file, written with owner-only permissions")
    parser.add_argument("--chrome", help="Path to the Chrome or Chromium executable")
    args = parser.parse_args()
    amazon_orders = args.site == AMAZON_ORDERS
    profile = AMAZON_US_PROFILE if amazon_orders else profiles[args.site][1]
    host = urlsplit(profile.origin).hostname
    chrome = find_chrome(args.chrome)
    if not chrome:
        parser.exit(1, "Google Chrome or Chromium was not found. Pass its executable with --chrome.\n")
    if args.output.exists():
        parser.exit(1, f"{args.output} already exists. Choose a new file name.\n")

    profile_dir = tempfile.mkdtemp(prefix="agw-site-login-")
    try:
        print(f"A new Chrome window opens {host}. Sign in there and choose 'Keep me signed in' if offered;\n"
              "sessions that end when the browser closes cannot be exported.\n"
              "Then quit that Chrome window (Cmd+Q / close all its windows) to continue.")
        sign_in(chrome, profile_dir, profile.origin + "/")
        cookies = saved_cookies(chrome, profile_dir)
    except (RuntimeError, OSError) as error:
        parser.exit(1, f"{error}\n")
    finally:
        shutil.rmtree(profile_dir, ignore_errors=True)

    try:
        captured = json.dumps(cookies)
        raw = import_amazon_orders_session(captured) if amazon_orders else import_session(captured, profile)
    except (ValueError, RecursionError):
        if amazon_orders:
            parser.exit(1, "No valid Amazon Orders sign-in was found. Sign in to Amazon US, "
                        "choose 'Keep me signed in' if offered, then quit Chrome and try again.\n")
        parser.exit(1, f"No saved cookies for {host}. Sign in with 'Keep me signed in', then quit Chrome.\n")
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write(raw)
    print(f"Wrote {len(json.loads(raw))} {host} cookies. Select {args.output} in the Gateway connector, "
          "then delete the local file after saving.")


if __name__ == "__main__":
    main()
