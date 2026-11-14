"""One-time Google consent for the Gmail connector. Prints a refresh token for gmail.readonly.

Run it on a computer with a browser, as the person whose mailbox it is:

    python -m agent_gateway.connectors.gmail_auth client_secret.json | agw secret set NAME

`client_secret.json` is the file Google Cloud Console offers for an OAuth client of
type "Desktop app". The browser shows Google's consent page; the refresh token is the
only thing written to standard output, so it goes into the secret store without being
shown on screen or kept in shell history.

Needs Google's own library, which does all of the OAuth work. Install it from a clone
of this repository: `pip install '.[gmail-auth]'` (the project is not published on
PyPI). It is not needed where the gateway runs.
"""

from __future__ import annotations

import argparse
import contextlib
import sys

SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent_gateway.connectors.gmail_auth", description=__doc__.splitlines()[0])
    parser.add_argument("client_secrets", help="the OAuth client file downloaded from Google Cloud Console")
    parser.add_argument("--no-browser", action="store_true", help="print the consent address instead of opening a browser")
    args = parser.parse_args(argv)
    if sys.stdout.isatty():
        sys.exit("The token would be shown on screen. Pipe the output into the secret store: ... | agw secret set NAME")
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:
        sys.exit("This needs google-auth-oauthlib: run `pip install '.[gmail-auth]'` in a clone of the repository")

    try:
        flow = InstalledAppFlow.from_client_secrets_file(args.client_secrets, scopes=[SCOPE])
        with contextlib.redirect_stdout(sys.stderr):  # the library prints its prompt; keep stdout for the token
            credentials = flow.run_local_server(
                port=0, open_browser=not args.no_browser, access_type="offline", prompt="consent", timeout_seconds=600
            )
    except Exception as exc:
        # The type only. The library also stops here if Google grants a different scope than asked for.
        sys.exit(f"Consent did not complete ({type(exc).__name__}). Nothing was stored.")
    granted = set(credentials.granted_scopes or credentials.scopes or ())
    if granted != {SCOPE}:
        sys.exit("Google granted something other than read-only access to mail. Nothing was stored.")
    if not credentials.refresh_token:
        sys.exit("Google returned no refresh token. Nothing was stored.")

    print(credentials.refresh_token)
    print(
        f"Done. Read-only access to Gmail was granted.\n"
        f"  GMAIL_CLIENT_ID for the connection: {flow.client_config['client_id']}\n"
        f"  The client secret from the same file belongs in the secret store too.\n"
        f"  If the Google Cloud project's consent screen is in \"Testing\" status, Google ends this token after 7 days.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
