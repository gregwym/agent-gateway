"""Start amazon-orders-mcp over stdio with the session the gateway passes in.

Runs in the Amazon Orders sidecar as `python -I -S start.py`: only the standard
library and `lib/` (this connector's locked packages) are importable.

The connection's credential, ORDERS_SESSION_SECRET, is a cookie array exported
from the owner's browser. The MCP reads its session only from its cookie file,
so the credential is written there when it changes. Each applied connection
keeps its own file so the MCP can save Amazon’s Cookie updates. A preview uses
a temporary directory for the process lifetime.
"""
import hashlib
import os
import sys
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))

# Removed before the MCP starts: it reads every AMAZON_* variable as its config,
# and nothing it runs needs the credential in the environment.
session = os.environ.pop("ORDERS_SESSION_SECRET", "")
connection = os.environ.pop("AGW_SIDECAR_CONNECTION", None)
base_jar = Path(os.environ["AMAZON_COOKIE_JAR_PATH"])
state = nullcontext(base_jar.parent / connection) if connection else TemporaryDirectory(prefix="amazon-orders-")

with state as directory:
    jar = Path(directory) / base_jar.name
    os.environ["AMAZON_COOKIE_JAR_PATH"] = str(jar)
    stamp = jar.with_suffix(".sha256")
    digest = hashlib.sha256(session.encode()).hexdigest()
    os.umask(0o077)
    jar.parent.mkdir(exist_ok=True, mode=0o700)
    if session and (not jar.exists() or not stamp.exists() or stamp.read_text() != digest):
        jar.write_text(session)
        stamp.write_text(digest)

    from amazonorders_mcp.server import main

    sys.exit(main())
