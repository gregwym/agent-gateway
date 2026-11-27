"""Start amazon-orders-mcp over stdio with the session the gateway passes in.

Runs in the Amazon Orders sidecar as `python -I -S start.py`: only the standard
library and `lib/` (this connector's locked packages) are importable.

The connection's credential, ORDERS_SESSION_SECRET, is a cookie array exported
from the owner's browser. The MCP reads its session only from its cookie file,
so the credential is written there when it changed. Otherwise the file is kept:
Amazon updates its cookies during a session and the MCP saves them there.
"""
import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))

# Removed before the MCP starts: it reads every AMAZON_* variable as its config,
# and nothing it runs needs the credential in the environment.
session = os.environ.pop("ORDERS_SESSION_SECRET", "")
jar = Path(os.environ["AMAZON_COOKIE_JAR_PATH"])
stamp = jar.with_name(jar.name + ".sha256")
digest = hashlib.sha256(session.encode()).hexdigest()
if session and not (stamp.exists() and stamp.read_text() == digest):
    os.umask(0o077)
    jar.write_text(session)
    stamp.write_text(digest)

from amazonorders_mcp.server import main  # noqa: E402

sys.exit(main())
