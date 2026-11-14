"""Security audit log: one JSON object per line, metadata only.

Recorded: who called what, on which account, the decision and why, timing and
sizes, the *names* of the arguments, and for approvals the request id and who decided. Never recorded: argument values,
results, tokens or secrets. Files rotate daily and are deleted after
`retention_days`.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# The complete set of fields an audit record may carry. `write` drops anything
# else, so a careless call site cannot start logging content.
FIELDS = frozenset(
    {
        "client", "principal", "tool", "connection", "service", "account", "upstream_tool",
        "decision", "reason", "duration_ms", "result_bytes", "is_error", "arg_keys",
        "remote", "detail", "approval", "approver",
    }
)  # fmt: skip


class Audit:
    def __init__(self, path: Path | None, retention_days: int = 90) -> None:
        # A private logger, not registered globally: nothing else can attach handlers to it.
        self._logger = logging.Logger("agent_gateway.audit", level=logging.INFO)
        if path is not None:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            handler: logging.Handler = logging.handlers.TimedRotatingFileHandler(
                path, when="midnight", backupCount=retention_days, utc=True, encoding="utf-8"
            )
        else:
            handler = logging.NullHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def write(self, event: str, **fields: Any) -> None:
        record: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
        }
        record.update({k: v for k, v in fields.items() if k in FIELDS and v is not None})
        self._logger.info(json.dumps(record, ensure_ascii=False, separators=(",", ":")))

    def close(self) -> None:
        for handler in list(self._logger.handlers):
            handler.close()
            self._logger.removeHandler(handler)
