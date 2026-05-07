"""JSON-Lines audit logger.

One record per request that touched the policy engine. Writes are buffered
by the OS; for durability callers may fsync via .flush() manually. The write
is protected by a lock so concurrent request handlers don't interleave lines.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..policy.rules import Decision

log = logging.getLogger(__name__)


class AuditLogger:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()

    async def log(
        self,
        *,
        ecosystem: str,
        name: str,
        version: str,
        decision: Decision,
        request_kind: str,
        client_ip: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        record = {
            "ts": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "action": "allow" if decision.allow else "block",
            "ecosystem": ecosystem,
            "package": name,
            "version": version,
            "rule": decision.rule,
            "reason": decision.reason,
            "source": decision.source,
            "request_kind": request_kind,
            "client_ip": client_ip,
        }
        if extra:
            record.update(extra)

        line = json.dumps(record, ensure_ascii=False) + "\n"
        async with self._lock:
            try:
                # Text append is atomic for small lines on POSIX; lock covers
                # multi-line safety if extra grows.
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
            except OSError as exc:
                log.error("audit write failed: %s", exc)
