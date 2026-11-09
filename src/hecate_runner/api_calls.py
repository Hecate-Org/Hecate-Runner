"""Per-request record of outbound HTTP calls, for the monitor's integration panel.

httpx logs one INFO line per completed request. The orchestrator log drops
them (they were half of every cycle's log), so this handler takes them off the
``httpx`` logger and appends a compact JSON line per request to a file of its
own. Only method, host and status are kept: provider keys travel in query
strings (``?key=``) on several APIs, so the path and query never reach disk.
Requests that fail before a response (timeouts, refused connections) are not
logged by httpx and so are not recorded here.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_HANDLER_NAME = "hecate-api-calls"


class ApiCallRecorder(logging.Handler):
    def __init__(self, path: Path) -> None:
        super().__init__(level=logging.INFO)
        self.name = _HANDLER_NAME
        self._path = path
        self._write_lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        entry = parse_httpx_record(record)
        if entry is None:
            return
        try:
            line = json.dumps(entry, separators=(",", ":")) + "\n"
            with self._write_lock, self._path.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            return
        from hecate_agent.core.cycle_events import emit as record_event

        record_event({"type": "http", **entry})


def parse_httpx_record(record: logging.LogRecord) -> dict[str, Any] | None:
    """``{"ts", "method", "host", "status"}`` (host keeps an explicit port) from httpx's request line, else None."""
    if not str(record.msg).startswith("HTTP Request:"):
        return None
    args = record.args if isinstance(record.args, tuple) else ()
    if len(args) < 4:
        return None
    method, url, _version, status = args[:4]
    try:
        parts = urlsplit(str(url))
        host = (parts.hostname or "").lower()
        if host and parts.port:
            host = f"{host}:{parts.port}"
        code = int(str(status))
    except (TypeError, ValueError):
        return None
    if not host:
        return None
    return {
        "ts": round(record.created or time.time(), 3),
        "method": str(method),
        "host": host,
        "status": code,
    }


def install_api_call_recorder(path: Path, *, also_propagate: bool = False) -> None:
    """Route httpx request lines into ``path``, replacing an earlier install.

    ``also_propagate`` keeps them in the main log too (DEBUG runs).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("httpx")
    for handler in list(logger.handlers):
        if handler.name == _HANDLER_NAME:
            logger.removeHandler(handler)
    logger.addHandler(ApiCallRecorder(path))
    logger.setLevel(logging.INFO)
    logger.propagate = also_propagate
