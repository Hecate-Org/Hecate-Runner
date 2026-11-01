"""SQLite connection helper with WAL mode, busy timeout, and safe pragmas."""

from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path
from typing import Any


def connect_sqlite(
    database: str | Path,
    timeout: float = 30.0,
    wal: bool = True,
    busy_timeout_ms: int = 5000,
    **kwargs: Any,
) -> sqlite3.Connection:
    """Connect to SQLite database with WAL journal mode and busy timeout configured."""
    conn = sqlite3.connect(str(database), timeout=timeout, **kwargs)
    if wal:
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute("PRAGMA journal_mode=WAL")
    if busy_timeout_ms > 0:
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
    return conn
