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
    db_str = str(database)
    if db_str != ":memory:":
        with contextlib.suppress(OSError):
            Path(database).parent.mkdir(parents=True, exist_ok=True)
    conn: sqlite3.Connection = sqlite3.connect(db_str, timeout=timeout, **kwargs)
    if wal:
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute("PRAGMA journal_mode=WAL")
    if busy_timeout_ms > 0:
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
    return conn
