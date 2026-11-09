"""SQLite connection helper with WAL mode, busy timeout, and safe pragmas."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, cast

from hecate_agent.core.sqlite_utils import connect_sqlite as _connect_sqlite
from hecate_agent.core.sqlite_utils import connect_sqlite_ro as _connect_sqlite_ro

__all__ = ["connect_sqlite", "connect_sqlite_ro"]


def connect_sqlite(database: str | Path, *args: Any, **kwargs: Any) -> sqlite3.Connection:
    return cast(sqlite3.Connection, _connect_sqlite(database, *args, **kwargs))


def connect_sqlite_ro(database: str | Path, *args: Any, **kwargs: Any) -> sqlite3.Connection:
    return cast(sqlite3.Connection, _connect_sqlite_ro(database, *args, **kwargs))
