"""SQLite connection helper with WAL mode, busy timeout, and safe pragmas."""

from __future__ import annotations

from hecate_agent.core.sqlite_utils import connect_sqlite, connect_sqlite_ro

__all__ = ["connect_sqlite", "connect_sqlite_ro"]
