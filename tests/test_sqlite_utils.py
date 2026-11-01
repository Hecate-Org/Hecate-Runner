"""Tests for SQLite connection helper."""

from __future__ import annotations

from pathlib import Path

from hecate_runner.sqlite_utils import connect_sqlite


def test_connect_sqlite_enables_wal_and_busy_timeout(tmp_path: Path) -> None:
    db_file = tmp_path / "test.db"
    conn = connect_sqlite(db_file, timeout=5.0, wal=True, busy_timeout_ms=3000)
    try:
        cur = conn.cursor()
        mode = cur.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"

        busy_to = cur.execute("PRAGMA busy_timeout").fetchone()[0]
        assert busy_to == 3000
    finally:
        conn.close()
