"""SQLite persistence for hunt execution watermarks and staged sweeps.

Tracks execution history, sliding lookback windows, and pending human approvals.
"""

from __future__ import annotations

import logging
import sqlite3
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hecate_runner.sqlite_utils import connect_sqlite

log = logging.getLogger(__name__)


@dataclass
class HuntExecutionWatermark:
    """Historical execution state and sliding lookback watermark for an active hunt."""

    hunt_id: str
    target_siem: str
    query_file: str
    last_executed_at: str
    last_window_start: str
    last_window_end: str
    run_count: int = 1
    last_outcome: str = "clean"
    last_matched_count: int = 0
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StagedSweep:
    """A scheduled hunt query staged for human / Slack approval before execution."""

    sweep_id: str
    hunt_id: str
    target_siem: str
    query_file: str
    query_text: str
    time_range_days: int = 1
    justification: str = ""
    staged_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    status: str = "pending_approval"  # pending_approval, approved, rejected, executed
    approved_by: str | None = None
    approved_at: str | None = None
    rejection_reason: str | None = None
    execution_outcome: str | None = None
    matched_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class WatermarkStore:
    """SQLite-backed storage for execution watermarks and staged sweep approvals."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = connect_sqlite(self.db_path)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS hunt_execution_watermarks (
                    hunt_id TEXT PRIMARY KEY,
                    target_siem TEXT NOT NULL,
                    query_file TEXT NOT NULL,
                    last_executed_at TEXT NOT NULL,
                    last_window_start TEXT NOT NULL,
                    last_window_end TEXT NOT NULL,
                    run_count INTEGER NOT NULL DEFAULT 1,
                    last_outcome TEXT NOT NULL,
                    last_matched_count INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS hunt_staged_sweeps (
                    sweep_id TEXT PRIMARY KEY,
                    hunt_id TEXT NOT NULL,
                    target_siem TEXT NOT NULL,
                    query_file TEXT NOT NULL,
                    query_text TEXT NOT NULL,
                    time_range_days INTEGER NOT NULL,
                    justification TEXT NOT NULL,
                    staged_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending_approval',
                    approved_by TEXT,
                    approved_at TEXT,
                    rejection_reason TEXT,
                    execution_outcome TEXT,
                    matched_count INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_staged_sweeps_status ON hunt_staged_sweeps(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_staged_sweeps_hunt_id ON hunt_staged_sweeps(hunt_id)"
            )

    def get_watermark(self, hunt_id: str) -> HuntExecutionWatermark | None:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM hunt_execution_watermarks WHERE hunt_id = ?",
                (hunt_id.upper(),),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return HuntExecutionWatermark(
                hunt_id=row["hunt_id"],
                target_siem=row["target_siem"],
                query_file=row["query_file"],
                last_executed_at=row["last_executed_at"],
                last_window_start=row["last_window_start"],
                last_window_end=row["last_window_end"],
                run_count=row["run_count"],
                last_outcome=row["last_outcome"],
                last_matched_count=row["last_matched_count"],
                updated_at=row["updated_at"],
            )

    def update_watermark(
        self,
        hunt_id: str,
        target_siem: str,
        query_file: str,
        last_window_start: str,
        last_window_end: str,
        outcome: str,
        matched_count: int,
    ) -> HuntExecutionWatermark:
        now_iso = datetime.now(UTC).isoformat()
        clean_hunt_id = hunt_id.upper()
        existing = self.get_watermark(clean_hunt_id)
        run_count = (existing.run_count + 1) if existing else 1

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO hunt_execution_watermarks (
                    hunt_id, target_siem, query_file, last_executed_at,
                    last_window_start, last_window_end, run_count,
                    last_outcome, last_matched_count, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hunt_id) DO UPDATE SET
                    target_siem = excluded.target_siem,
                    query_file = excluded.query_file,
                    last_executed_at = excluded.last_executed_at,
                    last_window_start = excluded.last_window_start,
                    last_window_end = excluded.last_window_end,
                    run_count = excluded.run_count,
                    last_outcome = excluded.last_outcome,
                    last_matched_count = excluded.last_matched_count,
                    updated_at = excluded.updated_at
                """,
                (
                    clean_hunt_id,
                    target_siem,
                    query_file,
                    now_iso,
                    last_window_start,
                    last_window_end,
                    run_count,
                    outcome,
                    matched_count,
                    now_iso,
                ),
            )

        return HuntExecutionWatermark(
            hunt_id=clean_hunt_id,
            target_siem=target_siem,
            query_file=query_file,
            last_executed_at=now_iso,
            last_window_start=last_window_start,
            last_window_end=last_window_end,
            run_count=run_count,
            last_outcome=outcome,
            last_matched_count=matched_count,
            updated_at=now_iso,
        )

    def list_watermarks(self) -> list[HuntExecutionWatermark]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM hunt_execution_watermarks ORDER BY last_executed_at DESC"
            )
            return [
                HuntExecutionWatermark(
                    hunt_id=row["hunt_id"],
                    target_siem=row["target_siem"],
                    query_file=row["query_file"],
                    last_executed_at=row["last_executed_at"],
                    last_window_start=row["last_window_start"],
                    last_window_end=row["last_window_end"],
                    run_count=row["run_count"],
                    last_outcome=row["last_outcome"],
                    last_matched_count=row["last_matched_count"],
                    updated_at=row["updated_at"],
                )
                for row in cursor.fetchall()
            ]

    def stage_sweep(
        self,
        hunt_id: str,
        target_siem: str,
        query_file: str,
        query_text: str,
        time_range_days: int = 1,
        justification: str = "",
    ) -> StagedSweep:
        clean_hunt_id = hunt_id.upper()
        sweep_id = f"SWEEP-{clean_hunt_id}-{uuid.uuid4().hex[:6]}"
        now_iso = datetime.now(UTC).isoformat()

        sweep = StagedSweep(
            sweep_id=sweep_id,
            hunt_id=clean_hunt_id,
            target_siem=target_siem,
            query_file=query_file,
            query_text=query_text,
            time_range_days=time_range_days,
            justification=justification or f"Automated scheduled sweep for {clean_hunt_id}",
            staged_at=now_iso,
            status="pending_approval",
        )

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO hunt_staged_sweeps (
                    sweep_id, hunt_id, target_siem, query_file, query_text,
                    time_range_days, justification, staged_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sweep.sweep_id,
                    sweep.hunt_id,
                    sweep.target_siem,
                    sweep.query_file,
                    sweep.query_text,
                    sweep.time_range_days,
                    sweep.justification,
                    sweep.staged_at,
                    sweep.status,
                ),
            )
        return sweep

    def get_staged_sweep(self, sweep_id_or_hunt_id: str) -> StagedSweep | None:
        key = sweep_id_or_hunt_id.strip()
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            if key.startswith("SWEEP-"):
                cursor = conn.execute(
                    "SELECT * FROM hunt_staged_sweeps WHERE sweep_id = ?",
                    (key,),
                )
            else:
                # Find most recent pending staged sweep for this hunt
                cursor = conn.execute(
                    """
                    SELECT * FROM hunt_staged_sweeps
                    WHERE hunt_id = ?
                    ORDER BY CASE WHEN status = 'pending_approval' THEN 0 ELSE 1 END, staged_at DESC
                    LIMIT 1
                    """,
                    (key.upper(),),
                )
            row = cursor.fetchone()
            if not row:
                return None
            return StagedSweep(
                sweep_id=row["sweep_id"],
                hunt_id=row["hunt_id"],
                target_siem=row["target_siem"],
                query_file=row["query_file"],
                query_text=row["query_text"],
                time_range_days=row["time_range_days"],
                justification=row["justification"],
                staged_at=row["staged_at"],
                status=row["status"],
                approved_by=row["approved_by"],
                approved_at=row["approved_at"],
                rejection_reason=row["rejection_reason"],
                execution_outcome=row["execution_outcome"],
                matched_count=row["matched_count"],
            )

    def list_staged_sweeps(self, status: str | None = "pending_approval") -> list[StagedSweep]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            if status:
                cursor = conn.execute(
                    "SELECT * FROM hunt_staged_sweeps WHERE status = ? ORDER BY staged_at DESC",
                    (status,),
                )
            else:
                cursor = conn.execute("SELECT * FROM hunt_staged_sweeps ORDER BY staged_at DESC")
            return [
                StagedSweep(
                    sweep_id=row["sweep_id"],
                    hunt_id=row["hunt_id"],
                    target_siem=row["target_siem"],
                    query_file=row["query_file"],
                    query_text=row["query_text"],
                    time_range_days=row["time_range_days"],
                    justification=row["justification"],
                    staged_at=row["staged_at"],
                    status=row["status"],
                    approved_by=row["approved_by"],
                    approved_at=row["approved_at"],
                    rejection_reason=row["rejection_reason"],
                    execution_outcome=row["execution_outcome"],
                    matched_count=row["matched_count"],
                )
                for row in cursor.fetchall()
            ]

    def mark_sweep_status(
        self,
        sweep_id: str,
        status: str,
        *,
        actor: str = "analyst",
        reason: str = "",
        outcome: str = "",
        matched_count: int = 0,
    ) -> None:
        now_iso = datetime.now(UTC).isoformat()
        with self._connect() as conn:
            if status in ("approved", "executed"):
                conn.execute(
                    """
                    UPDATE hunt_staged_sweeps SET
                        status = ?,
                        approved_by = ?,
                        approved_at = ?,
                        execution_outcome = ?,
                        matched_count = ?
                    WHERE sweep_id = ?
                    """,
                    (status, actor, now_iso, outcome, matched_count, sweep_id),
                )
            elif status == "rejected":
                conn.execute(
                    """
                    UPDATE hunt_staged_sweeps SET
                        status = ?,
                        rejection_reason = ?
                    WHERE sweep_id = ?
                    """,
                    (status, reason, sweep_id),
                )
            else:
                conn.execute(
                    "UPDATE hunt_staged_sweeps SET status = ? WHERE sweep_id = ?",
                    (status, sweep_id),
                )
