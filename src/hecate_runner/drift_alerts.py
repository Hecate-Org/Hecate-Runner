"""Durable suppression of unchanged automatic drift alerts."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from hecate_runner.sqlite_utils import connect_sqlite
from hecate_runner.work_locks import acquire_work_lock

if TYPE_CHECKING:
    from hecate_runner.config import Settings

log = logging.getLogger(__name__)

_PROBLEMS = {"missing_remote", "drift_detected"}
_CLEAN = {"in_sync", "decommissioned", "retired", "pending_decommission"}
_LEASE_SEC = 300


def _connect(settings: Settings) -> sqlite3.Connection:
    conn = connect_sqlite(settings.hecate_workspace / ".hecate/siem/drift_alerts.db")
    conn.row_factory = sqlite3.Row
    return conn


def _initialize(conn: sqlite3.Connection) -> None:
    """Called under a short write transaction, including the legacy migration."""
    conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
        hunt TEXT PRIMARY KEY, observed TEXT NOT NULL,
        delivered TEXT, last_sent REAL NOT NULL DEFAULT 0,
        generation TEXT NOT NULL DEFAULT '')""")
    if "generation" not in {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}:
        conn.execute("ALTER TABLE alerts ADD COLUMN generation TEXT NOT NULL DEFAULT ''")
    for row in conn.execute("SELECT hunt FROM alerts WHERE generation = ''").fetchall():
        conn.execute("UPDATE alerts SET generation=? WHERE hunt=?", (uuid.uuid4().hex, row[0]))
    conn.execute("""CREATE TABLE IF NOT EXISTS outbox (
        hunt TEXT PRIMARY KEY, generation TEXT NOT NULL, fingerprint TEXT NOT NULL,
        payload TEXT NOT NULL, claim_token TEXT, lease_until REAL NOT NULL DEFAULT 0,
        attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0)""")


def drift_alert_groups(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Combine missing and changed queries so a hunt receives one complete card."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for field in ("drifted_by_hunt", "missing_by_hunt"):
        for hunt, queries in report.get(field, {}).items():
            groups.setdefault(hunt, []).extend(queries)
    return groups


def _query_key(query: dict[str, Any]) -> str:
    return json.dumps([query.get("target"), query.get("file")])


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _condition(query: dict[str, Any]) -> str:
    return _fingerprint(
        {name: query.get(name) for name in ("target", "file", "status", "remote_id", "drift_diff")}
    )


def notify_drift_report(
    settings: Settings,
    report: dict[str, Any],
    send: Callable[..., tuple[bool, str]] | None = None,
    *,
    now: float | None = None,
) -> None:
    """Observe and enqueue atomically; optionally drain after committing.

    Called only for full, live daemon sweeps. Error observations preserve the last
    known condition; verified resolution clears it so recurrence alerts promptly.
    No network call runs under a SQLite transaction. The optional sender keeps
    callers compatible; maintenance separates observation from delivery entirely.
    """
    now = time.time() if now is None else now
    groups = drift_alert_groups(report)
    conn = _connect(settings)
    try:
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            _initialize(conn)
            previous = {
                row[0]: row[1:]
                for row in conn.execute(
                    "SELECT hunt, observed, delivered, last_sent, generation FROM alerts"
                )
            }
            hunts = report.get("hunts", {})
            for hunt, queries in hunts.items():
                old, delivered, last_sent, generation = previous.get(
                    hunt, ("{}", None, 0, uuid.uuid4().hex)
                )
                observed = json.loads(old)
                seen = set()
                has_errors = False
                for query in queries:
                    key = _query_key(query)
                    seen.add(key)
                    status = query.get("status")
                    if status in _PROBLEMS:
                        observed[key] = _condition(query)
                    elif status in _CLEAN:
                        observed.pop(key, None)
                    else:
                        has_errors = True
                if not has_errors:
                    observed = {key: value for key, value in observed.items() if key in seen}
                if not observed:
                    conn.execute("DELETE FROM alerts WHERE hunt = ?", (hunt,))
                    conn.execute("DELETE FROM outbox WHERE hunt = ?", (hunt,))
                    continue
                fingerprint = _fingerprint(observed)
                reminder = settings.siem_drift_alert_reminder_sec
                due = fingerprint != delivered or (reminder > 0 and now - last_sent >= reminder)
                queued = conn.execute("SELECT payload FROM outbox WHERE hunt=?", (hunt,)).fetchone()
                cards = (
                    {_query_key(query): query for query in json.loads(queued[0])} if queued else {}
                )
                cards.update({_query_key(query): query for query in groups.get(hunt, [])})
                payload = [
                    query for key, query in cards.items() if observed.get(key) == _condition(query)
                ]
                if payload and due:
                    conn.execute(
                        """INSERT INTO outbox(hunt,generation,fingerprint,payload) VALUES(?,?,?,?)
                        ON CONFLICT(hunt) DO UPDATE SET generation=excluded.generation,
                        fingerprint=excluded.fingerprint, payload=excluded.payload,
                        attempts=0, next_attempt=0
                        WHERE outbox.generation!=excluded.generation OR outbox.fingerprint!=excluded.fingerprint""",
                        (hunt, generation, fingerprint, json.dumps(payload)),
                    )
                else:
                    conn.execute("DELETE FROM outbox WHERE hunt=?", (hunt,))
                conn.execute(
                    "INSERT OR REPLACE INTO alerts(hunt,observed,delivered,last_sent,generation) VALUES (?, ?, ?, ?, ?)",
                    (
                        hunt,
                        json.dumps(observed),
                        delivered,
                        last_sent,
                        generation,
                    ),
                )
            # A complete successful sweep also resolves queries removed from the catalog.
            if (
                report.get("complete_sweep", True)
                and not report.get("error_count", 0)
                and (settings.hecate_workspace / "queries").is_dir()
            ):
                for hunt in previous.keys() - hunts.keys():
                    conn.execute("DELETE FROM alerts WHERE hunt = ?", (hunt,))
                    conn.execute("DELETE FROM outbox WHERE hunt = ?", (hunt,))
    finally:
        conn.close()
    if send is not None:
        deliver_drift_alerts(settings, send, now=now)


def deliver_drift_alerts(
    settings: Settings,
    send: Callable[..., tuple[bool, str]],
    *,
    now: float | None = None,
    max_items: int = 20,
) -> int:
    """Deliver bounded due work, using short claim/ack transactions.

    A per-hunt process lock prevents concurrent delivery even if a slow sender
    outlives its lease. A crash releases the lock; its durable claim is retried
    after expiry. Acknowledgements cannot overwrite a newer observed condition.
    """

    def clock() -> float:
        return now if now is not None else time.time()

    conn = _connect(settings)
    delivered_count = 0
    try:
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            _initialize(conn)
        candidates = conn.execute(
            "SELECT hunt FROM outbox WHERE next_attempt<=? AND lease_until<=? ORDER BY rowid LIMIT ?",
            (clock(), clock(), max_items),
        ).fetchall()
        for candidate in candidates:
            hunt = candidate[0]
            lock = acquire_work_lock(
                settings.hecate_workspace
                / ".hecate/siem/alert-locks"
                / (_fingerprint(hunt) + ".lock")
            )
            if lock is None:
                continue
            with lock:
                token = uuid.uuid4().hex
                with conn:
                    conn.execute("BEGIN IMMEDIATE")
                    row = conn.execute(
                        "SELECT * FROM outbox WHERE hunt=? AND next_attempt<=? AND lease_until<=?",
                        (hunt, clock(), clock()),
                    ).fetchone()
                    if row is None:
                        continue
                    conn.execute(
                        "UPDATE outbox SET claim_token=?,lease_until=? WHERE hunt=?",
                        (token, clock() + _LEASE_SEC, hunt),
                    )
                # The transaction is committed before any external request.
                try:
                    success, _ = send(settings, hunt, json.loads(row["payload"]))
                except Exception as exc:
                    log.warning(
                        "Could not deliver drift alert for %s (%s)", hunt, type(exc).__name__
                    )
                    success = False
                with conn:
                    conn.execute("BEGIN IMMEDIATE")
                    current = conn.execute(
                        "SELECT * FROM outbox WHERE hunt=? AND claim_token=?", (hunt, token)
                    ).fetchone()
                    if current is None:
                        continue
                    same = (current["generation"], current["fingerprint"]) == (
                        row["generation"],
                        row["fingerprint"],
                    )
                    alert = conn.execute(
                        "SELECT generation,observed FROM alerts WHERE hunt=?", (hunt,)
                    ).fetchone()
                    same = (
                        same
                        and alert is not None
                        and alert["generation"] == row["generation"]
                        and _fingerprint(json.loads(alert["observed"])) == row["fingerprint"]
                    )
                    if success and same:
                        conn.execute(
                            "UPDATE alerts SET delivered=?,last_sent=? WHERE hunt=? AND generation=?",
                            (row["fingerprint"], clock(), hunt, row["generation"]),
                        )
                        conn.execute(
                            "DELETE FROM outbox WHERE hunt=? AND claim_token=?", (hunt, token)
                        )
                        delivered_count += 1
                    else:
                        attempts = row["attempts"] + 1 if same else 0
                        delay = min(30 * 2 ** min(attempts - 1, 7), 3600) if attempts else 0
                        conn.execute(
                            "UPDATE outbox SET claim_token=NULL,lease_until=0,attempts=?,next_attempt=? WHERE hunt=? AND claim_token=?",
                            (attempts, clock() + delay, hunt, token),
                        )
    finally:
        conn.close()
    return delivered_count
