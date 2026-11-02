"""Detection-as-Code SIEM query drift auditing and automated reconciliation engine.

Provides automated periodic and on-demand synchronization sweeps across target SIEMs
and EDR platforms to detect out-of-band rule modifications, deletions, or configuration drift,
and offers one-click automated reconciliation back to git-authoritative Sigma definitions.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.slack_bot import sync_queries_for_hunt
from hecate_runner.sqlite_utils import connect_sqlite

log = logging.getLogger(__name__)


def audit_workspace_queries(
    workspace: Path,
    target: str | None = None,
    dry_run: bool = True,
    trigger: str = "cli",
) -> dict[str, Any]:
    """Audit all hunting queries in workspace against live or simulated SIEM/EDR platforms.

    Args:
        workspace: Path to the root Hecate workspace.
        target: Optional platform filter (e.g. 'splunk_spl', 'sentinel_kql').
        dry_run: When True, simulates the sync check without making network calls.
        trigger: Operational trigger initiating the audit ('cli', 'daemon', 'slack:<user>').

    Returns:
        Structured audit report including aggregated counts and per-hunt breakdown.
    """
    queries_root = workspace / "queries"
    if not queries_root.exists():
        log.warning("No queries directory found at %s", queries_root)
        return {
            "total_hunts": 0,
            "total_queries": 0,
            "in_sync_count": 0,
            "drifted_count": 0,
            "missing_count": 0,
            "error_count": 0,
            "hunts": {},
            "drifted_by_hunt": {},
            "missing_by_hunt": {},
            "audited_at": datetime.now(UTC).isoformat(),
            "dry_run": dry_run,
        }

    hunt_dirs = sorted([d for d in queries_root.iterdir() if d.is_dir()])
    total_queries = 0
    in_sync_count = 0
    drifted_count = 0
    missing_count = 0
    error_count = 0

    all_hunts: dict[str, list[dict[str, Any]]] = {}
    drifted_by_hunt: dict[str, list[dict[str, Any]]] = {}
    missing_by_hunt: dict[str, list[dict[str, Any]]] = {}

    for h_dir in hunt_dirs:
        hunt_id = h_dir.name
        results = sync_queries_for_hunt(workspace, hunt_id, dry_run=dry_run, target=target)
        if not results:
            continue

        all_hunts[hunt_id] = results
        total_queries += len(results)

        hunt_drifted: list[dict[str, Any]] = []
        hunt_missing: list[dict[str, Any]] = []

        for r in results:
            status = r.get("status")
            if status == "in_sync" or (dry_run and status == "dry_run"):
                in_sync_count += 1
            elif status == "drift_detected":
                drifted_count += 1
                hunt_drifted.append(r)
            elif status == "missing_remote":
                missing_count += 1
                hunt_missing.append(r)
            elif status == "error":
                error_count += 1

        if hunt_drifted:
            drifted_by_hunt[hunt_id] = hunt_drifted
        if hunt_missing:
            missing_by_hunt[hunt_id] = hunt_missing

    report = {
        "total_hunts": len(all_hunts),
        "total_queries": total_queries,
        "in_sync_count": in_sync_count,
        "drifted_count": drifted_count,
        "missing_count": missing_count,
        "error_count": error_count,
        "hunts": all_hunts,
        "drifted_by_hunt": drifted_by_hunt,
        "missing_by_hunt": missing_by_hunt,
        "audited_at": datetime.now(UTC).isoformat(),
        "dry_run": dry_run,
    }

    try:
        save_drift_state(workspace, report)
    except Exception as exc:
        log.warning("Could not persist drift state cache: %s", exc)

    try:
        record_audit_sweep(workspace, report, trigger=trigger, target_filter=target)
    except Exception as exc:
        log.warning("Could not record drift audit sweep in SQLite: %s", exc)

    return report


def reconcile_hunt_queries(
    workspace: Path,
    hunt_id: str,
    target: str | None = None,
    dry_run: bool = True,
    force: bool = False,
    actor: str = "cli",
) -> list[dict[str, Any]]:
    """Reconcile drifted or missing queries for a hunt back to the git-authoritative definitions.

    Args:
        workspace: Path to the root Hecate workspace.
        hunt_id: Target hunt ID (e.g. 'H-0007').
        target: Optional platform filter (e.g. 'splunk_spl').
        dry_run: When True, simulates the reconciliation push without mutating remote SIEM.
        force: If True, redeploys all queries regardless of current sync status.
        actor: Actor initiating the reconciliation ('cli', 'daemon', 'slack:<user>').

    Returns:
        List of reconciliation outcomes for each query.
    """
    from hecate_agent.api import deploy_transpiled_query, sync_transpiled_query

    query_dir = workspace / "queries" / hunt_id
    if not query_dir.exists():
        log.warning("Query directory not found for %s at %s", hunt_id, query_dir)
        return []

    query_exts = {
        ".kql": "sentinel_kql",
        ".cql": "crowdstrike_cql",
        ".leql": "rapid7_leql",
        ".s1ql": "sentinelone_s1ql",
        ".spl": "splunk_spl",
        ".eql": "elastic_eql",
    }

    # First discover current sync status unless forcing complete re-deploy
    current_sync = sync_queries_for_hunt(workspace, hunt_id, dry_run=dry_run, target=target)
    sync_map = {f"{item['file']}:{item['target']}": item for item in current_sync}

    reconciliation_results: list[dict[str, Any]] = []

    for q_file in sorted(query_dir.iterdir()):
        tgt = query_exts.get(q_file.suffix.lower())
        if not tgt:
            continue
        if target and target.lower() != tgt.lower():
            continue

        key = f"{q_file.name}:{tgt}"
        current = sync_map.get(key)
        prev_status = current.get("status") if current else "unknown"

        # Only reconcile if drifted, missing, or force is requested
        if not force and prev_status in {"in_sync", "dry_run"}:
            continue

        q_text = q_file.read_text(encoding="utf-8").strip()
        title = q_file.stem.replace("__", " - ").replace("_", " ").title()

        # Deploy git-authoritative query
        deploy_res = deploy_transpiled_query(
            target=tgt,
            query=q_text,
            hunt_id=hunt_id,
            title=title,
            dry_run=dry_run,
        )

        remote_id = deploy_res.get("remote_id")
        post_status = "in_sync" if dry_run else "reconciled"
        detail = deploy_res.get("detail", "")
        ok = deploy_res.get("ok", False)

        if not dry_run and ok:
            # Re-verify sync status live
            sync_check = sync_transpiled_query(
                target=tgt,
                query=q_text,
                hunt_id=hunt_id,
                title=title,
                dry_run=False,
            )
            post_status = sync_check.get("status", "in_sync")
            if sync_check.get("ok"):
                detail = f"Successfully reconciled and verified in sync with {tgt}"

        rec_outcome = {
            "file": q_file.name,
            "target": tgt,
            "remote_id": remote_id,
            "previous_status": prev_status,
            "status": post_status,
            "ok": ok and (post_status in {"in_sync", "dry_run", "reconciled"}),
            "detail": detail,
            "request_summary": deploy_res.get("request_summary", {}),
        }
        reconciliation_results.append(rec_outcome)

        if not dry_run:
            try:
                record_reconciliation_event(
                    workspace=workspace,
                    hunt_id=hunt_id,
                    rec_result=rec_outcome,
                    query_content=q_text,
                    actor=actor,
                )
            except Exception as exc:
                log.warning("Could not record reconciliation event in SQLite: %s", exc)

    return reconciliation_results


def reconcile_all_drifted_queries(
    workspace: Path,
    target: str | None = None,
    dry_run: bool = True,
    actor: str = "cli",
) -> dict[str, Any]:
    """Audit the workspace and automatically reconcile all detected query drift and missing rules.

    Args:
        workspace: Path to the root Hecate workspace.
        target: Optional platform filter.
        dry_run: When True, simulates the reconciliation.
        actor: Actor initiating the reconciliation ('cli', 'daemon', 'slack:<user>').

    Returns:
        Aggregated reconciliation summary.
    """
    audit = audit_workspace_queries(workspace, target=target, dry_run=dry_run, trigger=actor)
    hunts_to_reconcile = set(audit.get("drifted_by_hunt", {}).keys()) | set(
        audit.get("missing_by_hunt", {}).keys()
    )

    reconciled_by_hunt: dict[str, list[dict[str, Any]]] = {}
    total_reconciled = 0
    total_failed = 0

    for hunt_id in sorted(hunts_to_reconcile):
        results = reconcile_hunt_queries(
            workspace, hunt_id, target=target, dry_run=dry_run, actor=actor
        )
        if results:
            reconciled_by_hunt[hunt_id] = results
            for r in results:
                if r.get("ok"):
                    total_reconciled += 1
                else:
                    total_failed += 1

    return {
        "hunts_count": len(reconciled_by_hunt),
        "total_reconciled": total_reconciled,
        "total_failed": total_failed,
        "by_hunt": reconciled_by_hunt,
        "dry_run": dry_run,
        "reconciled_at": datetime.now(UTC).isoformat(),
    }


def save_drift_state(workspace: Path, state_data: dict[str, Any]) -> Path:
    """Persist latest drift audit state cache under .hecate/siem/drift_state.json."""
    cache_path = workspace / ".hecate" / "siem" / "drift_state.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(cache_path, json.dumps(state_data, indent=2))
    return cache_path


def load_drift_state(workspace: Path) -> dict[str, Any] | None:
    """Load cached drift state from .hecate/siem/drift_state.json if available."""
    cache_path = workspace / ".hecate" / "siem" / "drift_state.json"
    if not cache_path.exists():
        return None
    try:
        return json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("Failed to read drift state file at %s: %s", cache_path, exc)
        return None


def get_drift_db_path(workspace: Path) -> Path:
    """Return path to SQLite drift history database."""
    return workspace / ".hecate" / "siem" / "drift_history.db"


def init_drift_db(workspace: Path) -> sqlite3.Connection:
    """Initialize and return SQLite connection for SIEM drift history and versioning."""
    db_path = get_drift_db_path(workspace)
    conn = connect_sqlite(db_path)
    with conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit_sweeps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_hunts INTEGER NOT NULL,
                total_queries INTEGER NOT NULL,
                in_sync_count INTEGER NOT NULL,
                drifted_count INTEGER NOT NULL,
                missing_count INTEGER NOT NULL,
                error_count INTEGER NOT NULL,
                dry_run INTEGER NOT NULL,
                target TEXT,
                trigger TEXT NOT NULL DEFAULT 'cli'
            );

            CREATE TABLE IF NOT EXISTS drift_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sweep_id INTEGER,
                timestamp TEXT NOT NULL,
                hunt_id TEXT NOT NULL,
                target TEXT NOT NULL,
                file_name TEXT NOT NULL,
                remote_id TEXT,
                event_type TEXT NOT NULL,
                previous_status TEXT,
                new_status TEXT,
                local_query TEXT,
                remote_query TEXT,
                drift_diff TEXT,
                detail TEXT,
                actor TEXT NOT NULL DEFAULT 'system',
                FOREIGN KEY (sweep_id) REFERENCES audit_sweeps(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS query_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hunt_id TEXT NOT NULL,
                target TEXT NOT NULL,
                file_name TEXT NOT NULL,
                remote_id TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                query_hash TEXT NOT NULL,
                query_content TEXT NOT NULL,
                deployed_at TEXT NOT NULL,
                deployed_by TEXT NOT NULL DEFAULT 'system',
                status TEXT NOT NULL DEFAULT 'active'
            );

            CREATE INDEX IF NOT EXISTS idx_drift_events_hunt_id ON drift_events(hunt_id);
            CREATE INDEX IF NOT EXISTS idx_drift_events_target ON drift_events(target);
            CREATE INDEX IF NOT EXISTS idx_drift_events_timestamp ON drift_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_drift_events_type ON drift_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_audit_sweeps_timestamp ON audit_sweeps(timestamp);
            CREATE INDEX IF NOT EXISTS idx_query_versions_lookup ON query_versions(hunt_id, target, file_name);
            """
        )
    return conn


def record_audit_sweep(
    workspace: Path,
    report: dict[str, Any],
    trigger: str = "cli",
    target_filter: str | None = None,
) -> int:
    """Record an audit sweep and associated drift/missing events into SQLite history."""
    conn = init_drift_db(workspace)
    now_iso = report.get("audited_at") or datetime.now(UTC).isoformat()
    try:
        with conn:
            cur = conn.execute(
                """
                INSERT INTO audit_sweeps (
                    timestamp, total_hunts, total_queries, in_sync_count,
                    drifted_count, missing_count, error_count, dry_run, target, trigger
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now_iso,
                    report.get("total_hunts", 0),
                    report.get("total_queries", 0),
                    report.get("in_sync_count", 0),
                    report.get("drifted_count", 0),
                    report.get("missing_count", 0),
                    report.get("error_count", 0),
                    1 if report.get("dry_run") else 0,
                    target_filter,
                    trigger,
                ),
            )
            sweep_id = cur.lastrowid or 0

            drifted_by_hunt = report.get("drifted_by_hunt", {})
            for hunt_id, items in drifted_by_hunt.items():
                for item in items:
                    conn.execute(
                        """
                        INSERT INTO drift_events (
                            sweep_id, timestamp, hunt_id, target, file_name,
                            remote_id, event_type, previous_status, new_status,
                            local_query, remote_query, drift_diff, detail, actor
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sweep_id,
                            now_iso,
                            hunt_id,
                            item.get("target", "unknown"),
                            item.get("file", ""),
                            item.get("remote_id"),
                            "drift_detected",
                            "drift_detected",
                            "drift_detected",
                            item.get("local_query"),
                            item.get("remote_query"),
                            item.get("drift_diff"),
                            item.get("detail"),
                            trigger,
                        ),
                    )

            missing_by_hunt = report.get("missing_by_hunt", {})
            for hunt_id, items in missing_by_hunt.items():
                for item in items:
                    conn.execute(
                        """
                        INSERT INTO drift_events (
                            sweep_id, timestamp, hunt_id, target, file_name,
                            remote_id, event_type, previous_status, new_status,
                            local_query, remote_query, drift_diff, detail, actor
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sweep_id,
                            now_iso,
                            hunt_id,
                            item.get("target", "unknown"),
                            item.get("file", ""),
                            item.get("remote_id"),
                            "missing_remote",
                            "missing_remote",
                            "missing_remote",
                            item.get("local_query"),
                            None,
                            None,
                            item.get("detail"),
                            trigger,
                        ),
                    )
        return sweep_id
    finally:
        conn.close()


def record_query_version(
    workspace: Path,
    hunt_id: str,
    target: str,
    file_name: str,
    query_content: str,
    remote_id: str,
    deployed_by: str = "cli",
) -> int:
    """Record a deployed query version in query_versions.

    Returns the assigned version number.
    """
    conn = init_drift_db(workspace)
    q_hash = hashlib.sha256(query_content.strip().encode("utf-8")).hexdigest()
    now_iso = datetime.now(UTC).isoformat()

    try:
        with conn:
            cur = conn.execute(
                """
                SELECT version, query_hash FROM query_versions
                WHERE hunt_id = ? AND target = ? AND file_name = ?
                ORDER BY version DESC LIMIT 1
                """,
                (hunt_id, target, file_name),
            )
            row = cur.fetchone()
            if row:
                latest_version, latest_hash = row[0], row[1]
                if latest_hash == q_hash:
                    return latest_version
                new_version = latest_version + 1
            else:
                new_version = 1

            conn.execute(
                """
                INSERT INTO query_versions (
                    hunt_id, target, file_name, remote_id, version,
                    query_hash, query_content, deployed_at, deployed_by, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hunt_id,
                    target,
                    file_name,
                    remote_id,
                    new_version,
                    q_hash,
                    query_content.strip(),
                    now_iso,
                    deployed_by,
                    "active",
                ),
            )
        return new_version
    finally:
        conn.close()


def record_reconciliation_event(
    workspace: Path,
    hunt_id: str,
    rec_result: dict[str, Any],
    query_content: str | None = None,
    actor: str = "cli",
) -> int:
    """Record a reconciliation outcome in drift_events and query_versions."""
    conn = init_drift_db(workspace)
    now_iso = datetime.now(UTC).isoformat()
    ok = rec_result.get("ok", False)
    event_type = "reconciled" if ok else "deploy_failed"
    target = rec_result.get("target", "unknown")
    file_name = rec_result.get("file", "")
    remote_id = rec_result.get("remote_id")

    try:
        with conn:
            cur = conn.execute(
                """
                INSERT INTO drift_events (
                    sweep_id, timestamp, hunt_id, target, file_name,
                    remote_id, event_type, previous_status, new_status,
                    local_query, remote_query, drift_diff, detail, actor
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    None,
                    now_iso,
                    hunt_id,
                    target,
                    file_name,
                    remote_id,
                    event_type,
                    rec_result.get("previous_status"),
                    rec_result.get("status"),
                    query_content,
                    None,
                    None,
                    rec_result.get("detail"),
                    actor,
                ),
            )
            event_id = cur.lastrowid or 0
    finally:
        conn.close()

    if ok and query_content and remote_id:
        try:
            record_query_version(
                workspace=workspace,
                hunt_id=hunt_id,
                target=target,
                file_name=file_name,
                query_content=query_content,
                remote_id=remote_id,
                deployed_by=actor,
            )
        except Exception as exc:
            log.warning("Failed to record query version on reconciliation: %s", exc)

    return event_id


def get_drift_history(
    workspace: Path,
    hunt_id: str | None = None,
    target: str | None = None,
    event_type: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Retrieve historical drift and reconciliation events from SQLite."""
    conn = init_drift_db(workspace)
    conn.row_factory = sqlite3.Row
    query = "SELECT * FROM drift_events WHERE 1=1"
    params: list[Any] = []

    if hunt_id:
        query += " AND hunt_id = ?"
        params.append(hunt_id.upper())
    if target:
        query += " AND LOWER(target) = LOWER(?)"
        params.append(target)
    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)

    query += " ORDER BY timestamp DESC, id DESC LIMIT ?"
    params.append(limit)

    try:
        with conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
    finally:
        conn.close()


def get_query_versions(
    workspace: Path,
    hunt_id: str | None = None,
    target: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Retrieve deployed query version history from SQLite."""
    conn = init_drift_db(workspace)
    conn.row_factory = sqlite3.Row
    query = "SELECT * FROM query_versions WHERE 1=1"
    params: list[Any] = []

    if hunt_id:
        query += " AND hunt_id = ?"
        params.append(hunt_id.upper())
    if target:
        query += " AND LOWER(target) = LOWER(?)"
        params.append(target)

    query += " ORDER BY deployed_at DESC, id DESC LIMIT ?"
    params.append(limit)

    try:
        with conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
    finally:
        conn.close()


def get_siem_drift_metrics(workspace: Path, days: int = 7) -> dict[str, Any]:
    """Calculate aggregated SIEM drift metrics and operational health."""
    conn = init_drift_db(workspace)
    conn.row_factory = sqlite3.Row

    since_iso = (datetime.now(UTC) - timedelta(days=days)).isoformat()

    try:
        latest_sweep = None
        with conn:
            sweep_row = conn.execute(
                "SELECT * FROM audit_sweeps ORDER BY timestamp DESC, id DESC LIMIT 1"
            ).fetchone()
            if sweep_row:
                latest_sweep = dict(sweep_row)

        cached_state = load_drift_state(workspace)

        with conn:
            events_stats = conn.execute(
                """
                SELECT
                    COUNT(CASE WHEN event_type = 'drift_detected' THEN 1 END) as drift_count,
                    COUNT(CASE WHEN event_type = 'missing_remote' THEN 1 END) as missing_count,
                    COUNT(CASE WHEN event_type = 'reconciled' THEN 1 END) as reconciled_count,
                    COUNT(CASE WHEN event_type = 'deploy_failed' THEN 1 END) as failed_count,
                    COUNT(*) as total_events
                FROM drift_events
                WHERE timestamp >= ?
                """,
                (since_iso,),
            ).fetchone()

            sweeps_count = conn.execute(
                "SELECT COUNT(*) FROM audit_sweeps WHERE timestamp >= ?", (since_iso,)
            ).fetchone()[0]

            versions_count = conn.execute(
                "SELECT COUNT(DISTINCT hunt_id || target || file_name) FROM query_versions"
            ).fetchone()[0]

            target_breakdown = conn.execute(
                """
                SELECT target, COUNT(*) as cnt
                FROM drift_events
                WHERE event_type = 'drift_detected' AND timestamp >= ?
                GROUP BY target
                """,
                (since_iso,),
            ).fetchall()

            most_drifted = conn.execute(
                """
                SELECT hunt_id, COUNT(*) as drift_incidents
                FROM drift_events
                WHERE event_type = 'drift_detected' AND timestamp >= ?
                GROUP BY hunt_id
                ORDER BY drift_incidents DESC
                LIMIT 5
                """,
                (since_iso,),
            ).fetchall()
    finally:
        conn.close()

    target_map = {r["target"]: r["cnt"] for r in target_breakdown}
    top_hunts = [{"hunt_id": r["hunt_id"], "count": r["drift_incidents"]} for r in most_drifted]

    total_queries = 0
    in_sync_count = 0
    drifted_count = 0
    missing_count = 0
    sync_pct = 100.0
    last_audited = ""

    if latest_sweep:
        total_queries = latest_sweep.get("total_queries", 0)
        in_sync_count = latest_sweep.get("in_sync_count", 0)
        drifted_count = latest_sweep.get("drifted_count", 0)
        missing_count = latest_sweep.get("missing_count", 0)
        last_audited = latest_sweep.get("timestamp", "")
    elif cached_state:
        total_queries = cached_state.get("total_queries", 0)
        in_sync_count = cached_state.get("in_sync_count", 0)
        drifted_count = cached_state.get("drifted_count", 0)
        missing_count = cached_state.get("missing_count", 0)
        last_audited = cached_state.get("audited_at", "")

    if total_queries > 0:
        sync_pct = (in_sync_count / total_queries) * 100.0

    return {
        "sync_health_pct": round(sync_pct, 1),
        "total_queries": total_queries,
        "in_sync_count": in_sync_count,
        "drifted_count": drifted_count,
        "missing_count": missing_count,
        "last_audited": last_audited,
        "days_window": days,
        "sweeps_conducted": sweeps_count,
        "drift_incidents_period": events_stats["drift_count"] if events_stats else 0,
        "reconciliations_period": events_stats["reconciled_count"] if events_stats else 0,
        "failed_reconciliations_period": events_stats["failed_count"] if events_stats else 0,
        "tracked_query_versions": versions_count,
        "target_drift_breakdown": target_map,
        "top_drifted_hunts": top_hunts,
    }


def build_siem_markdown_report(
    report: dict[str, Any],
    title: str = "SIEM Detection-as-Code GitOps Report",
    trigger: str = "ci",
) -> str:
    """Generate a clean, GitHub Flavored Markdown report from an audit report.

    Suitable for PR comments, GITHUB_STEP_SUMMARY, and issue bodies.
    """
    total_h = report.get("total_hunts", 0)
    total_q = report.get("total_queries", 0)
    in_sync = report.get("in_sync_count", 0)
    drifted = report.get("drifted_count", 0)
    missing = report.get("missing_count", 0)
    errors = report.get("error_count", 0)
    dry_run = report.get("dry_run", True)
    audited_at = str(report.get("audited_at") or datetime.now(UTC).isoformat())

    sync_pct = round((in_sync / total_q) * 100.0, 1) if total_q > 0 else 100.0
    mode_str = "Simulated (Dry-Run)" if dry_run else "Live SIEM API"

    if drifted > 0:
        badge = f"⚠️ **DRIFT DETECTED** ({drifted} query{'s' if drifted != 1 else ''})"
    elif missing > 0:
        badge = f"⚠️ **MISSING ON REMOTE** ({missing} query{'s' if missing != 1 else ''})"
    elif errors > 0:
        badge = f"❌ **AUDIT ERRORS** ({errors} error{'s' if errors != 1 else ''})"
    elif total_q > 0:
        badge = "✅ **IN SYNC (100%)**"
    else:
        badge = "⚪ **STANDBY (0 queries)**"

    lines = [
        f"## 🛡️ {title}",
        "",
        f"> **Status:** {badge} | **Mode:** `{mode_str}` | **Audited At:** `{audited_at[:19].replace('T', ' ')} UTC`",
        "",
        "### 📊 Detection Sync Overview",
        "",
        "| Metric | Count | Ratio / Health |",
        "| :--- | :---: | :--- |",
        f"| **Total Hunts** | `{total_h}` | Monitored threat hunts |",
        f"| **Total Queries** | `{total_q}` | Transpiled query files |",
        f"| **In Sync** | `{in_sync}` | `{sync_pct}%` matching git HEAD |",
        f"| **Drifted** | `{drifted}` | {'⚠️ Needs reconciliation' if drifted > 0 else '🟢 Zero drift'} |",
        f"| **Missing on Remote** | `{missing}` | {'⚠️ Unindexed on target SIEM' if missing > 0 else '🟢 All deployed'} |",
        f"| **Errors** | `{errors}` | {'❌ API or transpilation error' if errors > 0 else '🟢 None'} |",
        "",
    ]

    target_counts: dict[str, dict[str, int]] = {}
    for hunt_id, results in report.get("hunts", {}).items():
        for res in results:
            tgt = str(res.get("target") or "unknown")
            st = str(res.get("status") or "unknown")
            if tgt not in target_counts:
                target_counts[tgt] = {"total": 0, "in_sync": 0, "drifted": 0, "missing": 0, "error": 0}
            target_counts[tgt]["total"] += 1
            if st == "in_sync":
                target_counts[tgt]["in_sync"] += 1
            elif st == "drift_detected":
                target_counts[tgt]["drifted"] += 1
            elif st == "missing_remote":
                target_counts[tgt]["missing"] += 1
            elif st == "error":
                target_counts[tgt]["error"] += 1

    if target_counts:
        lines.extend([
            "### 🎯 Target Platform Breakdown",
            "",
            "| Target Backend | Total Queries | In Sync | Drifted | Missing | Health |",
            "| :--- | :---: | :---: | :---: | :---: | :--- |",
        ])
        for tgt, counts in sorted(target_counts.items()):
            h_pct = round((counts["in_sync"] / counts["total"]) * 100, 1) if counts["total"] > 0 else 100.0
            if counts["drifted"] > 0:
                h_badge = "🔴 Drifted"
            elif counts["missing"] > 0:
                h_badge = "🟡 Missing"
            else:
                h_badge = "🟢 100% In Sync"
            lines.append(
                f"| `{tgt}` | `{counts['total']}` | `{counts['in_sync']}` | `{counts['drifted']}` | `{counts['missing']}` | {h_badge} (`{h_pct}%`) |"
            )
        lines.append("")

    drifted_by_hunt = report.get("drifted_by_hunt", {})
    if drifted_by_hunt:
        lines.extend([
            "### 🔍 Drift Inspection & AST Diff",
            "",
            "> ⚠️ *The following queries on remote SIEM consoles have drifted from local git repository source code:*",
            "",
        ])
        for hunt_id, res_list in sorted(drifted_by_hunt.items()):
            for res in res_list:
                file_name = res.get("file", "")
                tgt = res.get("target", "")
                remote_id = res.get("remote_id", "")
                diff = res.get("drift_diff", "")
                lines.extend([
                    "<details>",
                    f"<summary><b>⚠️ {hunt_id} / {tgt}: <code>{file_name}</code></b> (Remote ID: <code>{remote_id}</code>)</summary>",
                    "",
                    "```diff",
                    diff or "- Local and remote queries differ in AST syntax or query options",
                    "```",
                    "",
                    "</details>",
                    "",
                ])
    else:
        lines.extend([
            "### 🔍 Drift Inspection",
            "",
            "> ✅ **All deployed SIEM queries match git-authoritative AST and search definitions.** No active drift detected across targets.",
            "",
        ])

    lines.extend([
        "---",
        f"*Report generated by Hecate GitOps Detection Pipeline (trigger: `{trigger}`).*",
    ])

    return "\n".join(lines)
