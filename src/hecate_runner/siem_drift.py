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
from hecate_runner.lifecycle import get_hunt_lifecycle, set_hunt_lifecycle
from hecate_runner.slack_bot import sync_queries_for_hunt, undeploy_queries_for_hunt
from hecate_runner.sqlite_utils import connect_sqlite

log = logging.getLogger(__name__)


def get_tracked_query_statuses(workspace: Path) -> dict[tuple[str, str, str], str]:
    """Retrieve the latest deployment/lifecycle status for all queries from drift_history.db.

    Returns:
        Mapping of (hunt_id, target, file_name) -> status ('active', 'decommissioned', etc.)
    """
    db_path = get_drift_db_path(workspace)
    if not db_path.exists():
        return {}

    conn = connect_sqlite(db_path)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            rows = conn.execute(
                """
                SELECT qv.hunt_id, qv.target, qv.file_name, qv.status
                FROM query_versions qv
                INNER JOIN (
                    SELECT hunt_id, target, file_name, MAX(version) as max_ver
                    FROM query_versions
                    GROUP BY hunt_id, target, file_name
                ) latest ON qv.hunt_id = latest.hunt_id
                       AND qv.target = latest.target
                       AND qv.file_name = latest.file_name
                       AND qv.version = latest.max_ver
                """
            ).fetchall()
            return {
                (r["hunt_id"].upper(), r["target"].lower(), r["file_name"]): r["status"]
                for r in rows
            }
    except Exception as exc:
        log.debug("Could not retrieve tracked query statuses: %s", exc)
        return {}
    finally:
        conn.close()


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
            "decommissioned_count": 0,
            "pending_decommission_count": 0,
            "drifted_count": 0,
            "missing_count": 0,
            "error_count": 0,
            "hunts": {},
            "drifted_by_hunt": {},
            "missing_by_hunt": {},
            "decommissioned_by_hunt": {},
            "pending_decommission_by_hunt": {},
            "hunt_lifecycles": {},
            "audited_at": datetime.now(UTC).isoformat(),
            "dry_run": dry_run,
        }

    hunt_dirs = sorted([d for d in queries_root.iterdir() if d.is_dir()])
    total_queries = 0
    in_sync_count = 0
    decommissioned_count = 0
    pending_decommission_count = 0
    drifted_count = 0
    missing_count = 0
    error_count = 0

    all_hunts: dict[str, list[dict[str, Any]]] = {}
    drifted_by_hunt: dict[str, list[dict[str, Any]]] = {}
    missing_by_hunt: dict[str, list[dict[str, Any]]] = {}
    decommissioned_by_hunt: dict[str, list[dict[str, Any]]] = {}
    pending_decommission_by_hunt: dict[str, list[dict[str, Any]]] = {}
    hunt_lifecycles: dict[str, dict[str, Any]] = {}

    tracked_statuses = get_tracked_query_statuses(workspace)

    for h_dir in hunt_dirs:
        hunt_id = h_dir.name
        lifecycle = get_hunt_lifecycle(workspace, hunt_id)
        hunt_lifecycles[hunt_id] = lifecycle
        is_retired = lifecycle.get("is_retired", False)

        results = sync_queries_for_hunt(workspace, hunt_id, dry_run=dry_run, target=target)
        if not results:
            continue

        all_hunts[hunt_id] = results
        total_queries += len(results)

        hunt_drifted: list[dict[str, Any]] = []
        hunt_missing: list[dict[str, Any]] = []
        hunt_decommissioned: list[dict[str, Any]] = []
        hunt_pending: list[dict[str, Any]] = []

        for r in results:
            status = r.get("status")
            tgt = str(r.get("target") or "unknown").lower()
            fname = str(r.get("file") or "")
            ver_status = tracked_statuses.get((hunt_id.upper(), tgt, fname), "active")
            is_query_decommissioned = (ver_status in ("decommissioned", "retired")) or is_retired

            if status == "missing_remote":
                if is_query_decommissioned:
                    # Clean/expected decommissioning: rule was intentionally removed from SIEM
                    r["status"] = "decommissioned"
                    r["is_decommissioned"] = True
                    r["detail"] = f"Decommissioned (hunt_status={lifecycle.get('status')})"
                    decommissioned_count += 1
                    hunt_decommissioned.append(r)
                else:
                    missing_count += 1
                    hunt_missing.append(r)
            elif status == "in_sync" or (dry_run and status == "dry_run"):
                if is_retired:
                    # Anomaly: Hunt is marked retired in git, but Saved Search is still active in SIEM!
                    r["status"] = "pending_decommission"
                    r["detail"] = "Hunt retired in git, but rule is still active on remote SIEM"
                    pending_decommission_count += 1
                    hunt_pending.append(r)
                else:
                    in_sync_count += 1
            elif status == "drift_detected":
                if is_retired:
                    r["status"] = "pending_decommission"
                    r["detail"] = "Hunt retired in git, but rule is still active on remote SIEM"
                    pending_decommission_count += 1
                    hunt_pending.append(r)
                else:
                    drifted_count += 1
                    hunt_drifted.append(r)
            elif status == "error":
                error_count += 1

        if hunt_drifted:
            drifted_by_hunt[hunt_id] = hunt_drifted
        if hunt_missing:
            missing_by_hunt[hunt_id] = hunt_missing
        if hunt_decommissioned:
            decommissioned_by_hunt[hunt_id] = hunt_decommissioned
        if hunt_pending:
            pending_decommission_by_hunt[hunt_id] = hunt_pending

    report = {
        "total_hunts": len(all_hunts),
        "total_queries": total_queries,
        "in_sync_count": in_sync_count,
        "decommissioned_count": decommissioned_count,
        "pending_decommission_count": pending_decommission_count,
        "drifted_count": drifted_count,
        "missing_count": missing_count,
        "error_count": error_count,
        "hunts": all_hunts,
        "drifted_by_hunt": drifted_by_hunt,
        "missing_by_hunt": missing_by_hunt,
        "decommissioned_by_hunt": decommissioned_by_hunt,
        "pending_decommission_by_hunt": pending_decommission_by_hunt,
        "hunt_lifecycles": hunt_lifecycles,
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

    # First check hunt lifecycle: if retired, do not reconcile
    lifecycle = get_hunt_lifecycle(workspace, hunt_id)
    if lifecycle.get("is_retired"):
        log.info("Skipping reconciliation for retired hunt %s", hunt_id)
        return []

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
        if not force and prev_status in {"in_sync", "dry_run", "decommissioned"}:
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


def decommission_hunt_queries(
    workspace: Path,
    hunt_id: str,
    dry_run: bool = True,
    target: str | None = None,
    reason: str = "Decommissioned via Query Lifecycle Management",
    actor: str = "analyst",
    retire_hunt: bool = False,
) -> dict[str, Any]:
    """Decommission and undeploy queries for a hunt from target SIEM/EDR platforms.

    Updates query version state to 'decommissioned', records decommissioning provenance
    and sign-off in drift_events, and optionally transitions the hunt lifecycle in frontmatter
    to 'retired'.

    Args:
        workspace: Path to the root Hecate workspace.
        hunt_id: Hunt identifier (e.g. 'H-0011') or 'all'.
        dry_run: When True, simulates the undeployment and database update.
        target: Optional platform filter (e.g. 'splunk_spl').
        reason: Analyst rationale for decommissioning.
        actor: Analyst or system signing off on decommissioning.
        retire_hunt: If True, marks the hunt frontmatter lifecycle as 'retired'.

    Returns:
        Structured decommissioning summary dict.
    """
    queries_root = workspace / "queries"
    if hunt_id.lower() == "all":
        hunts = sorted(
            [d.name for d in queries_root.iterdir() if d.is_dir() and d.name.startswith("H-")]
        )
    else:
        hunts = [hunt_id]

    all_results: list[dict[str, Any]] = []
    total_queries = 0
    total_decommissioned = 0
    now_iso = datetime.now(UTC).isoformat()

    conn = init_drift_db(workspace)
    try:
        for h_id in hunts:
            if retire_hunt:
                try:
                    set_hunt_lifecycle(
                        workspace=workspace,
                        hunt_id=h_id,
                        new_status="retired",
                        reason=reason,
                        actor=actor,
                    )
                except Exception as exc:
                    log.warning("Could not update lifecycle to retired for %s: %s", h_id, exc)

            undeployments = undeploy_queries_for_hunt(
                workspace=workspace,
                hunt_id=h_id,
                dry_run=dry_run,
                target=target,
            )

            for res in undeployments:
                total_queries += 1
                f_name = str(res.get("file", ""))
                tgt = str(res.get("target", "unknown")).lower()
                rem_id = str(res.get("remote_id") or "")
                ok = res.get("ok", False)

                if ok:
                    total_decommissioned += 1

                res_record = {
                    "hunt_id": h_id,
                    "file": f_name,
                    "target": tgt,
                    "remote_id": rem_id,
                    "status": res.get("status"),
                    "ok": ok,
                    "detail": res.get("detail", ""),
                    "reason": reason,
                    "actor": actor,
                    "retired_hunt": retire_hunt,
                }
                all_results.append(res_record)

                if not dry_run and ok:
                    with conn:
                        # Mark existing query version as decommissioned
                        cur = conn.execute(
                            """
                            UPDATE query_versions
                            SET status = 'decommissioned'
                            WHERE hunt_id = ? AND LOWER(target) = ? AND file_name = ?
                            """,
                            (h_id, tgt, f_name),
                        )
                        if cur.rowcount == 0:
                            # Record baseline row if not tracked before
                            conn.execute(
                                """
                                INSERT INTO query_versions (
                                    hunt_id, target, file_name, remote_id, version,
                                    query_hash, query_content, deployed_at, deployed_by, status
                                ) VALUES (?, ?, ?, ?, 1, '', '', ?, ?, 'decommissioned')
                                """,
                                (h_id, tgt, f_name, rem_id, now_iso, actor),
                            )

                        # Insert decommission event into drift_events
                        conn.execute(
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
                                h_id,
                                tgt,
                                f_name,
                                rem_id,
                                "decommissioned",
                                "active",
                                "decommissioned",
                                None,
                                None,
                                None,
                                f"Decommissioned: {reason}",
                                actor,
                            ),
                        )
    finally:
        conn.close()

    summary = {
        "hunt_id": hunt_id,
        "total_hunts": len(hunts),
        "total_queries": total_queries,
        "total_decommissioned": total_decommissioned,
        "dry_run": dry_run,
        "reason": reason,
        "actor": actor,
        "retired_hunt": retire_hunt,
        "decommissioned_at": now_iso,
        "results": all_results,
    }

    # Refresh audit state cache
    try:
        audit_workspace_queries(
            workspace, target=target, dry_run=dry_run, trigger=f"decommission:{actor}"
        )
    except Exception as exc:
        log.warning("Could not refresh drift state after decommissioning: %s", exc)

    return summary


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
        cached: dict[str, Any] = json.loads(cache_path.read_text(encoding="utf-8"))
        return cached
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
                decommissioned_count INTEGER NOT NULL DEFAULT 0,
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

            CREATE TABLE IF NOT EXISTS detection_validations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                hunt_id TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                ability_id TEXT,
                bas_provider TEXT NOT NULL,
                siem_backend TEXT NOT NULL,
                status TEXT NOT NULL,
                rule_triggered INTEGER NOT NULL,
                telemetry_arrived INTEGER NOT NULL,
                detection_latency_sec REAL,
                matched_events_count INTEGER NOT NULL,
                query_used TEXT,
                search_job_id TEXT,
                detonation_time_utc TEXT NOT NULL,
                notes TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_detection_validations_hunt ON detection_validations(hunt_id);
            CREATE INDEX IF NOT EXISTS idx_detection_validations_technique ON detection_validations(technique_id);
            CREATE INDEX IF NOT EXISTS idx_detection_validations_timestamp ON detection_validations(timestamp);
            """
        )

    # Backwards-compatible schema migration
    try:
        with conn:
            conn.execute(
                "ALTER TABLE audit_sweeps ADD COLUMN decommissioned_count INTEGER NOT NULL DEFAULT 0"
            )
    except sqlite3.OperationalError:
        pass

    return conn


def record_audit_sweep(
    workspace: Path,
    report: dict[str, Any],
    trigger: str = "cli",
    target_filter: str | None = None,
) -> int:
    """Record an audit sweep and associated drift/missing/decommission events into SQLite history."""
    conn = init_drift_db(workspace)
    now_iso = report.get("audited_at") or datetime.now(UTC).isoformat()
    try:
        with conn:
            cur = conn.execute(
                """
                INSERT INTO audit_sweeps (
                    timestamp, total_hunts, total_queries, in_sync_count,
                    decommissioned_count, drifted_count, missing_count, error_count, dry_run, target, trigger
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now_iso,
                    report.get("total_hunts", 0),
                    report.get("total_queries", 0),
                    report.get("in_sync_count", 0),
                    report.get("decommissioned_count", 0),
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

            pending_by_hunt = report.get("pending_decommission_by_hunt", {})
            for hunt_id, items in pending_by_hunt.items():
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
                            "pending_decommission",
                            "active",
                            "pending_decommission",
                            item.get("local_query"),
                            item.get("remote_query"),
                            item.get("drift_diff"),
                            item.get("detail", "Hunt retired but rule active on SIEM"),
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
                latest_version, latest_hash = int(row[0]), row[1]
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


def record_detection_validation(
    workspace: Path,
    hunt_id: str,
    technique_id: str,
    ability_id: str | None = None,
    bas_provider: str = "mock",
    siem_backend: str = "splunk",
    status: str = "verified_true_positive",
    rule_triggered: bool = True,
    telemetry_arrived: bool = True,
    detection_latency_sec: float | None = None,
    matched_events_count: int = 1,
    query_used: str = "",
    search_job_id: str = "",
    detonation_time_utc: str = "",
    notes: str = "",
) -> int:
    """Record a closed-loop BAS adversary emulation and SIEM alert verification result."""
    conn = init_drift_db(workspace)
    now_iso = datetime.now(UTC).isoformat()
    try:
        with conn:
            cur = conn.execute(
                """
                INSERT INTO detection_validations (
                    timestamp, hunt_id, technique_id, ability_id,
                    bas_provider, siem_backend, status, rule_triggered,
                    telemetry_arrived, detection_latency_sec, matched_events_count,
                    query_used, search_job_id, detonation_time_utc, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now_iso,
                    hunt_id,
                    technique_id,
                    ability_id or "",
                    bas_provider,
                    siem_backend,
                    status,
                    1 if rule_triggered else 0,
                    1 if telemetry_arrived else 0,
                    detection_latency_sec,
                    matched_events_count,
                    query_used,
                    search_job_id,
                    detonation_time_utc or now_iso,
                    notes,
                ),
            )
            return cur.lastrowid or 0
    finally:
        conn.close()


def get_detection_validations(
    workspace: Path, hunt_id: str | None = None, limit: int = 50
) -> list[dict[str, Any]]:
    """Retrieve chronological detection validation results from drift_history.db."""
    conn = init_drift_db(workspace)
    conn.row_factory = sqlite3.Row
    query = "SELECT * FROM detection_validations"
    params: list[Any] = []
    if hunt_id:
        query += " WHERE UPPER(hunt_id) = UPPER(?)"
        params.append(hunt_id)
    query += " ORDER BY timestamp DESC, id DESC LIMIT ?"
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
                    COUNT(CASE WHEN event_type = 'decommissioned' THEN 1 END) as decommissioned_count,
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

            val_stats = conn.execute(
                """
                SELECT
                    COUNT(*) as total_validations,
                    COUNT(CASE WHEN status = 'verified_true_positive' THEN 1 END) as verified_count,
                    AVG(CASE WHEN status = 'verified_true_positive' THEN detection_latency_sec END) as avg_latency_sec
                FROM detection_validations
                WHERE timestamp >= ?
                """,
                (since_iso,),
            ).fetchone()

            latest_val = conn.execute(
                """
                SELECT * FROM detection_validations
                ORDER BY timestamp DESC, id DESC LIMIT 1
                """
            ).fetchone()
    finally:
        conn.close()

    target_map = {r["target"]: r["cnt"] for r in target_breakdown}
    top_hunts = [{"hunt_id": r["hunt_id"], "count": r["drift_incidents"]} for r in most_drifted]

    total_queries = 0
    in_sync_count = 0
    decommissioned_count = 0
    pending_decommission_count = 0
    drifted_count = 0
    missing_count = 0
    sync_pct = 100.0
    last_audited = ""

    if latest_sweep:
        total_queries = latest_sweep.get("total_queries", 0)
        in_sync_count = latest_sweep.get("in_sync_count", 0)
        decommissioned_count = latest_sweep.get("decommissioned_count", 0)
        drifted_count = latest_sweep.get("drifted_count", 0)
        missing_count = latest_sweep.get("missing_count", 0)
        last_audited = latest_sweep.get("timestamp", "")
    elif cached_state:
        total_queries = cached_state.get("total_queries", 0)
        in_sync_count = cached_state.get("in_sync_count", 0)
        decommissioned_count = cached_state.get("decommissioned_count", 0)
        pending_decommission_count = cached_state.get("pending_decommission_count", 0)
        drifted_count = cached_state.get("drifted_count", 0)
        missing_count = cached_state.get("missing_count", 0)
        last_audited = cached_state.get("audited_at", "")

    active_queries = max(1, total_queries - decommissioned_count)
    if total_queries > 0:
        sync_pct = (in_sync_count / active_queries) * 100.0
        if sync_pct > 100.0:
            sync_pct = 100.0

    return {
        "sync_health_pct": round(sync_pct, 1),
        "total_queries": total_queries,
        "in_sync_count": in_sync_count,
        "decommissioned_count": decommissioned_count,
        "pending_decommission_count": pending_decommission_count,
        "drifted_count": drifted_count,
        "missing_count": missing_count,
        "last_audited": last_audited,
        "days_window": days,
        "sweeps_conducted": sweeps_count,
        "drift_incidents_period": events_stats["drift_count"] if events_stats else 0,
        "reconciliations_period": events_stats["reconciled_count"] if events_stats else 0,
        "decommissions_period": events_stats["decommissioned_count"] if events_stats else 0,
        "failed_reconciliations_period": events_stats["failed_count"] if events_stats else 0,
        "tracked_query_versions": versions_count,
        "target_drift_breakdown": target_map,
        "top_drifted_hunts": top_hunts,
        "bas_verified_alerts_count": val_stats["verified_count"] if val_stats else 0,
        "avg_detection_latency_sec": round(float(val_stats["avg_latency_sec"] or 0.0), 3)
        if (val_stats and val_stats["avg_latency_sec"] is not None)
        else 0.0,
        "last_detection_latency_sec": round(float(latest_val["detection_latency_sec"] or 0.0), 3)
        if (latest_val and latest_val["detection_latency_sec"] is not None)
        else 0.0,
        "last_verified_hunt": str(latest_val["hunt_id"]) if latest_val else "",
        "last_verified_technique": str(latest_val["technique_id"]) if latest_val else "",
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
    decommissioned = report.get("decommissioned_count", 0)
    pending_decom = report.get("pending_decommission_count", 0)
    drifted = report.get("drifted_count", 0)
    missing = report.get("missing_count", 0)
    errors = report.get("error_count", 0)
    dry_run = report.get("dry_run", True)
    audited_at = str(report.get("audited_at") or datetime.now(UTC).isoformat())

    active_q = max(1, total_q - decommissioned)
    sync_pct = round((in_sync / active_q) * 100.0, 1) if total_q > 0 else 100.0
    if sync_pct > 100.0:
        sync_pct = 100.0
    mode_str = "Simulated (Dry-Run)" if dry_run else "Live SIEM API"

    if drifted > 0:
        badge = f"⚠️ **DRIFT DETECTED** ({drifted} query{'s' if drifted != 1 else ''})"
    elif pending_decom > 0:
        badge = (
            f"⚠️ **DECOMMISSION PENDING** ({pending_decom} query{'s' if pending_decom != 1 else ''})"
        )
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
        f"| **Decommissioned** | `{decommissioned}` | Cleanly decommissioned/archived |",
        f"| **Pending Decommission** | `{pending_decom}` | {'⚠️ Active query on remote for retired hunt' if pending_decom > 0 else '🟢 None'} |",
        f"| **Drifted** | `{drifted}` | {'⚠️ Needs reconciliation' if drifted > 0 else '🟢 Zero drift'} |",
        f"| **Missing on Remote** | `{missing}` | {'⚠️ Unindexed on target SIEM' if missing > 0 else '🟢 All deployed'} |",
        f"| **Errors** | `{errors}` | {'❌ API or transpilation error' if errors > 0 else '🟢 None'} |",
        "",
    ]

    target_counts: dict[str, dict[str, int]] = {}
    for results in report.get("hunts", {}).values():
        for res in results:
            tgt = str(res.get("target") or "unknown")
            st = str(res.get("status") or "unknown")
            if tgt not in target_counts:
                target_counts[tgt] = {
                    "total": 0,
                    "in_sync": 0,
                    "decommissioned": 0,
                    "drifted": 0,
                    "missing": 0,
                    "error": 0,
                }
            target_counts[tgt]["total"] += 1
            if st == "in_sync":
                target_counts[tgt]["in_sync"] += 1
            elif st == "decommissioned":
                target_counts[tgt]["decommissioned"] += 1
            elif st == "drift_detected":
                target_counts[tgt]["drifted"] += 1
            elif st == "missing_remote":
                target_counts[tgt]["missing"] += 1
            elif st == "error":
                target_counts[tgt]["error"] += 1

    if target_counts:
        lines.extend(
            [
                "### 🎯 Target Platform Breakdown",
                "",
                "| Target Backend | Total Queries | In Sync | Decommissioned | Drifted | Missing | Health |",
                "| :--- | :---: | :---: | :---: | :---: | :---: | :--- |",
            ]
        )
        for tgt, counts in sorted(target_counts.items()):
            active_tgt = max(1, counts["total"] - counts["decommissioned"])
            h_pct = round((counts["in_sync"] / active_tgt) * 100, 1) if active_tgt > 0 else 100.0
            if counts["drifted"] > 0:
                h_badge = "🔴 Drifted"
            elif counts["missing"] > 0:
                h_badge = "🟡 Missing"
            else:
                h_badge = "🟢 In Sync"
            lines.append(
                f"| `{tgt}` | `{counts['total']}` | `{counts['in_sync']}` | `{counts['decommissioned']}` | `{counts['drifted']}` | `{counts['missing']}` | {h_badge} (`{h_pct}%`) |"
            )
        lines.append("")

    pending_by_hunt = report.get("pending_decommission_by_hunt", {})
    if pending_by_hunt:
        lines.extend(
            [
                "### ⚠️ Pending Remote Decommissioning (Retired Hunts with Active Queries)",
                "",
                "> ⚠️ *The following queries belong to retired hunts but remain active on remote SIEM consoles:*",
                "",
            ]
        )
        for hunt_id, res_list in sorted(pending_by_hunt.items()):
            for res in res_list:
                file_name = res.get("file", "")
                tgt = res.get("target", "")
                remote_id = res.get("remote_id", "")
                lines.append(
                    f"- ⚠️ **{hunt_id} / {tgt}**: `{file_name}` (Remote ID: `{remote_id}`) — Run `hecate-runner decommission-queries {hunt_id} --live` to cleanly remove."
                )
        lines.append("")

    drifted_by_hunt = report.get("drifted_by_hunt", {})
    if drifted_by_hunt:
        lines.extend(
            [
                "### 🔍 Drift Inspection & AST Diff",
                "",
                "> ⚠️ *The following queries on remote SIEM consoles have drifted from local git repository source code:*",
                "",
            ]
        )
        for hunt_id, res_list in sorted(drifted_by_hunt.items()):
            for res in res_list:
                file_name = res.get("file", "")
                tgt = res.get("target", "")
                remote_id = res.get("remote_id", "")
                diff = res.get("drift_diff", "")
                lines.extend(
                    [
                        "<details>",
                        f"<summary><b>⚠️ {hunt_id} / {tgt}: <code>{file_name}</code></b> (Remote ID: <code>{remote_id}</code>)</summary>",
                        "",
                        "```diff",
                        diff or "- Local and remote queries differ in AST syntax or query options",
                        "```",
                        "",
                        "</details>",
                        "",
                    ]
                )
    else:
        lines.extend(
            [
                "### 🔍 Drift Inspection",
                "",
                "> ✅ **All deployed SIEM queries match git-authoritative AST and search definitions.** No active drift detected across targets.",
                "",
            ]
        )

    lines.extend(
        [
            "---",
            f"*Report generated by Hecate GitOps Detection Pipeline (trigger: `{trigger}`).*",
        ]
    )

    return "\n".join(lines)
