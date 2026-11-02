"""Detection-as-Code SIEM query drift auditing and automated reconciliation engine.

Provides automated periodic and on-demand synchronization sweeps across target SIEMs
and EDR platforms to detect out-of-band rule modifications, deletions, or configuration drift,
and offers one-click automated reconciliation back to git-authoritative Sigma definitions.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.slack_bot import sync_queries_for_hunt

log = logging.getLogger(__name__)


def audit_workspace_queries(
    workspace: Path,
    target: str | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Audit all hunting queries in workspace against live or simulated SIEM/EDR platforms.

    Args:
        workspace: Path to the root Hecate workspace.
        target: Optional platform filter (e.g. 'splunk_spl', 'sentinel_kql').
        dry_run: When True, simulates the sync check without making network calls.

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

    return report


def reconcile_hunt_queries(
    workspace: Path,
    hunt_id: str,
    target: str | None = None,
    dry_run: bool = True,
    force: bool = False,
) -> list[dict[str, Any]]:
    """Reconcile drifted or missing queries for a hunt back to the git-authoritative definitions.

    Args:
        workspace: Path to the root Hecate workspace.
        hunt_id: Target hunt ID (e.g. 'H-0007').
        target: Optional platform filter (e.g. 'splunk_spl').
        dry_run: When True, simulates the reconciliation push without mutating remote SIEM.
        force: If True, redeploys all queries regardless of current sync status.

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

        reconciliation_results.append(
            {
                "file": q_file.name,
                "target": tgt,
                "remote_id": remote_id,
                "previous_status": prev_status,
                "status": post_status,
                "ok": ok and (post_status in {"in_sync", "dry_run", "reconciled"}),
                "detail": detail,
                "request_summary": deploy_res.get("request_summary", {}),
            }
        )

    return reconciliation_results


def reconcile_all_drifted_queries(
    workspace: Path,
    target: str | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Audit the workspace and automatically reconcile all detected query drift and missing rules.

    Args:
        workspace: Path to the root Hecate workspace.
        target: Optional platform filter.
        dry_run: When True, simulates the reconciliation.

    Returns:
        Aggregated reconciliation summary.
    """
    audit = audit_workspace_queries(workspace, target=target, dry_run=dry_run)
    hunts_to_reconcile = set(audit.get("drifted_by_hunt", {}).keys()) | set(
        audit.get("missing_by_hunt", {}).keys()
    )

    reconciled_by_hunt: dict[str, list[dict[str, Any]]] = {}
    total_reconciled = 0
    total_failed = 0

    for hunt_id in sorted(hunts_to_reconcile):
        results = reconcile_hunt_queries(workspace, hunt_id, target=target, dry_run=dry_run)
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
