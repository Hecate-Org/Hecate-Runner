"""Autonomous Investigation Pivoting Engine for Hecate hunt sweeps.

Takes confirmed or suspicious findings from FindingTriageAgent, identifies key
entities (processes, parent processes, users, destinations/hosts, external IPs),
synthesizes targeted secondary investigation queries tailored to the SIEM dialect,
and executes them safely through the COUNT-FIRST SafeExecutionGate.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from hecate_runner.config import Settings
from hecate_runner.execution.query_values import address, basename, entity, quoted, username
from hecate_runner.execution.query_values import host as checked_host
from hecate_runner.execution.safe_gate import SafeExecutionGate
from hecate_runner.execution.watermark_store import WatermarkStore
from hecate_runner.query_execution import ProposedQuery

log = logging.getLogger(__name__)


@dataclass
class PivotExecutionResult:
    """Outcome of an autonomous investigation pivot query."""

    pivot_id: str
    finding_id: str
    pivot_type: (
        str  # "child_process" | "network_egress" | "user_auth" | "parent_process" | "lateral_ip"
    )
    target_siem: str
    query_text: str
    rationale: str
    technique: str
    outcome: str  # "hits_detected" | "clean" | "overmatch" | "error"
    matched_count: int = 0
    detail: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    executed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "pivot_id": self.pivot_id,
            "finding_id": self.finding_id,
            "pivot_type": self.pivot_type,
            "target_siem": self.target_siem,
            "query_text": self.query_text,
            "rationale": self.rationale,
            "technique": self.technique,
            "outcome": self.outcome,
            "matched_count": self.matched_count,
            "detail": self.detail,
            "events_count": len(self.events),
            "executed_at": self.executed_at,
        }


def synthesize_pivot_queries(
    target_siem: str,
    entities: Mapping[str, list[str]],
    techniques: list[str] | None = None,
    max_pivots: int = 3,
) -> list[dict[str, str]]:
    """Synthesize concrete secondary queries tailored to the target SIEM backend.

    Args:
        target_siem: Target SIEM dialect (e.g. splunk, sentinel, elastic, chronicle).
        entities: Dictionary of extracted entities (hosts, processes, parent_processes, users, ips).
        techniques: List of primary MITRE technique IDs identified during triage.
        max_pivots: Maximum number of pivot queries to generate.

    Returns:
        List of pivot specifications containing query text, rationale, and technique hints.
    """
    dialect = target_siem.strip().lower()
    hosts = entities.get("hosts") or []
    processes = entities.get("processes") or []
    parent_procs = entities.get("parent_processes") or []
    users = entities.get("users") or []
    ips = entities.get("ips") or []

    primary_host = hosts[0] if hosts else ""
    primary_proc = processes[0] if processes else ""
    primary_parent = parent_procs[0] if parent_procs else ""
    primary_user = users[0] if users else ""
    primary_ip = address(ips[0]) if ips else ""
    checked_host(primary_host)
    for value in (primary_proc, primary_parent, primary_user):
        entity(value)

    pivots: list[dict[str, str]] = []

    # 1. Child Process Pivot (T1059: Command and Scripting Interpreter)
    if primary_proc:
        query = _build_child_process_query(dialect, primary_host, primary_proc)
        pivots.append(
            {
                "type": "child_process",
                "query": query,
                "rationale": f"Investigate child processes spawned by {primary_proc} to identify command execution and post-exploitation activity.",
                "technique": "T1059",
            }
        )

    # 2. Network Egress Pivot (T1071: Application Layer Protocol / C2)
    if primary_ip or (primary_proc and primary_host):
        query = _build_network_egress_query(dialect, primary_host, primary_proc, primary_ip)
        ip_hint = f" to IP {primary_ip}" if primary_ip else f" from process {primary_proc}"
        pivots.append(
            {
                "type": "network_egress",
                "query": query,
                "rationale": f"Identify outbound network connections{ip_hint} across the environment to detect C2 traffic or staging.",
                "technique": "T1071",
            }
        )

    # 3. User Authentication Pivot (T1078: Valid Accounts)
    if primary_user and primary_user.lower() not in ("system", "root", "unknown"):
        query = _build_user_auth_query(dialect, primary_user, primary_host)
        pivots.append(
            {
                "type": "user_auth",
                "query": query,
                "rationale": f"Audit authentication events for user {primary_user} to verify source IPs and anomalous logons.",
                "technique": "T1078",
            }
        )

    # 4. Parent Process Execution Scope (T1190 / Exploit Scope)
    if len(pivots) < max_pivots and primary_parent:
        query = _build_parent_scope_query(dialect, primary_parent)
        pivots.append(
            {
                "type": "parent_process",
                "query": query,
                "rationale": f"Check other child processes spawned by parent service {primary_parent} across all hosts.",
                "technique": "T1190",
            }
        )

    return pivots[:max_pivots]


def _build_child_process_query(dialect: str, host: str, proc: str) -> str:
    clean_proc = basename(proc)
    host_value = quoted(checked_host(host), dialect)
    proc_value = quoted(clean_proc, dialect)
    pattern = quoted(clean_proc, dialect, prefix="*")
    if dialect in ("splunk", "spl"):
        host_filter = f"host={host_value} " if host else ""
        return f"index=* {host_filter}(parent_process_name={pattern} OR parent_process={pattern} OR ParentImage={pattern}) | head 50"
    if dialect in ("sentinel", "sentinel_kql", "kql"):
        host_filter = f"| where DeviceName =~ {host_value} " if host else ""
        return f"DeviceProcessEvents {host_filter}| where InitiatingProcessFileName =~ {proc_value} or InitiatingProcessCommandLine has {proc_value} | take 50"
    if dialect in ("elastic", "elastic_eql", "eql", "es_query"):
        host_filter = f"host.name: {host_value} and " if host else ""
        return f"{host_filter}process.parent.name: {pattern}"
    if dialect == "chronicle":
        host_filter = f"principal.hostname = {host_value} and " if host else ""
        return f"{host_filter}target.process.parent_process.file.full_path = {pattern}"
    if dialect in ("crowdstrike", "crowdstrike_cql", "cql", "logscale"):
        host_filter = f"ComputerName={host_value} " if host else ""
        return f"#event_simpleName=ProcessRollup2 {host_filter}ParentBaseFileName={proc_value} | limit(50)"
    host_filter = f"host = {quoted(host, 'sql')} AND " if host else ""
    return f"SELECT * FROM edr_events WHERE {host_filter}POSITION(LOWER({quoted(clean_proc, 'sql')}) IN LOWER(parent_process)) > 0 LIMIT 50"


def _build_network_egress_query(dialect: str, host: str, proc: str, ip: str) -> str:
    clean_proc = basename(proc)
    ip = address(ip)
    host_value = quoted(checked_host(host), dialect)
    proc_value = quoted(clean_proc, dialect)
    pattern = quoted(clean_proc, dialect, prefix="*")
    ip_value = quoted(ip, dialect)
    if dialect in ("splunk", "spl"):
        if ip:
            return f"index=* (dest_ip={ip_value} OR dst={ip_value} OR destination_ip={ip_value}) | head 50"
        host_filter = f"host={host_value} " if host else ""
        return f"index=* {host_filter}(process_name={pattern} OR Image={pattern}) (dest_ip=* OR dst=*) | head 50"
    if dialect in ("sentinel", "sentinel_kql", "kql"):
        if ip:
            return f"DeviceNetworkEvents | where RemoteIP == {ip_value} | take 50"
        host_filter = f"| where DeviceName =~ {host_value} " if host else ""
        return f"DeviceNetworkEvents {host_filter}| where InitiatingProcessFileName =~ {proc_value} | take 50"
    if dialect in ("elastic", "elastic_eql", "eql", "es_query"):
        if ip:
            return f"destination.ip: {ip_value}"
        host_filter = f"host.name: {host_value} and " if host else ""
        return f"{host_filter}process.name: {pattern} and destination.ip: *"
    if dialect == "chronicle":
        if ip:
            return f"target.ip = {ip_value}"
        host_filter = f"principal.hostname = {host_value} and " if host else ""
        return f'{host_filter}principal.process.file.full_path = {pattern} and target.ip != ""'
    if dialect in ("crowdstrike", "crowdstrike_cql", "cql", "logscale"):
        if ip:
            return f"#event_simpleName=NetworkConnectIP4 RemoteAddressIP4={ip_value} | limit(50)"
        host_filter = f"ComputerName={host_value} " if host else ""
        return (
            f"#event_simpleName=NetworkConnectIP4 {host_filter}ImageFileName={pattern} | limit(50)"
        )
    if ip:
        return f"SELECT * FROM network_events WHERE destination_ip = {quoted(ip, 'sql')} LIMIT 50"
    host_filter = f"host = {quoted(host, 'sql')} AND " if host else ""
    return f"SELECT * FROM network_events WHERE {host_filter}POSITION(LOWER({quoted(clean_proc, 'sql')}) IN LOWER(process_name)) > 0 LIMIT 50"


def _build_user_auth_query(dialect: str, user: str, host: str) -> str:
    clean_user = username(user)
    checked_host(host)
    value = quoted(clean_user, dialect)
    pattern = quoted(clean_user, dialect, prefix="*", suffix="*")
    if dialect in ("splunk", "spl"):
        return f'index=* (EventCode=4624 OR action="success") (user={pattern} OR User={pattern}) | head 50'
    if dialect in ("sentinel", "sentinel_kql", "kql"):
        return f"SecurityEvent | where EventID == 4624 and TargetUserName =~ {value} | take 50"
    if dialect in ("elastic", "elastic_eql", "eql", "es_query"):
        return f'event.code: "4624" and user.name: {pattern}'
    if dialect == "chronicle":
        return f'metadata.event_type = "USER_LOGIN" and target.user.userid = {value}'
    if dialect in ("crowdstrike", "crowdstrike_cql", "cql", "logscale"):
        return f"#event_simpleName=UserLogon UserName={pattern} | limit(50)"
    return f"SELECT * FROM auth_events WHERE POSITION(LOWER({quoted(clean_user, 'sql')}) IN LOWER(user_name)) > 0 AND event_type = 'LOGIN_SUCCESS' LIMIT 50"


def _build_parent_scope_query(dialect: str, parent: str) -> str:
    clean_parent = basename(parent)
    value = quoted(clean_parent, dialect)
    pattern = quoted(clean_parent, dialect, prefix="*")
    if dialect in ("splunk", "spl"):
        return f"index=* (parent_process_name={pattern} OR parent_process={pattern}) | head 50"
    if dialect in ("sentinel", "sentinel_kql", "kql"):
        return f"DeviceProcessEvents | where InitiatingProcessFileName =~ {value} | take 50"
    if dialect in ("elastic", "elastic_eql", "eql", "es_query"):
        return f"process.parent.name: {pattern}"
    if dialect == "chronicle":
        return f"target.process.parent_process.file.full_path = {pattern}"
    if dialect in ("crowdstrike", "crowdstrike_cql", "cql", "logscale"):
        return f"#event_simpleName=ProcessRollup2 ParentBaseFileName={value} | limit(50)"
    return f"SELECT * FROM edr_events WHERE POSITION(LOWER({quoted(clean_parent, 'sql')}) IN LOWER(parent_process)) > 0 LIMIT 50"


class PivotExecutionEngine:
    """Orchestrates autonomous secondary investigation pivot queries."""

    def __init__(
        self,
        gate: SafeExecutionGate,
        store: WatermarkStore,
        settings: Settings | None = None,
    ):
        self.gate = gate
        self.store = store
        self.settings = settings or Settings()

    def execute_pivots(
        self,
        finding_id: str,
        hunt_id: str,
        target_siem: str,
        entities: Mapping[str, list[str]],
        techniques: list[str] | None = None,
        lookback_days: int = 1,
        max_pivots: int | None = None,
    ) -> list[PivotExecutionResult]:
        """Synthesize and safely execute secondary pivot queries for a triaged finding."""
        limit = (
            max_pivots
            if max_pivots is not None
            else int(getattr(self.settings, "auto_hunt_max_pivots", 3))
        )
        try:
            specs = synthesize_pivot_queries(
                target_siem=target_siem,
                entities=entities,
                techniques=techniques,
                max_pivots=limit,
            )
        except ValueError:
            log.warning("Refusing automatic pivots with invalid telemetry entities")
            return []

        results: list[PivotExecutionResult] = []
        for spec in specs:
            pivot_id = f"PIVOT-{hunt_id.upper()}-{uuid.uuid4().hex[:6]}"
            proposed = ProposedQuery(
                hunt_id=hunt_id,
                data_source=target_siem,
                query_text=spec["query"],
                time_range_days=lookback_days,
                limit=50,  # Strict boundary for secondary investigation
                justification=f"Autonomous investigation pivot ({spec['type']}) for {finding_id}",
            )

            try:
                # Execute safely via COUNT-FIRST gate
                safe = self.gate.execute_safely(proposed)
                pivot_result = PivotExecutionResult(
                    pivot_id=pivot_id,
                    finding_id=finding_id,
                    pivot_type=spec["type"],
                    target_siem=target_siem,
                    query_text=spec["query"],
                    rationale=spec["rationale"],
                    technique=spec["technique"],
                    outcome=safe.outcome,
                    matched_count=safe.matched_count,
                    detail=safe.detail,
                    events=safe.events,
                    executed_at=safe.executed_at,
                )
            except Exception as exc:
                log.warning("Pivot execution %s failed (%s)", pivot_id, exc)
                pivot_result = PivotExecutionResult(
                    pivot_id=pivot_id,
                    finding_id=finding_id,
                    pivot_type=spec["type"],
                    target_siem=target_siem,
                    query_text=spec["query"],
                    rationale=spec["rationale"],
                    technique=spec["technique"],
                    outcome="error",
                    matched_count=0,
                    detail=f"Execution error: {exc}",
                )

            results.append(pivot_result)
            log.info(
                "Executed pivot %s (%s) for %s: %s (%d hits)",
                pivot_id,
                spec["type"],
                finding_id,
                pivot_result.outcome,
                pivot_result.matched_count,
            )

        # Record pivot executions in SQLite findings ledger
        if results:
            try:
                self.store.update_finding_pivots(
                    finding_id=finding_id,
                    pivots=[p.to_dict() for p in results],
                )
            except Exception as exc:
                log.warning("Could not persist pivots to watermark store (%s)", exc)

        return results
