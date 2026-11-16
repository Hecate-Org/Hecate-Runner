"""Automatic Endpoint-to-Network Fusion Engine for Hecate hunt sweeps.

When external C2 IPs or domains hit in network or DNS telemetry without endpoint
process context, this engine automatically executes immediate targeted secondary lookups
against network_connections and process_creation telemetry on the same timestamp and host
to recover process lineage (initiating process, parent process, command line, user).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from hecate_runner.config import Settings
from hecate_runner.execution.query_values import (
    address,
    basename,
    domain,
    quoted,
)
from hecate_runner.execution.query_values import (
    host as checked_host,
)
from hecate_runner.query_execution import ProposedQuery

if TYPE_CHECKING:
    from hecate_runner.execution.normalizer import NormalizedEvent
    from hecate_runner.execution.safe_gate import SafeExecutionGate

log = logging.getLogger(__name__)


def parse_time_window(
    timestamp_str: str,
    window_sec: int = 300,
) -> tuple[str, str, str, str]:
    """Calculate +/- window around an event timestamp.

    Returns:
        (earliest_iso, latest_iso, earliest_splunk, latest_splunk)
    """
    try:
        clean = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
    except Exception:
        dt = datetime.now(UTC)

    delta = timedelta(seconds=max(30, window_sec))
    start_dt = dt - delta
    end_dt = dt + delta

    earliest_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    latest_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    earliest_splunk = start_dt.strftime("%m/%d/%Y:%H:%M:%S")
    latest_splunk = end_dt.strftime("%m/%d/%Y:%H:%M:%S")
    return earliest_iso, latest_iso, earliest_splunk, latest_splunk


def build_network_connection_query(
    dialect: str,
    host: str,
    ip: str = "",
    domain_val: str = "",
    earliest: str = "",
    latest: str = "",
) -> str:
    """Build a secondary query searching for network socket connection telemetry on an endpoint."""
    dialect = dialect.strip().lower()
    clean_host = checked_host(host) if host else ""
    clean_ip = address(ip) if ip else ""
    clean_domain = domain(domain_val) if domain_val else ""

    host_val = quoted(clean_host, dialect) if clean_host else ""
    ip_val = quoted(clean_ip, dialect) if clean_ip else ""
    dom_val = quoted(clean_domain, dialect) if clean_domain else ""

    if dialect in ("splunk", "spl"):
        host_filter = f"host={host_val} " if clean_host else ""
        c2_clauses: list[str] = []
        if clean_ip:
            c2_clauses.append(
                f"dest_ip={ip_val} OR dst={ip_val} OR DestinationIp={ip_val} OR remote_ip={ip_val}"
            )
        if clean_domain:
            c2_clauses.append(
                f"query={dom_val} OR QueryName={dom_val} OR query_name={dom_val} OR dest={dom_val}"
            )
        c2_filter = f"({' OR '.join(c2_clauses)}) " if c2_clauses else ""
        time_filter = f'earliest="{earliest}" latest="{latest}" ' if earliest and latest else ""
        return (
            f"index=* {host_filter}{c2_filter}"
            f"(EventCode=3 OR sourcetype=*network* OR sourcetype=*sysmon* OR process_name=* OR Image=*) "
            f"{time_filter}| head 5"
        )

    if dialect in ("sentinel", "sentinel_kql", "kql"):
        clauses: list[str] = []
        if clean_host:
            clauses.append(f"DeviceName =~ {host_val}")
        if clean_ip:
            clauses.append(f"RemoteIP == {ip_val}")
        if clean_domain:
            clauses.append(f"RemoteUrl has {dom_val}")
        where_filter = f"| where {' and '.join(clauses)} " if clauses else ""
        time_filter = (
            f'| where TimeGenerated between (datetime("{earliest}") .. datetime("{latest}")) '
            if earliest and latest
            else ""
        )
        return f"DeviceNetworkEvents {time_filter}{where_filter}| take 5"

    if dialect in ("elastic", "elastic_eql", "eql", "es_query"):
        clauses = []
        if clean_host:
            clauses.append(f"host.name: {host_val}")
        if clean_ip:
            clauses.append(f"destination.ip: {ip_val}")
        if clean_domain:
            clauses.append(f"dns.question.name: {dom_val}")
        if earliest and latest:
            clauses.append(f'@timestamp >= "{earliest}" and @timestamp <= "{latest}"')
        clauses.append("(process.name: * or process.executable: *)")
        return " and ".join(clauses)

    if dialect == "chronicle":
        clauses = []
        if clean_host:
            clauses.append(f"principal.hostname = {host_val}")
        if clean_ip:
            clauses.append(f"target.ip = {ip_val}")
        if clean_domain:
            clauses.append(f"target.hostname = {dom_val}")
        if earliest and latest:
            clauses.append(f'metadata.event_timestamp >= "{earliest}"')
            clauses.append(f'metadata.event_timestamp <= "{latest}"')
        clauses.append('principal.process.file.full_path != ""')
        return " and ".join(clauses)

    if dialect in ("crowdstrike", "crowdstrike_cql", "cql", "logscale"):
        host_filter = f"ComputerName={host_val} " if clean_host else ""
        c2_parts: list[str] = []
        if clean_ip:
            c2_parts.append(f"RemoteAddressIP4={ip_val}")
        if clean_domain:
            c2_parts.append(f"(DomainName={dom_val} OR HostName={dom_val})")
        c2_filter = f"{' OR '.join(c2_parts)} " if c2_parts else ""
        time_filter = (
            f'| @timestamp >= "{earliest}" | @timestamp <= "{latest}" '
            if earliest and latest
            else ""
        )
        return (
            f"#event_simpleName=NetworkConnectIP4 {host_filter}{c2_filter}{time_filter}| limit(5)"
        )

    # SQL / Generic fallback
    clauses = []
    if clean_host:
        clauses.append(f"host = {quoted(clean_host, 'sql')}")
    if clean_ip:
        clauses.append(f"destination_ip = {quoted(clean_ip, 'sql')}")
    if clean_domain:
        clauses.append(f"domain = {quoted(clean_domain, 'sql')}")
    if earliest and latest:
        clauses.append(
            f"timestamp >= {quoted(earliest, 'sql')} AND timestamp <= {quoted(latest, 'sql')}"
        )
    where_str = " AND ".join(clauses) if clauses else "1=1"
    return f"SELECT * FROM network_connections WHERE {where_str} LIMIT 5"


def build_process_creation_query(
    dialect: str,
    host: str,
    earliest: str = "",
    latest: str = "",
    proc_filter: str = "",
    pid_filter: str = "",
) -> str:
    """Build a secondary query searching for process creation execution lineage on an endpoint."""
    dialect = dialect.strip().lower()
    clean_host = checked_host(host) if host else ""
    host_val = quoted(clean_host, dialect) if clean_host else ""

    if dialect in ("splunk", "spl"):
        host_filter = f"host={host_val} " if clean_host else ""
        proc_clauses: list[str] = []
        if proc_filter:
            p_pat = quoted(basename(proc_filter), dialect, prefix="*")
            proc_clauses.append(
                f"process_name={p_pat} OR Image={p_pat} OR parent_process_name={p_pat}"
            )
        if pid_filter and pid_filter.isdigit():
            proc_clauses.append(
                f"ProcessId={pid_filter} OR NewProcessId={pid_filter} OR pid={pid_filter}"
            )
        proc_str = f"({' OR '.join(proc_clauses)}) " if proc_clauses else ""
        time_filter = f'earliest="{earliest}" latest="{latest}" ' if earliest and latest else ""
        return (
            f"index=* {host_filter}{proc_str}"
            f"(EventCode=1 OR EventCode=4688 OR sourcetype=*process* OR sourcetype=*audit* OR CommandLine=* OR Image=*) "
            f"{time_filter}| head 10"
        )

    if dialect in ("sentinel", "sentinel_kql", "kql"):
        clauses: list[str] = []
        if clean_host:
            clauses.append(f"DeviceName =~ {host_val}")
        if proc_filter:
            p_name = basename(proc_filter)
            clauses.append(f"FileName =~ {quoted(p_name, dialect)}")
        if pid_filter and pid_filter.isdigit():
            clauses.append(f"ProcessId == {pid_filter}")
        where_filter = f"| where {' and '.join(clauses)} " if clauses else ""
        time_filter = (
            f'| where TimeGenerated between (datetime("{earliest}") .. datetime("{latest}")) '
            if earliest and latest
            else ""
        )
        return f"DeviceProcessEvents {time_filter}{where_filter}| take 10"

    if dialect in ("elastic", "elastic_eql", "eql", "es_query"):
        clauses = []
        if clean_host:
            clauses.append(f"host.name: {host_val}")
        if proc_filter:
            p_name = basename(proc_filter)
            clauses.append(f"process.name: {quoted(p_name, dialect, prefix='*')}")
        if earliest and latest:
            clauses.append(f'@timestamp >= "{earliest}" and @timestamp <= "{latest}"')
        clauses.append('(event.category: "process" or process.executable: *)')
        return " and ".join(clauses)

    if dialect == "chronicle":
        clauses = []
        if clean_host:
            clauses.append(f"principal.hostname = {host_val}")
        if proc_filter:
            clauses.append(
                f"target.process.file.full_path = {quoted(basename(proc_filter), dialect, prefix='*')}"
            )
        if earliest and latest:
            clauses.append(f'metadata.event_timestamp >= "{earliest}"')
            clauses.append(f'metadata.event_timestamp <= "{latest}"')
        clauses.append('target.process.file.full_path != ""')
        return " and ".join(clauses)

    if dialect in ("crowdstrike", "crowdstrike_cql", "cql", "logscale"):
        host_filter = f"ComputerName={host_val} " if clean_host else ""
        proc_str = ""
        if proc_filter:
            proc_str = f"ImageFileName={quoted(basename(proc_filter), dialect, prefix='*')} "
        time_filter = (
            f'| @timestamp >= "{earliest}" | @timestamp <= "{latest}" '
            if earliest and latest
            else ""
        )
        return f"#event_simpleName=ProcessRollup2 {host_filter}{proc_str}{time_filter}| limit(10)"

    # SQL / Generic fallback
    clauses = []
    if clean_host:
        clauses.append(f"host = {quoted(clean_host, 'sql')}")
    if proc_filter:
        clauses.append(
            f"POSITION(LOWER({quoted(basename(proc_filter), 'sql')}) IN LOWER(process_name)) > 0"
        )
    if earliest and latest:
        clauses.append(
            f"timestamp >= {quoted(earliest, 'sql')} AND timestamp <= {quoted(latest, 'sql')}"
        )
    where_str = " AND ".join(clauses) if clauses else "1=1"
    return f"SELECT * FROM process_creation WHERE {where_str} LIMIT 10"


class EndpointNetworkFusionEngine:
    """Recovers process lineage for external network/DNS detections via targeted secondary lookups."""

    def __init__(
        self,
        gate: SafeExecutionGate | None = None,
        settings: Settings | None = None,
    ):
        self.gate = gate
        self.settings = settings or Settings()
        self.fusion_window_sec = getattr(self.settings, "auto_hunt_fusion_window_sec", 300)

    def fuse_events(
        self,
        events: list[NormalizedEvent],
        target_siem: str,
        hunt_id: str,
        time_range_days: int = 1,
    ) -> list[NormalizedEvent]:
        """Perform automatic endpoint-to-network fusion on telemetry events.

        Detects network or DNS hits lacking process lineage, issues immediate secondary lookups
        against network_connections and process_creation on the target host/timestamp, and fuses
        recovered process lineage directly into the normalized events.
        """
        if not events or self.gate is None:
            return events

        candidates = [e for e in events if e.needs_lineage_fusion()]
        if not candidates:
            return events

        # Group candidates by (host, ip, domain) to avoid duplicate secondary lookups
        groups: dict[tuple[str, str, str], list[NormalizedEvent]] = {}
        for c in candidates:
            h = c.host or c.src_ip
            ip_val = c.dst_ip or c.ip
            dom_val = c.domain
            key = (h, ip_val, dom_val)
            groups.setdefault(key, []).append(c)

        for (host_val, ip_val, dom_val), grouped_events in groups.items():
            try:
                self._fuse_group(
                    grouped_events=grouped_events,
                    host=host_val,
                    ip=ip_val,
                    domain_val=dom_val,
                    target_siem=target_siem,
                    hunt_id=hunt_id,
                    time_range_days=time_range_days,
                )
            except Exception as exc:
                log.warning(
                    "Endpoint-to-network fusion failed for (%s, %s, %s): %s",
                    host_val,
                    ip_val,
                    dom_val,
                    exc,
                )

        return events

    def _fuse_group(
        self,
        grouped_events: list[NormalizedEvent],
        host: str,
        ip: str,
        domain_val: str,
        target_siem: str,
        hunt_id: str,
        time_range_days: int,
    ) -> None:
        """Execute secondary queries and fuse recovered process lineage into a group of events."""
        if self.gate is None or not host:
            return

        first_event = grouped_events[0]
        earliest_iso, latest_iso, earliest_sp, latest_sp = parse_time_window(
            first_event.timestamp,
            window_sec=self.fusion_window_sec,
        )
        e_time = earliest_sp if target_siem in ("splunk", "spl") else earliest_iso
        l_time = latest_sp if target_siem in ("splunk", "spl") else latest_iso

        recovered_proc = ""
        recovered_parent = ""
        recovered_cli = ""
        recovered_user = ""
        recovered_pid = ""
        recovered_parent_pid = ""

        # Step 1: Query network_connections on the endpoint
        try:
            net_query = build_network_connection_query(
                target_siem,
                host=host,
                ip=ip,
                domain_val=domain_val,
                earliest=e_time,
                latest=l_time,
            )
            proposed_net = ProposedQuery(
                hunt_id=hunt_id,
                data_source=target_siem,
                query_text=net_query,
                time_range_days=time_range_days,
                limit=5,
                justification=f"Endpoint-to-network fusion network lookup for host '{host}' connecting to '{ip or domain_val}'",
            )
            net_safe = self.gate.execute_safely(proposed_net)
            if net_safe.events:
                from hecate_runner.execution.normalizer import normalize_events

                norm_net = normalize_events(net_safe.events, target_siem, hunt_id)
                for ne in norm_net:
                    if ne.process_name and not recovered_proc:
                        recovered_proc = ne.process_name
                    if ne.parent_process and not recovered_parent:
                        recovered_parent = ne.parent_process
                    if ne.command_line and not recovered_cli:
                        recovered_cli = ne.command_line
                    if ne.user and not recovered_user:
                        recovered_user = ne.user
                    if ne.pid and not recovered_pid:
                        recovered_pid = ne.pid
                    if ne.parent_pid and not recovered_parent_pid:
                        recovered_parent_pid = ne.parent_pid
                    if recovered_proc:
                        break
        except Exception as exc:
            log.debug("Network connection lookup failed (%s); proceeding to process creation", exc)

        # Step 2: Query process_creation on the endpoint
        try:
            proc_query = build_process_creation_query(
                target_siem,
                host=host,
                earliest=e_time,
                latest=l_time,
                proc_filter=recovered_proc,
                pid_filter=recovered_pid,
            )
            proposed_proc = ProposedQuery(
                hunt_id=hunt_id,
                data_source=target_siem,
                query_text=proc_query,
                time_range_days=time_range_days,
                limit=10,
                justification=f"Endpoint-to-network fusion process creation lookup for host '{host}'",
            )
            proc_safe = self.gate.execute_safely(proposed_proc)
            if proc_safe.events:
                from hecate_runner.execution.normalizer import normalize_events

                norm_proc = normalize_events(proc_safe.events, target_siem, hunt_id)
                for pe in norm_proc:
                    if pe.process_name and not recovered_proc:
                        recovered_proc = pe.process_name
                    if pe.parent_process and not recovered_parent:
                        recovered_parent = pe.parent_process
                    if pe.command_line and not recovered_cli:
                        recovered_cli = pe.command_line
                    if pe.user and not recovered_user:
                        recovered_user = pe.user
                    if pe.pid and not recovered_pid:
                        recovered_pid = pe.pid
                    if pe.parent_pid and not recovered_parent_pid:
                        recovered_parent_pid = pe.parent_pid
                    if recovered_proc and (recovered_cli or recovered_parent):
                        break
        except Exception as exc:
            log.debug("Process creation lookup failed (%s)", exc)

        # Step 3: Apply fusion to all events in this group
        if recovered_proc or recovered_cli or recovered_parent:
            detail = (
                f"Endpoint-to-network fusion recovered process lineage on host '{host}': "
                f"process='{recovered_proc}', parent='{recovered_parent}', "
                f"command_line='{recovered_cli}' (indicator: {ip or domain_val})"
            )
            log.info(detail)
            for ev in grouped_events:
                ev.fuse_process_lineage(
                    process_name=recovered_proc,
                    parent_process=recovered_parent,
                    command_line=recovered_cli,
                    user=recovered_user,
                    pid=recovered_pid,
                    parent_pid=recovered_parent_pid,
                    fusion_source="endpoint_network_fusion",
                    fusion_detail=detail,
                )
