"""Tests for Phase 1 Auto Hunt Execution Engine.

Verifies:
- COUNT-FIRST Safe Execution Gate (SPL, KQL, EQL, CQL, Mock)
- WatermarkStore SQLite persistence & staging
- HuntExecutionScheduler discovery, eligibility, staging, execution, and frontmatter sync
- CLI sweep commands (list, stage, pending, approve, reject, run)
- Slack action simulation (hecate_approve_sweep, hecate_reject_sweep)
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from hecate_runner.cli import app
from hecate_runner.config import Settings
from hecate_runner.execution.safe_gate import (
    SafeExecutionGate,
    build_count_query,
    extract_count_from_result,
)
from hecate_runner.execution.scheduler import HuntExecutionScheduler
from hecate_runner.execution.watermark_store import WatermarkStore
from hecate_runner.lifecycle import get_hunt_lifecycle
from hecate_runner.query_execution import MockQueryProvider, ProposedQuery, QueryResult
from hecate_runner.slack_sim import SlackBotSimulator

runner = CliRunner()


@pytest.fixture
def mock_workspace(tmp_path: Path) -> Path:
    """Create a temporary workspace populated with active hunts and queries."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Create active hunt H-0021
    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0021.md"
    hunt_file.write_text(
        """---
hunt_id: H-0021
title: "Adversaries deploy malicious Node-RED flows"
status: active
findings_count: 0
execution_run_count: 0
tags: ["production"]
---

# H-0021: Node-RED Malicious Execution Hunt

### Hypothesis
Adversaries use unauthenticated HTTP POST requests to deploy flows.
""",
        encoding="utf-8",
    )

    # Create transpiled queries for H-0021
    queries_dir = workspace / "queries" / "H-0021"
    queries_dir.mkdir(parents=True)
    (queries_dir / "rule_process.spl").write_text(
        'ParentImage="*/node" Image="*/sh" CommandLine="* -c *"',
        encoding="utf-8",
    )
    (queries_dir / "rule_process.kql").write_text(
        'DeviceProcessEvents | where ProcessCommandLine contains "node-red"',
        encoding="utf-8",
    )

    # State dir
    (workspace / "state").mkdir(parents=True)
    return workspace


# --- SafeExecutionGate & COUNT-FIRST tests -----------------------------------


def test_build_count_query_dialects() -> None:
    spl = 'Image="*/sh" CommandLine="* -c *"'
    assert build_count_query(spl, "splunk") == f"{spl} | stats count"
    assert build_count_query(f"{spl} | stats count", "splunk") == f"{spl} | stats count"
    assert (
        build_count_query(f"{spl} | stats count by user", "splunk")
        == f"{spl} | stats count by user | stats sum(count) as count"
    )

    kql = "DeviceProcessEvents | where ProcessCommandLine contains 'test'"
    kql_count = build_count_query(kql, "sentinel")
    assert "| summarize count()" in kql_count
    assert "__hecate_bounded_query" in kql_count

    kql_let = "let timeframe = 1d;\nDeviceProcessEvents | where TimeGenerated > ago(timeframe)"
    kql_let_count = build_count_query(kql_let, "sentinel")
    assert "__hecate_bounded_query" not in kql_let_count
    assert kql_let_count.endswith("| summarize count()")

    cql = "CommandLine = /.*test.*/"
    assert build_count_query(cql, "crowdstrike") == f"{cql} | count()"


def test_extract_count_from_result() -> None:
    # From direct row count
    res1 = QueryResult(outcome="executed", provider="mock", row_count=42)
    assert extract_count_from_result(res1) == 42

    # From events dict with count_
    res2 = QueryResult(
        outcome="executed",
        provider="sentinel",
        row_count=1,
        events=[{"count_": 17}],
    )
    assert extract_count_from_result(res2) == 17

    # From multiple grouped events dict with count
    res_multi = QueryResult(
        outcome="executed",
        provider="splunk",
        row_count=2,
        events=[{"user": "alice", "count": 10}, {"user": "bob", "count": 25}],
    )
    assert extract_count_from_result(res_multi) == 35

    # From detail JSON
    res3 = QueryResult(
        outcome="executed",
        provider="sentinel",
        row_count=1,
        detail='{"rows": [[55]]}',
    )
    assert extract_count_from_result(res3) == 55

    # From error
    res_err = QueryResult(outcome="error", provider="mock", row_count=0)
    assert extract_count_from_result(res_err) == 0


def test_safe_execution_gate_clean_run() -> None:
    """When COUNT query returns 0, no raw telemetry is fetched."""
    mock_provider = MockQueryProvider(responses=[0])
    gate = SafeExecutionGate(mock_provider, max_auto_fetch=200)

    proposed = ProposedQuery(
        hunt_id="H-0021",
        data_source="splunk",
        query_text='Image="*/sh"',
        time_range_days=1,
        limit=100,
    )
    result = gate.execute_safely(proposed)

    assert result.ok
    assert result.outcome == "clean"
    assert result.matched_count == 0
    assert len(mock_provider.executed_queries) == 1  # Only COUNT query was executed!
    assert "count" in mock_provider.executed_queries[0].query_text.lower()


def test_safe_execution_gate_hits_detected() -> None:
    """When COUNT returns 5, raw query is fetched bounded to 5."""
    mock_provider = MockQueryProvider(responses=[5, 5])
    gate = SafeExecutionGate(mock_provider, max_auto_fetch=200)

    proposed = ProposedQuery(
        hunt_id="H-0021",
        data_source="splunk",
        query_text='Image="*/sh"',
        time_range_days=1,
        limit=100,
    )
    result = gate.execute_safely(proposed)

    assert result.ok
    assert result.outcome == "hits_detected"
    assert result.matched_count == 5
    assert len(mock_provider.executed_queries) == 2  # 1 COUNT + 1 raw fetch
    assert mock_provider.executed_queries[1].limit == 5
    assert len(result.events) == 5


def test_safe_execution_gate_overmatch() -> None:
    """When COUNT exceeds max_auto_fetch, raw query retrieval is halted."""
    mock_provider = MockQueryProvider(responses=[450])
    gate = SafeExecutionGate(mock_provider, max_auto_fetch=200)

    proposed = ProposedQuery(
        hunt_id="H-0021",
        data_source="splunk",
        query_text='Image="*/sh"',
        time_range_days=1,
        limit=100,
    )
    result = gate.execute_safely(proposed)

    assert not result.ok
    assert result.outcome == "overmatch"
    assert result.matched_count == 450
    assert len(mock_provider.executed_queries) == 1  # Raw fetch was prevented!
    assert "exceeding auto-fetch limit" in result.detail


# --- WatermarkStore SQLite tests ---------------------------------------------


def test_watermark_store_persistence(tmp_path: Path) -> None:
    db_path = tmp_path / "watermarks.db"
    store = WatermarkStore(db_path)

    # Initial watermark check
    assert store.get_watermark("H-0021") is None

    # Update watermark
    wm = store.update_watermark(
        hunt_id="H-0021",
        target_siem="splunk",
        query_file="rule.spl",
        last_window_start="2026-11-08T00:00:00Z",
        last_window_end="2026-11-09T00:00:00Z",
        outcome="clean",
        matched_count=0,
    )
    assert wm.hunt_id == "H-0021"
    assert wm.run_count == 1

    # Stage sweep
    sweep = store.stage_sweep(
        hunt_id="H-0021",
        target_siem="splunk",
        query_file="rule.spl",
        query_text='Image="*/sh"',
        time_range_days=1,
    )
    assert sweep.status == "pending_approval"
    assert sweep.sweep_id.startswith("SWEEP-H-0021-")

    # Retrieve staged sweep
    loaded = store.get_staged_sweep(sweep.sweep_id)
    assert loaded is not None
    assert loaded.hunt_id == "H-0021"

    # Mark executed
    store.mark_sweep_status(
        sweep.sweep_id,
        status="executed",
        actor="analyst",
        outcome="clean",
        matched_count=0,
    )
    assert store.get_staged_sweep(sweep.sweep_id).status == "executed"


# --- HuntExecutionScheduler tests --------------------------------------------


def test_scheduler_stage_and_execute(mock_workspace: Path) -> None:
    settings = Settings(
        hecate_workspace=mock_workspace,
        query_provider="mock",
        auto_hunt_max_fetch=200,
    )
    mock_provider = MockQueryProvider(responses=[3, 3])
    scheduler = HuntExecutionScheduler(settings=settings, provider=mock_provider)

    # Discover active hunts
    active = scheduler.discover_active_hunts()
    assert len(active) == 1
    assert active[0]["hunt_id"] == "H-0021"

    # Stage sweep
    staged_list = scheduler.stage_sweeps(hunt_id="H-0021", force=True)
    assert len(staged_list) == 1
    sweep = staged_list[0]
    assert sweep.status == "pending_approval"

    # Execute staged sweep
    result = scheduler.execute_sweep(sweep.sweep_id, approver="test_analyst")
    assert result.ok
    assert result.outcome == "hits_detected"
    assert result.matched_count == 3

    # Check watermark updated
    wm = scheduler.store.get_watermark("H-0021")
    assert wm is not None
    assert wm.last_outcome == "hits_detected"
    assert wm.last_matched_count == 3
    assert wm.run_count == 1

    # Check frontmatter and markdown body updated
    lifecycle = get_hunt_lifecycle(mock_workspace, "H-0021")
    assert lifecycle["is_active"]
    hunt_file = mock_workspace / "hunts" / "2026" / "Q4" / "H-0021.md"
    body = hunt_file.read_text(encoding="utf-8")
    assert "findings_count: 3" in body
    assert "execution_run_count: 1" in body
    assert "Automated Hunt Execution" in body


# --- CLI command tests -------------------------------------------------------


def test_cli_sweep_flow(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HECATE_WORKSPACE", str(mock_workspace))
    monkeypatch.setenv("HECATE_RUNNER_QUERY_PROVIDER", "mock")
    monkeypatch.setenv("HECATE_MOCK_QUERY_ROWS", "0")

    # 1. Sweep list
    res_list = runner.invoke(app, ["sweep", "list", "--force"])
    assert res_list.exit_code == 0
    assert "H-0021" in res_list.stdout

    # 2. Stage sweep
    res_stage = runner.invoke(app, ["sweep", "stage", "--force"])
    assert res_stage.exit_code == 0
    assert "Staged 1 hunt sweep(s)" in res_stage.stdout

    # 3. Sweep pending
    res_pending = runner.invoke(app, ["sweep", "pending"])
    assert res_pending.exit_code == 0
    assert "SWEEP-H-0021" in res_pending.stdout

    # 4. Sweep approve
    res_appr = runner.invoke(app, ["sweep", "approve", "H-0021", "--yes"])
    assert res_appr.exit_code == 0
    assert "Not observed:" in res_appr.stdout or "clean" in res_appr.stdout


def test_cli_sweep_reject(mock_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HECATE_WORKSPACE", str(mock_workspace))
    monkeypatch.setenv("HECATE_RUNNER_QUERY_PROVIDER", "mock")

    # Stage
    runner.invoke(app, ["sweep", "stage", "--force"])

    # Reject
    res_rej = runner.invoke(app, ["sweep", "reject", "H-0021", "--reason", "Not relevant"])
    assert res_rej.exit_code == 0
    assert "rejected" in res_rej.stdout


# --- Slack simulation tests --------------------------------------------------


def test_slack_simulation_sweep_actions(
    mock_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HECATE_WORKSPACE", str(mock_workspace))
    monkeypatch.setenv("HECATE_RUNNER_QUERY_PROVIDER", "mock")
    monkeypatch.setenv("HECATE_MOCK_QUERY_ROWS", "0")

    settings = Settings(hecate_workspace=mock_workspace, query_provider="mock")
    sim = SlackBotSimulator(settings)

    # Stage a sweep first
    scheduler = HuntExecutionScheduler(settings=settings)
    staged = scheduler.stage_sweeps(hunt_id="H-0021", force=True)[0]

    # Simulate Slack button click "hecate_approve_sweep"
    res = sim.simulate_action("hecate_approve_sweep", staged.sweep_id, user="secops_lead")
    assert res["ok"]
    assert "Clean Sweep" in res["message"] or "Hunt Sweep Executed" in res["message"]
