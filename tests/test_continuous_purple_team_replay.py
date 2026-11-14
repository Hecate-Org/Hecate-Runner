import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from hecate_runner.config import Settings
from hecate_runner.purple_team import run_continuous_replay_sweep


def test_continuous_replay_sweep_with_miss_generates_tuning_suggestion(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    hunt_id = "H-0099"

    # Set up queries directory and a rule that misses PowerShell
    query_dir = workspace / "queries" / hunt_id
    query_dir.mkdir(parents=True)
    rule_yaml = """title: Linux Command Execution
status: test
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/sh'
    condition: selection
"""
    (query_dir / "rule.yml").write_text(rule_yaml, encoding="utf-8")

    # Set up hunt frontmatter
    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / f"{hunt_id}.md"
    hunt_file.write_text(
        f"""---
id: {hunt_id}
title: Suspicious Linux Shell Execution
techniques:
  - T1059.006
platform:
  - linux
---

# Analysis
The adversary leveraged inline python code execution:
`python3 -c "import os; os.system('whoami')"`
""",
        encoding="utf-8",
    )

    settings = Settings(
        hecate_workspace=workspace,
        purple_team_continuous_replay_interval_sec=10,
        purple_team_auto_tune_on_miss=True,
    )

    outcomes = run_continuous_replay_sweep(settings)
    assert len(outcomes) == 1
    res = outcomes[0]
    assert res["hunt_id"] == hunt_id
    assert res["total_rules"] == 1
    assert res["passed_rules"] == 0  # Missing because rule only matches /sh, not python3

    # Verify tuning suggestion was generated and persisted
    sugg = res.get("tuning_suggestion")
    assert sugg is not None
    assert sugg["hunt_id"] == hunt_id
    assert "Expand Image" in sugg["action_summary"] or "python3" in sugg["action_summary"]

    persisted_file = workspace / ".hecate" / "tuning_suggestions" / f"{hunt_id}.json"
    assert persisted_file.is_file()
    saved_data = json.loads(persisted_file.read_text(encoding="utf-8"))
    assert saved_data["hunt_id"] == hunt_id
    assert "diff" in saved_data


def test_continuous_replay_sweep_clean_pass(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    hunt_id = "H-0098"

    query_dir = workspace / "queries" / hunt_id
    query_dir.mkdir(parents=True)
    # Rule that matches python execution
    rule_yaml = """title: Python Execution
status: test
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/python3'
            - '/python'
    condition: selection
"""
    (query_dir / "rule.yml").write_text(rule_yaml, encoding="utf-8")

    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    (hunts_dir / f"{hunt_id}.md").write_text(
        f"""---
id: {hunt_id}
title: Python Execution
techniques:
  - T1059.006
platform:
  - linux
---

# Analysis
`python3 -c "import os; os.system('whoami')"`
""",
        encoding="utf-8",
    )

    settings = Settings(
        hecate_workspace=workspace,
        purple_team_continuous_replay_interval_sec=10,
    )

    outcomes = run_continuous_replay_sweep(settings)
    assert len(outcomes) == 1
    res = outcomes[0]
    assert res["passed_rules"] >= 1
    assert res["tuning_suggestion"] is None


def test_daemon_periodic_continuous_replay_triggers(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    settings = Settings(
        hecate_workspace=workspace,
        purple_team_continuous_replay_interval_sec=1,
        auto_hunt_execution_enabled=False,
    )

    mock_orch = MagicMock()
    mock_orch.run_once.return_value = MagicMock(outcome="empty", hunt_id="", detail="")

    with (
        patch("hecate_runner.cli.Settings", return_value=settings),
        patch("hecate_runner.cli.build_default_orchestrator", return_value=mock_orch),
        patch("hecate_runner.cli._configure_logging"),
        patch("hecate_runner.cli._print_result"),
        patch("hecate_runner.integration_checks.start_health_refresh"),
        patch(
            "hecate_runner.purple_team.run_continuous_replay_sweep",
            return_value=[{"hunt_id": "H-0001", "passed_rules": 1, "total_rules": 1}],
        ) as mock_replay_sweep,
    ):
        import pytest
        import typer

        from hecate_runner.cli import daemon

        # Run daemon with max_cycles=1 and interval=0
        with pytest.raises(typer.Exit) as exc_info:
            daemon(interval=0, max_cycles=1, dry_run=False, sweeps=False)
        assert exc_info.value.exit_code == 0

        assert mock_replay_sweep.called


def test_maintenance_siem_drift_generates_tuning_suggestions(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    settings = Settings(hecate_workspace=workspace)
    drift_report = {
        "drifted_count": 1,
        "missing_count": 0,
        "drifted_by_hunt": {
            "H-0044": [{"target": "splunk_spl", "file_name": "rule.spl", "drift_type": "modified"}]
        },
    }

    with (
        patch("hecate_runner.siem_drift.audit_workspace_queries", return_value=drift_report),
        patch("hecate_runner.drift_alerts.notify_drift_report"),
    ):
        from hecate_runner.maintenance import run_job

        run_job(settings, "siem")

        suggestion_file = workspace / ".hecate" / "tuning_suggestions" / "H-0044_drift.json"
        assert suggestion_file.is_file()
        data = json.loads(suggestion_file.read_text(encoding="utf-8"))
        assert data["hunt_id"] == "H-0044"
        assert "splunk_spl" in data["target"]
        assert "action_summary" in data
