"""Edge-case coverage for refactored deploy/siem CLI command modules."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from hecate_runner.cli import app

runner = CliRunner()


def test_deploy_queries_rejects_empty_hunt_id(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "queries").mkdir()
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    result = runner.invoke(app, ["deploy-queries", "", "--dry-run"])
    assert result.exit_code == 1
    assert "Invalid hunt ID" in result.output


def test_deploy_queries_all_includes_hnt_prefix(tmp_path: Path, monkeypatch) -> None:
    queries = tmp_path / "queries"
    (queries / "H-0001").mkdir(parents=True)
    (queries / "HNT-0002").mkdir()
    (queries / "junk").mkdir()
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    with patch(
        "hecate_runner.commands.deploy.deploy_queries_for_hunt", return_value=[]
    ) as mock_dep:
        result = runner.invoke(app, ["deploy-queries", "all", "--dry-run"])
    assert result.exit_code == 0
    assert {c.args[1] for c in mock_dep.call_args_list} == {"H-0001", "HNT-0002"}


def test_sync_and_reconcile_reject_path_traversal(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "queries").mkdir()
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    for cmd in (["sync-queries", "../etc"], ["reconcile-queries", "H-0001/../../x"]):
        result = runner.invoke(app, [*cmd, "--dry-run"])
        assert result.exit_code == 1
        assert "Invalid hunt ID" in result.output


def test_siem_status_reflects_days_window(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "queries").mkdir()
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    with (
        patch(
            "hecate_runner.commands.siem.siem_drift.get_siem_drift_metrics",
            return_value={
                "sync_health_pct": 100.0,
                "in_sync_count": 0,
                "total_queries": 0,
                "drifted_count": 0,
                "missing_count": 0,
                "tracked_query_versions": 0,
                "sweeps_conducted": 2,
                "reconciliations_period": 1,
                "last_audited": "never",
                "target_drift_breakdown": {"splunk_spl": 3},
            },
        ),
        patch("hecate_runner.commands.siem.siem_drift.get_drift_history", return_value=[]),
    ):
        result = runner.invoke(app, ["siem-status", "--days", "14"])
    assert result.exit_code == 0
    assert "14-Day Audit Sweeps" in result.output
    assert "Past 14 Days" in result.output
    assert "7-Day" not in result.output


def test_siem_status_rejects_non_positive_days(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "queries").mkdir()
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    result = runner.invoke(app, ["siem-status", "--days", "0"])
    assert result.exit_code == 1
    assert "Invalid --days" in result.output


def test_deploy_verbose_tolerates_non_jsonable_summary(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "queries" / "H-0001").mkdir(parents=True)
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    with patch(
        "hecate_runner.commands.deploy.deploy_queries_for_hunt",
        return_value=[
            {
                "ok": True,
                "file": "q.kql",
                "target": "sentinel_kql",
                "status": "dry_run",
                "remote_id": None,
                "detail": "",
                "request_summary": {"path": Path("/tmp/x")},
            }
        ],
    ):
        result = runner.invoke(app, ["deploy-queries", "H-0001", "--dry-run", "--verbose"])
    assert result.exit_code == 0
    assert "Contract Payload" in result.output


def test_github_step_summary_creates_missing_parent(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "queries" / "H-0001").mkdir(parents=True)
    summary = tmp_path / "nested" / "missing" / "summary.md"
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    with patch(
        "hecate_runner.commands.deploy.deploy_queries_for_hunt",
        return_value=[
            {
                "ok": True,
                "file": "q.kql",
                "target": "t",
                "status": "dry_run",
                "remote_id": None,
                "detail": "",
            }
        ],
    ):
        result = runner.invoke(
            app, ["deploy-queries", "H-0001", "--dry-run", "--github-step-summary"]
        )
    assert result.exit_code == 0
    assert summary.exists()
    assert "Deployment" in summary.read_text()
