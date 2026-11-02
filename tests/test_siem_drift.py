"""Unit tests for Detection-as-Code SIEM query drift auditing and reconciliation."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest
from typer.testing import CliRunner

from hecate_runner.cli import app
from hecate_runner.config import Settings
from hecate_runner.notifications import notify_siem_drift
from hecate_runner.siem_drift import (
    audit_workspace_queries,
    load_drift_state,
    reconcile_all_drifted_queries,
    reconcile_hunt_queries,
    save_drift_state,
)
from hecate_runner.slack_blocks import build_siem_drift_alert_card


@pytest.fixture
def mock_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    q_dir = ws / "queries" / "H-0007"
    q_dir.mkdir(parents=True)
    (q_dir / "process__chmod.spl").write_text('Image="*/chmod"', encoding="utf-8")
    (q_dir / "process__chmod.kql").write_text("ProcessEvents | where Image has 'chmod'", encoding="utf-8")
    return ws


def test_audit_workspace_queries_empty(tmp_path: Path):
    ws = tmp_path / "empty_workspace"
    ws.mkdir()
    res = audit_workspace_queries(ws, dry_run=True)
    assert res["total_hunts"] == 0
    assert res["total_queries"] == 0
    assert res["in_sync_count"] == 0
    assert res["drifted_count"] == 0


def test_audit_workspace_queries_with_queries(mock_workspace: Path):
    res = audit_workspace_queries(mock_workspace, dry_run=True)
    assert res["total_hunts"] == 1
    assert res["total_queries"] == 2
    assert "H-0007" in res["hunts"]
    assert res["dry_run"] is True


def test_audit_workspace_queries_persistence(mock_workspace: Path):
    res = audit_workspace_queries(mock_workspace, dry_run=True)
    saved = load_drift_state(mock_workspace)
    assert saved is not None
    assert saved["total_hunts"] == res["total_hunts"]
    assert saved["total_queries"] == res["total_queries"]


def test_reconcile_hunt_queries_dry_run(mock_workspace: Path):
    results = reconcile_hunt_queries(mock_workspace, "H-0007", dry_run=True, force=True)
    assert len(results) == 2
    for r in results:
        assert r["status"] in {"in_sync", "dry_run"}
        assert r["ok"] is True
        assert r["target"] in {"splunk_spl", "sentinel_kql"}


def test_reconcile_all_drifted_queries_mocked(mock_workspace: Path):
    with mock.patch("hecate_runner.siem_drift.sync_queries_for_hunt") as mock_sync:
        mock_sync.return_value = [
            {
                "file": "process__chmod.spl",
                "target": "splunk_spl",
                "status": "drift_detected",
                "ok": False,
                "remote_id": "Hecate_H-0007_chmod",
                "drift_diff": "- Local: foo\n+ Remote: bar",
            }
        ]

        summary = reconcile_all_drifted_queries(mock_workspace, dry_run=True)
        assert summary["hunts_count"] == 1
        assert summary["total_reconciled"] >= 1
        assert "H-0007" in summary["by_hunt"]


def test_build_siem_drift_alert_card(mock_workspace: Path):
    settings = Settings(hecate_workspace=mock_workspace)
    drifted = [
        {
            "target": "splunk_spl",
            "file": "test.spl",
            "status": "drift_detected",
            "remote_id": "Hecate_H-0007_test",
            "drift_diff": "- Local: foo\n+ Remote: bar",
        }
    ]
    card = build_siem_drift_alert_card("H-0007", drifted, settings, interactive=True)
    assert len(card) == 1
    blocks = card[0]["blocks"]
    assert any("⚠️ SIEM Query Drift: H-0007" in b.get("text", {}).get("text", "") for b in blocks)
    actions = [b for b in blocks if b.get("type") == "actions"]
    assert len(actions) == 1
    action_ids = [btn.get("action_id") for btn in actions[0]["elements"]]
    assert "hecate_reconcile_drift" in action_ids


def test_notify_siem_drift(mock_workspace: Path):
    settings = Settings(
        hecate_workspace=mock_workspace,
        slack_webhook_url="https://hooks.slack.com/services/T00/B00/X00",
    )
    drifted = [
        {
            "target": "splunk_spl",
            "file": "test.spl",
            "status": "drift_detected",
            "remote_id": "Hecate_H-0007_test",
        }
    ]
    with mock.patch("httpx.post") as mock_post:
        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        ok, detail = notify_siem_drift(settings, "H-0007", drifted)
        assert ok is True


def test_cli_audit_siem_command(mock_workspace: Path):
    runner = CliRunner()
    with mock.patch.dict("os.environ", {"HECATE_WORKSPACE": str(mock_workspace)}):
        result = runner.invoke(app, ["audit-siem", "--dry-run"])
        assert result.exit_code == 0
        assert "SIEM & EDR Detection-as-Code Audit" in result.output
        assert "H-0007" in result.output
        assert "splunk_spl" in result.output


def test_cli_reconcile_queries_command(mock_workspace: Path):
    runner = CliRunner()
    with mock.patch.dict("os.environ", {"HECATE_WORKSPACE": str(mock_workspace)}):
        result = runner.invoke(app, ["reconcile-queries", "H-0007", "--dry-run", "--force"])
        assert result.exit_code == 0
        assert "SIEM & EDR Query Reconciliation for H-0007" in result.output
        assert "splunk_spl" in result.output
