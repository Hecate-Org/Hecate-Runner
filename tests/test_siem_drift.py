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


def test_siem_history_sqlite_records_sweeps_and_events(mock_workspace: Path):
    from hecate_runner.siem_drift import get_drift_history, get_drift_db_path

    # Trigger audit sweep
    res = audit_workspace_queries(mock_workspace, dry_run=True, trigger="cli")
    assert res["total_queries"] == 2

    db_path = get_drift_db_path(mock_workspace)
    assert db_path.exists()

    # Reconcile event recording
    rec_results = reconcile_hunt_queries(
        mock_workspace, "H-0007", dry_run=False, force=True, actor="test_analyst"
    )
    assert len(rec_results) >= 1

    history = get_drift_history(mock_workspace, limit=10)
    assert len(history) >= 1
    reconciled_events = [e for e in history if e["event_type"] == "reconciled"]
    assert len(reconciled_events) >= 1
    assert reconciled_events[0]["actor"] == "test_analyst"


def test_siem_query_versioning(mock_workspace: Path):
    from hecate_runner.siem_drift import get_query_versions, record_query_version

    v1 = record_query_version(
        mock_workspace,
        hunt_id="H-0007",
        target="splunk_spl",
        file_name="process__chmod.spl",
        query_content='Image="*/chmod"',
        remote_id="Hecate_H-0007_chmod",
        deployed_by="alice",
    )
    assert v1 == 1

    # Idempotent on same content
    v1_again = record_query_version(
        mock_workspace,
        hunt_id="H-0007",
        target="splunk_spl",
        file_name="process__chmod.spl",
        query_content='Image="*/chmod"',
        remote_id="Hecate_H-0007_chmod",
        deployed_by="alice",
    )
    assert v1_again == 1

    # Increments on updated content
    v2 = record_query_version(
        mock_workspace,
        hunt_id="H-0007",
        target="splunk_spl",
        file_name="process__chmod.spl",
        query_content='Image="*/chmod" CommandLine="*ghostlock*"',
        remote_id="Hecate_H-0007_chmod",
        deployed_by="bob",
    )
    assert v2 == 2

    versions = get_query_versions(mock_workspace, hunt_id="H-0007")
    assert len(versions) == 2
    assert versions[0]["version"] == 2
    assert versions[0]["deployed_by"] == "bob"
    assert versions[1]["version"] == 1


def test_siem_drift_metrics(mock_workspace: Path):
    from hecate_runner.siem_drift import get_siem_drift_metrics

    # Initial audit sweep
    audit_workspace_queries(mock_workspace, dry_run=True)

    metrics = get_siem_drift_metrics(mock_workspace, days=7)
    assert metrics["total_queries"] == 2
    assert metrics["sweeps_conducted"] >= 1
    assert "sync_health_pct" in metrics
    assert metrics["sync_health_pct"] >= 0.0


def test_build_siem_status_and_history_cards(mock_workspace: Path):
    from hecate_runner.slack_blocks import (
        build_runner_status_card,
        build_siem_history_card,
        build_siem_status_card,
    )
    from hecate_runner.siem_drift import get_drift_history, get_siem_drift_metrics

    audit_workspace_queries(mock_workspace, dry_run=True)
    settings = Settings(hecate_workspace=mock_workspace)

    metrics = get_siem_drift_metrics(mock_workspace, days=7)
    history = get_drift_history(mock_workspace, limit=5)

    status_card = build_siem_status_card(settings, metrics, history)
    assert len(status_card) == 1
    assert any("Detection-as-Code SIEM Health" in b.get("text", {}).get("text", "") for b in status_card[0]["blocks"])

    hist_card = build_siem_history_card("H-0007", history)
    assert len(hist_card) == 1
    assert any("SIEM Drift & Versioning History" in b.get("text", {}).get("text", "") for b in hist_card[0]["blocks"])

    runner_card = build_runner_status_card(settings)
    assert len(runner_card) == 1
    all_fields = [f.get("text", "") for f in runner_card[0]["blocks"][1].get("fields", [])]
    assert any("Detection-as-Code Sync" in f for f in all_fields)


def test_cli_drift_history_and_siem_status_and_query_versions(mock_workspace: Path):
    from hecate_runner.siem_drift import record_query_version

    record_query_version(
        mock_workspace,
        hunt_id="H-0007",
        target="splunk_spl",
        file_name="process__chmod.spl",
        query_content='Image="*/chmod"',
        remote_id="Hecate_H-0007_chmod",
        deployed_by="analyst1",
    )
    audit_workspace_queries(mock_workspace, dry_run=True)
    reconcile_hunt_queries(
        mock_workspace, "H-0007", dry_run=False, force=True, actor="analyst1"
    )

    runner = CliRunner()
    with mock.patch.dict("os.environ", {"HECATE_WORKSPACE": str(mock_workspace)}):
        res1 = runner.invoke(app, ["siem-status"])
        assert res1.exit_code == 0
        assert "SIEM Detection-as-Code Status Dashboard" in res1.output

        res2 = runner.invoke(app, ["drift-history"])
        assert res2.exit_code == 0
        assert "SIEM Detection-as-Code Drift & Reconciliation History" in res2.output

        res3 = runner.invoke(app, ["query-versions", "H-0007"])
        assert res3.exit_code == 0
        assert "SIEM Query Versions" in res3.output
        assert "v1" in res3.output
        assert "analyst1" in res3.output


def test_slack_slash_commands_siem_status_and_history(mock_workspace: Path):
    from slack_bolt import App
    from hecate_runner.slack_bot import SlackBotService
    from tests.test_slack_slash_commands import _get_command_listener

    audit_workspace_queries(mock_workspace, dry_run=True)
    settings = Settings(hecate_workspace=mock_workspace)
    mock_app = App(token="xoxb-fake", signing_secret="fake", token_verification_enabled=False)
    service = SlackBotService(settings=settings, app=mock_app)
    assert service.app is mock_app

    cmd_listener = _get_command_listener(mock_app, "/hecate")
    ack_mock = mock.MagicMock()
    respond_mock = mock.MagicMock()

    # /hecate siem-status
    cmd_listener.ack_function(
        ack=ack_mock,
        body={"command": "/hecate", "text": "siem-status", "user_id": "U123", "channel_id": "C123"},
        respond=respond_mock,
    )
    assert ack_mock.called
    assert respond_mock.called
    assert "attachments" in respond_mock.call_args[1]

    # /hecate history H-0007
    ack_mock.reset_mock()
    respond_mock.reset_mock()
    cmd_listener.ack_function(
        ack=ack_mock,
        body={"command": "/hecate", "text": "history H-0007", "user_id": "U123", "channel_id": "C123"},
        respond=respond_mock,
    )
    assert ack_mock.called
    assert respond_mock.called
    assert "attachments" in respond_mock.call_args[1]
