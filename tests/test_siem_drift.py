"""Unit tests for Detection-as-Code SIEM query drift auditing and reconciliation."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
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
)
from hecate_runner.slack_blocks import build_siem_drift_alert_card


@pytest.fixture
def mock_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    q_dir = ws / "queries" / "H-0007"
    q_dir.mkdir(parents=True)
    (q_dir / "process__chmod.spl").write_text('Image="*/chmod"', encoding="utf-8")
    (q_dir / "process__chmod.kql").write_text(
        "ProcessEvents | where Image has 'chmod'", encoding="utf-8"
    )

    h_dir = ws / "hunts" / "2026" / "Q4"
    h_dir.mkdir(parents=True)
    (h_dir / "H-0007.md").write_text(
        "---\n"
        "hunt_id: H-0007\n"
        "title: 'Test Hunt for Chmod'\n"
        "status: planning\n"
        "---\n\n"
        "# H-0007: Test Hunt\n",
        encoding="utf-8",
    )
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


def test_audit_skips_unchanged_hunts_via_mtime_watermark(mock_workspace: Path):
    first = audit_workspace_queries(mock_workspace, dry_run=True)
    assert first["skipped_unchanged"] == 0
    assert first["hunt_watermarks"]["H-0007"]["clean"] is True

    with mock.patch("hecate_runner.siem_drift.sync_queries_for_hunt") as mock_sync:
        second = audit_workspace_queries(mock_workspace, dry_run=True)
        mock_sync.assert_not_called()
    assert second["skipped_unchanged"] == 1
    assert second["total_queries"] == first["total_queries"]

    # Local query change invalidates the watermark.
    q = mock_workspace / "queries" / "H-0007" / "process__chmod.spl"
    q.write_text(q.read_text(encoding="utf-8") + "\n| stats count", encoding="utf-8")
    with mock.patch(
        "hecate_runner.siem_drift.sync_queries_for_hunt",
        return_value=[
            {
                "file": "process__chmod.spl",
                "target": "splunk_spl",
                "status": "dry_run",
                "ok": True,
            }
        ],
    ) as mock_sync:
        third = audit_workspace_queries(mock_workspace, dry_run=True)
        mock_sync.assert_called_once()
    assert third["skipped_unchanged"] == 0

    # force=True always re-syncs even when clean + unchanged.
    with mock.patch(
        "hecate_runner.siem_drift.sync_queries_for_hunt",
        return_value=[
            {
                "file": "process__chmod.spl",
                "target": "splunk_spl",
                "status": "dry_run",
                "ok": True,
            }
        ],
    ) as mock_sync:
        forced = audit_workspace_queries(mock_workspace, dry_run=True, force=True)
        mock_sync.assert_called_once()
    assert forced["skipped_unchanged"] == 0


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
    with (
        mock.patch("httpx.post") as mock_post,
        mock.patch(
            "hecate_runner.http_pool.get_shared_client",
            side_effect=lambda **kwargs: SimpleNamespace(post=mock_post),
        ),
    ):
        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        ok, _detail = notify_siem_drift(settings, "H-0007", drifted)
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


@pytest.fixture
def mock_live_reconcile(monkeypatch):
    monkeypatch.setattr(
        "hecate_runner.siem_drift.sync_queries_for_hunt",
        lambda *args, **kwargs: [
            {"file": "process__chmod.spl", "target": "splunk_spl", "status": "in_sync", "ok": True},
            {
                "file": "process__chmod.kql",
                "target": "sentinel_kql",
                "status": "in_sync",
                "ok": True,
            },
        ],
    )
    monkeypatch.setattr(
        "hecate_agent.api.deploy_transpiled_query",
        lambda **kwargs: {
            "ok": True,
            "remote_id": "test-saved-search",
            "detail": "Simulated deployment",
        },
    )
    monkeypatch.setattr(
        "hecate_agent.api.sync_transpiled_query",
        lambda **kwargs: {
            "ok": True,
            "status": "in_sync",
        },
    )


def test_siem_history_sqlite_records_sweeps_and_events(mock_workspace: Path, mock_live_reconcile):
    from hecate_runner.siem_drift import get_drift_db_path, get_drift_history

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
    from hecate_runner.siem_drift import get_drift_history, get_siem_drift_metrics
    from hecate_runner.slack_blocks import (
        build_runner_status_card,
        build_siem_history_card,
        build_siem_status_card,
    )

    audit_workspace_queries(mock_workspace, dry_run=True)
    settings = Settings(hecate_workspace=mock_workspace)

    metrics = get_siem_drift_metrics(mock_workspace, days=7)
    history = get_drift_history(mock_workspace, limit=5)

    status_card = build_siem_status_card(settings, metrics, history)
    assert len(status_card) == 1
    assert any(
        "Detection-as-Code SIEM Health" in b.get("text", {}).get("text", "")
        for b in status_card[0]["blocks"]
    )

    hist_card = build_siem_history_card("H-0007", history)
    assert len(hist_card) == 1
    assert any(
        "SIEM Drift & Versioning History" in b.get("text", {}).get("text", "")
        for b in hist_card[0]["blocks"]
    )

    runner_card = build_runner_status_card(settings)
    assert len(runner_card) == 1
    all_fields = [f.get("text", "") for f in runner_card[0]["blocks"][1].get("fields", [])]
    assert any("Detection-as-Code Sync" in f for f in all_fields)


def test_cli_drift_history_and_siem_status_and_query_versions(
    mock_workspace: Path, mock_live_reconcile
):
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
    reconcile_hunt_queries(mock_workspace, "H-0007", dry_run=False, force=True, actor="analyst1")

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
        body={
            "command": "/hecate",
            "text": "history H-0007",
            "user_id": "U123",
            "channel_id": "C123",
        },
        respond=respond_mock,
    )
    assert ack_mock.called
    assert respond_mock.called
    assert "attachments" in respond_mock.call_args[1]


def test_build_siem_markdown_report_in_sync() -> None:
    from hecate_runner.siem_drift import build_siem_markdown_report

    report = {
        "total_hunts": 2,
        "total_queries": 4,
        "in_sync_count": 4,
        "drifted_count": 0,
        "missing_count": 0,
        "error_count": 0,
        "dry_run": True,
        "audited_at": "2026-11-02T04:00:00Z",
        "hunts": {
            "H-0001": [
                {"target": "splunk_spl", "status": "in_sync"},
                {"target": "sentinel_kql", "status": "in_sync"},
            ],
            "H-0002": [
                {"target": "splunk_spl", "status": "in_sync"},
                {"target": "sentinel_kql", "status": "in_sync"},
            ],
        },
        "drifted_by_hunt": {},
    }

    md = build_siem_markdown_report(report)
    assert "## 🛡️ SIEM Detection-as-Code GitOps Report" in md
    assert "IN SYNC (100%)" in md
    assert "| **Total Hunts** | `2` |" in md
    assert "| `splunk_spl` | `2` | `2` | `0` | `0` | `0` | 🟢 In Sync (`100.0%`) |" in md
    assert "No active drift detected across targets." in md


def test_build_siem_markdown_report_with_drift() -> None:
    from hecate_runner.siem_drift import build_siem_markdown_report

    report = {
        "total_hunts": 1,
        "total_queries": 2,
        "in_sync_count": 1,
        "drifted_count": 1,
        "missing_count": 0,
        "error_count": 0,
        "dry_run": False,
        "audited_at": "2026-11-02T04:00:00Z",
        "hunts": {
            "H-0007": [
                {"target": "splunk_spl", "status": "in_sync"},
                {
                    "target": "splunk_spl",
                    "status": "drift_detected",
                    "file": "test.spl",
                    "remote_id": "Hecate_Test",
                    "drift_diff": "- Local: foo\n+ Remote: bar",
                },
            ]
        },
        "drifted_by_hunt": {
            "H-0007": [
                {
                    "target": "splunk_spl",
                    "status": "drift_detected",
                    "file": "test.spl",
                    "remote_id": "Hecate_Test",
                    "drift_diff": "- Local: foo\n+ Remote: bar",
                }
            ]
        },
    }

    md = build_siem_markdown_report(report)
    assert "⚠️ **DRIFT DETECTED** (1 query)" in md
    assert "<summary><b>⚠️ H-0007 / splunk_spl: <code>test.spl</code></b>" in md
    assert "- Local: foo" in md
    assert "+ Remote: bar" in md


def test_cli_audit_siem_markdown_and_fail_on_drift(mock_workspace: Path) -> None:
    from unittest import mock

    from typer.testing import CliRunner

    from hecate_runner.cli import app

    runner = CliRunner()
    with mock.patch.dict("os.environ", {"HECATE_WORKSPACE": str(mock_workspace)}):
        # Clean in-sync run: should succeed
        res = runner.invoke(
            app, ["audit-siem", "--format", "markdown", "--dry-run", "--fail-on-drift"]
        )
        assert res.exit_code == 0
        assert "## 🛡️ SIEM Detection-as-Code GitOps Report" in res.output

        # Output to markdown file and step summary
        summary_file = mock_workspace / "step_summary.md"
        out_file = mock_workspace / "pr_report.md"

        with mock.patch.dict("os.environ", {"GITHUB_STEP_SUMMARY": str(summary_file)}):
            res_out = runner.invoke(
                app,
                [
                    "audit-siem",
                    "--format",
                    "table",
                    "--output-markdown",
                    str(out_file),
                    "--github-step-summary",
                    "--dry-run",
                ],
            )
            assert res_out.exit_code == 0
            assert out_file.exists()
            assert summary_file.exists()
            assert "## 🛡️ SIEM Detection-as-Code GitOps Report" in out_file.read_text(
                encoding="utf-8"
            )


def test_cli_deploy_queries_all(mock_workspace: Path) -> None:
    from unittest import mock

    from typer.testing import CliRunner

    from hecate_runner.cli import app

    runner = CliRunner()
    summary_file = mock_workspace / "deploy_summary.md"

    with mock.patch.dict(
        "os.environ",
        {"HECATE_WORKSPACE": str(mock_workspace), "GITHUB_STEP_SUMMARY": str(summary_file)},
    ):
        res = runner.invoke(app, ["deploy-queries", "all", "--dry-run", "--github-step-summary"])
        assert res.exit_code == 0
        assert "SIEM & EDR Query Deployment (All Hunts)" in res.output
        assert summary_file.exists()
        assert "## 🚀 SIEM Detection-as-Code Deployment" in summary_file.read_text(encoding="utf-8")


def test_hunt_lifecycle_transitions(mock_workspace: Path) -> None:
    from hecate_runner.lifecycle import (
        get_hunt_lifecycle,
        normalize_lifecycle_state,
        set_hunt_lifecycle,
    )

    assert normalize_lifecycle_state("active") == "active"
    assert normalize_lifecycle_state("draft") == "planning"
    assert normalize_lifecycle_state("archived") == "retired"
    assert normalize_lifecycle_state("test") == "testing"

    # Initial state of H-0007
    lc = get_hunt_lifecycle(mock_workspace, "H-0007")
    assert lc["found"] is True
    assert lc["status"] in ("planning", "active")

    # Transition to deprecated
    dep_res = set_hunt_lifecycle(
        mock_workspace,
        "H-0007",
        "deprecated",
        reason="Superceded by H-0010",
        actor="secops_lead",
    )
    assert dep_res["ok"] is True
    assert dep_res["status"] == "deprecated"
    assert dep_res["deprecation_reason"] == "Superceded by H-0010"
    assert dep_res["deprecated_by"] == "secops_lead"
    assert dep_res["deprecated_at"] is not None

    # Transition to retired
    ret_res = set_hunt_lifecycle(
        mock_workspace,
        "H-0007",
        "retired",
        reason="Decommissioning production rules",
        actor="lead_hunter",
    )
    assert ret_res["ok"] is True
    assert ret_res["status"] == "retired"
    assert ret_res["retirement_reason"] == "Decommissioning production rules"
    assert ret_res["retired_by"] == "lead_hunter"
    assert ret_res["is_retired"] is True


@pytest.fixture
def mock_live_undeploy(monkeypatch):
    """Lifecycle tests exercise local persistence using a simulated SIEM response."""
    monkeypatch.setattr(
        "hecate_runner.siem_drift.undeploy_queries_for_hunt",
        lambda **kwargs: [
            {
                "file": "process__chmod.spl",
                "target": "splunk_spl",
                "status": "undeployed",
                "ok": True,
                "remote_id": "Hecate_H-0007_chmod",
            }
        ],
    )


def test_decommission_hunt_queries(mock_workspace: Path, mock_live_undeploy) -> None:
    import sqlite3

    from hecate_runner.siem_drift import (
        decommission_hunt_queries,
        get_drift_db_path,
        record_query_version,
    )

    # First record an active query version
    record_query_version(
        mock_workspace,
        hunt_id="H-0007",
        target="splunk_spl",
        file_name="process__chmod.spl",
        query_content='Image="*/chmod"',
        remote_id="Hecate_H-0007_chmod",
        deployed_by="ci",
    )

    # Run query decommissioning
    res = decommission_hunt_queries(
        mock_workspace,
        hunt_id="H-0007",
        dry_run=False,
        target="splunk_spl",
        reason="Threat actor dormant",
        actor="analyst_alice",
        retire_hunt=True,
    )

    assert res["total_decommissioned"] >= 1
    assert res["retired_hunt"] is True

    # Verify query_versions is updated to decommissioned
    db_path = get_drift_db_path(mock_workspace)
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT status FROM query_versions WHERE hunt_id = 'H-0007' AND target = 'splunk_spl'"
        ).fetchone()
        assert row is not None
        assert row[0] == "decommissioned"

        # Verify decommission event recorded in drift_events
        ev = conn.execute(
            "SELECT event_type, actor, detail FROM drift_events WHERE hunt_id = 'H-0007' AND event_type = 'decommissioned'"
        ).fetchone()
        assert ev is not None
        assert ev[0] == "decommissioned"
        assert ev[1] == "analyst_alice"
        assert "Threat actor dormant" in ev[2]
    finally:
        conn.close()


def test_audit_workspace_with_decommissioned_queries(
    mock_workspace: Path, mock_live_undeploy
) -> None:
    from unittest import mock

    from hecate_runner.siem_drift import (
        audit_workspace_queries,
        build_siem_markdown_report,
        decommission_hunt_queries,
    )

    # Decommission H-0007 and retire hunt
    decommission_hunt_queries(
        mock_workspace,
        hunt_id="H-0007",
        dry_run=False,
        target="splunk_spl",
        reason="Campaign concluded",
        actor="analyst_bob",
        retire_hunt=True,
    )

    # Mock sync check to simulate that the remote query is now missing from SIEM
    with mock.patch("hecate_runner.siem_drift.sync_queries_for_hunt") as mock_sync:
        mock_sync.return_value = [
            {
                "file": "process__chmod.spl",
                "target": "splunk_spl",
                "status": "missing_remote",
                "ok": False,
                "remote_id": "Hecate_H-0007_chmod",
                "detail": "Rule not found on remote SIEM",
            }
        ]

        report = audit_workspace_queries(mock_workspace, target="splunk_spl", dry_run=False)

        # Because hunt is retired / decommissioned, missing_remote is recognized as decommissioned!
        assert report["decommissioned_count"] == 1
        assert report["missing_count"] == 0
        assert report["drifted_count"] == 0

        h_queries = report["hunts"]["H-0007"]
        assert h_queries[0]["status"] == "decommissioned"
        assert h_queries[0]["is_decommissioned"] is True

        md = build_siem_markdown_report(report)
        assert "| **Decommissioned** | `1` |" in md
        assert "✅ **IN SYNC (100%)**" in md


def test_audit_workspace_pending_decommission(mock_workspace: Path) -> None:
    from unittest import mock

    from hecate_runner.lifecycle import set_hunt_lifecycle
    from hecate_runner.siem_drift import audit_workspace_queries, build_siem_markdown_report

    # Retire the hunt in git
    set_hunt_lifecycle(mock_workspace, "H-0007", "retired", reason="Retiring", actor="lead")

    # Remote SIEM still has the rule running (in_sync)
    with mock.patch("hecate_runner.siem_drift.sync_queries_for_hunt") as mock_sync:
        mock_sync.return_value = [
            {
                "file": "process__chmod.spl",
                "target": "splunk_spl",
                "status": "in_sync",
                "ok": True,
                "remote_id": "Hecate_H-0007_chmod",
                "detail": "Search exists on remote SIEM",
            }
        ]

        report = audit_workspace_queries(mock_workspace, target="splunk_spl", dry_run=False)

        assert report["pending_decommission_count"] == 1
        assert report["in_sync_count"] == 0
        h_queries = report["hunts"]["H-0007"]
        assert h_queries[0]["status"] == "pending_decommission"

        md = build_siem_markdown_report(report)
        assert "⚠️ **DECOMMISSION PENDING**" in md
        assert "Pending Remote Decommissioning" in md


def test_cli_decommission_and_lifecycle(mock_workspace: Path) -> None:
    from unittest import mock

    from typer.testing import CliRunner

    from hecate_runner.cli import app

    runner = CliRunner()
    summary_file = mock_workspace / "decom_summary.md"

    with mock.patch.dict(
        "os.environ",
        {"HECATE_WORKSPACE": str(mock_workspace), "GITHUB_STEP_SUMMARY": str(summary_file)},
    ):
        # View lifecycle
        res_view = runner.invoke(app, ["hunt-lifecycle", "H-0007"])
        assert res_view.exit_code == 0
        assert "Hunt Lifecycle Metadata: H-0007" in res_view.output

        # Update lifecycle to deprecated
        res_dep = runner.invoke(
            app,
            [
                "hunt-lifecycle",
                "H-0007",
                "deprecated",
                "--reason",
                "Under migration",
                "--actor",
                "eng_dan",
            ],
        )
        assert res_dep.exit_code == 0
        assert "deprecated" in res_dep.output

        # Decommission queries
        res_decom = runner.invoke(
            app,
            [
                "decommission-queries",
                "H-0007",
                "--dry-run",
                "--reason",
                "Decommissioning for sprint end",
                "--actor",
                "eng_dan",
                "--github-step-summary",
            ],
        )
        assert res_decom.exit_code == 0
        assert "SIEM Detection Query Decommissioning" in res_decom.output
        assert summary_file.exists()
        assert "SIEM Detection Query Decommissioning" in summary_file.read_text(encoding="utf-8")
