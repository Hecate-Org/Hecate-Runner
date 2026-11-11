"""Unit tests for closed-loop BAS adversary emulation and live SIEM alert verification."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from hecate_runner.bas.base import DetonationRequest, DetonationTarget
from hecate_runner.bas.mock import MockBASProvider
from hecate_runner.bas.siem_verifier import SiemAlertVerificationResult, SiemAlertVerifier
from hecate_runner.cli import app
from hecate_runner.siem_drift import get_detection_validations, init_drift_db

runner = CliRunner()


@pytest.fixture
def mock_siem_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir(parents=True)
    init_drift_db(ws)

    # Mock H-0011 queries
    query_dir = ws / "queries" / "H-0011"
    query_dir.mkdir(parents=True)
    spl_file = (
        query_dir
        / "process_creation__execution_of_comsvcs_dll_minidump_via_rundll32_exe_for_lsass.spl"
    )
    spl_file.write_text(
        'Image="*\\rundll32.exe" CommandLine="*comsvcs.dll*" CommandLine="*MiniDump*"',
        encoding="utf-8",
    )
    yml_file = (
        query_dir
        / "process_creation__execution_of_comsvcs_dll_minidump_via_rundll32_exe_for_lsass.yml"
    )
    yml_file.write_text(
        "title: MiniDump via comsvcs.dll\ntags:\n  - attack.t1003.001\n"
        "detection:\n  selection:\n    CommandLine|contains: MiniDump\n  condition: selection\n",
        encoding="utf-8",
    )

    # Mock H-0011 hunt markdown
    hunts_dir = ws / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0011.md"
    hunt_file.write_text(
        "---\n"
        "hunt_id: H-0011\n"
        "title: LSASS Memory Dump\n"
        "status: active\n"
        "platform:\n  - Windows\n"
        "techniques:\n  - T1003.001\n"
        "---\n\n"
        "# Description\nAdversaries use comsvcs.dll to dump LSASS memory.\n",
        encoding="utf-8",
    )
    return ws


def test_mock_provider_minidump_telemetry():
    """Verify MockBASProvider generates comsvcs MiniDump telemetry for T1003.001."""
    provider = MockBASProvider()
    target = DetonationTarget(environment="lab", platform="windows")
    req = DetonationRequest(
        hunt_id="H-0011",
        technique_id="T1003.001",
        platform="windows",
        target=target,
    )
    res = provider.detonate(req)
    assert res.success is True
    assert len(res.telemetry_signatures) == 1

    ev = res.telemetry_signatures[0]
    assert ev["process_name"] == "rundll32.exe"
    assert "comsvcs.dll" in ev["CommandLine"]
    assert "MiniDump" in ev["CommandLine"]
    assert "rundll32.exe" in ev["Image"]
    assert ev["technique_id"] == "T1003.001"
    assert ev["hunt_id"] == "H-0011"


def test_siem_verifier_query_resolution(mock_siem_workspace: Path):
    """Verify SiemAlertVerifier resolves correct SPL query for hunt and technique."""
    verifier = SiemAlertVerifier(mock_siem_workspace)
    query, src = verifier.resolve_candidate_query("H-0011", "T1003.001")
    assert "comsvcs.dll" in query
    assert "MiniDump" in query
    assert "process_creation__execution_of_comsvcs_dll_minidump" in src

    # Also verify resolve_candidate_rule returns candidate YAML
    q, s, y = verifier.resolve_candidate_rule("H-0011", "T1003.001")
    assert "comsvcs.dll" in q
    assert "MiniDump" in q
    assert "process_creation__execution_of_comsvcs_dll_minidump" in s
    assert "attack.t1003.001" in y


def test_siem_verifier_normalize_spl():
    """Verify SPL queries are normalized for Splunk search jobs against JSON events."""
    verifier = SiemAlertVerifier(Path("/tmp"))
    norm = verifier._normalize_spl_query(
        'search Image="*\\rundll32.exe" CommandLine="*comsvcs.dll*"'
    )
    assert norm.startswith("index=* | spath | search")
    assert 'Image="*rundll32.exe"' in norm
    assert 'CommandLine="*comsvcs.dll*"' in norm


def test_siem_verifier_mock_mode(mock_siem_workspace: Path):
    """Verify SiemAlertVerifier in mock mode measures latency and persists results."""
    provider = MockBASProvider()
    target = DetonationTarget(environment="lab", platform="windows")
    req = DetonationRequest(
        hunt_id="H-0011",
        technique_id="T1003.001",
        platform="windows",
        target=target,
    )
    det = provider.detonate(req)

    verifier = SiemAlertVerifier(mock_siem_workspace)
    res = verifier.verify_detonation_alert(
        detonation=det,
        hunt_id="H-0011",
        siem_target="mock",
    )

    assert isinstance(res, SiemAlertVerificationResult)
    assert res.status == "simulation_match"
    assert res.rule_triggered is True
    assert res.detection_latency_sec is None
    assert res.search_job_id == ""
    assert res.alert_time_utc == ""
    assert res.matched_events_count == 1

    # Verify persisted in SQLite
    validations = get_detection_validations(mock_siem_workspace, "H-0011")
    assert len(validations) >= 1
    assert validations[0]["hunt_id"] == "H-0011"
    assert validations[0]["status"] == "simulation_match"
    assert validations[0]["detection_latency_sec"] is None

    # Verify persisted in .hecate/bas/runs/
    runs_dir = mock_siem_workspace / ".hecate" / "bas" / "runs"
    assert runs_dir.is_dir()
    run_files = list(runs_dir.glob("*.json"))
    assert len(run_files) >= 1
    run_data = json.loads(run_files[0].read_text(encoding="utf-8"))
    assert run_data["hunt_id"] == "H-0011"
    assert run_data["status"] == "simulation_match"


def test_siem_verifier_live_execution_mocked(mock_siem_workspace: Path, monkeypatch):
    """Test live search jobs flow with mocked Splunk client measuring latency."""
    monkeypatch.setenv("SPLUNK_HOST", "https://localhost:8089")
    monkeypatch.setenv("SPLUNK_TOKEN", "mock-token-xyz")

    provider = MockBASProvider()
    target = DetonationTarget(environment="lab", platform="windows")
    req = DetonationRequest(
        hunt_id="H-0011",
        technique_id="T1003.001",
        platform="windows",
        target=target,
    )
    det = provider.detonate(req)
    det.provider = "caldera"

    mock_client = MagicMock()
    mock_client.create_search_job.return_value = "1793600999.123"
    mock_client.get_search_job_status.return_value = {
        "entry": [{"content": {"isDone": True, "resultCount": 1}}]
    }
    mock_client.get_search_results.return_value = [
        {"CommandLine": "rundll32.exe comsvcs.dll MiniDump"}
    ]

    with (
        patch("hecate_agent.core.splunk_client.SplunkClient", return_value=mock_client),
        patch("hecate_runner.bas.siem_verifier.forward_events_to_splunk", return_value=1),
    ):
        verifier = SiemAlertVerifier(
            mock_siem_workspace, max_wait_sec=0.02, poll_interval_sec=0.001
        )
        res = verifier.verify_detonation_alert(
            detonation=det,
            hunt_id="H-0011",
            siem_target="splunk",
            t0_detonate=123456.0,
        )

    assert res.status == "query_match"
    assert res.rule_triggered is True
    assert res.search_job_id == "1793600999.123"
    assert res.detection_latency_sec is None
    assert res.query_match_latency_sec > 0
    assert not res.siem_alert_fired
    assert res.alert_time_utc == ""
    assert res.matched_events_count == 1
    mock_client.create_search_job.assert_called_once()
    from datetime import datetime, timedelta

    expected = (datetime.fromisoformat(det.start_time_utc) - timedelta(seconds=30)).isoformat()
    assert mock_client.create_search_job.call_args.kwargs["earliest_time"] == expected
    mock_client.get_search_results.assert_called_once_with("1793600999.123", count=25)


def test_cli_bas_detonate_with_siem_verification(mock_siem_workspace: Path, monkeypatch):
    """Test bas-detonate CLI command with --verify-siem outputs detection latency."""
    mock_settings = MagicMock()
    mock_settings.hecate_workspace = mock_siem_workspace
    mock_settings.bas_allowed_hosts = ["lab-host"]
    mock_settings.bas_allowed_accounts = []
    mock_settings.bas_mode = "mock"

    with patch("hecate_runner.commands.bas._get_settings", return_value=mock_settings):
        result = runner.invoke(
            app,
            [
                "bas-detonate",
                "T1003.001",
                "--hunt-id",
                "H-0011",
                "--provider",
                "mock",
                "--platform",
                "windows",
                "--siem-target",
                "mock",
                "--verify-siem",
            ],
        )

    assert result.exit_code == 0
    assert "Closed-Loop Detection Validation" in result.output
    assert "True Positive Detection Latency" not in result.output
    assert "SIMULATION_MATCH" in result.output


def test_siem_verifier_mock_mode_non_matching_query_fails_detection(mock_siem_workspace: Path):
    """Verify mock SIEM actually evaluates query and reports detection_miss on non-matching query."""
    provider = MockBASProvider()
    target = DetonationTarget(environment="lab", platform="windows")
    req = DetonationRequest(
        hunt_id="H-0011",
        technique_id="T1003.001",
        platform="windows",
        target=target,
    )
    det = provider.detonate(req)

    verifier = SiemAlertVerifier(mock_siem_workspace)
    # Query that could never match the MiniDump telemetry
    res = verifier.verify_detonation_alert(
        detonation=det,
        hunt_id="H-0011",
        candidate_query='CommandLine="*CompletelyUnrelatedPayload*DoesNotExist*"',
        siem_target="mock",
    )

    assert res.status == "simulation_unsupported"
    assert res.rule_triggered is False
    assert res.matched_events_count == 0
    assert res.detection_latency_sec is None
    assert any("matched=0" in n for n in res.notes)


def test_siem_verifier_missing_credentials_refuses_silent_mock(
    mock_siem_workspace: Path, monkeypatch
):
    """Verify that when live Splunk target is requested without credentials, it refuses silent mock."""
    monkeypatch.delenv("SPLUNK_HOST", raising=False)
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.delenv("SPLUNK_PASSWORD", raising=False)

    provider = MockBASProvider()
    target = DetonationTarget(environment="lab", platform="windows")
    req = DetonationRequest(
        hunt_id="H-0011",
        technique_id="T1003.001",
        platform="windows",
        target=target,
    )
    det = provider.detonate(req)
    det.provider = "caldera"

    verifier = SiemAlertVerifier(mock_siem_workspace)
    res = verifier.verify_detonation_alert(
        detonation=det,
        hunt_id="H-0011",
        siem_target="splunk",
    )

    assert res.status == "unconfigured_credentials"
    assert res.rule_triggered is False
    assert res.siem_backend == "splunk"
    assert any("refusing silent mock fallback" in n for n in res.notes)


def test_mock_detonation_never_contacts_live_siem(mock_siem_workspace):
    det = MockBASProvider().detonate(DetonationRequest(hunt_id="H-0011", technique_id="T1003.001"))
    with (
        patch(
            "hecate_runner.bas.siem_verifier.splunk_settings",
            return_value={"SPLUNK_HOST": "https://siem.invalid", "SPLUNK_TOKEN": "test"},
        ),
        patch("hecate_runner.bas.siem_verifier.forward_events_to_splunk") as forward,
        patch("hecate_agent.core.splunk_client.SplunkClient") as client,
    ):
        result = SiemAlertVerifier(mock_siem_workspace).verify_detonation_alert(
            det, "H-0011", siem_target="splunk"
        )
    assert result.status == "simulation_match"
    assert result.siem_backend == "mock"
    assert result.detection_latency_sec is None
    forward.assert_not_called()
    client.assert_not_called()


def test_mock_cannot_approximate_native_query(mock_siem_workspace):
    det = MockBASProvider().detonate(DetonationRequest(hunt_id="H-0011", technique_id="T1003.001"))
    result = SiemAlertVerifier(mock_siem_workspace).verify_detonation_alert(
        det, "H-0011", candidate_query='Image="*rundll32.exe" | where 1=0', siem_target="mock"
    )
    assert result.status == "simulation_unsupported"
    assert not result.rule_triggered
    assert result.matched_events_count == 0


def test_missing_detection_never_creates_fallback(tmp_path):
    verifier = SiemAlertVerifier(tmp_path)
    for technique in ("T1033", "T1003.001", "T1059.001"):
        assert verifier.resolve_candidate_rule("H-MISSING", technique) == ("", "", "")


def test_yaml_only_detection_does_not_manufacture_spl(tmp_path):
    directory = tmp_path / "queries" / "H-TEST"
    directory.mkdir(parents=True)
    rule = "title: Actual Hunt Rule\ntags: [attack.t1033]\ndetection:\n  selection:\n    Image: /usr/bin/whoami\n  condition: selection\n"
    (directory / "actual.yml").write_text(rule)
    query, name, content = SiemAlertVerifier(tmp_path).resolve_candidate_rule("H-TEST", "T1033")
    assert query == ""
    assert name == "actual.yml"
    assert content == rule


def test_resolver_never_pairs_unrelated_native_query_and_sigma(tmp_path):
    directory = tmp_path / "queries" / "H-TEST"
    directory.mkdir(parents=True)
    (directory / "t1033.spl").write_text('Image="/usr/bin/whoami"')
    (directory / "other.yml").write_text("title: Other\ntags: [attack.t1057]\n")
    query, name, content = SiemAlertVerifier(tmp_path).resolve_candidate_rule("H-TEST", "T1033")
    assert query == 'Image="/usr/bin/whoami"'
    assert name == "t1033.spl"
    assert content == ""


def test_correlated_fired_alert_is_persisted_as_alert_proof(mock_siem_workspace):
    from datetime import UTC, datetime

    from hecate_runner.siem_drift import get_siem_drift_metrics

    det = MockBASProvider().detonate(DetonationRequest(hunt_id="H-0011", technique_id="T1003.001"))
    det.provider = "caldera"
    det.telemetry_signatures[0]["timestamp_utc"] = det.start_time_utc
    forwarded = []
    client = MagicMock()
    client.create_search_job.return_value = "ad-hoc-job"
    client.get_search_job_status.return_value = {"entry": [{"content": {"isDone": True}}]}

    def forward(events, **kwargs):
        forwarded.extend(events)
        return len(events)

    from hecate_agent.api import deploy_transpiled_query

    query, source, _ = SiemAlertVerifier(mock_siem_workspace).resolve_candidate_rule(
        "H-0011", "T1003.001"
    )
    file_title = Path(source).stem.replace("__", " - ").replace("_", " ").title()
    deployed = deploy_transpiled_query("splunk_spl", query, "H-0011", file_title, dry_run=True)
    expected_remote_id = deployed["remote_id"]

    def request(method, endpoint, params):
        name = endpoint.rsplit("/", 1)[-1]
        if name != expected_remote_id:
            raise LookupError("Saved search not found")
        if "/saved/searches/" in endpoint:
            return {"entry": [{"name": name, "content": {"search": query}}]}
        return {
            "entry": [
                {
                    "content": {
                        "savedsearch_name": name,
                        "sid": "scheduled-alert-job",
                        "trigger_time": datetime.now(UTC).timestamp(),
                    }
                }
            ]
        }

    client._request.side_effect = request
    client.get_search_results.side_effect = lambda sid, count: (
        forwarded if sid == "scheduled-alert-job" else [{"CommandLine": "MiniDump"}]
    )
    with (
        patch(
            "hecate_runner.bas.siem_verifier.splunk_settings",
            return_value={"SPLUNK_HOST": "https://splunk.invalid", "SPLUNK_TOKEN": "test"},
        ),
        patch("hecate_runner.bas.siem_verifier.forward_events_to_splunk", side_effect=forward),
        patch("hecate_agent.core.splunk_client.SplunkClient", return_value=client),
    ):
        result = SiemAlertVerifier(mock_siem_workspace, max_wait_sec=0.05).verify_detonation_alert(
            det, "H-0011"
        )
    assert result.status == "verified_true_positive"
    assert result.alert_name == expected_remote_id
    assert result.siem_alert_fired
    assert result.verification_scope == "siem_alert"
    assert result.alert_search_id == "scheduled-alert-job"
    assert result.search_job_id == "ad-hoc-job"
    assert result.detection_latency_sec is not None
    assert result.alert_time_utc
    assert result.query_match_latency_sec is not None
    assert forwarded[0]["hecate_bas_run_id"] == result.run_id
    assert "hecate_bas_run_id" not in det.telemetry_signatures[0]
    row = get_detection_validations(mock_siem_workspace)[0]
    assert row["siem_alert_fired"] == 1
    assert row["alert_search_id"] == "scheduled-alert-job"
    assert get_siem_drift_metrics(mock_siem_workspace)["bas_verified_alerts_count"] == 1
    saved = json.loads(
        (mock_siem_workspace / ".hecate" / "bas" / "runs" / f"{result.run_id}.json").read_text()
    )
    assert saved["alert_search_id"] == "scheduled-alert-job"
    assert saved["siem_alert_fired"]
    assert saved["alert_evidence"]["hecate_bas_run_id"] == result.run_id


def test_query_hits_and_alert_api_denial_do_not_become_alert_proof(mock_siem_workspace):
    from hecate_runner.siem_drift import get_siem_drift_metrics

    det = MockBASProvider().detonate(DetonationRequest(hunt_id="H-0011", technique_id="T1003.001"))
    det.provider = "caldera"
    client = MagicMock()
    client.create_search_job.return_value = "ad-hoc-job"
    client.get_search_job_status.return_value = {"entry": [{"content": {"isDone": True}}]}
    client.get_search_results.return_value = [{"Message": "alerts", "alert": True}]
    client._request.side_effect = PermissionError("403 forbidden")
    with (
        patch(
            "hecate_runner.bas.siem_verifier.splunk_settings",
            return_value={"SPLUNK_HOST": "https://splunk.invalid", "SPLUNK_TOKEN": "test"},
        ),
        patch("hecate_runner.bas.siem_verifier.forward_events_to_splunk", return_value=1),
        patch("hecate_agent.core.splunk_client.SplunkClient", return_value=client),
    ):
        result = SiemAlertVerifier(
            mock_siem_workspace, max_wait_sec=0.01, poll_interval_sec=0.001
        ).verify_detonation_alert(det, "H-0011")
    assert result.status == "query_match"
    assert not result.siem_alert_fired
    assert result.detection_latency_sec is None
    assert result.query_match_latency_sec is not None
    assert result.alert_time_utc == ""
    assert any("Alert verification unavailable" in note for note in result.notes)
    assert get_siem_drift_metrics(mock_siem_workspace)["bas_verified_alerts_count"] == 0
    assert get_siem_drift_metrics(mock_siem_workspace)["last_verified_hunt"] == ""
    client.create_search_job.assert_called_once()


def test_historical_unproven_successes_do_not_inflate_alert_metrics(mock_siem_workspace):
    from hecate_runner.siem_drift import get_siem_drift_metrics, record_detection_validation

    record_detection_validation(
        mock_siem_workspace,
        hunt_id="H-OLD",
        technique_id="T1033",
        status="verified_true_positive",
        detection_latency_sec=0.2,
    )
    metrics = get_siem_drift_metrics(mock_siem_workspace)
    assert metrics["bas_verified_alerts_count"] == 0
    assert metrics["avg_detection_latency_sec"] == 0
    assert metrics["last_verified_hunt"] == ""


def test_legacy_alert_history_schema_migrates_without_granting_proof(tmp_path):
    import sqlite3

    from hecate_runner.siem_drift import (
        get_detection_validations,
        get_drift_db_path,
        get_siem_drift_metrics,
    )

    db = get_drift_db_path(tmp_path)
    db.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db) as connection:
        connection.execute(
            "CREATE TABLE detection_validations (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, hunt_id TEXT, technique_id TEXT, ability_id TEXT, bas_provider TEXT, siem_backend TEXT, status TEXT, rule_triggered INTEGER, telemetry_arrived INTEGER, detection_latency_sec REAL, matched_events_count INTEGER, query_used TEXT, search_job_id TEXT, detonation_time_utc TEXT, notes TEXT)"
        )
        connection.execute(
            "INSERT INTO detection_validations (hunt_id, technique_id, status, detection_latency_sec) VALUES ('H-OLD', 'T1033', 'verified_true_positive', 0.5)"
        )
    init_drift_db(tmp_path).close()
    row = get_detection_validations(tmp_path)[0]
    assert row["hunt_id"] == "H-OLD"
    assert row["siem_alert_fired"] == 0
    assert row["alert_search_id"] == ""
    assert get_siem_drift_metrics(tmp_path)["bas_verified_alerts_count"] == 0
