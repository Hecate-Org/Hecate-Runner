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
        "title: MiniDump via comsvcs.dll\ntags:\n  - attack.t1003.001\n",
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
    assert res.status == "verified_true_positive"
    assert res.rule_triggered is True
    assert res.detection_latency_sec is not None
    assert res.detection_latency_sec > 0.0
    assert res.matched_events_count == 1

    # Verify persisted in SQLite
    validations = get_detection_validations(mock_siem_workspace, "H-0011")
    assert len(validations) >= 1
    assert validations[0]["hunt_id"] == "H-0011"
    assert validations[0]["status"] == "verified_true_positive"
    assert validations[0]["detection_latency_sec"] is not None

    # Verify persisted in .hecate/bas/runs/
    runs_dir = mock_siem_workspace / ".hecate" / "bas" / "runs"
    assert runs_dir.is_dir()
    run_files = list(runs_dir.glob("*.json"))
    assert len(run_files) >= 1
    run_data = json.loads(run_files[0].read_text(encoding="utf-8"))
    assert run_data["hunt_id"] == "H-0011"
    assert run_data["status"] == "verified_true_positive"


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

    mock_client = MagicMock()
    mock_client.create_search_job.return_value = "1793600999.123"
    mock_client.get_search_job_status.return_value = {
        "entry": [{"content": {"isDone": True, "resultCount": 1}}]
    }
    mock_client.get_search_results.return_value = [
        {"CommandLine": "rundll32.exe comsvcs.dll MiniDump"}
    ]

    with (
        patch("hecate_agent.core.splunk_client.create_client_from_env", return_value=mock_client),
        patch("hecate_runner.bas.siem_verifier.forward_events_to_splunk", return_value=1),
    ):
        verifier = SiemAlertVerifier(mock_siem_workspace)
        res = verifier.verify_detonation_alert(
            detonation=det,
            hunt_id="H-0011",
            siem_target="splunk",
        )

    assert res.status == "verified_true_positive"
    assert res.rule_triggered is True
    assert res.search_job_id == "1793600999.123"
    assert res.detection_latency_sec is not None
    assert res.detection_latency_sec > 0.0
    assert res.matched_events_count == 1
    mock_client.create_search_job.assert_called_once()
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
    assert "True Positive Detection Latency" in result.output
    assert "VERIFIED_TRUE_POSITIVE" in result.output
