"""Tests for CLI commands: `hecate-runner bas-detonate` and `hecate-runner bas-verify`."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from hecate_runner.cli import app
from hecate_runner.config import Settings

runner = CliRunner()


def test_cli_bas_detonate_mock_success() -> None:
    result = runner.invoke(app, ["bas-detonate", "T1059.001", "--provider", "mock", "--env", "lab"])
    assert result.exit_code == 0
    assert "Detonating technique T1059.001" in result.output
    assert "COMPLETED" in result.output
    assert "Mock detonation" in result.output


def test_cli_bas_detonate_safety_violation() -> None:
    result = runner.invoke(
        app, ["bas-detonate", "T1059.001", "--provider", "mock", "--env", "production"]
    )
    assert result.exit_code == 1
    assert "Detonation rejected: Environment is flagged as" in result.output
    assert "production" in result.output


def test_cli_bas_verify_nonexistent_hunt() -> None:
    result = runner.invoke(app, ["bas-verify", "H-9999", "--provider", "mock"])
    assert result.exit_code == 1
    assert "No hunt file found for H-9999" in result.output


def test_cli_bas_verify_success_with_writeback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Setup mock workspace structure
    workspace = tmp_path / "workspace"
    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    queries_dir = workspace / "queries" / "H-0042"
    queries_dir.mkdir(parents=True)

    hunt_file = hunts_dir / "H-0042.md"
    initial_frontmatter = {
        "hunt_id": "H-0042",
        "title": "Adversary execution via PowerShell download cradle",
        "status": "planning",
        "techniques": ["T1059.001"],
        "platform": ["windows"],
        "bas_verified": True,
        "bas_verified_rules": ["old-live-rule.yml"],
        "bas_rules_validated": 1,
        "bas_detection_latency_sec": 1.25,
        "bas_search_job_id": "old-live-job",
    }
    hunt_file.write_text(
        f"---\n{yaml.safe_dump(initial_frontmatter)}---\n\n# H-0042: Test Hunt Draft\n",
        encoding="utf-8",
    )

    sigma_file = queries_dir / "process_creation__powershell.yml"
    sigma_file.write_text(
        """title: PowerShell Download Cradle
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
""",
        encoding="utf-8",
    )

    # Point Settings to our temporary workspace
    mock_settings = Settings(
        _env_file=None,
        hecate_workspace=workspace,
        hunts_root=workspace / "hunts",
        bas_allowed_hosts=["lab-host"],
    )
    monkeypatch.setattr("hecate_runner.cli.Settings", lambda: mock_settings)

    result = runner.invoke(app, ["bas-verify", "H-0042", "--provider", "mock", "--write-back"])
    assert result.exit_code == 0
    assert "BAS Verification Results: H-0042" in result.output
    assert "SIMULATION_MATCH" in result.output
    assert "Updated hunt draft frontmatter in H-0042.md" in result.output

    # Check updated frontmatter
    updated_content = hunt_file.read_text(encoding="utf-8")
    parts = updated_content.split("---", 2)
    fm = yaml.safe_load(parts[1])
    assert fm["bas_verified"] is False
    assert fm["bas_provider"] == "mock"
    assert fm["bas_status"] == "simulation_match"
    assert fm["bas_detection_triggered"] is True
    assert "bas_verified_rules" not in fm
    assert fm["bas_siem_alert_fired"] is False
    assert fm["bas_rules_validated"] == 0
    assert "bas_detection_latency_sec" not in fm
    assert "bas_search_job_id" not in fm


def test_cli_bas_reset_clears_quarantine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    def docker(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd,
            0,
            "COMMAND\n/usr/bin/strace -f\n/usr/local/bin/sandcat\n" if "top" in cmd else "",
            "",
        )

    monkeypatch.setattr("hecate_runner.bas.lifecycle.subprocess.run", docker)
    from hecate_runner.bas.lifecycle import LabLease

    lease = LabLease(
        lease_path=tmp_path / "lab.lease",
        quarantine_path=tmp_path / "lab.quarantine",
        lock_path=tmp_path / "lab.lock",
    )
    lease.quarantine("Unconfirmed remote cleanup", hunt_id="H-0001")
    assert lease.is_quarantined()

    monkeypatch.setattr("hecate_runner.bas.lifecycle.LabLease", lambda *args, **kwargs: lease)
    monkeypatch.setattr("hecate_runner.cli.Settings", lambda: Settings(hecate_workspace=tmp_path))

    result = runner.invoke(app, ["bas-reset", "--note", "CLI audit test"])
    assert result.exit_code == 0
    assert "BAS Lab Reset & Audit Complete" in result.output
    assert "Cleared prior quarantine" in result.output
    assert not lease.is_quarantined()


def test_cli_bas_detonate_caldera_refuses_unreviewed_in_lab(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "hecate_runner.cli.Settings",
        lambda: Settings(bas_enabled=True, bas_allowed_hosts=["lab-host"]),
    )
    result = runner.invoke(
        app,
        ["bas-detonate", "T1003", "--provider", "caldera", "--env", "lab", "--host", "lab-host"],
    )
    assert result.exit_code == 1
    assert "reviewed Linux procedure" in result.output


def test_cli_bas_detonate_caldera_refuses_quarantined_lab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hecate_runner.bas.lifecycle import LabLease

    lease = LabLease(
        lease_path=tmp_path / "lab.lease",
        quarantine_path=tmp_path / "lab.quarantine",
        lock_path=tmp_path / "lab.lock",
    )
    lease.quarantine("Test quarantine", hunt_id="H-0001")

    monkeypatch.setattr("hecate_runner.bas.lifecycle.LabLease", lambda *args, **kwargs: lease)
    monkeypatch.setattr(
        "hecate_runner.cli.Settings",
        lambda: Settings(
            bas_enabled=True, bas_allowed_hosts=["lab-host"], hecate_workspace=tmp_path
        ),
    )

    result = runner.invoke(
        app,
        ["bas-detonate", "T1033", "--provider", "caldera", "--env", "lab", "--host", "lab-host"],
    )
    assert result.exit_code == 1
    assert "quarantined" in result.output


def test_cli_bas_reset_reports_purged_tmpfs_files(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "hecate_runner.bas.lifecycle.reset_lab",
        lambda *args, **kwargs: {
            "status": "clean",
            "lingering_processes_found": [],
            "lingering_files_found": ["/tmp/hecate-canary.tmp"],
            "files_purged": ["/tmp/hecate-canary.tmp"],
            "prior_quarantine": None,
        },
    )
    result = runner.invoke(app, ["bas-reset"])
    assert result.exit_code == 0
    assert "Lingering tmpfs files purged:" in result.output
    assert "/tmp/hecate-canary.tmp" in result.output


@pytest.mark.parametrize(
    "rule", [None, "title: No detection\ntags: [attack.t1033]\n", "[invalid YAML"]
)
def test_cli_missing_or_invalid_hunt_rule_refuses_before_detonation(tmp_path, monkeypatch, rule):
    from unittest.mock import Mock

    hunt_dir = tmp_path / "hunts"
    hunt_dir.mkdir()
    (hunt_dir / "H-TEST.md").write_text(
        "---\nhunt_id: H-TEST\ntechniques: [T1033]\nplatform: [linux]\n---\n"
    )
    if rule is not None:
        query_dir = tmp_path / "queries" / "H-TEST"
        query_dir.mkdir(parents=True)
        (query_dir / "actual.yml").write_text(rule)
    provider = Mock()
    settings = Settings(
        _env_file=None, hecate_workspace=tmp_path, hunts_root=hunt_dir, bas_mode="mock"
    )
    monkeypatch.setattr("hecate_runner.cli.Settings", lambda: settings)
    monkeypatch.setattr("hecate_runner.bas.get_bas_provider", lambda *args: provider)
    result = runner.invoke(app, ["bas-verify", "H-TEST", "--provider", "mock", "--no-siem"])
    assert result.exit_code == 1
    assert "no matching Sigma detection" in result.output
    provider.detonate.assert_not_called()


def test_cli_independent_lab_observations_remain_locally_verified(tmp_path, monkeypatch):
    from datetime import UTC, datetime
    from unittest.mock import Mock

    from hecate_runner.bas.base import DetonationResult

    hunt_dir = tmp_path / "hunts"
    hunt_dir.mkdir()
    hunt = hunt_dir / "H-TEST.md"
    hunt.write_text("---\nhunt_id: H-TEST\ntechniques: [T1033]\nplatform: [linux]\n---\n")
    query_dir = tmp_path / "queries" / "H-TEST"
    query_dir.mkdir(parents=True)
    (query_dir / "actual.yml").write_text(
        "title: Actual Whoami Hunt\ntags: [attack.t1033]\nlogsource:\n  category: process_creation\n  product: linux\ndetection:\n  selection:\n    Image|endswith: /whoami\n  condition: selection\n"
    )
    now = datetime.now(UTC).isoformat()
    provider = Mock()
    provider.detonate.return_value = DetonationResult(
        success=True,
        hunt_id="H-TEST",
        technique_id="T1033",
        ability_id="whoami",
        provider="caldera",
        start_time_utc=now,
        end_time_utc=now,
        duration_seconds=1,
        exit_code=0,
        stdout="lab",
        stderr="",
        cleanup_success=True,
    )
    sensor = Mock()
    sensor.collect_fused.return_value = [
        {"Image": "/usr/bin/whoami", "data_source": "process_creation"}
    ]
    settings = Settings(
        _env_file=None,
        hecate_workspace=tmp_path,
        hunts_root=hunt_dir,
        bas_allowed_hosts=["lab-host"],
    )
    monkeypatch.setattr("hecate_runner.cli.Settings", lambda: settings)
    monkeypatch.setattr("hecate_runner.bas.get_bas_provider", lambda *args: provider)
    monkeypatch.setattr("hecate_runner.bas.sensor.LabProcessSensor", lambda *args: sensor)
    result = runner.invoke(
        app, ["bas-verify", "H-TEST", "--provider", "caldera", "--host", "lab-host", "--no-siem"]
    )
    assert result.exit_code == 0, result.output
    fm = yaml.safe_load(hunt.read_text().split("---", 2)[1])
    assert fm["bas_verified"] is True
    assert fm["bas_status"] == "verified_true_positive"
    assert fm["bas_backend"] == "lab_fusion"
    assert fm["bas_siem_alert_fired"] is False
    assert fm["bas_verified_rules"] == ["actual.yml"]
    sensor.collect_fused.assert_called_once()


@pytest.mark.parametrize("proved,cleanup", [(False, True), (True, True), (False, False)])
def test_cli_writes_only_authoritative_alert_proof(tmp_path, monkeypatch, proved, cleanup):
    from datetime import UTC, datetime
    from unittest.mock import Mock

    from hecate_runner.bas.base import DetonationResult
    from hecate_runner.bas.siem_verifier import SiemAlertVerificationResult

    hunt_dir = tmp_path / "hunts"
    hunt_dir.mkdir()
    hunt = hunt_dir / "H-TEST.md"
    hunt.write_text(
        "---\nhunt_id: H-TEST\ntechniques: [T1033]\nplatform: [linux]\nbas_siem_alert_fired: true\nbas_alert_search_id: old-job\nbas_alert_name: old-alert\nbas_alert_time_utc: yesterday\nbas_detection_latency_sec: 99\n---\n"
    )
    query_dir = tmp_path / "queries" / "H-TEST"
    query_dir.mkdir(parents=True)
    (query_dir / "actual.yml").write_text(
        "title: Actual Hunt\ntags: [attack.t1033]\ndetection:\n  selection:\n    Image: /usr/bin/whoami\n  condition: selection\n"
    )
    (query_dir / "actual.spl").write_text('Image="/usr/bin/whoami"')
    now = datetime.now(UTC).isoformat()
    provider = Mock()
    provider.detonate.return_value = DetonationResult(
        success=True,
        cleanup_success=cleanup,
        hunt_id="H-TEST",
        technique_id="T1033",
        ability_id="whoami",
        provider="caldera",
        start_time_utc=now,
        end_time_utc=now,
        duration_seconds=1,
        exit_code=0,
        stdout="lab",
        stderr="",
    )
    sensor = Mock()
    observed = [{"Image": "/usr/bin/whoami", "data_source": "process_creation"}]
    sensor.collect_fused.return_value = observed
    settings = Settings(
        _env_file=None,
        hecate_workspace=tmp_path,
        hunts_root=hunt_dir,
        bas_allowed_hosts=["lab-host"],
    )
    monkeypatch.setattr("hecate_runner.cli.Settings", lambda: settings)
    monkeypatch.setattr("hecate_runner.bas.get_bas_provider", lambda *args: provider)
    monkeypatch.setattr("hecate_runner.bas.sensor.LabProcessSensor", lambda *args: sensor)
    monkeypatch.setenv("SPLUNK_HOST", "https://siem.invalid")
    verification = Mock(
        return_value=SiemAlertVerificationResult(
            hunt_id="H-TEST",
            technique_id="T1033",
            ability_id="whoami",
            bas_provider="caldera",
            siem_backend="splunk",
            status="verified_true_positive" if proved else "query_match",
            rule_triggered=True,
            telemetry_arrived=True,
            detection_latency_sec=2.0 if proved else None,
            query_match_latency_sec=1.0,
            detonation_time_utc=now,
            alert_time_utc=now if proved else "",
            matched_events_count=1,
            query_used='Image="/usr/bin/whoami"',
            search_job_id="ad-hoc-job",
            siem_alert_fired=proved,
            alert_search_id="scheduled-job" if proved else "",
            alert_name="actual-alert" if proved else "",
            verification_scope="siem_alert" if proved else "siem_query",
        )
    )
    monkeypatch.setattr(
        "hecate_runner.bas.siem_verifier.SiemAlertVerifier.verify_detonation_alert", verification
    )
    result = runner.invoke(
        app, ["bas-verify", "H-TEST", "--provider", "caldera", "--host", "lab-host", "--siem"]
    )
    assert result.exit_code == (0 if cleanup else 1), result.output
    fm = yaml.safe_load(hunt.read_text().split("---", 2)[1])
    assert fm["bas_cleanup_success"] is cleanup
    assert fm["bas_siem_alert_fired"] is proved
    assert fm["bas_verified"] is proved
    if proved:
        assert fm["bas_alert_search_id"] == "scheduled-job"
        assert fm["bas_detection_latency_sec"] == 2.0
        assert fm["bas_verification_scope"] == "siem_alert"
    else:
        assert "bas_alert_search_id" not in fm
        assert "bas_alert_time_utc" not in fm
        assert "bas_detection_latency_sec" not in fm
    if cleanup:
        assert verification.call_args.kwargs["raw_events"] == observed
    else:
        verification.assert_not_called()
