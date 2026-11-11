"""Command exit behavior and smoke-check credit, without live emulation."""

from __future__ import annotations

import json
import shlex
import subprocess
from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest
import yaml
from typer.testing import CliRunner

from hecate_runner.bas.approved import APPROVED_PROCEDURES, confirms_technique, select_approved_rule
from hecate_runner.bas.base import DetonationResult
from hecate_runner.bas.verifier import DetectionVerifier, VerificationStatus
from hecate_runner.config import Settings


@pytest.fixture
def command_lab(tmp_path):
    """Run only sandbox-path copies of catalog commands with fake executables."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls"
    artifact = tmp_path / "artifact"
    scripts = {
        "curl": """if [ "$BAS_CURL_EXIT" -ne 0 ]; then exit "$BAS_CURL_EXIT"; fi
while [ "$#" -gt 0 ]; do
    if [ "$1" = '-o' ]; then shift; printf '%s' "$BAS_CURL_BODY" > "$1"; fi
    shift
done
""",
        "touch": ': > "$1"\n',
        "crontab": 'printf "crontab %s\\n" "$*" >> "$BAS_TEST_LOG"\nexit "$BAS_CRON_EXIT"\n',
        "rm": 'printf "rm\\n" >> "$BAS_TEST_LOG"\nif [ "$BAS_RM_EXIT" -ne 0 ]; then exit "$BAS_RM_EXIT"; fi\n/bin/rm "$@"\n',
    }
    for name, body in scripts.items():
        executable = bin_dir / name
        executable.write_text("#!/bin/sh\n" + body)
        executable.chmod(0o700)

    def run(
        technique,
        *,
        cleanup=False,
        curl_exit=0,
        body="inert-transfer-content",
        cron_exit=0,
        rm_exit=0,
    ):
        procedure = APPROVED_PROCEDURES[technique]
        command = procedure.cleanup_command if cleanup else procedure.command
        command = command.replace(procedure.expected_files[0], str(artifact))
        args = shlex.split(command)
        script = args[2] if args[:2] == ["sh", "-c"] else command
        return subprocess.run(
            ["/bin/sh", "-c", script],
            text=True,
            capture_output=True,
            timeout=3,
            env={
                "PATH": str(bin_dir),
                "BAS_TEST_LOG": str(log),
                "BAS_CURL_EXIT": str(curl_exit),
                "BAS_CURL_BODY": body,
                "BAS_CRON_EXIT": str(cron_exit),
                "BAS_RM_EXIT": str(rm_exit),
            },
        )

    return run, artifact, log


@pytest.mark.parametrize("exit_code", [7, 22, 28])
def test_failed_download_cannot_create_successful_placeholder(command_lab, exit_code):
    run, artifact, _log = command_lab
    result = run("T1105", curl_exit=exit_code)
    assert result.returncode == exit_code
    assert not artifact.exists()


def test_empty_download_cannot_count_as_success(command_lab):
    run, artifact, _log = command_lab
    result = run("T1105", body="")
    assert result.returncode != 0
    assert artifact.read_bytes() == b""


def test_successful_download_requires_transferred_content(command_lab):
    run, artifact, _log = command_lab
    result = run("T1105")
    assert result.returncode == 0
    assert artifact.read_text() == "inert-transfer-content"


def test_cron_installation_errors_propagate(command_lab):
    run, artifact, log = command_lab
    result = run("T1053.003", cron_exit=42)
    assert result.returncode == 42
    assert "true # hecate-t1053" in artifact.read_text()
    assert "crontab" in log.read_text()


def test_cron_installation_can_still_succeed(command_lab):
    run, _artifact, _log = command_lab
    assert run("T1053.003").returncode == 0


@pytest.mark.parametrize("cron_exit,rm_exit,expected", [(42, 0, 42), (0, 43, 43), (0, 0, 0)])
def test_cron_cleanup_propagates_each_failure(command_lab, cron_exit, rm_exit, expected):
    run, artifact, log = command_lab
    artifact.write_text("inert-test-crontab")
    result = run("T1053.003", cleanup=True, cron_exit=cron_exit, rm_exit=rm_exit)
    assert result.returncode == expected
    assert "crontab -r" in log.read_text()
    assert artifact.exists() is (expected != 0)
    if cron_exit:
        assert "rm\n" not in log.read_text()


SMOKE_RULE = """title: Service Availability Smoke Check
tags: [attack.t1543.002]
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /systemctl
    CommandLine: systemctl is-active cron
  condition: selection
"""


@pytest.fixture
def smoke_lab(tmp_path, monkeypatch):
    procedure = APPROVED_PROCEDURES["T1543.002"]
    now = datetime.now(UTC).isoformat()
    event = {
        "Image": "/usr/bin/systemctl",
        "CommandLine": "systemctl is-active cron",
        "data_source": "process_creation",
        "timestamp_utc": now,
    }
    detonation = DetonationResult(
        success=True,
        cleanup_success=True,
        hunt_id="H-SMOKE",
        technique_id=procedure.technique_id,
        ability_id=procedure.ability_id,
        provider="caldera",
        start_time_utc=now,
        end_time_utc=now,
        duration_seconds=1,
        exit_code=0,
        stdout="active",
        stderr="",
        telemetry_signatures=[event],
    )
    sensor = Mock()
    sensor.collect_fused.return_value = [event]
    provider = Mock()
    provider.detonate.return_value = detonation
    monkeypatch.setattr("hecate_runner.bas.get_bas_provider", lambda *args: provider)
    monkeypatch.setattr("hecate_runner.bas.runtime.LabProcessSensor", lambda *args: sensor)
    monkeypatch.setattr("hecate_runner.bas.sensor.LabProcessSensor", lambda *args: sensor)
    monkeypatch.setattr("hecate_runner.bas.runtime.audit_container_tmpfs", lambda *args: [])
    settings = Settings(
        _env_file=None,
        hecate_workspace=tmp_path,
        hunts_root=tmp_path / "hunts",
        bas_enabled=True,
        bas_mode="caldera",
        bas_auto_execute_live=True,
        bas_telemetry="lab_fusion",
        bas_allowed_hosts=["lab"],
        bas_linux_host="lab",
        caldera_agent_group="hecate-local-lab",
        bas_auto_techniques=[procedure.technique_id],
    )
    return settings, procedure, detonation


@pytest.mark.parametrize("technique", ["T1543.002", "T1190", "T1041", "T1071.001"])
def test_nonbehavioral_controls_are_explicitly_classified(technique):
    assert APPROVED_PROCEDURES[technique].fidelity_scope == "smoke_check"


def test_pinned_smoke_procedure_cannot_be_upgraded_by_caller(smoke_lab):
    _settings, _procedure, detonation = smoke_lab
    result = DetectionVerifier().verify_detonation(
        detonation, rule_yaml=SMOKE_RULE, backend="lab_fusion", fidelity_scope="behavioral"
    )
    assert result.status == VerificationStatus.SMOKE_CHECK_MATCH
    assert result.rule_triggered
    assert result.fidelity_scope == "smoke_check"
    assert not confirms_technique(result.to_dict())


def test_smoke_procedures_are_not_selected_to_validate_hunts(smoke_lab):
    _settings, procedure, _detonation = smoke_lab
    selection = select_approved_rule(
        [{"rule_yaml": SMOKE_RULE, "techniques": [procedure.technique_id]}],
        [procedure.technique_id],
        [procedure.technique_id],
    )
    assert selection is None


def test_smoke_runtime_keeps_observation_but_awards_no_validation(smoke_lab):
    from hecate_runner.bas.runtime import run_approved_validation

    settings, procedure, _detonation = smoke_lab
    result = run_approved_validation(settings, "H-SMOKE", procedure, SMOKE_RULE)
    assert result["status"] == "smoke_check_match"
    assert result["fidelity_scope"] == "smoke_check"
    assert result["rule_triggered"]
    assert result["validated_rules_count"] == 0
    assert result["sensor_events_count"] == 1
    saved = json.loads(
        (
            settings.hecate_workspace / ".hecate" / "bas" / "runs" / f"{result['run_id']}.json"
        ).read_text()
    )
    assert saved["status"] == "smoke_check_match"
    assert saved["validated_rules_count"] == 0


def test_smoke_cli_does_not_write_verified_hunt_metadata(smoke_lab, monkeypatch):
    from hecate_runner.cli import app

    settings, _procedure, _detonation = smoke_lab
    settings.hunts_root.mkdir()
    hunt = settings.hunts_root / "H-SMOKE.md"
    hunt.write_text(
        "---\nhunt_id: H-SMOKE\ntechniques: [T1543.002]\nplatform: [linux]\nbas_verified: true\nbas_rules_validated: 1\nbas_verified_rules: [old.yml]\n---\n"
    )
    query_dir = settings.hecate_workspace / "queries" / "H-SMOKE"
    query_dir.mkdir(parents=True)
    (query_dir / "smoke.yml").write_text(SMOKE_RULE)
    monkeypatch.setattr("hecate_runner.cli.Settings", lambda: settings)
    result = CliRunner().invoke(
        app, ["bas-verify", "H-SMOKE", "--provider", "caldera", "--no-siem"]
    )
    assert result.exit_code == 0, result.output
    assert "SMOKE_CHECK_MATCH" in result.output
    frontmatter = yaml.safe_load(hunt.read_text().split("---", 2)[1])
    assert frontmatter["bas_verified"] is False
    assert frontmatter["bas_fidelity_scope"] == "smoke_check"
    assert frontmatter["bas_rules_validated"] == 0
    assert frontmatter["bas_detection_triggered"] is True
    assert "bas_verified_rules" not in frontmatter


def test_smoke_diagnostic_can_pass_without_claiming_technique_coverage(smoke_lab, monkeypatch):
    from hecate_runner.cli import app

    settings, _procedure, _detonation = smoke_lab
    monkeypatch.setattr("hecate_runner.cli.Settings", lambda: settings)
    result = CliRunner().invoke(app, ["bas-check"])
    assert result.exit_code == 0, result.output
    assert "smoke_check_match" in result.output
    records = list((settings.hecate_workspace / ".hecate" / "bas" / "runs").glob("*.json"))
    saved = json.loads(records[0].read_text())
    assert saved["purpose"] == "sensor_control"
    assert saved["validated_rules_count"] == 0


def test_even_confirmed_siem_alert_cannot_upgrade_a_smoke_check(smoke_lab):
    from hecate_runner.bas.alerts import AlertProof
    from hecate_runner.bas.siem_verifier import SiemAlertVerifier
    from hecate_runner.siem_drift import get_siem_drift_metrics

    settings, _procedure, detonation = smoke_lab
    directory = settings.hecate_workspace / "queries" / "H-SMOKE"
    directory.mkdir(parents=True)
    (directory / "smoke.yml").write_text(SMOKE_RULE)
    (directory / "smoke.spl").write_text('Image="/usr/bin/systemctl"')
    client = Mock()
    client.create_search_job.return_value = "adhoc"
    client.get_search_job_status.return_value = {"entry": [{"content": {"isDone": True}}]}
    client.get_search_results.return_value = [detonation.telemetry_signatures[0]]
    proof = AlertProof(
        "actual-alert",
        "scheduled",
        detonation.end_time_utc,
        0.1,
        detonation.telemetry_signatures[0],
    )
    with (
        patch(
            "hecate_runner.bas.siem_verifier.splunk_settings",
            return_value={"SPLUNK_HOST": "https://siem.invalid", "SPLUNK_TOKEN": "test"},
        ),
        patch("hecate_agent.core.splunk_client.SplunkClient", return_value=client),
        patch("hecate_runner.bas.siem_verifier.forward_events_to_splunk", return_value=1),
        patch("hecate_runner.bas.alerts.find_fired_alert", return_value=proof),
    ):
        result = SiemAlertVerifier(settings.hecate_workspace).verify_detonation_alert(
            detonation, "H-SMOKE", fidelity_scope="behavioral"
        )
    assert result.siem_alert_fired
    assert result.status == "smoke_check_match"
    assert result.rule_triggered
    assert result.fidelity_scope == "smoke_check"
    assert not confirms_technique(result.to_dict())
    assert get_siem_drift_metrics(settings.hecate_workspace)["bas_verified_alerts_count"] == 0
    state = json.loads((settings.hecate_workspace / ".hecate" / "bas" / "state.json").read_text())
    assert state["last_status"] == "smoke_check_match"
    assert "last_verified_hunt" not in state


@pytest.mark.parametrize("scope", ["smoke_check", "behavioral"])
def test_hunt_rendering_rejects_stale_full_credit_for_known_smoke_checks(smoke_lab, scope):
    from hecate_runner.hecate_client import HypothesisResult
    from hecate_runner.hunt_writer import DraftHuntRequest, render_draft

    _settings, procedure, _detonation = smoke_lab
    request = DraftHuntRequest(
        hunt_id="H-SMOKE",
        generated_at=datetime.now(UTC),
        hypothesis=HypothesisResult(
            hypothesis="Test service control", techniques=[procedure.technique_id]
        ),
        platforms=["linux"],
        threat_intel="test",
        bas_rules_evaluated=1,
        bas_rules_validated=1,
        bas_verification={
            "status": "verified_true_positive",
            "provider": "caldera",
            "technique_id": procedure.technique_id,
            "ability_id": procedure.ability_id,
            "fidelity_scope": scope,
            "rule_triggered": True,
        },
    )
    output = render_draft(request)
    frontmatter = yaml.safe_load(output.split("---", 2)[1])
    assert frontmatter["bas_verified"] is False
    assert frontmatter["bas_rules_validated"] == 0
    assert frontmatter["bas_fidelity_scope"] == "smoke_check"
    assert frontmatter["bas_status"] == "smoke_check_match"
    assert "SMOKE CHECK MATCH" in output
    assert "VERIFIED TRUE POSITIVE" not in output


@pytest.mark.parametrize("legacy_success", [False, True])
def test_orchestrator_does_not_credit_any_rules_from_smoke_evidence(
    smoke_lab, monkeypatch, legacy_success
):
    from hecate_runner.cti.base import CTIItem
    from hecate_runner.hecate_client import HypothesisResult
    from hecate_runner.hunt_writer import DraftHuntRequest
    from hecate_runner.orchestrator import Orchestrator

    settings, procedure, detonation = smoke_lab
    monkeypatch.setattr(
        "hecate_runner.bas.approved.select_approved_rule", lambda *args: (procedure, SMOKE_RULE)
    )
    if legacy_success:
        monkeypatch.setattr(
            "hecate_runner.bas.runtime.run_approved_validation",
            lambda *args: {
                "status": "verified_true_positive",
                "fidelity_scope": "behavioral",
                "telemetry_arrived": True,
                "rule_triggered": True,
                "events": detonation.telemetry_signatures,
                "validated_rules_count": 2,
            },
        )
    request = DraftHuntRequest(
        hunt_id="H-SMOKE",
        generated_at=datetime.now(UTC),
        hypothesis=HypothesisResult(
            hypothesis="Test service control", techniques=[procedure.technique_id]
        ),
        platforms=["linux"],
        threat_intel="test",
    )
    rules = [
        {"title": "First", "rule_yaml": SMOKE_RULE},
        {
            "title": "Second",
            "rule_yaml": SMOKE_RULE.replace("Service Availability", "Other Service"),
        },
    ]
    orchestrator = Orchestrator(settings=settings, hecate=Mock(), cti_provider=Mock())
    item = CTIItem(
        source="test", title="Test", source_url="https://example.invalid", content="test"
    )
    orchestrator._run_bas_validation(request, rules, settings.hecate_workspace, item)
    assert request.bas_verification["status"] == "smoke_check_match"
    assert request.bas_verification["fidelity_scope"] == "smoke_check"
    assert request.bas_verification["validated_rules_count"] == 0
    assert request.bas_verification["verified_rules"] == []
    assert request.bas_rules_validated == 0
    assert request.purple_team_rules_validated == 0


def test_catalog_digest_includes_fidelity_policy(monkeypatch):
    from dataclasses import replace

    from hecate_runner.bas.approved import catalog_digest

    before = catalog_digest()
    monkeypatch.setitem(
        APPROVED_PROCEDURES,
        "T1033",
        replace(APPROVED_PROCEDURES["T1033"], fidelity_scope="smoke_check"),
    )
    assert catalog_digest() != before


@pytest.mark.parametrize("technique", ["t1543.002", "T1057"])
def test_technique_label_cannot_upgrade_a_pinned_smoke_ability(smoke_lab, technique):
    _settings, _procedure, detonation = smoke_lab
    detonation.technique_id = technique
    result = DetectionVerifier().verify_detonation(
        detonation, rule_yaml=SMOKE_RULE, backend="lab_fusion"
    )
    assert result.status == VerificationStatus.SMOKE_CHECK_MATCH
    assert not confirms_technique(result.to_dict())


@pytest.mark.parametrize("failure", ["execution", "cleanup"])
def test_smoke_check_never_hides_execution_or_cleanup_failure(smoke_lab, failure):
    _settings, _procedure, detonation = smoke_lab
    if failure == "execution":
        detonation.success = False
    else:
        detonation.cleanup_success = False
    result = DetectionVerifier().verify_detonation(
        detonation, rule_yaml=SMOKE_RULE, backend="lab_fusion"
    )
    assert result.status in {VerificationStatus.DETONATION_FAILED, VerificationStatus.ERROR}
    assert not result.rule_triggered
    assert not confirms_technique(result.to_dict())
