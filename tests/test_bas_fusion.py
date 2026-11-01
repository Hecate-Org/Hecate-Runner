"""Tests for multi-category telemetry parsing, sensor fusion, and Sigma evaluation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hecate_runner.bas.approved import APPROVED_PROCEDURES
from hecate_runner.bas.base import DetonationResult
from hecate_runner.bas.runtime import run_approved_validation
from hecate_runner.bas.sensor import (
    LabFileDeltaSensor,
    LabSensorFusion,
    parse_file_trace,
    parse_net_trace,
)
from hecate_runner.bas.verifier import DetectionVerifier
from hecate_runner.config import Settings


def test_parse_file_trace_openat_and_resumed():
    trace = """
 100 1000.000000 execve("/bin/sh", ["sh", "-c", "touch /tmp/test.tmp"], 0x7fff) = 0
 101 1001.000000 openat(AT_FDCWD, "/tmp/test.tmp", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
 102 1002.000000 openat(AT_FDCWD, "/tmp/async.tmp", O_WRONLY|O_CREAT, 0666 <unfinished ...>
 102 1002.500000 <... openat resumed> ) = 4
 103 1003.000000 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
 104 1004.000000 openat(AT_FDCWD, "/tmp/hecate-exec.trace", O_RDWR) = 3
 105 1005.000000 openat(AT_FDCWD, "/tmp/failed.tmp", O_RDONLY) = -1 ENOENT (No such file or directory)
 106 1006.000000 creat("/tmp/created.tmp", 0644) = 5
"""
    events = parse_file_trace(trace, start=999.0, end=1007.0, host="lab-host")
    assert len(events) == 3

    # /tmp/test.tmp
    assert events[0]["TargetFilename"] == "/tmp/test.tmp"
    assert events[0]["event_type"] == "create"
    assert events[0]["ProcessId"] == 101
    assert events[0]["category"] == "file_event"
    assert events[0]["Computer"] == "lab-host"

    # /tmp/async.tmp
    assert events[1]["TargetFilename"] == "/tmp/async.tmp"
    assert events[1]["event_type"] == "create"
    assert events[1]["ProcessId"] == 102

    # /tmp/created.tmp
    assert events[2]["TargetFilename"] == "/tmp/created.tmp"
    assert events[2]["event_type"] == "create"
    assert events[2]["ProcessId"] == 106


def test_parse_file_trace_unlink_and_rename():
    trace = """
 201 1010.000000 unlink("/tmp/hecate-t1070-canary.tmp") = 0
 202 1011.000000 unlinkat(AT_FDCWD, "/tmp/other.tmp", 0) = 0
 203 1012.000000 rename("/tmp/source.tmp", "/tmp/dest.tmp") = 0
 204 1013.000000 unlink("/tmp/nonexistent.tmp") = -1 ENOENT
"""
    events = parse_file_trace(trace, start=1009.0, end=1014.0, host="lab-host")
    assert len(events) == 3

    assert events[0]["TargetFilename"] == "/tmp/hecate-t1070-canary.tmp"
    assert events[0]["event_type"] == "delete"
    assert events[0]["ProcessId"] == 201

    assert events[1]["TargetFilename"] == "/tmp/other.tmp"
    assert events[1]["event_type"] == "delete"

    assert events[2]["TargetFilename"] == "/tmp/dest.tmp"
    assert events[2]["event_type"] == "rename"
    assert events[2]["ProcessId"] == 203


def test_parse_net_trace_connect():
    trace = """
 301 1020.000000 connect(3, {sa_family=AF_INET, sin_port=htons(8888), sin_addr=inet_addr("172.21.0.2")}, 16) = 0
 302 1021.000000 connect(4, {sa_family=AF_INET, sin_port=htons(8888), sin_addr=inet_addr("172.21.0.2")}, 16) = -1 EINPROGRESS
 303 1022.000000 connect(5, {sa_family=AF_INET, sin_port=htons(9999), sin_addr=inet_addr("172.21.0.3")}, 16) = -1 ECONNREFUSED
"""
    events = parse_net_trace(trace, start=1019.0, end=1023.0, host="lab-host")
    # Only successful or in-progress connections
    assert len(events) == 2
    assert events[0]["DestinationPort"] == 8888
    assert events[0]["DestinationIp"] == "172.21.0.2"
    assert events[0]["Protocol"] == "tcp"
    assert events[0]["category"] == "network_connection"
    assert events[0]["ProcessId"] == 301

    assert events[1]["DestinationPort"] == 8888
    assert events[1]["ProcessId"] == 302


@pytest.mark.parametrize("file_hash", ["", "abcdef1234567890"])
def test_expected_paths_cannot_generate_file_evidence(file_hash):
    from hecate_runner.bas.base import SafetyViolationError

    sensor = LabFileDeltaSensor("fake-container", "lab-host")
    sensor.compute_file_sha256 = MagicMock(return_value=file_hash)
    with pytest.raises(SafetyViolationError, match="not sensor observations"):
        sensor.collect_delta_events(
            created_files=["/tmp/never-observed"],
            deleted_files=["/tmp/never-observed"],
            start_utc="2026-10-31T04:00:00Z",
            end_utc="2026-10-31T04:00:02Z",
        )


def test_lab_sensor_fusion_lineage_and_deduplication():
    proc_ev = {
        "category": "process_creation",
        "data_source": "process_creation",
        "product": "linux",
        "ProcessId": 400,
        "Image": "/bin/base64",
        "CommandLine": "base64 -d",
        "UtcTime": "2026-10-31T04:00:00.000Z",
    }
    file_ev1 = {
        "category": "file_event",
        "data_source": "file_event",
        "product": "linux",
        "ProcessId": 400,
        "TargetFilename": "/tmp/hecate-t1027.tmp",
        "event_type": "create",
        "UtcTime": "2026-10-31T04:00:00.100Z",
    }
    # Duplicate file observation (e.g. captured by delta sensor and syscall trace)
    file_ev2 = {
        "category": "file_event",
        "data_source": "file_event",
        "product": "linux",
        "ProcessId": 400,
        "TargetFilename": "/tmp/hecate-t1027.tmp",
        "event_type": "create",
        "UtcTime": "2026-10-31T04:00:00.100Z",
    }
    net_ev = {
        "category": "network_connection",
        "data_source": "network_connection",
        "product": "linux",
        "ProcessId": 400,
        "DestinationPort": 8888,
        "DestinationIp": "172.21.0.2",
        "Protocol": "tcp",
        "UtcTime": "2026-10-31T04:00:00.200Z",
    }

    fused = LabSensorFusion.fuse(
        [net_ev, file_ev1, file_ev2, proc_ev],
        hunt_id="H-FUSION-01",
        technique_id="T1027",
    )
    # Deduplication removed file_ev2
    assert len(fused) == 3

    # Chronologically sorted
    assert fused[0]["category"] == "process_creation"
    assert fused[1]["category"] == "file_event"
    assert fused[2]["category"] == "network_connection"

    # Lineage propagated Image & CommandLine to file and net events
    assert fused[1]["Image"] == "/bin/base64"
    assert fused[1]["CommandLine"] == "base64 -d"
    assert fused[2]["Image"] == "/bin/base64"

    # Hunt ID tagged
    assert all(e["hunt_id"] == "H-FUSION-01" for e in fused)
    assert all(e["technique_id"] == "T1027" for e in fused)


def test_detection_verifier_multi_category_sigma():
    verifier = DetectionVerifier()
    detonation = DetonationResult(
        success=True,
        cleanup_success=True,
        hunt_id="H-0001",
        technique_id="T1027",
        ability_id="abi-01",
        provider="caldera",
        start_time_utc="2026-10-31T04:00:00Z",
        end_time_utc="2026-10-31T04:00:05Z",
        duration_seconds=5.0,
        exit_code=0,
        stdout="",
        stderr="",
    )

    fused_events = [
        {
            "category": "process_creation",
            "data_source": "process_creation",
            "product": "linux",
            "Image": "/bin/base64",
            "CommandLine": "base64 -d",
            "ProcessId": 100,
            "UtcTime": "2026-10-31T04:00:01Z",
        },
        {
            "category": "file_event",
            "data_source": "file_event",
            "product": "linux",
            "TargetFilename": "/tmp/hecate-t1027.tmp",
            "event_type": "create",
            "ProcessId": 100,
            "UtcTime": "2026-10-31T04:00:02Z",
        },
        {
            "category": "network_connection",
            "data_source": "network_connection",
            "product": "linux",
            "DestinationPort": 8888,
            "Protocol": "tcp",
            "ProcessId": 100,
            "UtcTime": "2026-10-31T04:00:03Z",
        },
    ]

    # 1. Process Rule
    proc_rule = """
title: Detect Base64
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: "/base64"
    condition: selection
"""
    v_proc = verifier.verify_detonation(
        detonation, rule_yaml=proc_rule, raw_events=fused_events, backend="lab_fusion"
    )
    assert v_proc.rule_triggered is True
    assert v_proc.status.value == "verified_true_positive"

    # 2. File Rule
    file_rule = """
title: Detect T1027 Tmp File
logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename|endswith: "hecate-t1027.tmp"
    condition: selection
"""
    v_file = verifier.verify_detonation(
        detonation, rule_yaml=file_rule, raw_events=fused_events, backend="lab_fusion"
    )
    assert v_file.rule_triggered is True
    assert v_file.status.value == "verified_true_positive"

    legacy = {**fused_events[1], "sensor": "lab_file_delta"}
    unobserved = verifier.verify_detonation(
        detonation, rule_yaml=file_rule, raw_events=[legacy], backend="lab_fusion"
    )
    assert not unobserved.rule_triggered
    assert not unobserved.telemetry_arrived

    # 3. Network Rule
    net_rule = """
title: Detect Caldera Lab Beacon
logsource:
    product: linux
    category: network_connection
detection:
    selection:
        DestinationPort: 8888
        Protocol: tcp
    condition: selection
"""
    v_net = verifier.verify_detonation(
        detonation, rule_yaml=net_rule, raw_events=fused_events, backend="lab_fusion"
    )
    assert v_net.rule_triggered is True
    assert v_net.status.value == "verified_true_positive"

    # 4. Wrong Category Rule (fails closed)
    registry_rule = """
title: Detect Windows Registry (Mismatched)
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains: "Run"
    condition: selection
"""
    v_reg = verifier.verify_detonation(
        detonation, rule_yaml=registry_rule, raw_events=fused_events, backend="lab_fusion"
    )
    assert v_reg.rule_triggered is False
    assert v_reg.status.value == "detection_miss"


def test_run_approved_validation_with_lab_fusion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("hecate_runner.bas.runtime.audit_container_tmpfs", lambda *args: [])

    fake_sensor = MagicMock()
    fake_sensor.agent_image = "agent-img"
    fake_sensor.controller_image = "controller-img"
    fake_sensor.collect_fused.return_value = [
        {
            "category": "process_creation",
            "data_source": "process_creation",
            "product": "linux",
            "Image": "/bin/base64",
            "CommandLine": "base64 -d",
            "ProcessId": 100,
            "UtcTime": "2026-10-31T04:00:01Z",
        },
        {
            "category": "file_event",
            "data_source": "file_event",
            "product": "linux",
            "TargetFilename": "/tmp/hecate-t1027.tmp",
            "event_type": "create",
            "ProcessId": 100,
            "UtcTime": "2026-10-31T04:00:02Z",
        },
    ]
    monkeypatch.setattr("hecate_runner.bas.runtime.LabProcessSensor", lambda *args: fake_sensor)

    provider = MagicMock()
    provider.detonate.return_value = DetonationResult(
        success=True,
        cleanup_success=True,
        hunt_id="H-FUSION",
        technique_id="T1027",
        ability_id="b027ca8e-0b44-482d-82d7-b3528fcfec44",
        provider="caldera",
        start_time_utc="2026-10-31T04:00:00Z",
        end_time_utc="2026-10-31T04:00:05Z",
        duration_seconds=5.0,
        exit_code=0,
        stdout="hecate-bas",
        stderr="",
    )
    monkeypatch.setattr("hecate_runner.bas.get_bas_provider", lambda *args: provider)

    file_rule = """
title: Detect T1027 Ephemeral Drop
logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename: "/tmp/hecate-t1027.tmp"
    condition: selection
"""
    settings = Settings(
        _env_file=None,
        hecate_workspace=tmp_path,
        bas_enabled=True,
        bas_mode="caldera",
        bas_telemetry="lab_fusion",
        bas_allowed_hosts=["lab"],
        bas_linux_host="lab",
        caldera_agent_group="hecate-local-lab",
        bas_auto_techniques=["T1027"],
    )
    result = run_approved_validation(settings, "H-FUSION", APPROVED_PROCEDURES["T1027"], file_rule)
    assert result["status"] == "verified_true_positive"
    assert result["rule_triggered"] is True
    assert result["backend"] == "lab_fusion"
    assert "file_event" in result["telemetry_categories"]
    assert "process_creation" in result["telemetry_categories"]
    assert result["sensor_events_count"] == 2
