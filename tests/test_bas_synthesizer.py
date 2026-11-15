"""Tests for predicate-aware telemetry synthesis and automatic closed-loop BAS validation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hecate_runner.bas.synthesizer import (
    evaluate_rule_synthetically,
    synthesize_events_from_rule,
)
from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.hecate_client import HypothesisResult
from hecate_runner.hunt_writer import DraftHuntRequest, render_draft
from hecate_runner.orchestrator import Orchestrator

PROCESS_RULE = """
title: Suspicious Curl Ingress Tool Transfer
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/curl'
        CommandLine|contains: 'http://'
    condition: selection
"""

FILE_RULE = """
title: Temporary Executable Script Drop
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|endswith: '.sh'
        TargetFilename|contains: '/tmp/'
    condition: selection
"""

NETWORK_RULE = """
title: Suspicious Outbound C2 Connection
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        DestinationIp: '198.51.100.24'
        DestinationPort: 443
    condition: selection
"""

WEBSERVER_RULE = """
title: Web Exploitation Account Creation Request
logsource:
    category: webserver
    product: linux
detection:
    selection:
        cs-method: 'POST'
        cs-uri-stem|contains: '/manage/account/create'
    condition: selection
"""

WIN_REGISTRY_RULE = """
title: Windows Persistence via Registry Run Key
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: 'CurrentVersion\\Run'
        Details|endswith: '.exe'
    condition: selection
"""

WIN_PIPE_RULE = """
title: Suspicious Named Pipe Creation
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|contains: 'hecate_canary'
    condition: selection
"""

AWS_CLOUDTRAIL_RULE = """
title: AWS CloudTrail Disabled or Stopped
logsource:
    service: cloudtrail
    product: aws
detection:
    selection:
        eventSource: 'cloudtrail.amazonaws.com'
        eventName: 'StopLogging'
    condition: selection
"""


@pytest.mark.parametrize(
    "rule_yaml,category,expected_field,expected_val",
    [
        (PROCESS_RULE, "process_creation", "Image", "/usr/bin/curl"),
        (FILE_RULE, "file_event", "TargetFilename", "/tmp/hecate_canary.sh"),
        (NETWORK_RULE, "network_connection", "DestinationIp", "198.51.100.24"),
        (WEBSERVER_RULE, "webserver", "cs-uri-stem", "/manage/account/create"),
        (WIN_REGISTRY_RULE, "registry_set", "TargetObject", "CurrentVersion\\Run"),
        (WIN_PIPE_RULE, "pipe_created", "PipeName", "hecate_canary"),
        (AWS_CLOUDTRAIL_RULE, "cloud_audit", "eventName", "StopLogging"),
    ],
)
def test_synthesizer_generates_matching_telemetry(
    rule_yaml: str, category: str, expected_field: str, expected_val: str
) -> None:
    tp, benign = synthesize_events_from_rule(rule_yaml, "H-TEST", "T1000")
    assert expected_val in str(tp.get(expected_field))
    assert len(benign) == 2


@pytest.mark.parametrize(
    "rule_yaml",
    [
        PROCESS_RULE,
        FILE_RULE,
        NETWORK_RULE,
        WEBSERVER_RULE,
        WIN_REGISTRY_RULE,
        WIN_PIPE_RULE,
        AWS_CLOUDTRAIL_RULE,
    ],
)
def test_synthetic_evaluation_verifies_true_positives_and_clean_controls(
    rule_yaml: str,
) -> None:
    res = evaluate_rule_synthetically(rule_yaml, "H-TEST", "T1000")
    assert res["rule_triggered"] is True
    assert res["true_positives"] == 1
    assert res["false_positives"] == 0
    assert res["is_clean"] is True


def test_automatic_pipeline_bas_validates_multiple_rules(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "hunts").mkdir(parents=True)
    out_dir = workspace / "queries" / "H-0030"
    out_dir.mkdir(parents=True)

    settings = Settings(
        hecate_workspace=workspace,
        hunts_root=workspace / "hunts",
        bas_enabled=True,
        bas_mode="mock",
    )

    orchestrator = Orchestrator(settings=settings, hecate=MagicMock(), cti_provider=MagicMock())

    req = DraftHuntRequest(
        hunt_id="H-0030",
        generated_at=datetime.now(UTC),
        hypothesis=HypothesisResult(
            hypothesis="Multi-stage adversary attack",
            techniques=["T1190", "T1105", "T1071.001"],
        ),
        platforms=["linux"],
        threat_intel="Exploitation of web app and ingress tool transfer.",
    )

    rules = [
        {"title": "Web Exploit", "rule_yaml": WEBSERVER_RULE, "techniques": ["T1190"]},
        {"title": "Curl Download", "rule_yaml": PROCESS_RULE, "techniques": ["T1105"]},
        {"title": "Script Drop", "rule_yaml": FILE_RULE, "techniques": ["T1059.004"]},
        {"title": "C2 Conn", "rule_yaml": NETWORK_RULE, "techniques": ["T1071.001"]},
    ]

    item = CTIItem(
        source="test_feed",
        title="Threat Alert",
        source_url="https://example.com",
        content="Adversary intelligence",
    )

    orchestrator._run_bas_validation(req, rules, out_dir, item)

    assert req.bas_verification is not None
    assert req.bas_verification["status"] == "simulation_match"
    assert req.bas_verification["rule_triggered"] is True
    assert req.bas_verification["telemetry_arrived"] is True
    assert req.bas_verification["matched_events_count"] == 4
    assert req.bas_verification["validated_rules_count"] == 0
    assert req.bas_verification["simulation_rules_matched"] == 4
    assert req.bas_rules_evaluated == 4
    assert req.bas_rules_validated == 0
    assert all(not rule["bas_validated"] for rule in rules)

    assert req.purple_team_rules_evaluated == 0
    assert req.purple_team_rules_validated == 0

    # Verify hunt draft frontmatter & Markdown rendering
    rendered = render_draft(req)
    assert "purple_team_validated: true" not in rendered
    assert "bas_rules_evaluated: 4" in rendered
    assert "bas_rules_validated: 0" in rendered
    assert "bas_verified: false" in rendered
    assert 'bas_status: "simulation_match"' in rendered
    assert "bas_detection_triggered: true" in rendered
    assert "🧪 **SIMULATION MATCH" in rendered
    assert "- **Detection Triggered:** Yes (4 hit(s))" in rendered


def test_infer_splunk_sourcetype() -> None:
    from hecate_runner.bas.forwarder import infer_splunk_sourcetype

    assert (
        infer_splunk_sourcetype({"product": "windows", "category": "registry_set"})
        == "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    )
    assert (
        infer_splunk_sourcetype({"product": "windows", "category": "pipe_created"})
        == "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    )
    assert (
        infer_splunk_sourcetype({"product": "windows", "category": "windows_security"})
        == "WinEventLog:Security"
    )
    assert (
        infer_splunk_sourcetype({"product": "aws", "category": "cloud_audit"}) == "aws:cloudtrail"
    )
    assert (
        infer_splunk_sourcetype({"product": "gcp", "category": "cloud_audit"})
        == "google:gcp:pubsub:message"
    )
    assert (
        infer_splunk_sourcetype({"product": "azure", "category": "cloud_audit"}) == "azure:activity"
    )
    assert (
        infer_splunk_sourcetype({"product": "kubernetes", "category": "kubernetes_audit"})
        == "kube:audit"
    )
    assert (
        infer_splunk_sourcetype({"product": "linux", "category": "webserver"}) == "access_combined"
    )


def test_rule_tuner_diagnoses_missed_registry_and_cloud_constraints(tmp_path: Path) -> None:
    from hecate_runner.rule_tuner import RuleTuner

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    q_dir = workspace / "queries" / "H-0999"
    q_dir.mkdir(parents=True)
    rule_file = q_dir / "detection.yml"
    rule_file.write_text(WIN_REGISTRY_RULE, encoding="utf-8")

    missed = [
        {
            "product": "windows",
            "category": "registry_set",
            "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
            "Details": "C:\\temp\\backdoor.exe",
        }
    ]

    tuner = RuleTuner(workspace)
    res = tuner.auto_tune_from_miss("H-0999", missed)
    assert res.ok is True
    assert "TargetObject" in res.action_summary


def test_bas_synthesize_cli(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from hecate_runner.cli import app

    rule_file = tmp_path / "test_rule.yml"
    rule_file.write_text(WIN_REGISTRY_RULE, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(app, ["bas-synthesize", str(rule_file)])
    assert result.exit_code == 0
    assert "Synthesized Telemetry & Evaluation" in result.stdout
    assert "PASSED (True Positive Triggered, Controls Clean)" in result.stdout
