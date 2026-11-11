"""Purple-team replay: rules against events synthesised from the source's artifacts.

The stage this replaces read ``CTIItem.indicators`` and
``SourceEvidence.commands``, neither of which exists, so every rule was replayed
against nothing and marked validated. H-0830's five rules -- one with a
condition naming selections it did not have -- were reported "verified against
attack telemetry" with "0 false positives".
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import yaml
from hecate_agent.core.provenance import IndicatorRecord

from hecate_runner.config import Settings
from hecate_runner.hecate_client import HypothesisResult
from hecate_runner.hunt_writer import DraftHuntRequest, render_draft
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.purple_team import (
    BENIGN_SAMPLE,
    BENIGN_SAMPLE_CLOUD,
    BENIGN_SAMPLE_CONTAINER,
    BENIGN_SAMPLE_LINUX,
    BENIGN_SAMPLE_NETWORK,
    BENIGN_SAMPLE_WEBSERVER,
    BENIGN_SAMPLE_WINDOWS,
    get_benign_sample_for_rule,
    replay_events,
    replay_rule,
)

_FILE_RULE = """title: File the source says the malware writes
logsource:
  category: file_event
detection:
  selection:
    TargetFilename: /var/kw2s11
  condition: selection
"""

_IP_RULE = """title: Connection to an address named in the source
logsource:
  category: network_connection
detection:
  selection:
    DestinationIp: 209.141.43.95
  condition: selection
"""

#: H-0830's dual-use rule: a condition naming selection_dest_* with none present.
_BROKEN_RULE = """title: Outbound connection to dual-use endpoint
logsource:
  category: network_connection
detection:
  filter_legit:
    Image|endswith:
    - \\chrome.exe
  condition: (1 of selection_dest_*) and not filter_legit
"""

_CRON_RULE = """title: Any cron execution
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: /cron
  condition: selection
"""


def _records() -> list[IndicatorRecord]:
    return [
        IndicatorRecord(value="209.141.43.95", type="ipv4", role="download", status="active"),
        IndicatorRecord(value="13.1.0.9", type="ipv4", role="target", status="active"),
        IndicatorRecord(
            value="old.example.net", type="domain", role="historical", status="historical"
        ),
    ]


def _artifacts() -> list[SimpleNamespace]:
    return [
        SimpleNamespace(value="/var/kw2s11", kind="file_path", status="active"),
        SimpleNamespace(value="chmod 755 /var/kw2s11", kind="command_line", status="active"),
    ]


def test_events_come_from_the_source_and_skip_victims_and_history() -> None:
    events = replay_events(_records(), _artifacts())
    assert events["network_connection"] == [{"DestinationIp": "209.141.43.95"}]
    assert events["file_event"] == [{"TargetFilename": "/var/kw2s11"}]
    assert events["process_creation"] == [
        {"CommandLine": "chmod 755 /var/kw2s11", "Image": "chmod"}
    ]
    assert "dns_query" not in events


def test_a_rule_matching_its_events_validates() -> None:
    events = replay_events(_records(), _artifacts())
    outcome = replay_rule(_FILE_RULE, events["file_event"], BENIGN_SAMPLE)
    assert outcome.status == "self_consistent"
    assert (outcome.true_positives, outcome.false_positives) == (1, 0)


def test_a_rule_with_nothing_to_replay_is_not_validated() -> None:
    outcome = replay_rule(_FILE_RULE, [], BENIGN_SAMPLE)
    assert outcome.status == "no_replay_events"
    assert outcome.matched is False


def test_a_condition_without_its_selections_does_not_validate() -> None:
    events = replay_events(_records(), _artifacts())
    outcome = replay_rule(_BROKEN_RULE, events["network_connection"], BENIGN_SAMPLE)
    assert outcome.matched is False


def test_a_rule_matching_the_benign_sample_is_not_validated() -> None:
    events = [{"Image": "/usr/sbin/cron", "CommandLine": "/usr/sbin/cron -f"}]
    outcome = replay_rule(_CRON_RULE, events, BENIGN_SAMPLE)
    assert outcome.status == "baseline_match"


def test_tuning_never_fits_a_rule_to_events_it_missed() -> None:
    """The tuner appends a missed event's CommandLine to the rule; offered the
    events grading it, every rule would 'validate'."""
    tuner = MagicMock()
    events = [{"Image": "/usr/bin/perl", "CommandLine": "perl /var/vpn/x.pl"}]
    outcome = replay_rule(_CRON_RULE, events, BENIGN_SAMPLE, tuner)
    tuner.tune.assert_not_called()
    assert outcome.status == "no_match"
    assert outcome.final_rule == _CRON_RULE


def _orchestrator(tmp_path: Path) -> Orchestrator:
    orch = Orchestrator(
        settings=Settings(hecate_workspace=tmp_path), hecate=MagicMock(), cti_provider=MagicMock()
    )
    orch.trail = MagicMock()
    orch.trail.elapsed = 1.0
    orch._indicator_records = _records()
    orch._source_evidence = SimpleNamespace(artifacts=_artifacts(), text="")
    return orch


def test_the_stage_replays_by_log_source_and_marks_only_validated_files(tmp_path: Path) -> None:
    out_dir = tmp_path / "queries" / "H-9999"
    out_dir.mkdir(parents=True)
    rules = []
    for name, body, category in (
        ("file_event__kw2s11.yml", _FILE_RULE, "file_event"),
        ("network_connection__dual_use.yml", _BROKEN_RULE, "network_connection"),
        ("dns_query__none.yml", _IP_RULE.replace("network_connection", "dns_query"), "dns_query"),
    ):
        (out_dir / name).write_text(body, encoding="utf-8")
        rules.append(
            {"logsource_category": category, "rule_yaml": body, "path": str(out_dir / name)}
        )
    req = DraftHuntRequest(
        hunt_id="H-9999", threat_intel="x", hypothesis=MagicMock(), generated_at=datetime.now(UTC)
    )

    _orchestrator(tmp_path)._run_purple_team_validation(req, rules, out_dir, MagicMock())

    assert [r["purple_team"]["status"] for r in rules] == [
        "self_consistent",
        "no_match",
        "no_replay_events",
    ]
    assert (
        req.purple_team_rules_evaluated,
        req.purple_team_rules_replay_matched,
        req.purple_team_rules_validated,
    ) == (2, 1, 0)
    matched_rule = (out_dir / "file_event__kw2s11.yml").read_text()
    assert "x_hecate_replay_matched: true" in matched_rule
    assert "x_hecate_purple_team_validated" not in matched_rule
    assert (
        "x_hecate_replay_matched" not in (out_dir / "network_connection__dual_use.yml").read_text()
    )
    assert yaml.safe_load((out_dir / "file_event__kw2s11.yml").read_text())["detection"]


def test_the_draft_claims_only_what_the_replay_showed(sample_hypothesis: HypothesisResult) -> None:
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="x",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 10, 23, tzinfo=UTC),
        sigma_rules=[
            {
                "logsource_category": "file_event",
                "title": "a",
                "rule_yaml": _FILE_RULE,
                "purple_team": {"status": "no_match", "matched": False},
            },
            {
                "logsource_category": "dns_query",
                "title": "b",
                "rule_yaml": _IP_RULE,
                "purple_team": {"status": "no_replay_events", "matched": False},
            },
        ],
        purple_team_rules_evaluated=1,
        purple_team_rules_validated=0,
    )
    md = render_draft(req)
    assert "purple_team_validated: false" in md
    assert "0 of 1 replayed rule(s)" in md
    assert "attack telemetry" not in md
    assert "0 false positives" not in md


@pytest.mark.parametrize(("validated", "flag"), [(2, "false"), (12, "true")])
def test_the_hunt_is_validated_only_when_every_evaluated_rule_is(
    sample_hypothesis: HypothesisResult, validated: int, flag: str
) -> None:
    """H-0016 carried purple_team_validated: true with 2 of 12 rules validated."""
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="x",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 10, 23, tzinfo=UTC),
        purple_team_rules_evaluated=12,
        purple_team_rules_validated=validated,
    )
    assert f"purple_team_validated: {flag}\n" in render_draft(req)


def test_an_attack_source_replays_as_inbound_traffic() -> None:
    records = [
        IndicatorRecord(value="45.153.212.101", type="ipv4", role="inbound", status="active")
    ]
    events = replay_events(records, [])
    assert events["webserver"] == [{"c-ip": "45.153.212.101"}]
    assert events["network_connection"] == [{"SourceIp": "45.153.212.101", "Initiated": "false"}]
    rule = """title: Web request from an attack source
logsource:
  category: webserver
detection:
  selection:
    c-ip:
    - 45.153.212.101
  condition: selection
"""
    assert replay_rule(rule, events["webserver"], BENIGN_SAMPLE).status == "self_consistent"


def test_cloud_audit_and_identity_audit_replay_events() -> None:
    cti = """The adversary called sts:AssumeRole and sts:AssumeRoleWithWebIdentity.
    Also executed illicit OAuth consent grant with Directory.ReadWrite.All and Mail.ReadWrite."""
    artifacts = [
        SimpleNamespace(
            value="aws s3 sync s3://target-bucket/ .", kind="command_line", status="active"
        ),
        SimpleNamespace(value="Core-CloudHealth-Monitor", kind="application", status="active"),
    ]
    events = replay_events([], artifacts, cti_text=cti)
    assert "cloud_audit" in events
    assert "identity_audit" in events

    cloud_events = events["cloud_audit"]
    assert any(e.get("eventName") == "AssumeRole" for e in cloud_events)
    assert any(e.get("eventSource") == "sts.amazonaws.com" for e in cloud_events)
    assert any(e.get("eventSource") == "s3.amazonaws.com" for e in cloud_events)

    identity_events = events["identity_audit"]
    assert any(e.get("operationName") == "Consent to application" for e in identity_events)

    # Validate an AWS STS cloud_audit rule
    sts_rule = """title: Suspicious AWS STS AssumeRole
logsource:
  category: cloud_audit
detection:
  selection:
    eventSource: sts.amazonaws.com
    eventName:
    - AssumeRole
    - AssumeRoleWithWebIdentity
  condition: selection
"""
    sts_outcome = replay_rule(sts_rule, cloud_events, BENIGN_SAMPLE)
    assert sts_outcome.status == "self_consistent"
    assert sts_outcome.false_positives == 0

    # Validate an Entra ID identity_audit rule
    entra_rule = """title: Consent to Application with Sensitive Scopes
logsource:
  category: identity_audit
detection:
  selection:
    operationName: Consent to application
    targetResources.modifiedProperties.newValue|contains: Directory.ReadWrite.All
  condition: selection
"""
    entra_outcome = replay_rule(entra_rule, identity_events, BENIGN_SAMPLE)
    assert entra_outcome.status == "self_consistent"
    assert entra_outcome.false_positives == 0


def test_replay_events_synthesises_tls_fingerprints() -> None:
    records = [
        IndicatorRecord(
            value="07d14d16d21d21d07c42d41407d41d4ae3d3e5896041892ff5da154584d1c4",
            type="jarm",
            role="c2",
            status="active",
        ),
        IndicatorRecord(
            value="t13d1516h2_8daaf6152771_019a76b17a1d",
            type="ja4",
            role="c2",
            status="active",
        ),
    ]

    events = replay_events(records, [])
    assert "network_connection" in events
    net_events = events["network_connection"]
    assert any(
        e.get("jarm") == "07d14d16d21d21d07c42d41407d41d4ae3d3e5896041892ff5da154584d1c4"
        for e in net_events
    )
    assert any(e.get("ja4") == "t13d1516h2_8daaf6152771_019a76b17a1d" for e in net_events)

    jarm_rule = """title: Cobalt Strike Default JARM Fingerprint
logsource:
  category: network_connection
detection:
  selection:
    jarm: 07d14d16d21d21d07c42d41407d41d4ae3d3e5896041892ff5da154584d1c4
  condition: selection
"""
    outcome = replay_rule(jarm_rule, net_events, BENIGN_SAMPLE)
    assert outcome.status == "self_consistent"
    assert outcome.true_positives == 1
    assert outcome.false_positives == 0


def test_replay_events_synthesises_kubernetes_audit() -> None:
    cti_text = "Adversary deployed privileged container escape using hostPath volume in kubernetes cluster-admin."
    events = replay_events([], [], cti_text=cti_text)
    assert "kubernetes_audit" in events
    k8s_events = events["kubernetes_audit"]
    assert any(e.get("resource") == "pods" for e in k8s_events)
    assert any(e.get("userAgent") == "kubectl/v1.28.0" for e in k8s_events)

    k8s_rule = """title: Privileged Pod Creation in Kubernetes
logsource:
  category: kubernetes_audit
detection:
  selection:
    resource: pods
    verb: create
  condition: selection
"""
    outcome = replay_rule(k8s_rule, k8s_events, BENIGN_SAMPLE)
    assert outcome.status == "self_consistent"
    assert outcome.true_positives == 1
    assert outcome.false_positives == 0


def test_replay_events_synthesises_webserver_and_validates_rule() -> None:
    cti_text = "Adversaries targeted unauthenticated endpoints at /api/v1/publish/audit using SQL injection payloads."
    events = replay_events([], [], cti_text=cti_text)
    assert "webserver" in events
    web_events = events["webserver"]
    assert any("/api/v1/publish/audit" in str(e.get("cs-uri-stem")) for e in web_events)

    web_rule = """title: DotCMS SQL Injection Detection
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains: /api/v1/publish/audit
  condition: selection
"""
    outcome = replay_rule(web_rule, web_events, BENIGN_SAMPLE)
    assert outcome.status == "self_consistent"
    assert outcome.true_positives >= 1
    assert outcome.false_positives == 0


def test_hashes_that_are_not_file_hashes_are_not_replayed_as_processes() -> None:
    """H-0018's hash rule "validated" against Node-RED flow revision IDs."""
    rev = "781d7e7c1a2f4b3c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c"
    events = replay_events(
        [IndicatorRecord(value=rev, type="sha256", role="non_file", status="active")], []
    )
    assert not any(rev in str(e) for e in events.get("process_creation", []))


def test_artifacts_not_tied_to_the_intrusion_are_not_replayed() -> None:
    """A PoC README's own test output (fast.log) is demoted, so it cannot validate a rule."""
    events = replay_events(
        [],
        [SimpleNamespace(value="/tmp/suricata-test/fast.log", kind="file_path", status="unknown")],
    )
    assert "file_event" not in events


def test_a_path_the_source_shows_posted_replays_as_a_post() -> None:
    events = replay_events(
        [],
        [SimpleNamespace(value="/flows", kind="url_path", status="active")],
        cti_text="The attacker deploys a new flow through `POST /flows` with no token.",
    )
    assert {"cs-method": "POST", "cs-uri-stem": "/flows"}.items() <= events["webserver"][0].items()


def test_get_benign_sample_for_rule_partitions() -> None:
    linux_rule = "title: Linux Process\nlogsource:\n  category: process_creation\n  product: linux"
    windows_rule = "title: Windows Process\nlogsource:\n  category: process_creation\n  product: windows"
    web_rule = "title: Web Request\nlogsource:\n  category: webserver"
    cloud_rule = "title: Cloud Trail\nlogsource:\n  product: aws\n  service: cloudtrail"
    k8s_rule = "title: K8s Container\nlogsource:\n  product: kubernetes"

    assert get_benign_sample_for_rule(linux_rule) == BENIGN_SAMPLE_LINUX
    assert get_benign_sample_for_rule(windows_rule) == BENIGN_SAMPLE_WINDOWS
    assert get_benign_sample_for_rule(web_rule) == BENIGN_SAMPLE_WEBSERVER + BENIGN_SAMPLE_NETWORK
    assert get_benign_sample_for_rule(cloud_rule) == BENIGN_SAMPLE_CLOUD
    assert get_benign_sample_for_rule(k8s_rule) == BENIGN_SAMPLE_CONTAINER

    # Fallback cases
    assert get_benign_sample_for_rule("") == BENIGN_SAMPLE
    assert get_benign_sample_for_rule("invalid: [yaml: {") == BENIGN_SAMPLE


def test_replay_rule_defaults_to_partitioned_baseline() -> None:
    web_rule = """title: Specific Web Exploit
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem: /vulnerable/path.php
  condition: selection
"""
    events = [{"cs-uri-stem": "/vulnerable/path.php", "cs-method": "GET"}]
    # Calling without baseline argument defaults to get_benign_sample_for_rule
    outcome = replay_rule(web_rule, events)
    assert outcome.status == "self_consistent"
    assert outcome.true_positives == 1
    assert outcome.false_positives == 0


def test_overly_broad_webserver_rule_triggers_baseline_match() -> None:
    broad_web_rule = """title: Catch All GET Requests
logsource:
  category: webserver
detection:
  selection:
    cs-method: GET
  condition: selection
"""
    events = [{"cs-uri-stem": "/exploit.php", "cs-method": "GET"}]
    outcome = replay_rule(broad_web_rule, events)
    assert outcome.status == "baseline_match"
    assert outcome.false_positives > 0
