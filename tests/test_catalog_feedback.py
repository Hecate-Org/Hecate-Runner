"""Production → catalog fidelity loop: SIEM hits, FPs, and tune writeback."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import yaml

from hecate_runner.bas.siem_verifier import SiemAlertVerificationResult, SiemAlertVerifier
from hecate_runner.catalog_feedback import (
    record_rule_tune_feedback,
    record_siem_verification_feedback,
)
from hecate_runner.lifecycle import parse_hunt_frontmatter
from hecate_runner.rule_tuner import RuleTuner
from hecate_runner.siem_drift import init_drift_db


def _seed_hunt(
    workspace: Path,
    hunt_id: str = "H-0099",
    *,
    true_positives: int = 0,
    false_positives: int = 0,
) -> Path:
    init_drift_db(workspace)
    q = workspace / "queries" / hunt_id
    q.mkdir(parents=True)
    (q / "process_creation__core.yml").write_text(
        "title: Core Behavioral\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n  selection:\n    Image|endswith: \\\\evil.exe\n"
        "  condition: selection\n"
        "level: high\n"
        "tags:\n  - attack.t1059.001\n",
        encoding="utf-8",
    )
    (q / "process_creation__core.spl").write_text(
        'Image="*\\\\evil.exe"',
        encoding="utf-8",
    )
    hunts = workspace / "hunts" / "2026" / "Q4"
    hunts.mkdir(parents=True)
    hunt = hunts / f"{hunt_id}.md"
    hunt.write_text(
        "---\n"
        f"hunt_id: {hunt_id}\n"
        "title: Catalog Feedback Fixture\n"
        "status: active\n"
        f"true_positives: {true_positives}\n"
        f"false_positives: {false_positives}\n"
        "---\n\n"
        f"# {hunt_id}\n",
        encoding="utf-8",
    )
    return hunt


def test_siem_verified_tp_increments_hunt_frontmatter(tmp_path: Path) -> None:
    hunt = _seed_hunt(tmp_path)
    result = record_siem_verification_feedback(
        tmp_path,
        {
            "hunt_id": "H-0099",
            "status": "verified_true_positive",
            "fidelity_scope": "behavioral",
            "verification_scope": "siem_alert",
            "bas_provider": "caldera",
            "siem_backend": "splunk",
            "rule_triggered": True,
            "siem_alert_fired": True,
            "detection_latency_sec": 1.25,
            "alert_search_id": "sid-1",
            "alert_name": "hecate_H-0099",
            "alert_time_utc": "2026-11-16T00:00:00+00:00",
        },
        increment_outcomes=True,
    )
    assert result["ok"] is True
    assert result["outcome_bumped"] == "true_positive"

    fm, _, _ = parse_hunt_frontmatter(hunt.read_text(encoding="utf-8"))
    assert fm["true_positives"] == 1
    assert fm["bas_verified"] is True
    assert fm["bas_status"] == "verified_true_positive"
    assert fm["bas_siem_alert_fired"] is True
    assert fm["bas_detection_latency_sec"] == 1.25
    assert fm["last_siem_verification_status"] == "verified_true_positive"
    assert fm["bas_alert_search_id"] == "sid-1"


def test_smoke_check_does_not_count_as_tp(tmp_path: Path) -> None:
    hunt = _seed_hunt(tmp_path)
    record_siem_verification_feedback(
        tmp_path,
        {
            "hunt_id": "H-0099",
            "status": "verified_true_positive",
            "fidelity_scope": "smoke",
            "bas_provider": "mock",
            "siem_backend": "mock",
            "rule_triggered": True,
        },
        increment_outcomes=True,
    )
    fm, _, _ = parse_hunt_frontmatter(hunt.read_text(encoding="utf-8"))
    assert fm["true_positives"] == 0
    assert fm["bas_verified"] is False
    assert fm["bas_status"] == "smoke_check_match"


def test_detection_miss_increments_miss_count(tmp_path: Path) -> None:
    hunt = _seed_hunt(tmp_path)
    record_siem_verification_feedback(
        tmp_path,
        {
            "hunt_id": "H-0099",
            "status": "detection_miss",
            "fidelity_scope": "behavioral",
            "bas_provider": "caldera",
            "siem_backend": "splunk",
            "rule_triggered": False,
            "siem_alert_fired": False,
        },
        increment_outcomes=True,
    )
    fm, _, _ = parse_hunt_frontmatter(hunt.read_text(encoding="utf-8"))
    assert fm["detection_miss_count"] == 1
    assert fm["true_positives"] == 0
    assert fm["bas_verified"] is False


def test_siem_verifier_persist_writes_catalog(tmp_path: Path) -> None:
    hunt = _seed_hunt(tmp_path)
    verifier = SiemAlertVerifier(tmp_path)
    res = SiemAlertVerificationResult(
        hunt_id="H-0099",
        technique_id="T1059.001",
        ability_id="ability-1",
        bas_provider="caldera",
        siem_backend="splunk",
        status="verified_true_positive",
        rule_triggered=True,
        telemetry_arrived=True,
        detection_latency_sec=0.4,
        detonation_time_utc="2026-11-16T00:00:00+00:00",
        alert_time_utc="2026-11-16T00:00:01+00:00",
        matched_events_count=1,
        query_used='Image="*\\\\evil.exe"',
        search_job_id="job-9",
        siem_alert_fired=True,
        fidelity_scope="behavioral",
        verification_scope="siem_alert",
        alert_search_id="alert-9",
        alert_name="hecate_H-0099",
    )
    with patch("hecate_runner.bas.siem_verifier.record_detection_validation"):
        verifier._persist_result(res)

    fm, _, _ = parse_hunt_frontmatter(hunt.read_text(encoding="utf-8"))
    assert fm["true_positives"] == 1
    assert fm["bas_verified"] is True
    assert fm["bas_search_job_id"] == "job-9"


def test_exclude_tune_records_filters_and_nudges_level_under_fp_pressure(
    tmp_path: Path,
) -> None:
    hunt = _seed_hunt(tmp_path, false_positives=3, true_positives=0)
    rule = tmp_path / "queries" / "H-0099" / "process_creation__core.yml"

    with patch(
        "hecate_agent.api.transpile_sigma_rule",
        return_value={},
    ):
        res = RuleTuner(tmp_path).tune_hunt_rule("H-0099", "Exclude Image svchost.exe")
    assert res.ok is True

    fm, _, body = parse_hunt_frontmatter(hunt.read_text(encoding="utf-8"))
    assert fm["tune_count"] == 1
    assert fm["filters_applied_count"] == 1
    assert fm["last_tune_action"] == "exclude"
    assert "svchost" in str(fm.get("last_detection_filter") or "").lower() or "Exclude" in str(
        fm.get("last_tune_summary") or ""
    )
    assert fm["detection_level"] == "medium"
    assert "Conversational Rule Tuning" in body

    rule_data = yaml.safe_load(rule.read_text(encoding="utf-8"))
    assert rule_data["level"] == "medium"
    # Filter filter was applied to the rule body
    dumped = yaml.safe_dump(rule_data)
    assert "svchost" in dumped.lower()


def test_exclude_tune_skips_level_nudge_when_tps_dominate(tmp_path: Path) -> None:
    hunt = _seed_hunt(tmp_path, false_positives=1, true_positives=4)
    rule = tmp_path / "queries" / "H-0099" / "process_creation__core.yml"

    outcome = record_rule_tune_feedback(
        tmp_path,
        "H-0099",
        summary="Excluded `Image` value `svchost.exe`",
        instruction="Exclude Image svchost.exe",
        action_kind="exclude",
        rule_file=rule,
    )
    assert outcome["ok"] is True
    assert outcome["level_adjusted"] is None

    fm, _, _ = parse_hunt_frontmatter(hunt.read_text(encoding="utf-8"))
    assert fm["filters_applied_count"] == 1
    assert "detection_level" not in fm or fm.get("detection_level") is None
    assert yaml.safe_load(rule.read_text(encoding="utf-8"))["level"] == "high"


def test_invalid_hunt_ids_return_error_not_raise(tmp_path: Path) -> None:
    from hecate_runner.catalog_feedback import patch_hunt_frontmatter

    assert record_siem_verification_feedback(tmp_path, {"hunt_id": ""})["ok"] is False
    assert record_siem_verification_feedback(tmp_path, {"hunt_id": "nope"})["ok"] is False
    assert record_rule_tune_feedback(tmp_path, "", summary="x")["ok"] is False
    assert patch_hunt_frontmatter(tmp_path, "bad", {"x": 1})["ok"] is False


def test_corrupt_counters_and_latency_do_not_crash(tmp_path: Path) -> None:
    hunt = _seed_hunt(tmp_path)
    content = hunt.read_text(encoding="utf-8")
    content = content.replace("true_positives: 0", "true_positives: not_a_number")
    content = content.replace("false_positives: 0", "false_positives: ???")
    hunt.write_text(content, encoding="utf-8")

    result = record_siem_verification_feedback(
        tmp_path,
        {
            "hunt_id": "H-0099",
            "status": "verified_true_positive",
            "fidelity_scope": "behavioral",
            "rule_triggered": True,
            "detection_latency_sec": "fast",
            "query_match_latency_sec": "",
        },
        increment_outcomes=True,
    )
    assert result["ok"] is True
    assert result["outcome_bumped"] == "true_positive"
    fm, _, _ = parse_hunt_frontmatter(hunt.read_text(encoding="utf-8"))
    assert fm["true_positives"] == 1
    assert "bas_detection_latency_sec" not in fm

    rule = tmp_path / "queries" / "H-0099" / "process_creation__core.yml"
    tune = record_rule_tune_feedback(
        tmp_path,
        "H-0099",
        summary="Added exclusion filter for Image",
        instruction="",
        rule_file=rule,
    )
    assert tune["ok"] is True
    assert tune["action_kind"] == "exclude"
    assert tune["filters_applied_count"] == 1


def test_quoted_and_commented_sigma_level_nudge(tmp_path: Path) -> None:
    from hecate_runner.catalog_feedback import _nudge_sigma_level

    quoted = tmp_path / "quoted.yml"
    quoted.write_text('title: t\nlevel: "critical"\ndetection:\n  condition: selection\n')
    assert _nudge_sigma_level(quoted, tmp_path) == "high"
    assert 'level: "high"' in quoted.read_text(encoding="utf-8")

    commented = tmp_path / "commented.yml"
    commented.write_text("title: t\nlevel: high  # keep\ndetection:\n  condition: selection\n")
    assert _nudge_sigma_level(commented, tmp_path) == "medium"
    text = commented.read_text(encoding="utf-8")
    assert "level: medium" in text
    assert "# keep" in text

    floor = tmp_path / "floor.yml"
    floor.write_text("title: t\nlevel: low\ndetection:\n  condition: selection\n")
    assert _nudge_sigma_level(floor, tmp_path) is None


def test_no_increment_preserves_tp_on_metadata_rewrite(tmp_path: Path) -> None:
    hunt = _seed_hunt(tmp_path)
    record_siem_verification_feedback(
        tmp_path,
        {
            "hunt_id": "H-0099",
            "status": "verified_true_positive",
            "fidelity_scope": "behavioral",
            "rule_triggered": True,
            "siem_alert_fired": True,
            "alert_search_id": "a1",
        },
        increment_outcomes=True,
    )
    record_siem_verification_feedback(
        tmp_path,
        {
            "hunt_id": "H-0099",
            "status": "verified_true_positive",
            "fidelity_scope": "behavioral",
            "rule_triggered": True,
            "siem_alert_fired": True,
            "alert_search_id": "a2",
            "bas_provider": "caldera",
        },
        increment_outcomes=False,
        extra_updates={"bas_type": "live_detonation"},
    )
    fm, _, _ = parse_hunt_frontmatter(hunt.read_text(encoding="utf-8"))
    assert fm["true_positives"] == 1
    assert fm["bas_alert_search_id"] == "a2"
    assert fm["bas_type"] == "live_detonation"


def test_telemetry_missing_does_not_bump_miss_or_tp(tmp_path: Path) -> None:
    hunt = _seed_hunt(tmp_path)
    record_siem_verification_feedback(
        tmp_path,
        {
            "hunt_id": "H-0099",
            "status": "telemetry_missing",
            "fidelity_scope": "behavioral",
            "rule_triggered": False,
        },
        increment_outcomes=True,
    )
    fm, _, _ = parse_hunt_frontmatter(hunt.read_text(encoding="utf-8"))
    assert fm.get("true_positives", 0) == 0
    assert fm.get("detection_miss_count") in (None, 0)
    assert fm["last_siem_verification_status"] == "telemetry_missing"


def test_extra_updates_cannot_clobber_incremented_tp(tmp_path: Path) -> None:
    hunt = _seed_hunt(tmp_path, true_positives=5)
    record_siem_verification_feedback(
        tmp_path,
        {
            "hunt_id": "H-0099",
            "status": "verified_true_positive",
            "fidelity_scope": "behavioral",
            "rule_triggered": True,
        },
        increment_outcomes=True,
        extra_updates={"true_positives": 0, "bas_type": "live_detonation"},
    )
    fm, _, _ = parse_hunt_frontmatter(hunt.read_text(encoding="utf-8"))
    assert fm["true_positives"] == 6
    assert fm["bas_type"] == "live_detonation"


def test_status_enum_value_counts_as_verified_tp(tmp_path: Path) -> None:
    from hecate_runner.bas.verifier import VerificationStatus

    hunt = _seed_hunt(tmp_path)
    record_siem_verification_feedback(
        tmp_path,
        {
            "hunt_id": "H-0099",
            "status": VerificationStatus.VERIFIED_TRUE_POSITIVE,
            "fidelity_scope": "behavioral",
            "rule_triggered": True,
        },
        increment_outcomes=True,
    )
    fm, _, _ = parse_hunt_frontmatter(hunt.read_text(encoding="utf-8"))
    assert fm["true_positives"] == 1
    assert fm["bas_verified"] is True


def test_include_tune_does_not_count_as_filter(tmp_path: Path) -> None:
    hunt = _seed_hunt(tmp_path, false_positives=5)
    rule = tmp_path / "queries" / "H-0099" / "process_creation__core.yml"
    outcome = record_rule_tune_feedback(
        tmp_path,
        "h-0099",
        summary="Expanded Image with pwsh.exe",
        instruction="Broaden Image to include pwsh.exe",
        rule_file=rule,
    )
    assert outcome["ok"] is True
    assert outcome["action_kind"] == "include"
    assert outcome.get("filters_applied_count") in (None, 0)
    assert outcome["level_adjusted"] is None
    fm, _, _ = parse_hunt_frontmatter(hunt.read_text(encoding="utf-8"))
    assert fm["last_tune_action"] == "include"
    assert fm.get("filters_applied_count") in (None, 0)
    assert yaml.safe_load(rule.read_text(encoding="utf-8"))["level"] == "high"
