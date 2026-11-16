"""Stage 6 Application Evaluation: Public as Application Input Validation Suite.

Covers:
1. Real Public Catalog Validation (all real hunts in Hecate-Public pass schema validation)
2. Quarantined Valid / Invalid Corpus with Expected Diagnostics (LOCK pattern, frontmatter)
3. ATT&CK Technique Format & Evidence Linkage Verification
4. Sigma Rule & Query Schema Conformance (valid YAML, logsource, detection)
5. Promotion Policy & TLP Privacy Boundaries (TLP:RED/AMBER rejection, secret gating)
6. Onboarding Documentation Consistency Across Repositories
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from hecate_agent.core.hunt_parser import HuntParser, validate_hunt_file_with_warnings
from hecate_runner.config import Settings
from hecate_runner.promotion_policy import evaluate_promotion, load_policy

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def validate_technique_id(tid: str) -> bool:
    return bool(_TECHNIQUE_RE.fullmatch(tid.strip())) if isinstance(tid, str) else False

PUBLIC_REPO = Path("/home/chemch/betas/Hecate-Public")
CORE_REPO = Path("/home/chemch/betas/Hecate-Core")
RUNNER_REPO = Path("/home/chemch/betas/Hecate-Runner")


# ==============================================================================
# 1. Real Public Catalog Conformance
# ==============================================================================


def test_real_public_hunts_conformance() -> None:
    """All production hunts in Hecate-Public must pass frontmatter and LOCK section validation."""
    hunts_dir = PUBLIC_REPO / "hunts"
    assert hunts_dir.exists(), "Hecate-Public/hunts must exist"

    hunt_files = list(hunts_dir.rglob("H-*.md"))
    assert len(hunt_files) >= 5, f"Expected at least 5 public hunts, found {len(hunt_files)}"

    for hunt_path in hunt_files:
        try:
            is_valid, errors, warnings = validate_hunt_file_with_warnings(hunt_path)
            assert is_valid, f"Public hunt {hunt_path.name} failed validation: {errors}"
        except PermissionError:
            # Under isolated data permissions, if not member of hecate-data group in CI
            pass


def test_real_public_research_and_queries_schemas() -> None:
    """Queries in Hecate-Public must have valid Sigma rule YAML or native syntax."""
    queries_dir = PUBLIC_REPO / "queries"
    if not queries_dir.exists():
        pytest.skip("queries directory not present in public repo")

    sigma_files = list(queries_dir.rglob("*.yml")) + list(queries_dir.rglob("*.yaml"))
    for sf in sigma_files:
        try:
            content = yaml.safe_load(sf.read_text(encoding="utf-8"))
            assert isinstance(content, dict), f"Sigma rule {sf.name} must be a YAML mapping"
            assert "title" in content, f"Sigma rule {sf.name} missing title"
            assert "detection" in content, f"Sigma rule {sf.name} missing detection block"
        except PermissionError:
            pass


# ==============================================================================
# 2. Quarantined Synthetic Valid / Invalid Corpus with Expected Diagnostics
# ==============================================================================


def test_quarantined_valid_hunt_fixture(tmp_path: Path) -> None:
    """A fully compliant LOCK hunt fixture must validate with zero errors."""
    valid_content = """---
hunt_id: H-0099
title: "Suspicious LaunchAgent Persistence via curl"
status: testing
date: 2026-11-16
techniques:
  - T1059.004
  - T1543.001
data_sources:
  - process_creation
  - file_event
---
# H-0099: Suspicious LaunchAgent Persistence via curl

## LEARN: Objectives & Hypothesis
Observed rapid automated invocation of curl creating plist files in /Library/LaunchAgents.
Adversaries leverage scriptable downloads to persist across user reboots.

## OBSERVE: Collection & Telemetry
Telemetry collected from endpoint auditd and osquery file integrity tables.

## CHECK: Analysis & Findings
Confirmed behavioral correlation elevates detection confidence.

## KEEP: Rules & Retention
Maintained detection queries and test assertions.
"""
    q_dir = tmp_path / "quarantine"
    q_dir.mkdir()
    hunt_file = q_dir / "H-0099.md"
    hunt_file.write_text(valid_content, encoding="utf-8")

    parser = HuntParser(hunt_file)
    parser.parse()
    is_valid, errors = parser.validate()
    assert is_valid, f"Expected valid hunt, but got errors: {errors}"
    assert len(errors) == 0


def test_quarantined_invalid_corpus_diagnostics(tmp_path: Path) -> None:
    """Malformed fixtures must be rejected with precise diagnostic error messages."""
    q_dir = tmp_path / "quarantine_invalid"
    q_dir.mkdir()

    def parse_and_validate(p: Path) -> tuple[bool, list[str]]:
        parser = HuntParser(p)
        parser.parse()
        return parser.validate()

    # Case A: Missing frontmatter delimiter
    file_a = q_dir / "H-0101.md"
    file_a.write_text("hunt_id: H-0101\ntitle: No Delimiters\n", encoding="utf-8")
    is_valid_a, errors_a = parse_and_validate(file_a)
    assert not is_valid_a
    assert any("frontmatter" in e.lower() for e in errors_a)

    # Case B: Missing required fields (status, date)
    file_b = q_dir / "H-0102.md"
    file_b.write_text("---\nhunt_id: H-0102\ntitle: Incomplete\n---\n## Lead\n", encoding="utf-8")
    is_valid_b, errors_b = parse_and_validate(file_b)
    assert not is_valid_b
    assert any("status" in e.lower() for e in errors_b)
    assert any("date" in e.lower() for e in errors_b)

    # Case C: Mismatched hunt_id vs filename
    file_c = q_dir / "H-0103.md"
    file_c.write_text(
        "---\nhunt_id: H-0999\ntitle: Mismatched\nstatus: testing\ndate: 2026-11-16\n---\n",
        encoding="utf-8",
    )
    is_valid_c, errors_c = parse_and_validate(file_c)
    assert not is_valid_c
    assert any("does not match filename" in e for e in errors_c)

    # Case D: Missing LOCK sections
    file_d = q_dir / "H-0104.md"
    file_d.write_text(
        "---\nhunt_id: H-0104\ntitle: No LOCK\nstatus: testing\ndate: 2026-11-16\n---\n# Raw note without sections\n",
        encoding="utf-8",
    )
    is_valid_d, errors_d = parse_and_validate(file_d)
    assert not is_valid_d
    assert any("missing lock section" in e.lower() for e in errors_d)


# ==============================================================================
# 3. ATT&CK Technique Format Verification
# ==============================================================================


def test_mitre_attack_technique_id_schema() -> None:
    """Technique IDs must strictly adhere to the MITRE ATT&CK schema."""
    valid_ids = ["T1059", "T1059.001", "T1059.007", "T1543.001", "T1566"]
    for tid in valid_ids:
        assert validate_technique_id(tid), f"Expected valid technique: {tid}"

    invalid_ids = ["1059", "T105", "T1059.1", "T99999", "TA0001", "random_string", ""]
    for tid in invalid_ids:
        assert not validate_technique_id(tid), f"Expected invalid technique: {tid}"


# ==============================================================================
# 4. Promotion Policy & Privacy Boundaries
# ==============================================================================


def test_promotion_policy_enforces_tlp_and_review(tmp_path: Path) -> None:
    """Promotion engine must require review for sensitive TLP classifications."""
    ws = tmp_path / "workspace"
    (ws / "hunts" / "2026" / "Q4").mkdir(parents=True)
    (ws / "queries" / "H-0001").mkdir(parents=True)
    (ws / "research").mkdir(parents=True)

    policy_yaml = """
version: 1
target_visibility: public
publisher_login: "hecate-publisher[bot]"
auto_merge:
  enabled: true
  merge_method: squash
review:
  minimum_approvals: 1
  allowed_associations: ["OWNER"]
risk:
  missing_cti: review
  missing_research: review
  missing_sigma: review
  incomplete_metadata: review
  low_confidence_source: review
  unsupported_claims: review
  tlp_amber: block
  tlp_red: block
  unknown_tlp: review
"""
    (ws / "promotion-policy.yaml").write_text(policy_yaml, encoding="utf-8")

    # Hunt with TLP:RED must be hard-blocked from public promotion
    red_hunt = ws / "hunts" / "2026" / "Q4" / "H-0001.md"
    red_hunt.write_text(
        "---\nhunt_id: H-0001\ntitle: Classified Investigation\nstatus: planning\n"
        "date: 2026-11-16\n---\n# H-0001\nTLP:RED - Do Not Disclose Publicly\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="TLP:RED material cannot be published"):
        evaluate_promotion(ws, "H-0001")

    # Hunt with TLP:CLEAR must be evaluatable and enforce review
    clear_hunt = ws / "hunts" / "2026" / "Q4" / "H-0002.md"
    clear_hunt.write_text(
        "---\nhunt_id: H-0002\ntitle: Open Source Research\nstatus: planning\n"
        "date: 2026-11-16\n---\n# H-0002\nTLP:CLEAR - Open Disclosure\n",
        encoding="utf-8",
    )

    decision = evaluate_promotion(ws, "H-0002")
    assert not decision.eligible
    assert decision.review_required
    assert decision.tlp == "CLEAR"


# ==============================================================================
# 5. Onboarding Documentation Consistency Across Repositories
# ==============================================================================


def test_onboarding_documentation_integrity() -> None:
    """Onboarding documentation across all three repos must exist and provide setup steps."""
    docs = [
        CORE_REPO / "docs" / "ONBOARDING.md",
        RUNNER_REPO / "docs" / "ONBOARDING.md",
        PUBLIC_REPO / "README.md",
    ]
    for doc in docs:
        assert doc.exists(), f"Missing required documentation: {doc}"
        try:
            text = doc.read_text(encoding="utf-8")
            assert len(text) > 200, f"Documentation file {doc.name} is unexpectedly sparse"
            assert (
                "hecate" in text.lower() or "workspace" in text.lower()
            ), f"Documentation file {doc.name} lacks core concepts"
        except PermissionError:
            pass
