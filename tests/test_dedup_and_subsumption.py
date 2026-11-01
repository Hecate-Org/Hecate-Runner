"""Unit tests for Hecate-Runner Sigma deduplication and AST subsumption integrations."""

import json
from pathlib import Path

from typer.testing import CliRunner

from hecate_runner.cli import app
from hecate_runner.rule_tuner import RuleTuner

runner = CliRunner()


def test_cli_runner_dedup_json(tmp_path: Path) -> None:
    # Create two test rules: Rule A (broad), Rule B (narrow)
    rule_a = tmp_path / "broad.yml"
    rule_a.write_text("""
title: Broad CMD
id: aaaa-1111
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: selection
""")
    rule_b = tmp_path / "narrow.yml"
    rule_b.write_text("""
title: Narrow CMD Whoami
id: bbbb-2222
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\cmd.exe'
    CommandLine|contains: 'whoami'
  condition: selection
""")

    result = runner.invoke(app, ["dedup", str(tmp_path), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["total_rules"] == 2
    assert data["subsumption_count"] == 1
    assert data["subsumptions"][0]["relation"] == "SUBSUMES"


def test_cli_runner_dedup_check_flag(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "existing.yml").write_text("""
title: Existing Powershell Rule
id: exist-001
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
  condition: selection
""")

    candidate = tmp_path / "candidate.yml"
    candidate.write_text("""
title: Encoded Powershell Rule
id: cand-001
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
""")

    result = runner.invoke(app, ["dedup", str(corpus_dir), "--check", str(candidate)])
    assert result.exit_code == 0
    assert "SUBSUMED_BY" in result.output
    assert "Existing Powershell Rule" in result.output


def test_rule_tuner_populates_subsumption_warnings(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    queries_dir = workspace / "queries" / "H-9999"
    queries_dir.mkdir(parents=True)
    hunts_dir = workspace / "hunts"
    hunts_dir.mkdir()

    # Rule 1 in another hunt directory: broad powershell rule
    other_query_dir = workspace / "queries" / "H-1000"
    other_query_dir.mkdir(parents=True)
    (other_query_dir / "broad_ps.yml").write_text("""
title: Generic PowerShell Detection
id: broad-ps-01
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
  condition: selection
""")

    # Rule 2 in H-9999: will be tuned to powershell.exe with -enc
    rule_file = queries_dir / "test_rule.yml"
    rule_file.write_text("""
title: Tuned PowerShell Detection
id: tuned-ps-01
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
  condition: selection
""")

    # Mock hunt markdown doc
    hunt_doc = hunts_dir / "H-9999.md"
    hunt_doc.write_text("# Hunt H-9999\n\nInitial draft content.\n")

    tuner = RuleTuner(workspace)
    # Analyst instruction adds a command line filter, making it narrower than broad_ps.yml
    res = tuner.tune_hunt_rule("H-9999", "Filter CommandLine containing -enc")
    assert res.ok is True
    # The rule tuner should have checked against workspace queries and identified
    # that it is now subsumed by Generic PowerShell Detection
    assert len(res.subsumption_warnings) >= 1
    assert any("subsumed" in w.lower() for w in res.subsumption_warnings)
