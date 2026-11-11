"""Disjoint replay grading must not become another round of training."""

import copy
import hashlib
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
import yaml

from hecate_runner.purple_team import replay_rule
from hecate_runner.replay_holdout import event_group, reserve_holdout

BROAD = """title: Curl activity
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /curl
  condition: selection
"""

GOOD = """title: Curl payload activity
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /curl
    CommandLine|contains: /tmp/payload-
  condition: selection
"""


@pytest.fixture
def corpus():
    return (
        [{"Image": "/usr/bin/curl", "CommandLine": f"curl /tmp/payload-{i}"} for i in range(4)],
        [
            {"Image": "/usr/bin/curl", "CommandLine": f"curl /opt/admin/update-{i}"}
            for i in range(4)
        ],
    )


def test_partition_is_deterministic_disjoint_and_deduplicated(corpus):
    positive, benign = corpus
    p_before, b_before = copy.deepcopy(corpus)
    duplicate = {**positive[0], "ProcessId": 10, "UtcTime": "2026-11-01T00:00:00Z"}
    first = reserve_holdout([*positive, duplicate], benign)
    second = reserve_holdout(list(reversed(positive)), list(reversed(benign)))
    assert first.digest == second.digest
    assert first.available
    training = {event_group(e) for e in first.positive + first.benign}
    withheld = {event_group(e) for e in first.holdout_positive + first.holdout_benign}
    assert not training & withheld
    assert len(training | withheld) == 8
    assert positive == p_before and benign == b_before
    first.positive[0]["CommandLine"] = "mutated"
    assert positive == p_before


def test_repeated_execution_metadata_cannot_manufacture_independent_samples():
    positive = [{"Image": "/bin/probe", "ProcessId": i, "UtcTime": str(i)} for i in range(10)]
    split = reserve_holdout(positive, [{"Image": "/bin/admin"}, {"Image": "/bin/backup"}])
    assert not split.available
    assert "distinct" in split.reason


def test_ambiguous_labels_disable_tuning(corpus):
    positive, benign = corpus
    tuner = Mock()
    outcome = replay_rule(BROAD, positive, [*benign, dict(positive[0])], tuner)
    tuner.tune.assert_not_called()
    assert outcome.holdout["status"] == "unavailable"
    assert "overlapping" in outcome.holdout["reason"]
    assert not outcome.tuned


def test_small_corpora_keep_sanity_checks_but_do_not_tune(corpus):
    positive, benign = corpus
    tuner = Mock()
    outcome = replay_rule(BROAD, positive[:1], benign, tuner)
    assert outcome.status == "baseline_match"
    assert outcome.evaluation_scope == "replay_sanity"
    assert outcome.holdout["status"] == "unavailable"
    assert outcome.final_rule == BROAD
    tuner.tune.assert_not_called()


def test_tuner_cannot_see_or_mutate_held_out_events(corpus):
    positive, benign = corpus
    split = reserve_holdout(positive, benign)
    unseen = {event_group(e) for e in split.holdout_positive + split.holdout_benign}
    tuner = Mock()

    def tune(rule, samples, baseline):
        assert not {event_group(e) for e in samples + baseline} & unseen
        assert len(samples) == len(split.positive)
        baseline.clear()
        samples[0]["CommandLine"] = "tampered training copy"
        return SimpleNamespace(final_rule=GOOD)

    tuner.tune.side_effect = tune
    outcome = replay_rule(BROAD, positive, benign, tuner)
    assert outcome.status == "self_consistent"
    assert outcome.tuned
    assert outcome.final_rule == GOOD
    assert outcome.holdout["status"] == "passed"
    assert outcome.holdout["fn"] == outcome.holdout["fp"] == 0
    assert outcome.holdout["positive_events"] == outcome.holdout["benign_events"] == 1
    assert outcome.evaluation_scope == "synthetic_holdout"
    assert outcome.holdout["evaluated_rule_sha256"] == hashlib.sha256(GOOD.encode()).hexdigest()
    tuner.tune.assert_called_once()
    assert all("tampered" not in event["CommandLine"] for event in positive)


def test_training_overfit_fails_once_and_cannot_replace_rule():
    positive = [
        {"Image": "/usr/bin/curl", "CommandLine": f"curl /tmp/payload-{i}"} for i in range(2)
    ]
    benign = [{"Image": "/usr/bin/curl", "CommandLine": f"curl /opt/admin-{i}"} for i in range(2)]
    split = reserve_holdout(positive, benign)
    parsed = yaml.safe_load(BROAD)
    parsed["detection"]["selection"]["CommandLine"] = split.positive[0]["CommandLine"]
    overfit = yaml.safe_dump(parsed)
    tuner = Mock()
    tuner.tune.return_value = SimpleNamespace(final_rule=overfit)
    from hecate_agent.core.sigma_evaluator import SigmaEvaluator

    evaluate = SigmaEvaluator.evaluate_rule
    with patch.object(SigmaEvaluator, "evaluate_rule", wraps=evaluate) as calls:
        outcome = replay_rule(BROAD, positive, benign, tuner)
    heldout_calls = [
        call
        for call in calls.call_args_list
        if call.args[1] == split.holdout_positive and call.args[2] == split.holdout_benign
    ]
    assert len(heldout_calls) == 1
    assert heldout_calls[0].args[0] == overfit
    tuner.tune.assert_called_once()
    assert outcome.status == "holdout_failed"
    assert not outcome.matched
    assert not outcome.tuned
    assert outcome.tuning_rejected
    assert outcome.final_rule == BROAD
    assert outcome.training_metrics["tp"] == 1
    assert outcome.holdout["fn"] == 1
    assert outcome.holdout["evaluated_rule_sha256"] == hashlib.sha256(overfit.encode()).hexdigest()
    assert outcome.to_dict()["holdout"]["status"] == "failed"


def test_untuned_rule_is_also_graded_on_withheld_data(corpus):
    positive, benign = corpus
    outcome = replay_rule(GOOD, positive, benign)
    assert outcome.matched
    assert not outcome.tuned
    assert outcome.holdout["status"] == "passed"
    assert outcome.holdout["recall"] == 1.0
    assert outcome.holdout["false_positive_rate"] == 0.0


def test_baseline_widening_does_not_pass_only_by_training_fit(corpus):
    positive, benign = corpus
    outcome = replay_rule(BROAD, positive, benign)
    assert outcome.status == "baseline_match"
    assert outcome.holdout["status"] == "failed"
    assert outcome.holdout["fp"] > 0
    assert not outcome.matched


def test_holdout_reporting_keeps_its_synthetic_scope(sample_hypothesis):
    from datetime import UTC, datetime

    from hecate_runner.hunt_writer import DraftHuntRequest, render_draft

    request = DraftHuntRequest(
        hunt_id="H-TEST",
        generated_at=datetime.now(UTC),
        hypothesis=sample_hypothesis,
        threat_intel="test",
        sigma_rules=[
            {
                "rule_yaml": GOOD,
                "purple_team": {
                    "status": "self_consistent",
                    "matched": True,
                    "holdout": {"status": "passed"},
                },
            }
        ],
    )
    output = render_draft(request)
    assert "Withheld synthetic samples" in output
    assert "1 of 1 scored rule(s) passed" in output
    assert "does not measure production detection quality" in output
    assert "purple_team_validated: true" not in output


def test_failed_tuning_clears_stale_success_annotations_in_pipeline(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    from hecate_runner.config import Settings
    from hecate_runner.hecate_client import HypothesisResult
    from hecate_runner.hunt_writer import DraftHuntRequest
    from hecate_runner.orchestrator_validation import run_purple_team_validation

    positive = [
        {"Image": "/usr/bin/curl", "CommandLine": f"curl /tmp/payload-{i}"} for i in range(2)
    ]
    benign = [{"Image": "/usr/bin/curl", "CommandLine": f"curl /opt/admin-{i}"} for i in range(2)]
    split = reserve_holdout(positive, benign)
    parsed = yaml.safe_load(BROAD)
    parsed["detection"]["selection"]["CommandLine"] = split.positive[0]["CommandLine"]
    tuner = Mock()
    tuner.tune.return_value = SimpleNamespace(final_rule=yaml.safe_dump(parsed))
    settings = Settings(
        _env_file=None, hecate_workspace=tmp_path, purple_team_atomic_emulation=False
    )
    trail = Mock()
    trail.elapsed = 1.0
    orch = SimpleNamespace(
        settings=settings,
        trail=trail,
        _source_evidence=None,
        _indicator_records=[],
        _technique_evidence=[],
        _primary_evidence_text=lambda item: "report",
    )
    path = tmp_path / "rule.yml"
    original = BROAD + "x_hecate_replay_matched: true\nx_hecate_tuned: true\n"
    path.write_text(original)
    rules = [{"rule_yaml": original, "path": str(path), "logsource_category": "process_creation"}]
    request = DraftHuntRequest(
        hunt_id="H-TEST",
        generated_at=datetime.now(UTC),
        hypothesis=HypothesisResult(hypothesis="test"),
        threat_intel="test",
        platforms=["linux"],
    )
    monkeypatch.setattr(
        "hecate_runner.purple_team.replay_events",
        lambda *args, **kwargs: {"process_creation": positive},
    )
    monkeypatch.setattr(
        "hecate_runner.purple_team.get_benign_sample_for_rule", lambda *args: benign
    )
    with (
        patch("hecate_agent.core.sigma_self_tuner.SigmaSelfTuner", return_value=tuner),
        patch("hecate_runner.notifications.notify_purple_team") as notify,
    ):
        run_purple_team_validation(orch, request, rules, tmp_path, SimpleNamespace(metadata={}))
    saved = yaml.safe_load(path.read_text())
    assert "x_hecate_replay_matched" not in saved
    assert "x_hecate_tuned" not in saved
    assert saved["x_hecate_synthetic_holdout_status"] == "failed"
    assert saved["detection"] == yaml.safe_load(BROAD)["detection"]
    assert rules[0]["purple_team"]["tuning_rejected"]
    assert request.purple_team_rules_tuned == 0
    assert request.purple_team_rules_validated == 0
    assert "1 failed" in notify.call_args.kwargs["summary"]
