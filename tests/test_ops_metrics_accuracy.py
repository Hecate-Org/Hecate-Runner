import json
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from typer.testing import CliRunner

from hecate_runner import cli
from hecate_runner.metrics import CycleMetrics, MetricsStore
from hecate_runner.slack_blocks import build_ops_metrics_card


def record(store, outcome="draft_created", hunt_id="H-0001", rules=2, age=0, cost=0.25, at=None):
    cycle = CycleMetrics("test")
    cycle.sigma_rules_produced = rules
    data = cycle.to_record(outcome=outcome, hunt_id=hunt_id)
    data["started_at"] = ((at or datetime.now(UTC)) - timedelta(days=age)).isoformat()
    data["stages"].append({"stage": "sigma", "llm_calls": 1, "estimated_cost_usd": cost})
    store.append(data)
    return data


def test_digest_counts_drafts_and_records_rule_counts(tmp_path):
    store = MetricsStore(tmp_path / "metrics.jsonl")
    record(store)
    record(store, outcome="no_cti", hunt_id=None, rules=0)
    record(store, outcome="spacing_cooldown", hunt_id=None, rules=0)
    record(store, outcome="error", hunt_id=None, rules=0)
    record(store, hunt_id="H-0002", age=2, rules=3)
    summary = store.summary(days=1)
    assert summary["completed_cycles"] == 4
    assert summary["hunts_completed"] == 1
    assert summary["sigma_rules_produced"] == 2
    assert store.summary(days=7)["sigma_rules_produced"] == 5


def test_today_cost_uses_utc_midnight_and_selected_window_is_labeled(tmp_path):
    now = datetime(2026, 11, 9, 12, tzinfo=UTC)
    store = MetricsStore(tmp_path / "metrics.jsonl")
    with patch("hecate_runner.metrics.datetime") as clock:
        clock.now.return_value = now
        clock.fromisoformat.side_effect = datetime.fromisoformat
        record(store, cost=0.5, at=now)
        record(store, age=2, cost=1.5, hunt_id="H-0002", at=now)
        summary = store.summary(days=7)
    assert summary["total_cost_usd"] == 2.0
    assert summary["spend_today_usd"] == 0.5
    card = build_ops_metrics_card(summary)[0]["blocks"]
    assert "7-Day" in card[0]["text"]["text"]
    assert "Unavailable" in card[1]["fields"][2]["text"]


def test_unknown_and_partially_priced_usage_remain_unavailable(tmp_path):
    store = MetricsStore(tmp_path / "metrics.jsonl")
    record(store, cost=1)
    record(store, hunt_id="H-0002", cost=None)
    summary = store.summary()
    assert summary["total_cost_usd"] is None
    assert summary["spend_today_usd"] is None
    assert summary["stages"]["sigma"]["cost_usd"] is None
    assert "Unavailable" in str(build_ops_metrics_card(summary))


def test_legacy_rule_counts_are_unavailable_and_bad_records_are_skipped(tmp_path):
    store = MetricsStore(tmp_path / "metrics.jsonl")
    legacy = record(store)
    del legacy["sigma_rules_produced"]
    store.path.write_text("broken json\n" + json.dumps(legacy) + "\n")
    assert store.summary()["sigma_rules_produced"] is None


def test_digest_reports_delivery_failure(settings, monkeypatch):
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    settings.slack_bot_token = "test-token"
    monkeypatch.setattr(
        "hecate_runner.commands.slack.notify_ops_metrics",
        lambda *a, **k: (False, "channel_not_found"),
    )
    result = CliRunner().invoke(cli.app, ["ops-digest"])
    assert result.exit_code == 1
    assert "channel_not_found" in result.output
    assert "posted to" not in result.output


def test_partially_priced_repeated_stage_cannot_look_fully_priced(tmp_path):
    store = MetricsStore(tmp_path / "metrics.jsonl")
    data = record(store)
    data["stages"].append({"stage": "sigma", "llm_calls": 1})
    store.path.write_text(json.dumps(data) + "\n")
    assert store.summary()["total_cost_usd"] is None


def test_legacy_llm_stage_without_usage_is_unpriced(tmp_path):
    store = MetricsStore(tmp_path / "metrics.jsonl")
    data = record(store)
    data["stages"] = [{"stage": "sigma_generation", "duration_ms": 10}]
    store.path.write_text(json.dumps(data) + "\n")
    assert store.summary()["total_cost_usd"] is None
