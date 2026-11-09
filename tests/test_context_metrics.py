import json
import logging
import sys
from types import SimpleNamespace
from unittest.mock import Mock

from hecate_runner.context_metrics import log_payload_metrics, measure_tokens
from hecate_runner.metrics import CycleMetrics, LLMUsage, MetricsStore


def test_unknown_models_never_use_gpt_fallback(monkeypatch):
    tokenizer = SimpleNamespace(
        encoding_for_model=Mock(side_effect=KeyError("qwen")), get_encoding=Mock()
    )
    monkeypatch.setitem(sys.modules, "tiktoken", tokenizer)
    assert measure_tokens("full source text", "qwen3.6:35b") is None
    tokenizer.get_encoding.assert_not_called()
    assert measure_tokens("text") is None
    assert measure_tokens("") == 0


def test_known_model_estimate_uses_its_tokenizer(monkeypatch):
    encoding = SimpleNamespace(encode=Mock(return_value=[1, 2, 3]))
    tokenizer = SimpleNamespace(encoding_for_model=Mock(return_value=encoding))
    monkeypatch.setitem(sys.modules, "tiktoken", tokenizer)
    assert measure_tokens("literal <|endoftext|>", "gpt-4") == 3
    tokenizer.encoding_for_model.assert_called_once_with("gpt-4")
    encoding.encode.assert_called_once_with("literal <|endoftext|>", disallowed_special=())


def test_missing_tokenizer_is_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "tiktoken", None)
    assert measure_tokens("text", "gpt-4") is None


def test_payload_log_is_explicit_and_does_not_expose_content(caplog):
    with caplog.at_level(logging.INFO):
        log_payload_metrics("hypothesis_generation", "PRIVATE_INTELLIGENCE")
    assert "scope=payload_only" in caplog.text
    assert "payload_tokens=unavailable" in caplog.text
    assert "PRIVATE_INTELLIGENCE" not in caplog.text
    assert "Context Window Metrics" not in caplog.text


def test_peak_prompt_is_a_maximum_and_survives_persistence(tmp_path, caplog):
    store = MetricsStore(tmp_path / "metrics.jsonl")
    with caplog.at_level(logging.INFO):
        for peak in (500, 700):
            cycle = CycleMetrics("test")
            with cycle.measure("sigma_generation") as stage:
                stage.set_usage(
                    LLMUsage.from_metadata(
                        {
                            "llm_calls": 2,
                            "input_tokens": 800,
                            "output_tokens": 40,
                            "max_input_tokens": peak,
                            "input_token_samples": 2,
                        }
                    )
                )
            store.append(cycle.to_record(outcome="draft_created", hunt_id="H-0001"))
    row = next(r for r in store.aggregate() if r["stage"] == "sigma_generation")
    assert row["max_input_tokens"] == 700
    assert row["input_tokens"] == 1600
    assert row["input_token_samples"] == 4
    assert "max_reported_prompt_tokens=700" in caplog.text
    assert (
        json.loads(store.path.read_text().splitlines()[0])["stages"][0]["max_input_tokens"] == 500
    )


def test_old_core_metadata_and_partial_usage_do_not_invent_peak_or_totals():
    old = LLMUsage.from_metadata({"llm_calls": 2, "input_tokens": 120})
    assert old.max_input_tokens is None and old.input_token_samples is None
    assert old.input_tokens == 120
    missing = LLMUsage.from_metadata({"llm_calls": 1, "input_tokens": 0})
    assert missing.input_tokens is None
    partial = LLMUsage.from_metadata(
        {"llm_calls": 2, "input_tokens": 300, "input_token_samples": 1, "max_input_tokens": 300}
    )
    assert partial.input_tokens is None
    assert partial.max_input_tokens == 300


def test_historical_stage_records_show_peak_as_unavailable(tmp_path):
    store = MetricsStore(tmp_path / "metrics.jsonl")
    cycle = CycleMetrics("legacy")
    record = cycle.to_record(outcome="no_cti")
    record["stages"] = [{"stage": "sigma_generation", "input_tokens": 100, "llm_calls": 1}]
    store.append(record)
    assert store.aggregate()[0]["max_input_tokens"] is None
    assert store.aggregate()[0]["input_token_samples"] is None


def test_partial_totals_stay_unknown_after_aggregation_and_in_digest(tmp_path):
    store = MetricsStore(tmp_path / "metrics.jsonl")
    for samples in (1, 2):
        cycle = CycleMetrics("partial")
        with cycle.measure("sigma_generation") as stage:
            stage.set_usage(
                LLMUsage(
                    llm_calls=2,
                    input_tokens=800,
                    output_tokens=20,
                    max_input_tokens=500,
                    input_token_samples=samples,
                )
            )
        store.append(cycle.to_record(outcome="draft_created", hunt_id="H-0001"))
    row = next(r for r in store.aggregate() if r["stage"] == "sigma_generation")
    assert row["input_tokens"] is None
    assert row["max_input_tokens"] == 500
    assert row["input_token_samples"] == 3
    summary = store.summary()
    assert summary["total_input_tokens"] is None
    assert summary["stages"]["sigma_generation"]["input_tokens"] is None


def test_research_usage_keeps_context_metrics_across_client_boundary(tmp_path, monkeypatch):
    import hecate_agent.api

    output = SimpleNamespace(
        research_id="R-0001",
        recommended_hypothesis="",
        related_work=SimpleNamespace(sources=[]),
        llm_calls=4,
        input_tokens=4000,
        output_tokens=100,
        max_input_tokens=1800,
        input_token_samples=4,
    )
    monkeypatch.setattr(hecate_agent.api, "generate_research", lambda **kw: (output, None))
    from hecate_runner.hecate_client import HecateClient

    client = HecateClient(hecate_bin=tmp_path / "hecate-agent", workspace=tmp_path)
    result = client.research_new(topic="test")
    assert result.usage.input_tokens == 4000
    assert result.usage.max_input_tokens == 1800
    assert result.usage.input_token_samples == 4
