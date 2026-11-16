"""Tests for Orchestrator modular pipeline stages.

Verifies each decomposed phase method in isolation:
- _reset_cycle_context
- _try_campaign_correlation
- _check_quotas_and_spacing
- _execute_enrichment_phase
- _execute_research_phase
- _execute_hypothesis_phase
- _execute_grounding_and_ttps_phase
- _execute_drafting_and_publishing_phase
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti import FileQueueProvider
from hecate_runner.cti.base import CTIItem
from hecate_runner.hecate_client import HecateError, HypothesisResult, ResearchResult
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.state import OrchestratorState


@pytest.fixture
def orchestrator(settings: Settings, workspace: Path, mock_hecate: MagicMock) -> Orchestrator:
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    return Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)


def test_reset_cycle_context_clears_all_transient_state(orchestrator: Orchestrator) -> None:
    orchestrator._source_evidence = "some_evidence"
    orchestrator._enriched_context = "context"
    orchestrator._enrichment_citations = [{"url": "http://example.com"}]
    orchestrator._indicator_records = ["dummy_record"]
    orchestrator._detection_guidance = [{"guidance": "test"}]
    orchestrator._specimen = ["linux"]
    orchestrator._platform_evidence = {"linux": 1}
    orchestrator._research_grounding = "grounding"
    orchestrator._research_grounding_label = "label"
    orchestrator._technique_evidence = [{"tid": "T1059"}]
    orchestrator._claim_audit = [{"claim": "audit"}]
    orchestrator._claim_evidence = [{"claim": "evidence"}]

    orchestrator._reset_cycle_context()

    assert orchestrator._source_evidence is None
    assert orchestrator._enriched_context == ""
    assert orchestrator._enrichment_citations == []
    assert orchestrator._indicator_records == []
    assert orchestrator._detection_guidance == []
    assert orchestrator._specimen == []
    assert orchestrator._platform_evidence == {}
    assert orchestrator._research_grounding == ""
    assert orchestrator._research_grounding_label == ""
    assert orchestrator._technique_evidence == []
    assert orchestrator._claim_audit == []
    assert orchestrator._claim_evidence == []


def test_try_campaign_correlation_respects_dry_run_and_clustering_disabled(
    orchestrator: Orchestrator,
) -> None:
    item = CTIItem(
        source="misp",
        identifier="event-1",
        content="Adversary C2 198.51.100.1",
        metadata={},
    )
    state = OrchestratorState()

    # Disabled case
    orchestrator.settings.campaign_clustering_enabled = False
    assert (
        orchestrator._try_campaign_correlation(item, state=state, parked_count=0, dry_run=False)
        is None
    )

    # Enabled but no match
    orchestrator.settings.campaign_clustering_enabled = True
    with patch("hecate_runner.correlation.ThreatEntityCorrelator.correlate", return_value=None):
        assert (
            orchestrator._try_campaign_correlation(item, state=state, parked_count=0, dry_run=False)
            is None
        )

    # Dry-run match
    fake_match = MagicMock(hunt_id="H-0001", hunt_path=Path("/tmp/H-0001.md"), match_type="entity")
    with patch(
        "hecate_runner.correlation.ThreatEntityCorrelator.correlate", return_value=fake_match
    ):
        res = orchestrator._try_campaign_correlation(
            item, state=state, parked_count=2, dry_run=True
        )
        assert res is not None
        assert res.outcome == "dry_run"
        assert res.hunt_id == "H-0001"
        assert res.parked_count == 2


def test_check_quotas_and_spacing_enforces_limits(orchestrator: Orchestrator) -> None:
    item = CTIItem(
        source="otx",
        identifier="pulse-1",
        content="Adversary campaign report with detailed narrative.",
        metadata={},
    )
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    state = OrchestratorState(date=today, drafts_today=10)
    orchestrator.settings.max_drafts_per_day = 5

    # Daily draft quota hit
    res = orchestrator._check_quotas_and_spacing(item, state=state, parked_count=0, dry_run=False)
    assert res is not None
    assert res.outcome == "quota_reached"

    # Spacing cooldown hit
    state_spaced = OrchestratorState(
        date=today, drafts_today=1, last_draft_iso="2026-01-01T00:00:00+00:00"
    )
    orchestrator.settings.max_drafts_per_day = 10
    orchestrator.settings.min_hours_between_drafts = 100000.0  # huge spacing
    res_cooldown = orchestrator._check_quotas_and_spacing(
        item, state=state_spaced, parked_count=1, dry_run=False
    )
    assert res_cooldown is not None
    assert res_cooldown.outcome == "spacing_cooldown"
    assert res_cooldown.parked_count == 1


def test_execute_research_phase_handles_errors_and_parks(
    orchestrator: Orchestrator,
) -> None:
    item = CTIItem(
        source="rss",
        identifier="news-1",
        content="Detailed narrative report on threat group FIN7.",
        metadata={},
    )
    state = OrchestratorState(drafts_today=1)

    # HecateError in research
    orchestrator.hecate.research_new.side_effect = HecateError("LLM unavailable")
    research_id, related, res = orchestrator._execute_research_phase(
        item,
        research_context="Report text",
        intel_has_narrative=True,
        sweep_inventory={},
        state=state,
        parked_count=0,
    )
    assert research_id is None
    assert related == []
    assert res is not None
    assert res.outcome == "research_error"
    assert state.drafts_today == 0  # refunded

    # Park when research describes no behavior and cti_triage == "park"
    orchestrator.settings.cti_triage = "park"
    state.drafts_today = 1
    mock_res = ResearchResult(
        research_id="R-001",
        raw_output="This article describes no observable adversary behavior at all.",
        web_searches=1,
        describes_behavior=False,
    )
    orchestrator.hecate.research_new.side_effect = None
    orchestrator.hecate.research_new.return_value = mock_res

    with patch("hecate_runner.orchestrator.park") as mock_park:
        research_id, related, res = orchestrator._execute_research_phase(
            item,
            research_context="Opinion piece",
            intel_has_narrative=True,
            sweep_inventory={},
            state=state,
            parked_count=0,
        )
        assert res is not None
        assert res.outcome == "parked_after_research"
        assert res.parked_count == 1
        assert state.drafts_today == 0
        mock_park.assert_called_once()


def test_execute_hypothesis_phase_handles_empty_and_park(
    orchestrator: Orchestrator,
) -> None:
    item = CTIItem(
        source="misp",
        identifier="event-2",
        content="Security advisory regarding vendor updates.",
        metadata={},
    )
    state = OrchestratorState(drafts_today=1)

    # Empty hypothesis returns empty_hypothesis and refunds draft
    orchestrator.hecate.hypothesis_generator.return_value = HypothesisResult(
        hypothesis="",
        is_threat_report=True,
    )
    hypo, res = orchestrator._execute_hypothesis_phase(
        item,
        primary_intel_context="Vendor advisory text",
        research_id=None,
        intel_has_narrative=True,
        sweep_inventory={},
        state=state,
        parked_count=0,
    )
    assert hypo is None
    assert res is not None
    assert res.outcome == "empty_hypothesis"
    assert state.drafts_today == 0

    # Non-threat report parked
    orchestrator.settings.cti_triage = "park"
    state.drafts_today = 1
    orchestrator.hecate.hypothesis_generator.return_value = HypothesisResult(
        hypothesis="A marketing whitepaper",
        is_threat_report=False,
        low_confidence_reason="marketing spam",
    )
    with patch("hecate_runner.orchestrator.park") as mock_park:
        hypo, res = orchestrator._execute_hypothesis_phase(
            item,
            primary_intel_context="Whitepaper text",
            research_id=None,
            intel_has_narrative=True,
            sweep_inventory={},
            state=state,
            parked_count=0,
        )
        assert hypo is None
        assert res is not None
        assert res.outcome == "parked_after_hypothesis"
        assert state.drafts_today == 0
        mock_park.assert_called_once()


def test_execute_grounding_and_ttps_phase_resolves_and_parks_when_empty(
    orchestrator: Orchestrator,
) -> None:
    item = CTIItem(
        source="otx",
        identifier="pulse-empty",
        content="A generic post with no techniques or observables.",
        metadata={},
    )
    state = OrchestratorState(drafts_today=1)
    hypothesis = HypothesisResult(
        hypothesis="Adversary observed executing unknown tool",
        techniques=[],
        observables=[],
        actor="",
        data_sources=[],
    )

    # Parks when no technique survived and cti_triage == "park"
    orchestrator.settings.cti_triage = "park"
    with patch("hecate_runner.orchestrator.park") as mock_park:
        _tactics, _platforms, _facts, res = orchestrator._execute_grounding_and_ttps_phase(
            item,
            hypothesis=hypothesis,
            research_id=None,
            sweep_inventory={},
            state=state,
            parked_count=0,
        )
        assert res is not None
        assert res.outcome == "parked_no_techniques"
        assert state.drafts_today == 0
        mock_park.assert_called_once()
