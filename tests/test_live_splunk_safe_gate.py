"""Tests for live Splunk integration with SafeExecutionGate and COUNT-FIRST safety."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hecate_runner.config import Settings
from hecate_runner.execution.safe_gate import SafeExecutionGate
from hecate_runner.query_execution import ProposedQuery, get_provider

pytestmark = pytest.mark.network


@pytest.fixture(autouse=True)
def _explicit_live_splunk_configuration(monkeypatch):
    # Deliberately separate test credentials from the operator's selected workspace.
    required = ("HECATE_TEST_LIVE_WORKSPACE", "HECATE_TEST_SPLUNK_URL", "HECATE_TEST_SPLUNK_TOKEN")
    if not all(os.getenv(name) for name in required):
        pytest.skip(
            "Set HECATE_TEST_LIVE_WORKSPACE, HECATE_TEST_SPLUNK_URL and HECATE_TEST_SPLUNK_TOKEN"
        )
    monkeypatch.setenv("SPLUNK_HOST", os.environ["HECATE_TEST_SPLUNK_URL"])
    monkeypatch.setenv("SPLUNK_TOKEN", os.environ["HECATE_TEST_SPLUNK_TOKEN"])


def test_live_splunk_clean_query() -> None:
    live_ws = Path(os.environ["HECATE_TEST_LIVE_WORKSPACE"])
    settings = Settings(_env_file=None, hecate_workspace=live_ws)
    provider = get_provider(
        "splunk",
        hecate_bin=settings.hecate_bin_resolved,
        workspace=live_ws,
    )
    gate = SafeExecutionGate(provider)

    proposed = ProposedQuery(
        hunt_id="H-0021",
        data_source="splunk",
        query_text='ParentImage="*/node" ParentCommandLine="*node-red*" Image="*/sh"',
        time_range_days=1,
        limit=50,
    )
    result = gate.execute_safely(proposed)
    assert result.outcome == "clean"
    assert result.matched_count == 0


def test_live_splunk_hits_detected_query() -> None:
    live_ws = Path(os.environ["HECATE_TEST_LIVE_WORKSPACE"])
    settings = Settings(_env_file=None, hecate_workspace=live_ws)
    provider = get_provider(
        "splunk",
        hecate_bin=settings.hecate_bin_resolved,
        workspace=live_ws,
    )
    gate = SafeExecutionGate(provider)

    proposed = ProposedQuery(
        hunt_id="H-0021",
        data_source="splunk",
        query_text="index=_internal sourcetype=splunkd | head 3",
        time_range_days=1,
        limit=5,
    )
    result = gate.execute_safely(proposed)
    assert result.outcome == "hits_detected"
    assert result.matched_count == 3
    assert len(result.events) == 3


def test_live_splunk_overmatch_protection() -> None:
    live_ws = Path(os.environ["HECATE_TEST_LIVE_WORKSPACE"])
    settings = Settings(_env_file=None, hecate_workspace=live_ws)
    provider = get_provider(
        "splunk",
        hecate_bin=settings.hecate_bin_resolved,
        workspace=live_ws,
    )
    gate = SafeExecutionGate(provider, max_auto_fetch=2)

    proposed = ProposedQuery(
        hunt_id="H-0021",
        data_source="splunk",
        query_text="index=_internal sourcetype=splunkd | head 3",
        time_range_days=1,
        limit=5,
    )
    result = gate.execute_safely(proposed)
    assert result.outcome == "overmatch"
    assert result.matched_count == 3
    assert len(result.events) == 0
