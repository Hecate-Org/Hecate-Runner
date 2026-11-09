"""Tests for live Splunk integration with SafeExecutionGate and COUNT-FIRST safety."""

from __future__ import annotations

import ssl
import urllib.request
from pathlib import Path

import pytest

from hecate_runner.config import Settings
from hecate_runner.execution.safe_gate import SafeExecutionGate
from hecate_runner.query_execution import ProposedQuery, get_provider


def _is_live_splunk_running() -> bool:
    try:
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request("https://localhost:8089/services/server/info")
        with urllib.request.urlopen(req, context=ctx, timeout=2.0) as resp:
            return resp.status in (200, 401)
    except urllib.error.HTTPError as exc:
        return exc.code in (200, 401)
    except Exception:
        return False


@pytest.mark.skipif(
    not _is_live_splunk_running(),
    reason="Live Splunk instance not running on localhost:8089",
)
def test_live_splunk_clean_query() -> None:
    live_ws = Path("/home/chemch/betas/Hecate-Public")
    settings = Settings(hecate_workspace=live_ws)
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


@pytest.mark.skipif(
    not _is_live_splunk_running(),
    reason="Live Splunk instance not running on localhost:8089",
)
def test_live_splunk_hits_detected_query() -> None:
    live_ws = Path("/home/chemch/betas/Hecate-Public")
    settings = Settings(hecate_workspace=live_ws)
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


@pytest.mark.skipif(
    not _is_live_splunk_running(),
    reason="Live Splunk instance not running on localhost:8089",
)
def test_live_splunk_overmatch_protection() -> None:
    live_ws = Path("/home/chemch/betas/Hecate-Public")
    settings = Settings(hecate_workspace=live_ws)
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
