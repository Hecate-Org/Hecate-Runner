"""Outbound request records for the monitor, and per-service enrichment trail lines."""

import json
import logging

import pytest

from hecate_runner.api_calls import install_api_call_recorder
from hecate_runner.orchestrator_derivations import enrichment_trail_lines


@pytest.fixture(autouse=True)
def _restore_httpx_logger():
    logger = logging.getLogger("httpx")
    saved = (list(logger.handlers), logger.level, logger.propagate)
    yield
    logger.handlers[:], logger.level, logger.propagate = saved


def _log_request(url: str, status: int) -> None:
    logging.getLogger("httpx").info(
        'HTTP Request: %s %s "%s %d %s"', "GET", url, "HTTP/1.1", status, "OK"
    )


def test_requests_are_recorded_without_path_or_query(tmp_path) -> None:
    path = tmp_path / "logs" / "api_calls.jsonl"
    install_api_call_recorder(path)
    _log_request("https://api.shodan.io/shodan/host/1.2.3.4?key=do-not-log-this", 200)
    _log_request("https://localhost:8443/attributes/restSearch", 429)
    logging.getLogger("httpx").info("unrelated line")
    text = path.read_text()
    assert "do-not-log-this" not in text and "/shodan/host" not in text
    calls = [json.loads(line) for line in text.splitlines()]
    assert [(c["host"], c["status"]) for c in calls] == [
        ("api.shodan.io", 200),
        ("localhost:8443", 429),
    ]


def test_reinstalling_replaces_the_previous_recorder(tmp_path) -> None:
    first, second = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    install_api_call_recorder(first)
    install_api_call_recorder(second)
    _log_request("https://www.virustotal.com/api/v3/files/x", 200)
    assert not first.exists()
    assert len(second.read_text().splitlines()) == 1


def test_enrichment_trail_lines_report_each_service_that_looked_up() -> None:
    stats = {
        "VirusTotal": {
            "checked": 4,
            "found": 2,
            "flagged": 1,
            "missing": 2,
            "errors": 0,
            "unconfigured": 0,
            "skipped": 0,
        },
        "Spur": {
            "checked": 2,
            "found": 0,
            "flagged": 0,
            "missing": 0,
            "errors": 0,
            "unconfigured": 2,
            "skipped": 0,
        },
        "Shodan": {
            "checked": 2,
            "found": 0,
            "flagged": 0,
            "missing": 0,
            "errors": 1,
            "unconfigured": 0,
            "skipped": 1,
        },
        "Tor/Proxy": {
            "checked": 2,
            "found": 0,
            "flagged": 0,
            "missing": 0,
            "errors": 0,
            "unconfigured": 0,
            "skipped": 2,
        },
    }
    assert enrichment_trail_lines(stats) == [
        ("Shodan", "1 checked · 1 error(s)"),
        ("Spur", "not configured"),
        ("VirusTotal", "4 checked · 2 found (1 flagged) · 2 not found"),
    ]


def test_a_trail_step_is_recorded_as_an_event(monkeypatch, tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    monkeypatch.setenv("HECATE_EVENTS_LOG", str(path))
    from hecate_runner.trail import CycleTrail

    CycleTrail().step(
        "enrichment",
        "%s: %s",
        "VirusTotal",
        "1 checked",
        data={"kind": "enrichment", "service": "VirusTotal", "summary": "1 checked"},
    )
    row = json.loads(path.read_text())
    assert row["type"] == "stage"
    assert row["message"] == "VirusTotal: 1 checked"
    assert row["data"]["service"] == "VirusTotal"
    assert row["cycle_id"]
