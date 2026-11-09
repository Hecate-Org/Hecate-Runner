"""Draft-time lab hit probe."""

from __future__ import annotations

from pathlib import Path

from hecate_runner.lab_hits import (
    format_lab_probe_slack,
    probe_lab_hits,
)
from hecate_runner.query_execution import MockQueryProvider


def test_probe_skips_mock_provider_by_default(tmp_path: Path) -> None:
    query_dir = tmp_path / "queries"
    query_dir.mkdir()
    (query_dir / "rule.kql").write_text("DeviceProcessEvents | where FileName =~ 'a.exe'\n")

    report = probe_lab_hits("H-0001", query_dir, provider_name="mock")

    assert report.status == "skipped"
    assert "mock" in report.detail.lower()
    assert report.results == []


def test_probe_miss_on_configured_mock(tmp_path: Path) -> None:
    query_dir = tmp_path / "queries"
    query_dir.mkdir()
    (query_dir / "rule.spl").write_text("index=main sourcetype=WinEventLog | search EventCode=1\n")

    report = probe_lab_hits(
        "H-0001",
        query_dir,
        provider=MockQueryProvider(responses=[0]),
        window_days=1,
    )

    assert report.status == "miss"
    assert report.total_hits == 0
    assert report.queries_run == 1
    assert report.results[0].outcome == "miss"
    assert report.results[0].hits == 0
    assert report.window_days == 1


def test_probe_hit_counts(tmp_path: Path) -> None:
    query_dir = tmp_path / "queries"
    query_dir.mkdir()
    (query_dir / "a.spl").write_text("index=main | search foo\n")
    (query_dir / "b.spl").write_text("index=main | search bar\n")

    # COUNT-FIRST: one response per query (no raw fetch when count is used).
    report = probe_lab_hits(
        "H-0002",
        query_dir,
        provider=MockQueryProvider(responses=[3, 0]),
        window_days=2,
    )

    assert report.status == "hit"
    assert report.total_hits == 3
    assert report.queries_run == 2
    outcomes = {r.query_file: r.outcome for r in report.results}
    assert outcomes["a.spl"] == "hit"
    assert outcomes["b.spl"] == "miss"


def test_probe_overmatch(tmp_path: Path) -> None:
    query_dir = tmp_path / "queries"
    query_dir.mkdir()
    (query_dir / "broad.spl").write_text("index=main\n")

    report = probe_lab_hits(
        "H-0003",
        query_dir,
        provider=MockQueryProvider(responses=[500]),
        window_days=1,
        max_auto_fetch=200,
    )

    assert report.status == "overmatch"
    assert report.total_hits == 500
    assert report.results[0].outcome == "overmatch"


def test_probe_no_query_files(tmp_path: Path) -> None:
    query_dir = tmp_path / "queries"
    query_dir.mkdir()
    (query_dir / "rule.yml").write_text("title: only sigma\n")

    report = probe_lab_hits(
        "H-0004",
        query_dir,
        provider=MockQueryProvider(responses=[1]),
    )

    assert report.status == "skipped"
    assert "no native query" in report.detail.lower()


def test_format_lab_probe_slack_miss() -> None:
    text = format_lab_probe_slack(
        {
            "status": "miss",
            "provider": "sentinel",
            "window_days": 1,
            "total_hits": 0,
        }
    )
    assert "miss" in text
    assert "`sentinel`" in text
    assert "1d" in text


def test_format_lab_probe_slack_skips_mock_quietly_when_empty_status() -> None:
    assert format_lab_probe_slack(None) == ""
    assert format_lab_probe_slack({"status": ""}) == ""
