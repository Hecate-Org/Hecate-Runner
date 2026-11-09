"""Indexed intake retains literal source/CVE matching and live-file freshness."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hecate_runner.cti.base import CTIItem
from hecate_runner.orchestrator import Orchestrator

URL = "https://report.example/article"


@pytest.fixture
def intake(settings, mock_hecate):
    return Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=MagicMock())


def write_hunt(intake, name, text):
    root = intake.settings.hunts_root
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.md"
    path.write_text(text)
    return path


def item(url=URL, cve=None):
    return CTIItem(
        source="otx",
        content="Narrative report",
        source_url=url,
        metadata={"indicators": {"cve": [cve]}} if cve else {},
    )


def test_repeated_source_lookups_do_not_reread_hunts(intake, monkeypatch):
    write_hunt(intake, "H-0001", f"[Report]({URL})")
    write_hunt(intake, "H-0002", "Unrelated hunt")
    assert intake._drafted_from_same_source(item()) == "H-0001"
    read = MagicMock(side_effect=AssertionError("Unexpected body read"))
    monkeypatch.setattr(Path, "read_text", read)
    for _ in range(3):
        assert intake._drafted_from_same_source(item()) == "H-0001"
        assert intake._drafted_from_same_source(item(url="https://other.example/report")) is None
    read.assert_not_called()


def test_cve_recency_uses_updated_mtime_even_when_content_is_unchanged(intake):
    path = write_hunt(intake, "H-0001", "CVE-2026-12345")
    old = time.time() - 4 * 86400
    os.utime(path, (old, old))
    assert intake._drafted_from_same_source(item(url="", cve="CVE-2026-12345")) is None
    path.touch()
    assert "H-0001 covering CVE-2026-12345" in intake._drafted_from_same_source(
        item(url="", cve="CVE-2026-12345")
    )


def test_path_order_and_source_priority_within_one_file_are_preserved(intake):
    write_hunt(intake, "H-0001", f"[Report]({URL})")
    path = write_hunt(intake, "H-0002", "CVE-2026-12345")
    assert intake._drafted_from_same_source(item(cve="CVE-2026-1234")).startswith("H-0002 covering")
    path.write_text(path.read_text() + f"\n[Report]({URL})")
    assert intake._drafted_from_same_source(item(cve="CVE-2026-1234")) == "H-0002"


def test_manual_edit_rename_and_delete_do_not_leave_phantom_duplicates(intake):
    path = write_hunt(intake, "H-0001", f"[Report]({URL})")
    assert intake._drafted_from_same_source(item()) == "H-0001"
    path.write_text("No source references remain")
    assert intake._drafted_from_same_source(item()) is None
    path.write_text(f"[Report]({URL})")
    path = path.rename(path.with_name("H-0003.md"))
    assert intake._drafted_from_same_source(item()) == "H-0003"
    path.unlink()
    assert intake._drafted_from_same_source(item()) is None


def test_markdown_url_parentheses_and_literal_cve_fallback(intake):
    url = URL + "/report(revised)"
    write_hunt(intake, "H-0001", f"[Report]({url})\nCUSTOM-CVE-LABEL\n")
    assert intake._drafted_from_same_source(item(url=url)) == "H-0001"
    assert "H-0001 covering CUSTOM-CVE-LABEL" in intake._drafted_from_same_source(
        item(url="", cve="CUSTOM-CVE-LABEL")
    )


def test_older_core_retains_duplicate_protection(intake, monkeypatch):
    write_hunt(intake, "H-0001", f"[Report]({URL})")
    monkeypatch.setitem(sys.modules, "hecate_agent.core.hunt_catalog", None)
    assert intake._drafted_from_same_source(item()) == "H-0001"
