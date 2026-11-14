"""ATT&CK covered-technique mtime cache."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from hecate_runner.cti.attack_deltas import AttackDeltaProvider


def test_covered_techniques_cache_by_hunt_mtime(tmp_path: Path) -> None:
    hunts = tmp_path / "hunts"
    hunts.mkdir()
    hunt = hunts / "H-0001.md"
    hunt.write_text("---\nstatus: active\ntechniques: [T1059.001]\n---\n", encoding="utf-8")

    provider = AttackDeltaProvider(tmp_path, client=MagicMock(), interval_seconds=999)
    first = provider.covered()
    assert first == {"T1059.001"}
    assert provider._covered_cache is not None

    # Unchanged mtimes → same frozenset identity from cache.
    second = provider.covered()
    assert second == first
    assert provider._covered_cache[1] is provider._covered_cache[1]

    hunt.write_text("---\nstatus: active\ntechniques: [T1059.001, T1003]\n---\n", encoding="utf-8")
    third = provider.covered()
    assert third == {"T1059.001", "T1003"}
