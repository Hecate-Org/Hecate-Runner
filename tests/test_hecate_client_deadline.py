"""Stage deadlines must fail closed when Hecate API calls hang."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from hecate_runner.hecate_client import HecateClient


def test_with_deadline_returns_result_before_timeout(tmp_path: Path) -> None:
    client = HecateClient(Path("hecate"), tmp_path, default_timeout_sec=5)

    def quick() -> str:
        return "ok"

    assert client._with_deadline(1, quick, stage="test") == "ok"


def test_with_deadline_raises_timeout_error(tmp_path: Path) -> None:
    client = HecateClient(Path("hecate"), tmp_path, default_timeout_sec=5)

    def hang() -> str:
        time.sleep(2.0)
        return "late"

    with pytest.raises(TimeoutError, match="test timed out"):
        client._with_deadline(0.2, hang, stage="test")


def test_nonpositive_timeout_disables_enforcement(tmp_path: Path) -> None:
    client = HecateClient(Path("hecate"), tmp_path, default_timeout_sec=0)

    def quick() -> str:
        return "ok"

    assert client._with_deadline(0, quick, stage="test") == "ok"
    assert client._resolve_timeout(None) is None
