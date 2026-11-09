"""Autonomous Hunt Execution Engine for Hecate."""

from __future__ import annotations

from hecate_runner.execution.safe_gate import (
    SafeExecutionGate,
    SafeExecutionResult,
    build_count_query,
    extract_count_from_result,
)
from hecate_runner.execution.scheduler import HuntExecutionScheduler
from hecate_runner.execution.watermark_store import (
    HuntExecutionWatermark,
    StagedSweep,
    WatermarkStore,
)

__all__ = [
    "HuntExecutionScheduler",
    "HuntExecutionWatermark",
    "SafeExecutionGate",
    "SafeExecutionResult",
    "StagedSweep",
    "WatermarkStore",
    "build_count_query",
    "extract_count_from_result",
]
