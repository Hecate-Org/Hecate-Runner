"""Autonomous Hunt Execution Engine for Hecate."""

from __future__ import annotations

from hecate_runner.execution.fusion import (
    EndpointNetworkFusionEngine,
    build_network_connection_query,
    build_process_creation_query,
)
from hecate_runner.execution.normalizer import (
    NormalizedEvent,
    OCSFCategoryUID,
    OCSFClassUID,
    classify_ocsf_event,
    extract_entities_from_events,
    normalize_event,
    normalize_events,
)
from hecate_runner.execution.pivot_engine import (
    PivotExecutionEngine,
    PivotExecutionResult,
    synthesize_pivot_queries,
)
from hecate_runner.execution.safe_gate import (
    SafeExecutionGate,
    SafeExecutionResult,
    build_count_query,
    extract_count_from_result,
)
from hecate_runner.execution.scheduler import HuntExecutionScheduler
from hecate_runner.execution.triage_agent import (
    FindingTriageAgent,
    FindingTriageReport,
)
from hecate_runner.execution.watermark_store import (
    HuntExecutionWatermark,
    StagedSweep,
    WatermarkStore,
)

__all__ = [
    "EndpointNetworkFusionEngine",
    "FindingTriageAgent",
    "FindingTriageReport",
    "HuntExecutionScheduler",
    "HuntExecutionWatermark",
    "NormalizedEvent",
    "OCSFCategoryUID",
    "OCSFClassUID",
    "PivotExecutionEngine",
    "PivotExecutionResult",
    "SafeExecutionGate",
    "SafeExecutionResult",
    "StagedSweep",
    "WatermarkStore",
    "build_count_query",
    "build_network_connection_query",
    "build_process_creation_query",
    "classify_ocsf_event",
    "extract_count_from_result",
    "extract_entities_from_events",
    "normalize_event",
    "normalize_events",
    "synthesize_pivot_queries",
]
