"""Deterministic Safe Execution Gate implementing the COUNT-FIRST paradigm.

Protects production SIEM clusters and downstream LLM contexts by executing
a lightweight aggregate COUNT query before retrieving raw telemetry. If the
event count exceeds the safe auto-fetch ceiling, raw retrieval is halted
and the query is flagged for rule tuning.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from hecate_runner.query_execution import (
    ProposedQuery,
    QueryProvider,
    QueryResult,
    validate_guardrails,
)

log = logging.getLogger(__name__)


def build_count_query(query_text: str, dialect_or_provider: str) -> str:
    """Transform a hunt detection query into a lightweight COUNT-FIRST query.

    Args:
        query_text: Raw hunting detection query.
        dialect_or_provider: SIEM backend or query language dialect.

    Returns:
        COUNT query string.
    """
    target = dialect_or_provider.strip().lower()
    text = query_text.strip().rstrip(";")

    if target in ("splunk", "spl"):
        if "stats count" in text.lower():
            return text
        return f"{text} | stats count"

    if target in ("sentinel", "sentinel_kql", "kql"):
        if "summarize count()" in text.lower():
            return text
        return (
            f"let __hecate_bounded_query = () {{\n{text}\n}};\n"
            f"__hecate_bounded_query()\n| summarize count()"
        )

    if target in ("crowdstrike", "crowdstrike_cql", "cql", "logscale"):
        if "| count(" in text.lower() or text.endswith("| count"):
            return text
        return f"{text} | count()"

    if target in ("elastic", "elastic_eql", "eql"):
        return text

    # Mock / generic fallback
    if "count" not in text.lower():
        return f"{text} | count"
    return text


def extract_count_from_result(result: QueryResult) -> int:
    """Extract integer count of matching telemetry events from a QueryResult.

    Inspects structured events, parsed JSON response details, or row counts.
    """
    if not result.ok:
        return 0

    # 1. Check if the result contains a single aggregate count event
    if result.events and len(result.events) == 1:
        first = result.events[0]
        if isinstance(first, dict):
            for key in ("count", "count_", "total", "events"):
                if key in first:
                    try:
                        return int(first[key])
                    except (ValueError, TypeError):
                        pass

    # 2. Inspect detail JSON string (e.g. Sentinel tabular rows [[55]] or Splunk stats count)
    if result.detail:
        try:
            parsed = json.loads(result.detail)
            if isinstance(parsed, dict):
                rows = parsed.get("rows")
                if isinstance(rows, list) and len(rows) > 0:
                    first_row = rows[0]
                    if isinstance(first_row, list) and len(first_row) > 0:
                        try:
                            return int(first_row[0])
                        except (ValueError, TypeError):
                            pass
                    elif isinstance(first_row, dict):
                        for k in ("count", "count_", "total"):
                            if k in first_row:
                                try:
                                    return int(first_row[k])
                                except (ValueError, TypeError):
                                    pass
                if "row_count" in parsed:
                    return int(parsed["row_count"])
        except (json.JSONDecodeError, ValueError, TypeError):
            match = re.search(r'["\']?count[_]?["\']?\s*[:=]\s*(\d+)', result.detail, re.IGNORECASE)
            if match:
                return int(match.group(1))

    # 3. Direct row count from provider
    return result.row_count


@dataclass
class SafeExecutionResult:
    """Outcome of safely executing a query through the SafeExecutionGate."""

    hunt_id: str
    target: str
    outcome: str  # "clean" | "hits_detected" | "overmatch" | "error"
    matched_count: int = 0
    detail: str = ""
    executed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    count_query: str = ""
    raw_query: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    triage_report: Any | None = None
    pivot_results: list[Any] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True if the query executed safely without system error (clean or hits)."""
        return self.outcome in ("clean", "hits_detected")


class SafeExecutionGate:
    """Enforces COUNT-FIRST execution and safe volume thresholds on live queries."""

    def __init__(
        self,
        provider: QueryProvider,
        *,
        max_auto_fetch: int = 200,
        max_time_range_days: int = 7,
        max_limit: int = 1000,
    ):
        self.provider = provider
        self.max_auto_fetch = max_auto_fetch
        self.max_time_range_days = max_time_range_days
        self.max_limit = max_limit

    def execute_safely(
        self,
        proposed: ProposedQuery,
        *,
        force_raw: bool = False,
    ) -> SafeExecutionResult:
        """Execute a proposed query using the COUNT-FIRST safety paradigm.

        1. Validates deterministic guardrails (time range, limits).
        2. Executes lightweight COUNT query against target SIEM.
        3. If count == 0: records clean sweep immediately (no raw events pulled).
        4. If count > max_auto_fetch: flags overmatch and halts raw event pull.
        5. If 1 <= count <= max_auto_fetch: safely pulls bounded raw events for triage.
        """
        # Step 1: Guardrail verification
        violations = validate_guardrails(
            proposed,
            max_time_range_days=self.max_time_range_days,
            max_limit=self.max_limit,
        )
        if violations:
            return SafeExecutionResult(
                hunt_id=proposed.hunt_id,
                target=self.provider.name,
                outcome="error",
                matched_count=0,
                detail=f"Guardrail violation(s): {'; '.join(violations)}",
                raw_query=proposed.query_text,
            )

        # Step 2: COUNT-FIRST evaluation (unless force_raw is explicitly requested)
        if not force_raw:
            count_query_text = build_count_query(proposed.query_text, self.provider.name)
            count_proposed = ProposedQuery(
                hunt_id=proposed.hunt_id,
                data_source=proposed.data_source,
                query_text=count_query_text,
                time_range_days=proposed.time_range_days,
                limit=1,
                justification=f"COUNT-FIRST pre-flight sweep for {proposed.hunt_id}",
            )

            log.info(
                "Running COUNT-FIRST query for %s on %s (window: %dd)",
                proposed.hunt_id,
                self.provider.name,
                proposed.time_range_days,
            )
            count_res = self.provider.execute(count_proposed)

            if not count_res.ok:
                return SafeExecutionResult(
                    hunt_id=proposed.hunt_id,
                    target=self.provider.name,
                    outcome="error",
                    matched_count=0,
                    detail=f"COUNT-FIRST pre-flight failed: {count_res.detail}",
                    executed_at=count_res.executed_at,
                    count_query=count_query_text,
                    raw_query=proposed.query_text,
                )

            matched_count = extract_count_from_result(count_res)

            # Scenario A: Clean run
            if matched_count == 0:
                log.info(
                    "Clean sweep for %s on %s (0 events matched)",
                    proposed.hunt_id,
                    self.provider.name,
                )
                return SafeExecutionResult(
                    hunt_id=proposed.hunt_id,
                    target=self.provider.name,
                    outcome="clean",
                    matched_count=0,
                    detail=f"Clean sweep: 0 events matched on {self.provider.name}.",
                    executed_at=count_res.executed_at,
                    count_query=count_query_text,
                    raw_query=proposed.query_text,
                    events=[],
                )

            # Scenario B: Overmatch / Broad query
            if matched_count > self.max_auto_fetch:
                log.warning(
                    "Overmatch for %s on %s: %d events exceeds safe ceiling %d",
                    proposed.hunt_id,
                    self.provider.name,
                    matched_count,
                    self.max_auto_fetch,
                )
                return SafeExecutionResult(
                    hunt_id=proposed.hunt_id,
                    target=self.provider.name,
                    outcome="overmatch",
                    matched_count=matched_count,
                    detail=(
                        f"Overmatch: {matched_count} events matched, exceeding auto-fetch limit "
                        f"({self.max_auto_fetch}). Halting raw telemetry pull; rule tuning recommended."
                    ),
                    executed_at=count_res.executed_at,
                    count_query=count_query_text,
                    raw_query=proposed.query_text,
                    events=[],
                )

            # Scenario C: Hits detected within safe ceiling -> Retrieve raw events
            log.info(
                "Hits detected for %s on %s (%d events). Fetching raw telemetry bounded to %d.",
                proposed.hunt_id,
                self.provider.name,
                matched_count,
                self.max_auto_fetch,
            )
            raw_limit = min(matched_count, self.max_auto_fetch)
            raw_proposed = ProposedQuery(
                hunt_id=proposed.hunt_id,
                data_source=proposed.data_source,
                query_text=proposed.query_text,
                time_range_days=proposed.time_range_days,
                limit=raw_limit,
                justification=f"Automated raw telemetry retrieval for {matched_count} hits",
            )
            raw_res = self.provider.execute(raw_proposed)

            if not raw_res.ok:
                return SafeExecutionResult(
                    hunt_id=proposed.hunt_id,
                    target=self.provider.name,
                    outcome="error",
                    matched_count=matched_count,
                    detail=f"Raw telemetry retrieval failed after count match: {raw_res.detail}",
                    executed_at=raw_res.executed_at,
                    count_query=count_query_text,
                    raw_query=proposed.query_text,
                )

            return SafeExecutionResult(
                hunt_id=proposed.hunt_id,
                target=self.provider.name,
                outcome="hits_detected",
                matched_count=matched_count,
                detail=f"Sweep detected {matched_count} event(s) in {self.provider.name}.",
                executed_at=raw_res.executed_at,
                count_query=count_query_text,
                raw_query=proposed.query_text,
                events=raw_res.events,
            )

        # Force raw path
        raw_res = self.provider.execute(proposed)
        if not raw_res.ok:
            return SafeExecutionResult(
                hunt_id=proposed.hunt_id,
                target=self.provider.name,
                outcome="error",
                matched_count=0,
                detail=raw_res.detail,
                executed_at=raw_res.executed_at,
                raw_query=proposed.query_text,
            )

        outcome = "clean" if raw_res.row_count == 0 else "hits_detected"
        return SafeExecutionResult(
            hunt_id=proposed.hunt_id,
            target=self.provider.name,
            outcome=outcome,
            matched_count=raw_res.row_count,
            detail=raw_res.detail,
            executed_at=raw_res.executed_at,
            raw_query=proposed.query_text,
            events=raw_res.events,
        )
