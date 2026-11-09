"""Append-only per-cycle and per-stage runtime metrics."""

from __future__ import annotations

import json
import logging
import os
import time
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

log = logging.getLogger(__name__)


def _optional_int(value: Any) -> int | None:
    return int(value) if value is not None else None


def _optional_float(value: Any) -> float | None:
    return float(value) if value is not None else None


@dataclass
class LLMUsage:
    """Provider usage reported by Core for one pipeline stage."""

    llm_calls: int | None = None
    max_input_tokens: int | None = None
    input_token_samples: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    llm_duration_ms: int | None = None
    estimated_cost_usd: float | None = None
    models: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # A sum over only some requests cannot represent the stage's full input.
        # Older Core versions lack sample counts; preserve their nonzero totals.
        if self.llm_calls and (
            self.input_tokens == 0
            or (self.input_token_samples is not None and self.input_token_samples < self.llm_calls)
        ):
            self.input_tokens = None
            if self.output_tokens == 0:
                self.output_tokens = None

    @classmethod
    def from_metadata(cls, metadata: Mapping[str, Any]) -> LLMUsage:
        """Parse Core's additive usage fields, tolerating older Core versions."""
        models = metadata.get("models", metadata.get("llm_models", [])) or []
        if isinstance(models, str):
            models = [models]
        return cls(
            llm_calls=_optional_int(metadata.get("llm_calls")),
            max_input_tokens=_optional_int(metadata.get("max_input_tokens")),
            input_token_samples=_optional_int(metadata.get("input_token_samples")),
            input_tokens=_optional_int(metadata.get("input_tokens")),
            output_tokens=_optional_int(metadata.get("output_tokens")),
            llm_duration_ms=_optional_int(metadata.get("llm_duration_ms")),
            estimated_cost_usd=_optional_float(
                metadata.get("estimated_cost_usd", metadata.get("total_cost_usd"))
            ),
            models=[str(model) for model in models],
        )


@dataclass
class StageMetric:
    stage: str
    duration_ms: int
    status: str = "ok"
    llm_calls: int | None = None
    max_input_tokens: int | None = None
    input_token_samples: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    llm_duration_ms: int | None = None
    estimated_cost_usd: float | None = None
    models: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def apply_usage(self, usage: LLMUsage | None) -> None:
        if usage is None:
            return
        self.llm_calls = usage.llm_calls
        self.max_input_tokens = usage.max_input_tokens
        self.input_token_samples = usage.input_token_samples
        self.input_tokens = usage.input_tokens
        self.output_tokens = usage.output_tokens
        self.llm_duration_ms = usage.llm_duration_ms
        self.estimated_cost_usd = usage.estimated_cost_usd
        self.models = usage.models


class StageMeasurement:
    """Context manager that records wall latency even when a stage fails."""

    def __init__(self, owner: CycleMetrics, stage: str):
        self.owner = owner
        self.stage = stage
        self.started = time.monotonic()
        self.status = "ok"
        self.usage: LLMUsage | None = None
        self.details: dict[str, Any] = {}

    def __enter__(self) -> StageMeasurement:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> Literal[False]:
        if exc is not None:
            self.status = "error"
            if self.usage is None:
                self.usage = getattr(exc, "usage", None)
        usage_kwargs = (
            asdict(self.usage) if (self.usage is not None and is_dataclass(self.usage)) else {}
        )
        self.owner._record(
            StageMetric(
                stage=self.stage,
                duration_ms=max(0, round((time.monotonic() - self.started) * 1000)),
                status=self.status,
                details=self.details,
                **usage_kwargs,
            )
        )
        if self.usage is not None and is_dataclass(self.usage):
            usage = self.usage
            log.info(
                "LLM stage usage: stage=%s calls=%s reported_input_tokens=%s reported_output_tokens=%s "
                "max_reported_prompt_tokens=%s input_token_samples=%s models=%s",
                self.stage,
                usage.llm_calls,
                usage.input_tokens if usage.input_tokens is not None else "unavailable",
                usage.output_tokens if usage.output_tokens is not None else "unavailable",
                usage.max_input_tokens if usage.max_input_tokens is not None else "unavailable",
                usage.input_token_samples
                if usage.input_token_samples is not None
                else "unavailable",
                ",".join(usage.models) or "unavailable",
            )
        return False

    def set_usage(self, usage: LLMUsage | None) -> None:
        self.usage = usage

    def set_status(self, status: str) -> None:
        self.status = status


class CycleMetrics:
    """Metrics accumulated for one Runner cycle."""

    def __init__(self, cycle_id: str):
        self.cycle_id = cycle_id
        self.started_at = datetime.now(UTC)
        self._started = time.monotonic()
        self.source = "unknown"
        self.source_id = ""
        self._stages: list[StageMetric] = []
        self.sigma_rules_produced = 0

    def measure(self, stage: str) -> StageMeasurement:
        return StageMeasurement(self, stage)

    def set_source(self, source: str, source_id: str = "") -> None:
        self.source = source or "unknown"
        self.source_id = source_id or ""

    def _record(self, metric: StageMetric) -> None:
        self._stages.append(metric)

    def to_record(
        self,
        *,
        outcome: str,
        hunt_id: str | None = None,
        research_id: str | None = None,
    ) -> dict[str, Any]:
        duration_ms = max(0, round((time.monotonic() - self._started) * 1000))
        stages = [asdict(metric) for metric in self._stages]
        stages.append(asdict(StageMetric(stage="cycle", duration_ms=duration_ms)))
        return {
            "schema_version": 2,
            "sigma_rules_produced": self.sigma_rules_produced,
            "cycle_id": self.cycle_id,
            "started_at": self.started_at.isoformat(),
            "source": self.source,
            "source_id": self.source_id,
            "outcome": outcome,
            "hunt_id": hunt_id,
            "research_id": research_id,
            "duration_ms": duration_ms,
            "stages": stages,
        }


class MetricsStore:
    """Stores compact JSONL cycle records and aggregates them on demand."""

    def __init__(self, path: Path):
        self.path = path

    def append(self, record: Mapping[str, Any]) -> None:
        """Append one JSON object with a single O_APPEND write."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = (json.dumps(record, separators=(",", ":"), allow_nan=False) + "\n").encode()
        fd = os.open(self.path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            offset = 0
            while offset < len(payload):
                offset += os.write(fd, payload[offset:])
        finally:
            os.close(fd)

    def aggregate(
        self, *, days: int = 30, source: str | None = None, since: datetime | None = None
    ) -> list[dict[str, Any]]:
        """Summarize average stage latency and total LLM usage per source."""
        if not self.path.exists():
            return []

        cutoff = since or datetime.now(UTC) - timedelta(days=days)
        totals: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {
                "cycles": 0,
                "duration_ms": 0,
                "usage_samples": 0,
                "known_fields": set(),
                "missing_fields": set(),
                "max_input_tokens": None,
                "input_token_samples": None,
                "llm_calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "llm_duration_ms": 0,
                "estimated_cost_usd": 0.0,
                "cost_samples": 0,
                "unpriced_samples": 0,
                "models": set(),
                "errors": 0,
            }
        )

        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            log.warning("Could not read stage metrics %s (%s)", self.path, exc)
            return []

        for line in lines:
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise TypeError("metrics record must be an object")
                timestamp = datetime.fromisoformat(record["started_at"])
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
                if timestamp < cutoff:
                    continue
                record_source = str(record.get("source") or "unknown")
                if source and record_source.lower() != source.lower():
                    continue

                # Coalesce repeated measurements of a stage within one cycle
                # (grounding can run before and after Sigma) so `cycles` and
                # average latency remain per-cycle statistics.
                cycle_stages: dict[str, dict[str, Any]] = {}
                stages = record.get("stages", [])
                if not isinstance(stages, list):
                    raise TypeError("metrics stages must be a list")
                for item in stages:
                    if not isinstance(item, dict):
                        raise TypeError("metrics stage must be an object")
                    name = str(item.get("stage") or "unknown")
                    combined = cycle_stages.setdefault(
                        name,
                        {
                            "duration_ms": 0,
                            "usage_known": False,
                            "known_fields": set(),
                            "missing_fields": set(),
                            "max_input_tokens": None,
                            "input_token_samples": None,
                            "llm_calls": 0,
                            "input_tokens": 0,
                            "output_tokens": 0,
                            "llm_duration_ms": 0,
                            "estimated_cost_usd": 0.0,
                            "cost_known": False,
                            "unpriced": False,
                            "models": set(),
                            "errors": 0,
                        },
                    )
                    peak = item.get("max_input_tokens")
                    if peak is not None:
                        combined["max_input_tokens"] = max(
                            combined["max_input_tokens"] or 0, int(peak)
                        )
                    samples = item.get("input_token_samples")
                    if samples is not None:
                        combined["input_token_samples"] = (
                            combined["input_token_samples"] or 0
                        ) + int(samples)
                    combined["duration_ms"] += int(item.get("duration_ms") or 0)
                    for field_name in (
                        "llm_calls",
                        "input_tokens",
                        "output_tokens",
                        "llm_duration_ms",
                    ):
                        value = item.get(field_name)
                        if value is not None:
                            combined[field_name] += int(value)
                            combined["usage_known"] = True
                            combined["known_fields"].add(field_name)
                        elif any(
                            item.get(name) is not None
                            for name in (
                                "llm_calls",
                                "input_tokens",
                                "output_tokens",
                                "llm_duration_ms",
                            )
                        ) or name in {"research", "hypothesis_generation", "sigma_generation"}:
                            combined["missing_fields"].add(field_name)
                    cost = item.get("estimated_cost_usd")
                    if cost is not None:
                        combined["estimated_cost_usd"] += float(cost)
                        combined["cost_known"] = True
                    if cost is None and (
                        item.get("llm_calls")
                        or item.get("input_tokens")
                        or item.get("output_tokens")
                        or item.get("models")
                        or (
                            item.get("llm_calls") is None
                            and name in {"research", "hypothesis_generation", "sigma_generation"}
                        )
                    ):
                        combined["unpriced"] = True
                    combined["models"].update(item.get("models") or [])
                    combined["errors"] += int(item.get("status") in {"error", "partial"})

                for stage_name, stage in cycle_stages.items():
                    aggregate = totals[(stage_name, record_source)]
                    if stage["max_input_tokens"] is not None:
                        aggregate["max_input_tokens"] = max(
                            aggregate["max_input_tokens"] or 0, stage["max_input_tokens"]
                        )
                    if stage["input_token_samples"] is not None:
                        aggregate["input_token_samples"] = (
                            aggregate["input_token_samples"] or 0
                        ) + stage["input_token_samples"]
                    aggregate["cycles"] += 1
                    aggregate["duration_ms"] += stage["duration_ms"]
                    aggregate["usage_samples"] += int(stage["usage_known"])
                    aggregate["known_fields"].update(stage["known_fields"])
                    aggregate["missing_fields"].update(stage["missing_fields"])
                    for field_name in (
                        "llm_calls",
                        "input_tokens",
                        "output_tokens",
                        "llm_duration_ms",
                    ):
                        aggregate[field_name] += stage[field_name]
                    if stage["cost_known"]:
                        aggregate["estimated_cost_usd"] += stage["estimated_cost_usd"]
                        aggregate["cost_samples"] += 1
                    if stage["unpriced"]:
                        aggregate["unpriced_samples"] += 1
                    aggregate["models"].update(stage["models"])
                    aggregate["errors"] += stage["errors"]
            except (KeyError, TypeError, ValueError, AttributeError):
                log.warning("Skipping malformed stage metrics line in %s", self.path)

        rows = []
        for (stage_name, record_source), values in totals.items():
            count = values["cycles"]
            rows.append(
                {
                    "max_input_tokens": values["max_input_tokens"],
                    "input_token_samples": values["input_token_samples"],
                    "stage": stage_name,
                    "source": record_source,
                    "cycles": count,
                    "avg_duration_ms": round(values["duration_ms"] / count),
                    "total_duration_ms": values["duration_ms"],
                    "llm_calls": values["llm_calls"]
                    if "llm_calls" in values["known_fields"]
                    and "llm_calls" not in values["missing_fields"]
                    else None,
                    "input_tokens": values["input_tokens"]
                    if "input_tokens" in values["known_fields"]
                    and "input_tokens" not in values["missing_fields"]
                    else None,
                    "output_tokens": values["output_tokens"]
                    if "output_tokens" in values["known_fields"]
                    and "output_tokens" not in values["missing_fields"]
                    else None,
                    "llm_duration_ms": values["llm_duration_ms"]
                    if "llm_duration_ms" in values["known_fields"]
                    and "llm_duration_ms" not in values["missing_fields"]
                    else None,
                    "estimated_cost_usd": (
                        round(values["estimated_cost_usd"], 6) if values["cost_samples"] else None
                    ),
                    "cost_samples": values["cost_samples"],
                    "unpriced_samples": values["unpriced_samples"],
                    "models": sorted(values["models"]),
                    "errors": values["errors"],
                }
            )
        return sorted(rows, key=lambda row: (row["source"], row["stage"]))

    def summary(self, *, days: int = 7) -> dict[str, Any]:
        """Summarize recorded drafts and usage; preserve unavailable measurements."""
        if days < 1:
            raise ValueError("days must be positive")
        now = datetime.now(UTC)
        cutoff = now - timedelta(days=days)
        records = []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            lines = []
        except OSError as exc:
            log.warning("Could not read cycle metrics %s (%s)", self.path, exc)
            lines = []
        for line in lines:
            try:
                record = json.loads(line)
                timestamp = datetime.fromisoformat(record["started_at"])
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
                if cutoff <= timestamp <= now:
                    records.append(record)
            except (KeyError, TypeError, ValueError):
                log.warning("Skipping malformed cycle metrics line in %s", self.path)

        aggregates = self.aggregate(days=days)
        drafts = [r for r in records if r.get("outcome") == "draft_created" and r.get("hunt_id")]
        rule_counts = [r.get("sigma_rules_produced") for r in drafts]

        def cost(rows: list[dict[str, Any]]) -> float | None:
            if any(row["unpriced_samples"] for row in rows):
                return None
            return round(sum(row["estimated_cost_usd"] or 0.0 for row in rows), 6)

        stages: dict[str, dict[str, Any]] = {}
        for a in aggregates:
            st = a["stage"]
            if st == "cycle":
                continue
            entry = stages.setdefault(
                st, {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
            )
            for name, usage_field in (
                ("calls", "llm_calls"),
                ("input_tokens", "input_tokens"),
                ("output_tokens", "output_tokens"),
            ):
                entry[name] += a[usage_field] or 0
            if a["unpriced_samples"] or entry["cost_usd"] is None:
                entry["cost_usd"] = None
            else:
                entry["cost_usd"] += a["estimated_cost_usd"] or 0.0

        def usage_total(rows: list[dict[str, Any]], field: str) -> int | None:
            measured = [
                row
                for row in rows
                if row["llm_calls"] is not None
                or row["models"]
                or row["stage"] in {"research", "hypothesis_generation", "sigma_generation"}
            ]
            if any(row[field] is None and row["llm_calls"] != 0 for row in measured):
                return None
            return sum(row[field] or 0 for row in measured)

        for stage_name, entry in stages.items():
            rows = [row for row in aggregates if row["stage"] == stage_name]
            for destination, usage_field in (
                ("calls", "llm_calls"),
                ("input_tokens", "input_tokens"),
                ("output_tokens", "output_tokens"),
            ):
                entry[destination] = usage_total(rows, usage_field)

        return {
            "window_days": days,
            "completed_cycles": len(records),
            "hunts_completed": len({r["hunt_id"] for r in drafts}),
            "sigma_rules_produced": sum(rule_counts)
            if all(isinstance(n, int) and n >= 0 for n in rule_counts)
            else None,
            "total_cost_usd": cost(aggregates),
            "spend_today_usd": cost(
                self.aggregate(since=now.replace(hour=0, minute=0, second=0, microsecond=0))
            ),
            "purple_team_pass_pct": None,
            "total_llm_calls": usage_total(aggregates, "llm_calls"),
            "total_input_tokens": usage_total(aggregates, "input_tokens"),
            "total_output_tokens": usage_total(aggregates, "output_tokens"),
            "active_sources": sorted(
                {str(r["source"]) for r in records if r.get("source") and r["source"] != "unknown"}
            ),
            "stages": stages,
        }


def format_usd(value: float | None, precision: int = 2) -> str:
    """Render unpriced usage explicitly instead of implying zero spend."""
    return "Unavailable" if value is None else f"${value:.{precision}f}"


def format_count(value: int | None) -> str:
    return "Unavailable" if value is None else f"{value:,}"
