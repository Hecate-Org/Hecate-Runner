"""Draft-time lab query probe: run drafted native queries against the configured SIEM.

Surfaces hit count, time window, and miss/hit/error on the review card next to
publish findings. Skips clearly when the provider is mock or unconfigured.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from hecate_runner.execution.safe_gate import SafeExecutionGate
from hecate_runner.execution.scheduler import DIALECT_EXTENSIONS
from hecate_runner.query_execution import ProposedQuery, QueryProvider, get_provider

log = logging.getLogger(__name__)

# Cap how many drafted query files we probe at draft time.
_DEFAULT_MAX_QUERIES = 8


@dataclass
class LabHitResult:
    """One drafted query file run against the lab."""

    query_file: str
    provider: str
    hits: int
    window_days: int
    outcome: str  # hit | miss | overmatch | error | skipped
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LabProbeReport:
    """Aggregate lab probe for a hunt draft."""

    provider: str
    window_days: int
    status: str  # hit | miss | overmatch | error | skipped | unconfigured
    total_hits: int = 0
    queries_run: int = 0
    detail: str = ""
    results: list[LabHitResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "window_days": self.window_days,
            "status": self.status,
            "total_hits": self.total_hits,
            "queries_run": self.queries_run,
            "detail": self.detail,
            "results": [r.to_dict() for r in self.results],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> LabProbeReport | None:
        if not data or not isinstance(data, dict):
            return None
        results = [
            LabHitResult(
                **{k: v for k, v in item.items() if k in LabHitResult.__dataclass_fields__}
            )
            for item in (data.get("results") or [])
            if isinstance(item, dict)
        ]
        return cls(
            provider=str(data.get("provider") or ""),
            window_days=int(data.get("window_days") or 0),
            status=str(data.get("status") or "skipped"),
            total_hits=int(data.get("total_hits") or 0),
            queries_run=int(data.get("queries_run") or 0),
            detail=str(data.get("detail") or ""),
            results=results,
        )


def _skipped(provider: str, window_days: int, detail: str) -> LabProbeReport:
    return LabProbeReport(
        provider=provider,
        window_days=window_days,
        status="skipped",
        detail=detail,
    )


def _unconfigured(provider: str, window_days: int, errors: list[str]) -> LabProbeReport:
    return LabProbeReport(
        provider=provider,
        window_days=window_days,
        status="unconfigured",
        detail="; ".join(errors) or "lab credentials not configured",
    )


def discover_query_files(query_dir: Path, provider_name: str) -> list[Path]:
    """Native query files for the configured provider dialect."""
    if not query_dir.is_dir():
        return []
    name = provider_name.strip().lower()
    exts = DIALECT_EXTENSIONS.get(name, (".spl", ".kql", ".eql", ".cql"))
    files: list[Path] = []
    for ext in exts:
        files.extend(sorted(query_dir.glob(f"*{ext}")))
    # Deduplicate while preserving order (same stem across dialects only for mock).
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in files:
        if path in seen:
            continue
        seen.add(path)
        unique.append(path)
    return unique


def _map_outcome(gate_outcome: str, matched_count: int) -> str:
    if gate_outcome == "clean":
        return "miss"
    if gate_outcome == "hits_detected":
        return "hit"
    if gate_outcome == "overmatch":
        return "overmatch"
    if gate_outcome == "error":
        return "error"
    return "hit" if matched_count > 0 else "miss"


def _aggregate_status(results: list[LabHitResult]) -> tuple[str, int, str]:
    if not results:
        return "skipped", 0, "no query files executed"
    total = sum(r.hits for r in results)
    errors = [r for r in results if r.outcome == "error"]
    hits = [r for r in results if r.outcome in ("hit", "overmatch")]
    if hits:
        status = "overmatch" if any(r.outcome == "overmatch" for r in hits) else "hit"
        detail = f"{len(results)} quer{'y' if len(results) == 1 else 'ies'}, {total} hit(s)"
        return status, total, detail
    if errors and len(errors) == len(results):
        return "error", 0, errors[0].detail or "all lab queries failed"
    if errors:
        detail = f"{len(results)} quer{'y' if len(results) == 1 else 'ies'}, 0 hits, {len(errors)} error(s)"
        return "miss", 0, detail
    detail = f"{len(results)} quer{'y' if len(results) == 1 else 'ies'}, 0 hits"
    return "miss", 0, detail


def probe_lab_hits(
    hunt_id: str,
    query_dir: Path,
    *,
    provider: QueryProvider | None = None,
    provider_name: str = "mock",
    hecate_bin: Path | None = None,
    workspace: Path | None = None,
    max_time_range_days: int = 7,
    max_limit: int = 1000,
    env_overrides: dict[str, str] | None = None,
    window_days: int = 1,
    max_queries: int = _DEFAULT_MAX_QUERIES,
    max_auto_fetch: int = 200,
    allow_mock: bool = False,
) -> LabProbeReport:
    """Run drafted native queries against the lab SIEM (COUNT-FIRST).

    When ``provider_name`` is ``mock`` and ``allow_mock`` is false, returns a
    skipped report so draft cards never present simulated counts as lab hits.
    Tests pass ``allow_mock=True`` or an explicit ``provider``.
    """
    name = (provider.name if provider is not None else provider_name).strip().lower()
    window = max(1, min(int(window_days), int(max_time_range_days)))

    if name == "mock" and provider is None and not allow_mock:
        return _skipped("mock", window, "query provider is mock (no lab backend)")

    if provider is None:
        try:
            provider = get_provider(
                name,
                hecate_bin=hecate_bin,
                workspace=workspace,
                max_time_range_days=max_time_range_days,
                max_limit=max_limit,
                env_overrides=env_overrides,
            )
        except ValueError as exc:
            return _skipped(name, window, str(exc))

    config_errors = provider.configuration_errors()
    if config_errors:
        return _unconfigured(provider.name, window, config_errors)

    files = discover_query_files(query_dir, provider.name)
    if not files:
        return _skipped(
            provider.name,
            window,
            f"no native query files for {provider.name} in {query_dir.name or query_dir}",
        )

    gate = SafeExecutionGate(
        provider,
        max_auto_fetch=max_auto_fetch,
        max_time_range_days=max_time_range_days,
        max_limit=max_limit,
    )

    results: list[LabHitResult] = []
    for path in files[: max(1, max_queries)]:
        try:
            text = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            results.append(
                LabHitResult(
                    query_file=path.name,
                    provider=provider.name,
                    hits=0,
                    window_days=window,
                    outcome="error",
                    detail=f"could not read query file: {exc}",
                )
            )
            continue
        if not text:
            results.append(
                LabHitResult(
                    query_file=path.name,
                    provider=provider.name,
                    hits=0,
                    window_days=window,
                    outcome="skipped",
                    detail="empty query file",
                )
            )
            continue

        proposed = ProposedQuery(
            hunt_id=hunt_id,
            data_source=f"lab:{provider.name}",
            query_text=text,
            time_range_days=window,
            limit=min(max_limit, max_auto_fetch),
            justification=f"Draft-time lab hit probe for {hunt_id}",
        )
        try:
            safe = gate.execute_safely(proposed)
        except Exception as exc:
            log.warning("Lab hit probe failed for %s (%s): %s", hunt_id, path.name, exc)
            results.append(
                LabHitResult(
                    query_file=path.name,
                    provider=provider.name,
                    hits=0,
                    window_days=window,
                    outcome="error",
                    detail=str(exc)[:240],
                )
            )
            continue

        outcome = _map_outcome(safe.outcome, safe.matched_count)
        results.append(
            LabHitResult(
                query_file=path.name,
                provider=provider.name,
                hits=int(safe.matched_count),
                window_days=window,
                outcome=outcome,
                detail=(safe.detail or "")[:240],
            )
        )

    status, total_hits, detail = _aggregate_status(
        [r for r in results if r.outcome != "skipped"] or results
    )
    report = LabProbeReport(
        provider=provider.name,
        window_days=window,
        status=status,
        total_hits=total_hits,
        queries_run=sum(1 for r in results if r.outcome != "skipped"),
        detail=f"{detail} in {window}d",
        results=results,
    )
    log.info(
        "Lab hit probe for %s on %s: %s (%s)",
        hunt_id,
        provider.name,
        report.status,
        report.detail,
    )
    return report


def format_lab_probe_slack(probe: dict[str, Any] | LabProbeReport | None) -> str:
    """One Slack mrkdwn block for a lab probe, empty when nothing useful to show."""
    data = probe.to_dict() if isinstance(probe, LabProbeReport) else probe
    if not data or not isinstance(data, dict):
        return ""
    status = str(data.get("status") or "").strip().lower()
    if not status or status == "skipped":
        detail = str(data.get("detail") or "")
        if "mock" in detail.lower():
            return "*Lab hits:* skipped (mock provider — not a live lab)."
        return ""
    provider = str(data.get("provider") or "lab")
    window = data.get("window_days") or "?"
    hits = data.get("total_hits")
    if status == "unconfigured":
        return f"*Lab hits:* `{provider}` not configured — {data.get('detail') or 'missing credentials'}."
    if status == "error":
        return f"*Lab hits:* error on `{provider}` — {data.get('detail') or 'query failed'}."
    if status == "miss":
        return f"*Lab hits:* miss on `{provider}` (0 hits in {window}d)."
    if status == "overmatch":
        return (
            f"*Lab hits:* overmatch on `{provider}` "
            f"({hits} hits in {window}d — query may be too broad)."
        )
    return f"*Lab hits:* {hits} hit(s) on `{provider}` in {window}d."
