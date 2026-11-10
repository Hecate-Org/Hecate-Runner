"""Autonomous Hunt Execution Scheduler for recurring production sweeps.

Discovers active hunts, matches them against target SIEM dialects, determines
execution eligibility based on watermarks, stages sweeps for human approval,
and invokes the SafeExecutionGate.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from hecate_runner.config import Settings
from hecate_runner.execution.safe_gate import SafeExecutionGate, SafeExecutionResult
from hecate_runner.execution.watermark_store import StagedSweep, WatermarkStore
from hecate_runner.lifecycle import (
    find_hunt_path,
    normalize_lifecycle_state,
    parse_hunt_frontmatter,
    record_hunt_execution,
)
from hecate_runner.query_execution import ProposedQuery, QueryProvider, get_provider

log = logging.getLogger(__name__)

# File extension mappings for supported SIEM backends
DIALECT_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "splunk": (".spl",),
    "sentinel": (".kql",),
    "elastic": (".eql",),
    "crowdstrike": (".cql",),
    "mock": (".spl", ".kql", ".eql", ".cql"),
}


class HuntExecutionScheduler:
    """Discovers, schedules, stages, and executes hunting sweeps across active hunts."""

    def __init__(
        self,
        settings: Settings | None = None,
        provider: QueryProvider | None = None,
        notify_fn: Callable[[list[dict[str, Any]] | str], None] | None = None,
    ):
        self.settings = settings or Settings()
        self.workspace = self.settings.hecate_workspace
        self.store = WatermarkStore(self.settings.hunt_executions_db_resolved)
        self.notify_fn = notify_fn

        if provider is not None:
            self.provider = provider
        else:
            self.provider = get_provider(
                self.settings.query_provider,
                hecate_bin=self.settings.hecate_bin_resolved,
                workspace=self.workspace,
                max_time_range_days=self.settings.max_query_time_range_days,
                max_limit=self.settings.max_query_limit,
                env_overrides=self.settings.query_provider_env(),
            )

        self.gate = SafeExecutionGate(
            self.provider,
            max_auto_fetch=self.settings.auto_hunt_max_fetch,
            max_time_range_days=self.settings.max_query_time_range_days,
            max_limit=self.settings.max_query_limit,
        )

        if self.notify_fn is None and (
            self.settings.slack_bot_token or self.settings.slack_webhook_url
        ):
            try:
                from hecate_runner.notifications import SlackNotificationRouter

                notifier = SlackNotificationRouter(self.settings)
                if notifier.is_configured:
                    channel = self.settings.slack_channel_hunts_exec or "#all-hecate-hunt"

                    def _notify(b: list[dict[str, Any]] | str) -> None:
                        is_attachment = isinstance(b, list) and len(b) > 0 and "color" in b[0]
                        notifier.post_message(
                            channel,
                            "Hecate Auto Hunt Notification",
                            blocks=None if is_attachment else (b if isinstance(b, list) else None),
                            attachments=b if is_attachment else None,
                        )

                    self.notify_fn = _notify
            except Exception as exc:
                log.debug("Could not initialize default SlackNotifier for scheduler: %s", exc)

    def discover_active_hunts(self) -> list[dict[str, Any]]:
        """Find all hunts with status: active and associated query files in the workspace."""
        hunts_dir = self.workspace / "hunts"
        if not hunts_dir.exists():
            return []

        active_hunts = []
        target = self.provider.name.lower()
        allowed_exts = DIALECT_EXTENSIONS.get(target, (".spl", ".kql", ".eql", ".cql"))

        for hunt_file in sorted(hunts_dir.glob("**/*.md")):
            try:
                content = hunt_file.read_text(encoding="utf-8")
                fm, _, _ = parse_hunt_frontmatter(content)
                status = str(fm.get("status") or "")
                try:
                    canonical = normalize_lifecycle_state(status)
                except ValueError:
                    continue

                if canonical != "active":
                    continue

                hunt_id = str(fm.get("hunt_id") or hunt_file.stem).upper()
                query_dir = self.workspace / "queries" / hunt_id
                query_files: list[Path] = []
                if query_dir.exists():
                    for ext in allowed_exts:
                        query_files.extend(sorted(query_dir.glob(f"*{ext}")))

                watermark = self.store.get_watermark(hunt_id)
                active_hunts.append(
                    {
                        "hunt_id": hunt_id,
                        "title": fm.get("title", ""),
                        "path": hunt_file,
                        "query_files": query_files,
                        "watermark": watermark,
                        "frontmatter": fm,
                    }
                )
            except Exception as exc:
                log.warning("Skipping unreadable hunt file %s: %s", hunt_file, exc)

        return active_hunts

    def check_eligibility(self, hunt_meta: dict[str, Any], force: bool = False) -> bool:
        """Check whether an active hunt is due for a scheduled sweep."""
        if force:
            return True

        if not hunt_meta.get("query_files"):
            return False

        watermark = hunt_meta.get("watermark")
        if watermark is None:
            return True

        try:
            last_run = datetime.fromisoformat(watermark.last_executed_at)
            elapsed = datetime.now(UTC) - last_run
            cadence = timedelta(hours=self.settings.auto_hunt_cadence_hours)
            return elapsed >= cadence
        except Exception:
            return True

    def stage_sweeps(
        self,
        hunt_id: str | None = None,
        *,
        force: bool = False,
        time_range_days: int | None = None,
    ) -> list[StagedSweep]:
        """Stage sweeps for eligible active hunts awaiting approval."""
        active_hunts = self.discover_active_hunts()
        staged: list[StagedSweep] = []
        lookback = time_range_days or self.settings.auto_hunt_default_lookback_days

        for h in active_hunts:
            h_id = h["hunt_id"]
            if hunt_id and h_id != hunt_id.upper():
                continue

            if not self.check_eligibility(h, force=force):
                log.debug("Hunt %s is not yet eligible for scheduled sweep", h_id)
                continue

            q_files: list[Path] = h["query_files"]
            if not q_files:
                log.info(
                    "Active hunt %s has no query files for dialect %s", h_id, self.provider.name
                )
                continue

            # Pick the primary query file (or first available)
            q_file = q_files[0]
            query_text = q_file.read_text(encoding="utf-8").strip()

            sweep = self.store.stage_sweep(
                hunt_id=h_id,
                target_siem=self.provider.name,
                query_file=q_file.name,
                query_text=query_text,
                time_range_days=lookback,
                justification=f"Scheduled sweep against {self.provider.name}",
            )
            staged.append(sweep)
            log.info("Staged sweep %s for hunt %s", sweep.sweep_id, h_id)

            # Notify via Slack if callback configured
            if self.notify_fn:
                try:
                    from hecate_runner.slack_blocks import build_staged_sweep_card

                    blocks = build_staged_sweep_card(sweep, title=h.get("title", ""))
                    self.notify_fn(blocks)
                except Exception as exc:
                    log.warning("Could not dispatch staged sweep Slack card (%s)", exc)

        return staged

    def execute_sweep(
        self,
        sweep_id_or_hunt_id: str,
        *,
        approver: str = "analyst",
        force_raw: bool = False,
    ) -> SafeExecutionResult:
        """Execute a staged sweep through the SafeExecutionGate and sync state."""
        staged = self.store.get_staged_sweep(sweep_id_or_hunt_id)
        now_dt = datetime.now(UTC)

        if staged is None:
            # If a hunt_id was passed directly, try staging on the fly
            clean_id = sweep_id_or_hunt_id.upper()
            staged_list = self.stage_sweeps(hunt_id=clean_id, force=True)
            if not staged_list:
                return SafeExecutionResult(
                    hunt_id=clean_id,
                    target=self.provider.name,
                    outcome="error",
                    detail=f"No staged sweep found and could not stage sweep for {clean_id}",
                    executed_at=now_dt.isoformat(),
                )
            staged = staged_list[0]

        if staged.status == "executed":
            return SafeExecutionResult(
                hunt_id=staged.hunt_id,
                target=staged.target_siem,
                outcome="error",
                detail=f"Sweep {staged.sweep_id} has already been executed",
                executed_at=now_dt.isoformat(),
            )

        window_start = (now_dt - timedelta(days=staged.time_range_days)).isoformat()
        window_end = now_dt.isoformat()

        proposed = ProposedQuery(
            hunt_id=staged.hunt_id,
            data_source=staged.target_siem,
            query_text=staged.query_text,
            time_range_days=staged.time_range_days,
            limit=self.settings.max_query_limit,
            justification=staged.justification,
        )

        # Execute via COUNT-FIRST Safe Execution Gate
        result = self.gate.execute_safely(proposed, force_raw=force_raw)

        # Update watermark in SQLite
        self.store.update_watermark(
            hunt_id=staged.hunt_id,
            target_siem=staged.target_siem,
            query_file=staged.query_file,
            last_window_start=window_start,
            last_window_end=window_end,
            outcome=result.outcome,
            matched_count=result.matched_count,
        )

        # Mark staged sweep status
        self.store.mark_sweep_status(
            staged.sweep_id,
            status="executed",
            actor=approver,
            outcome=result.outcome,
            matched_count=result.matched_count,
        )

        # Triage telemetry hits if events were retrieved
        triage_report = None
        if result.outcome == "hits_detected" and result.events:
            try:
                from hecate_runner.execution.normalizer import normalize_events
                from hecate_runner.execution.triage_agent import FindingTriageAgent

                hunt_path = find_hunt_path(self.workspace, staged.hunt_id)
                hypothesis = ""
                techniques: list[str] = []
                if hunt_path and hunt_path.exists():
                    fm, _, _ = parse_hunt_frontmatter(hunt_path.read_text(encoding="utf-8"))
                    hypothesis = str(fm.get("hypothesis") or fm.get("title") or "")
                    techniques = list(fm.get("techniques") or [])

                normalized = normalize_events(result.events, staged.target_siem, staged.hunt_id)
                agent = FindingTriageAgent(settings=self.settings)
                triage_report = agent.triage(
                    hunt_id=staged.hunt_id,
                    sweep_id=staged.sweep_id,
                    target_siem=staged.target_siem,
                    events=normalized,
                    hypothesis=hypothesis,
                    techniques=techniques,
                )
                finding_id = self.store.record_finding(triage_report)
                triage_report.finding_id = finding_id
                result.triage_report = triage_report
            except Exception as exc:
                log.warning("Finding triage failed for sweep %s (%s)", staged.sweep_id, exc)

        # Execute autonomous pivots for confirmed or suspicious threat findings
        if (
            triage_report
            and triage_report.verdict in ("true_positive", "suspicious")
            and getattr(self.settings, "auto_hunt_pivots_enabled", True)
            and triage_report.confidence
            >= getattr(self.settings, "auto_hunt_pivot_min_confidence", 0.70)
        ):
            try:
                from hecate_runner.execution.pivot_engine import PivotExecutionEngine

                pivot_engine = PivotExecutionEngine(
                    gate=self.gate,
                    store=self.store,
                    settings=self.settings,
                )
                finding_id = (
                    triage_report.finding_id or f"FINDING-{staged.hunt_id}-{uuid.uuid4().hex[:6]}"
                )
                pivot_results = pivot_engine.execute_pivots(
                    finding_id=finding_id,
                    hunt_id=staged.hunt_id,
                    target_siem=staged.target_siem,
                    entities=triage_report.extracted_entities,
                    techniques=triage_report.technique_matches,
                    lookback_days=staged.time_range_days,
                )
                result.pivot_results = pivot_results
            except Exception as exc:
                log.warning("Pivot execution failed for sweep %s (%s)", staged.sweep_id, exc)

        # Record execution in hunt frontmatter and markdown body
        try:
            record_hunt_execution(
                self.workspace,
                staged.hunt_id,
                outcome=result.outcome,
                matched_count=result.matched_count,
                target=staged.target_siem,
                detail=result.detail,
                events=result.events,
                triage_report=triage_report,
                pivot_results=result.pivot_results,
            )
        except Exception as exc:
            log.warning("Could not record execution in hunt markdown (%s)", exc)

        # Notify via Slack if callback configured
        if self.notify_fn:
            try:
                from hecate_runner.slack_blocks import build_sweep_result_card

                blocks = build_sweep_result_card(result)
                self.notify_fn(blocks)
            except Exception as exc:
                log.warning("Could not dispatch sweep result Slack card (%s)", exc)

        return result

    def reject_sweep(
        self,
        sweep_id_or_hunt_id: str,
        reason: str = "Rejected by analyst",
        actor: str = "analyst",
    ) -> StagedSweep | None:
        """Reject and cancel a staged sweep."""
        staged = self.store.get_staged_sweep(sweep_id_or_hunt_id)
        if not staged:
            return None

        self.store.mark_sweep_status(
            staged.sweep_id,
            status="rejected",
            actor=actor,
            reason=reason,
        )
        staged.status = "rejected"
        staged.rejection_reason = reason
        log.info("Rejected sweep %s for %s (%s)", staged.sweep_id, staged.hunt_id, reason)
        return staged

    def run_scheduled_sweeps(
        self,
        *,
        force: bool = False,
    ) -> list[SafeExecutionResult | StagedSweep]:
        """Discover eligible active hunts, stage sweeps, and execute or request approval.

        If `auto_hunt_approval_required` is True:
            Stages eligible sweeps and dispatches Slack HITL approval cards.
        If `auto_hunt_approval_required` is False:
            Stages eligible sweeps and executes them autonomously via the safe gate.
        """
        if not self.settings.auto_hunt_execution_enabled:
            log.info("Auto hunt execution is disabled; skipping scheduled sweeps.")
            return []

        staged: list[SafeExecutionResult | StagedSweep] = list(self.stage_sweeps(force=force))
        if not staged:
            log.debug("No eligible active hunts found for scheduled sweep.")
            return []

        if self.settings.auto_hunt_approval_required:
            log.info(
                "Staged %d sweeps awaiting analyst approval (HITL enabled).",
                len(staged),
            )
            return staged

        # When approval is not required, autonomously execute each staged sweep
        results: list[SafeExecutionResult | StagedSweep] = []
        for item in staged:
            s = cast(StagedSweep, item)
            log.info("Autonomously executing scheduled sweep %s for %s...", s.sweep_id, s.hunt_id)
            res = self.execute_sweep(s.sweep_id, approver="daemon")
            results.append(res)
        return results
