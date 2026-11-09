"""Main orchestrator loop.

One run == one cycle: pick up CTI, call hecate, write a draft. Composable so
tests can drive it with fakes and so a future long-running loop could reuse
the same ``run_once`` primitive.
"""

from __future__ import annotations

import functools
import logging
import os
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hecate_agent.core.grounding import (
    TechniqueFact,
)
from hecate_agent.core.hunt_ids import hunt_id_lock, next_hunt_id

from hecate_runner.config import Settings
from hecate_runner.context_metrics import log_payload_metrics
from hecate_runner.cti import CTIItem, CTIProvider, get_provider
from hecate_runner.dead_letter import clear_retry
from hecate_runner.github_publisher import enqueue_hunt, sync_outbox
from hecate_runner.hecate_client import HecateClient, HecateError
from hecate_runner.hunt_writer import (
    DraftHuntRequest,
    write_draft,
)
from hecate_runner.indicator_sweep import build_indicator_sweep, parse_indicator_inventory
from hecate_runner.metrics import CycleMetrics, MetricsStore
from hecate_runner.misp_publisher import enqueue_misp_hunt, sync_misp_outbox
from hecate_runner.notifications import notify_draft_created
from hecate_runner.orchestrator_derivations import (
    _MAX_SKIPS_PER_CYCLE,
    _NO_OBSERVABLES,
    _RULE_IOC_RE,
    _fill_empty_source_slot,
    _indicator_only_source,
    _merge_indicator_record,
    attributed_actor,
    derive_data_sources,
    derive_research_topic,
    enrichment_trail_lines,
    has_narrative,
    is_actionable,
    merge_techniques,
    platform_consistent_data_sources,
    platforms_named_in,
    substantive_observables,
)
from hecate_runner.orchestrator_derivations import (
    platforms_evidenced_in as platforms_evidenced_in,
)
from hecate_runner.orchestrator_derivations import (
    research_tradecraft_text as research_tradecraft_text,
)
from hecate_runner.orchestrator_grounding import OrchestratorGroundingMixin
from hecate_runner.orchestrator_intake import OrchestratorIntakeMixin
from hecate_runner.orchestrator_publishing import OrchestratorPublishingMixin
from hecate_runner.orchestrator_rules import OrchestratorRulesMixin
from hecate_runner.orchestrator_ttp import resolve_ttps
from hecate_runner.orchestrator_validation import (
    run_bas_validation,
    run_purple_team_validation,
)
from hecate_runner.parked_store import park, prune_parked
from hecate_runner.state import OrchestratorState
from hecate_runner.trail import CycleTrail, clip, listing

log = logging.getLogger(__name__)

__all__ = [
    "_MAX_SKIPS_PER_CYCLE",
    "_NO_OBSERVABLES",
    "_RULE_IOC_RE",
    "HecateClient",
    "Orchestrator",
    "RunResult",
    "_fill_empty_source_slot",
    "_indicator_only_source",
    "_merge_indicator_record",
    "attributed_actor",
    "build_default_orchestrator",
    "build_orchestrator_for_item",
    "derive_data_sources",
    "derive_research_topic",
    "enqueue_hunt",
    "enqueue_misp_hunt",
    "get_provider",
    "has_narrative",
    "is_actionable",
    "merge_techniques",
    "park",
    "platform_consistent_data_sources",
    "platforms_evidenced_in",
    "platforms_named_in",
    "research_tradecraft_text",
    "substantive_observables",
    "sync_misp_outbox",
    "sync_outbox",
]


@dataclass
class RunResult:
    """Structured outcome of one orchestrator cycle."""

    outcome: str
    detail: str = ""
    hunt_id: str | None = None
    draft_path: Path | None = None
    research_id: str | None = None
    parked_count: int = 0
    cooldown_remaining_sec: float | None = None

    @property
    def ok(self) -> bool:
        return self.outcome in {
            "draft_created",
            "incremental_enrichment",
            "dry_run",
            "no_cti",
            "no_actionable_cti",
            "quota_reached",
            "spacing_cooldown",
            "research_quota_reached",
            "parked_after_research",
            "parked_after_hypothesis",
            "parked_no_techniques",
            "dead_letter",
        }


class Orchestrator(
    OrchestratorIntakeMixin,
    OrchestratorGroundingMixin,
    OrchestratorRulesMixin,
    OrchestratorPublishingMixin,
):
    """Coordinates threat intelligence intake, analysis, research, and Sigma draft generation.

    Decomposed into stage mixins:
    - OrchestratorIntakeMixin: item acquisition, cursor advance, dead-letter retries
    - OrchestratorGroundingMixin: primary source extraction, platform scope, claim audits
    - OrchestratorRulesMixin: multi-pass Sigma rule synthesis, review gaps, query deployment
    - OrchestratorPublishingMixin: GitHub/MISP synchronization and notifications
    """

    def __init__(
        self,
        settings: Settings,
        hecate: HecateClient,
        cti_provider: CTIProvider,
        notify: Callable[[RunResult], None] | None = None,
    ):
        self.settings = settings
        self.hecate = hecate
        self.cti = cti_provider
        # Replaced at the start of every cycle; this one only serves callers
        # that use a stage method directly (tests, `_resolve_ttps`).
        self.trail = CycleTrail()
        self.metrics = CycleMetrics(self.trail.cycle_id)
        # Techniques `_resolve_ttps` dropped for contradicting the hunt's
        # platform, so the later drop step does not call them unknown IDs.
        self._platform_dropped: set[str] = set()
        # This cycle's techniques whose names the intel's wording uses, and
        # the model picks dropped for having no source at all ("ID Name").
        # Both are read back when the grounding section is rendered.
        self._wording_matched: list[str] = []
        #: Supporting passage per technique (hecate_agent.core.technique_evidence
        #: TechniqueEvidence dicts), including techniques dropped as capability-only.
        self._technique_evidence: list[dict[str, str]] = []
        self._unevidenced_dropped: list[str] = []
        #: ClaimFinding dicts from the claim audit (hecate_agent.core.claim_audit).
        self._claim_audit: list[dict[str, str]] = []
        self._claim_evidence: list[dict[str, str]] = []
        # hecate_agent.core.source_evidence.SourceEvidence and the feed's
        # indicators typed against it (IndicatorRecord); reset every cycle.
        self._source_evidence: Any = None
        self._indicator_records: list[Any] = []
        #: The source's detection guidance (hecate_agent.core.detection_guidance
        #: GuidanceItem dicts): cited, routed, and fed to Sigma drafting.
        self._detection_guidance: list[dict[str, Any]] = []
        #: Platforms the specimen's evidence shows (platform_evidence), and the markers.
        self._specimen: list[str] = []
        self._platform_evidence: dict[str, Any] = {}
        #: The cycle's research grounding: "", "independent" or "source-only".
        self._research_grounding = ""
        self._research_grounding_label = ""
        # Defaults to a no-op so tests and callers that don't care about
        # notifications don't have to pass one.
        self.notify = notify or (lambda result: None)

    # --- Public API --------------------------------------------------------

    def run_once(self, *, dry_run: bool = False) -> RunResult:
        """Execute one cycle. Never raises; always returns a RunResult."""
        log.info("=== Orchestrator cycle starting (dry_run=%s) ===", dry_run)
        state = OrchestratorState.load(self.settings.state_file)
        self.trail = CycleTrail()
        self.metrics = CycleMetrics(self.trail.cycle_id)
        self._reset_llm_call_log()
        result = RunResult(outcome="error", detail="cycle did not complete")
        self.trail.step(
            "start",
            "cycle %s%s; drafts today %d/%d, research runs today %d/%d",
            self.trail.cycle_id,
            " (dry run)" if dry_run else "",
            state.drafts_today,
            self.settings.max_drafts_per_day,
            state.research_runs_today,
            self.settings.max_research_runs_per_day,
        )

        if self.settings.parked_max_age_days > 0:
            prune_parked(self.settings.cti_queue_dir_resolved, self.settings.parked_max_age_days)
        try:
            result = self._run_body(state, dry_run=dry_run)
            state.mark_run(success=result.ok)
            if result.outcome == "draft_created":
                state.last_draft_iso = datetime.now(UTC).isoformat()
            self.trail.step(
                "done",
                "%s%s%s in %.0fs",
                result.outcome,
                f" -> {result.hunt_id}" if result.hunt_id else "",
                f" ({clip(result.detail, 90)})" if result.detail else "",
                self.trail.elapsed,
            )
            return result
        except Exception as exc:  # top-level guard
            log.exception("Cycle failed unexpectedly: %s", exc)
            state.refund_draft()
            state.mark_run(success=False)
            self.trail.step("done", "error after %.0fs: %s", self.trail.elapsed, clip(str(exc)))
            result = RunResult(outcome="error", detail=str(exc))
            return result
        finally:
            try:
                state.save(self.settings.state_file)
            finally:
                try:
                    MetricsStore(self.settings.metrics_file).append(
                        self.metrics.to_record(
                            outcome=result.outcome,
                            hunt_id=result.hunt_id,
                            research_id=result.research_id,
                        )
                    )
                except Exception as exc:  # telemetry must not change a cycle result
                    log.warning("Could not persist stage metrics (%s)", exc)
            log.info("=== Orchestrator cycle complete ===")

    def _reset_llm_call_log(self) -> None:
        """Clear the shared agent LLM-call log so this cycle's monitor sees only its own calls."""
        try:
            target = self.settings.llm_calls_file
            if target.exists():
                target.write_text("", encoding="utf-8")
        except OSError as exc:  # the log is for watching; a cycle runs without it
            log.debug("Could not reset %s: %s", self.settings.llm_calls_file, exc)

    def _run_purple_team_validation(
        self,
        req: DraftHuntRequest,
        rules: list[dict[str, Any]],
        out_dir: Path,
        item: CTIItem,
    ) -> None:
        run_purple_team_validation(self, req, rules, out_dir, item)

    def _run_bas_validation(
        self,
        req: DraftHuntRequest,
        rules: list[dict[str, Any]],
        out_dir: Path,
        item: CTIItem,
    ) -> None:
        run_bas_validation(self, req, rules, out_dir, item)

    def _resolve_ttps(
        self,
        techniques: list[str],
        scope_text: str = "",
        facts: dict[str, TechniqueFact] | None = None,
        protected: list[str] | None = None,
        asserted: list[str] | None = None,
        intel_text: str = "",
        specimen: list[str] | None = None,
    ) -> tuple[list[str], list[str]]:
        return resolve_ttps(
            self,
            techniques,
            scope_text=scope_text,
            facts=facts,
            protected=protected,
            asserted=asserted,
            intel_text=intel_text,
            specimen=specimen,
        )

    def _run_body(self, state: OrchestratorState, *, dry_run: bool) -> RunResult:
        # Primary-source evidence for this cycle's item; see _gather_source_evidence.
        self._source_evidence = None
        self._enriched_context = ""
        self._enrichment_citations: list[dict[str, str]] = []
        self._indicator_records = []
        self._detection_guidance = []
        self._specimen = []
        self._platform_evidence = {}
        self._research_grounding = ""
        self._research_grounding_label = ""
        self._technique_evidence = []
        self._claim_audit = []
        self._claim_evidence = []
        with self.metrics.measure("cti_intake"):
            item, skipped, parked_count = self._next_actionable_item()
        if item is None:
            if skipped:
                log.info("No actionable CTI this cycle; %d item(s) had nothing to hunt.", skipped)
                return RunResult(
                    outcome="no_actionable_cti",
                    detail=f"skipped {skipped}",
                    parked_count=parked_count,
                )
            log.info("No CTI in queue; nothing to do this cycle.")
            return RunResult(outcome="no_cti", parked_count=parked_count)

        log.info("Picked up CTI item from %s (%d chars)", item.source, len(item.content))
        self.metrics.set_source(item.source, item.identifier)

        # Campaign Clustering & Incremental Enrichment
        if self.settings.campaign_clustering_enabled:
            from hecate_runner.correlation import IncrementalEnricher, ThreatEntityCorrelator

            correlator = ThreatEntityCorrelator(self.settings.hunts_root)
            match = correlator.correlate(
                item, threshold=self.settings.correlation_confidence_threshold
            )
            if match is not None:
                if dry_run:
                    return RunResult(
                        outcome="dry_run",
                        hunt_id=match.hunt_id,
                        draft_path=match.hunt_path,
                        detail=f"Would enrich {match.hunt_id} via {match.match_type}",
                        parked_count=parked_count,
                    )
                log.info(
                    "Correlated CTI item from %s with existing hunt %s via %s (%s, confidence %.2f)",
                    item.source,
                    match.hunt_id,
                    match.match_type,
                    ", ".join(match.matched_entities),
                    match.confidence,
                )
                self.trail.step(
                    "correlation",
                    "matched %s via %s (%s, confidence %.2f); performing incremental enrichment",
                    match.hunt_id,
                    match.match_type,
                    ", ".join(match.matched_entities),
                    match.confidence,
                )
                enrichment = IncrementalEnricher.enrich(item, match, self.settings.hecate_workspace)
                self.trail.step(
                    "enrichment",
                    "enriched %s: +%d indicator(s), +%d rule(s)",
                    match.hunt_id,
                    enrichment.new_indicators_count,
                    enrichment.new_rules_count,
                )
                clear_retry(self.settings.cti_queue_dir_resolved, item)
                self._advance_past(item)
                return RunResult(
                    outcome="incremental_enrichment",
                    hunt_id=match.hunt_id,
                    draft_path=match.hunt_path,
                    detail=enrichment.details,
                    parked_count=parked_count,
                )

        is_sweep = item.metadata.get("processing_track") != "deep" and (
            bool(parse_indicator_inventory(item.content))
            if not has_narrative(item.content)
            else False
        )
        effective_spacing = (
            self.settings.min_hours_between_sweeps
            if is_sweep
            else self.settings.min_hours_between_drafts
        )
        if not dry_run and self.settings.max_drafts_per_day < 900000:
            spaced, elapsed = state.check_spacing(effective_spacing)
            if not spaced:
                track = "indicator sweep" if is_sweep else "narrative research"
                log.info(
                    "Spacing cooldown active for %s: last draft was %.1fh ago (min spacing: %.1fh). Leaving CTI in queue.",
                    track,
                    elapsed,
                    effective_spacing,
                )
                self.trail.step(
                    "quota",
                    "spacing cooldown (%s): last draft was %.1fh ago (needs %.1fh); item stays queued",
                    track,
                    elapsed,
                    effective_spacing,
                )
                remaining_sec = max(0.0, (effective_spacing - elapsed) * 3600.0)
                return RunResult(
                    outcome="spacing_cooldown",
                    detail=f"{elapsed:.1f}h/{effective_spacing:.1f}h",
                    cooldown_remaining_sec=remaining_sec,
                    parked_count=parked_count,
                )

        if not state.check_and_reserve_draft(self.settings.max_drafts_per_day):
            log.warning(
                "Daily draft quota reached (%d). Leaving CTI in queue for next cycle.",
                self.settings.max_drafts_per_day,
            )
            self.trail.step("quota", "daily draft quota full; item stays queued")
            return RunResult(
                outcome="quota_reached",
                detail=f"{state.drafts_today}/{self.settings.max_drafts_per_day}",
            )
        self.trail.step(
            "quota",
            "draft slot %d/%d reserved",
            state.drafts_today,
            self.settings.max_drafts_per_day,
        )

        if dry_run:
            log.info("[dry-run] Would call hecate and write a draft; leaving CTI in queue.")
            state.refund_draft()  # reverse the reservation in dry-run
            return RunResult(
                outcome="dry_run", detail=item.content[:100], parked_count=parked_count
            )

        # Notify Slack only when the draft slot has actually been reserved and not dry run!
        try:
            from hecate_runner.notifications import notify_threat_intake

            notify_threat_intake(self.settings, item)
        except Exception as exc:
            log.warning("Threat-intake Slack notification failed (%s)", exc)

        source_is_indicator_only = _indicator_only_source(item)
        intel_has_narrative = not source_is_indicator_only and (
            item.metadata.get("processing_track") == "deep" or has_narrative(item.content)
        )
        if not intel_has_narrative:
            log.info(
                "CTI item has no behavior evidence (indicator/sample metadata); disabling web search and "
                "constraining the hypothesis to indicator presence for this cycle."
            )

        sweep_inventory = {} if intel_has_narrative else parse_indicator_inventory(item.content)
        if sweep_inventory:
            route = (
                "indicator dump -> deterministic sweep hypothesis (no research or hypothesis LLM)"
            )
        elif not self.settings.research_enabled:
            route = "research disabled -> hypothesis from primary CTI, without research context"
        elif intel_has_narrative:
            route = "narrative -> research with web search -> hypothesis"
        else:
            route = "no narrative -> research without web search -> indicator-only hypothesis"
        self.trail.step("route", "%s", route)

        if (
            not sweep_inventory
            and self.settings.research_enabled
            and intel_has_narrative
            and not state.check_and_reserve_research(self.settings.max_research_runs_per_day)
        ):
            log.warning(
                "Daily research quota reached (%d). Leaving CTI in queue for next cycle.",
                self.settings.max_research_runs_per_day,
            )
            state.refund_draft()
            return RunResult(
                outcome="research_quota_reached",
                detail=f"{state.research_runs_today}/{self.settings.max_research_runs_per_day}",
                parked_count=parked_count,
            )

        if source_is_indicator_only:
            self.trail.step(
                "source",
                "provider marks this as sample/indicator metadata; using the feed record only",
            )
        else:
            self._gather_source_evidence(item)
            self._demote_tooling_artifacts(item)
        source_block = (
            self._source_evidence.summary_block()
            if self._source_evidence is not None and self._source_evidence.artifacts
            else ""
        )

        # Enrich the CTI using external OSINT sources
        from hecate_agent.api import extract_indicators, generate_enrichment_summary

        log.info(
            "Extracting sample indicators without secondary OSINT lookups."
            if source_is_indicator_only
            else "Enriching CTI observables via OSINT sources..."
        )
        norm: dict[str, list[str]] = {}
        total_obs = 0
        try:
            indicators = (
                {} if item.metadata.get("reference_only") else extract_indicators(item.content)
            )
            ips_count = len(indicators.get("ips", []))
            hashes_count = len(indicators.get("hashes", []))
            domains_count = len(indicators.get("domains", []))
            cves_count = len(indicators.get("cves", []))
            urls_count = len(indicators.get("urls", []))
            total_obs = ips_count + hashes_count + domains_count + cves_count + urls_count
            if total_obs:
                obs_detail = []
                if ips_count:
                    obs_detail.append(f"{ips_count} ip")
                if hashes_count:
                    obs_detail.append(f"{hashes_count} hash")
                if domains_count:
                    obs_detail.append(f"{domains_count} domain")
                if urls_count:
                    obs_detail.append(f"{urls_count} url")
                if cves_count:
                    obs_detail.append(f"{cves_count} cve")
                if source_is_indicator_only:
                    self.trail.step(
                        "enrichment",
                        "%d indicator(s) (%s) extracted from sample metadata; secondary OSINT lookup skipped",
                        total_obs,
                        ", ".join(obs_detail),
                    )
                else:
                    self.trail.step(
                        "enrichment",
                        "%d observable(s) (%s) sent to OSINT lookup",
                        total_obs,
                        ", ".join(obs_detail),
                    )
                item_inds = item.metadata.setdefault("indicators", {})
                norm = {
                    "ipv4": indicators.get("ips", []),
                    "domain": indicators.get("domains", []),
                    "url": indicators.get("urls", []),
                }
                for h in indicators.get("hashes", []):
                    htype = "sha256" if len(h) == 64 else ("sha1" if len(h) == 40 else "md5")
                    norm.setdefault(htype, []).append(h)
                for k, vs in norm.items():
                    item_inds.setdefault(k, [])
                    for v in vs:
                        if v not in item_inds[k]:
                            item_inds[k].append(v)
                if indicators.get("cves"):
                    item_inds.setdefault("cve", [])
                    for cve in indicators["cves"]:
                        if cve not in item_inds["cve"]:
                            item_inds["cve"].append(cve)

                from hecate_agent.core.provenance import records_from_cti

                cti_records = records_from_cti(norm)
                for rec in cti_records:
                    _merge_indicator_record(self._indicator_records, rec)
            else:
                self.trail.step("enrichment", "no observable IPs/hashes/domains in source")
        except Exception as exc:
            log.warning("Indicator extraction failed before enrichment: %s", exc)

        enrichment_stats: dict[str, dict[str, int]] = {}
        enrichment_citations: list[dict[str, str]] = []
        self._enriched_context = (
            ""
            if source_is_indicator_only or item.metadata.get("reference_only")
            else generate_enrichment_summary(item.content, enrichment_stats, enrichment_citations)
        )
        self._enrichment_citations = enrichment_citations
        for service, line in enrichment_trail_lines(enrichment_stats):
            self.trail.step(
                "enrichment",
                "%s: %s",
                service,
                line,
                data={
                    "kind": "enrichment",
                    "service": service,
                    "summary": line,
                    **enrichment_stats[service],
                },
            )

        if self.settings.catalog_enrichment_enabled and not item.metadata.get("reference_only"):
            import json

            enabled = (
                self.settings.cti_multi_provider_names
                if self.settings.cti_provider == "multi"
                else [self.settings.cti_provider]
            )
            for catalog in ("lolbas", "loldrivers", "gtfobins"):
                if catalog not in enabled:
                    continue
                from hecate_runner import cti
                from hecate_runner.cti.catalogs import CatalogProvider

                provider = cti.get_provider(catalog, settings=self.settings)
                if not isinstance(provider, CatalogProvider):
                    continue
                try:
                    matches = provider.enrich(item.content)
                    if matches:
                        self._enriched_context += (
                            "\nSecondary capability reference (not incident evidence):\n"
                            + json.dumps(matches, default=str)
                        )
                        self.trail.step(
                            "enrichment",
                            "%s: %d documented capability reference(s)",
                            catalog,
                            len(matches),
                        )
                except Exception as exc:
                    from hecate_runner.integration_health import record_health

                    record_health(
                        self.settings.hecate_workspace,
                        catalog,
                        False,
                        "catalog enrichment fetch/schema failure",
                    )
                    log.warning(
                        "Catalog enrichment %s unavailable: %s", catalog, type(exc).__name__
                    )
                finally:
                    provider.close()

        # VirusTotal v3 Behavioral Graph expansion
        vt_behavior_blocks: list[str] = []
        if (
            self.settings.vt_behavior_enrichment
            and (self.settings.vt_api_key or os.environ.get("VT_API_KEY"))
            and total_obs
        ):
            try:
                from hecate_agent.api import extract_vt_behavior_graph

                candidate_hashes = (
                    norm.get("sha256", []) + norm.get("md5", []) + norm.get("sha1", [])
                )[:2]
                for chash in candidate_hashes:
                    bg = extract_vt_behavior_graph(chash)
                    if bg:
                        techs = [t["id"] for t in bg.get("mitre_techniques", [])]
                        c2_ips = bg.get("contacted_ips", [])
                        c2_domains = bg.get("contacted_domains", [])
                        tags = bg.get("tags", [])
                        dropped = bg.get("dropped_files", [])

                        if techs or c2_ips or c2_domains or tags:
                            self.trail.step(
                                "enrichment",
                                "VT behavior graph (%s...): %d technique(s), %d C2 IP(s), %d domain(s), %d tag(s)",
                                chash[:10],
                                len(techs),
                                len(c2_ips),
                                len(c2_domains),
                                len(tags),
                            )
                            item.metadata.setdefault("vt_behavior_graphs", []).append(
                                {"sample_hash": chash, "graph": bg}
                            )

                            bg_lines = [f"#### 🧬 VirusTotal Behavioral Graph ({chash[:12]}...)"]
                            if techs:
                                bg_lines.append(
                                    f"- **Sandbox ATT&CK labels (context only):** {', '.join(techs[:6])}"
                                )
                            if tags:
                                bg_lines.append(f"- **Capability Tags:** {', '.join(tags[:6])}")
                            if c2_ips:
                                bg_lines.append(
                                    f"- **Sandbox-contacted addresses (unverified role):** {', '.join(c2_ips[:5])}"
                                )
                            if c2_domains:
                                bg_lines.append(
                                    f"- **Resolved Hostnames:** {', '.join(c2_domains[:5])}"
                                )
                            if dropped:
                                bg_lines.append(
                                    f"- **Dropped Artifacts:** {', '.join(Path(p).name for p in dropped[:4])}"
                                )
                            vt_behavior_blocks.append("\n".join(bg_lines))
            except Exception as exc:
                log.debug("VT behavior graph extraction omitted (%s)", exc)

        if vt_behavior_blocks:
            vt_section = "\n\n### 🧬 VirusTotal Sandbox Execution Graph\n" + "\n\n".join(
                vt_behavior_blocks
            )
            self._enriched_context = (
                (self._enriched_context + vt_section) if self._enriched_context else vt_section
            )

        primary_intel_context = (
            f"{item.content}\n\n{source_block}" if source_block else item.content
        )
        research_context = primary_intel_context
        if self._enriched_context:
            research_context += (
                "\n\nSECONDARY OSINT ENRICHMENT (context lead only; not source evidence):\n"
                + self._enriched_context
            )

        research_id: str | None = None
        related_hunts: list[str] = []
        if sweep_inventory:
            log.info("CTI is a parseable indicator dump; skipping research context.")
        elif self.settings.research_enabled:
            topic, technique = derive_research_topic(item.content, title=item.title or None)
            self.trail.step(
                "research",
                'starting: topic "%s"%s; web search %s; source text %d chars',
                clip(topic, 80),
                f", technique {technique}" if technique else "",
                "on" if intel_has_narrative else "off",
                len(research_context),
            )
            research_started = self.trail.elapsed

            reused_doc = None
            describes_behavior = True
            if self.settings.research_reuse_enabled:
                try:
                    from hecate_agent.core.research_manager import ResearchManager

                    manager = ResearchManager(self.hecate.workspace / "research")
                    reused_doc = manager.find_recent_match(
                        topic=topic,
                        technique_id=technique,
                        max_age_days=self.settings.research_reuse_max_age_days,
                    )
                except Exception as exc:
                    log.debug("Research reuse lookup failed: %s", exc)

            if reused_doc and reused_doc.get("research_id"):
                research_id = reused_doc["research_id"]
                fm = reused_doc.get("frontmatter", {})
                linked_hunts = [h for h in fm.get("linked_hunts", []) if isinstance(h, str)]
                self._research_grounding = fm.get("grounding", "web_and_local")
                self._research_grounding_label = f"reused {research_id}"
                related_hunts = linked_hunts
                content = reused_doc.get("content", "")
                if "describes no observable adversary behavior" in content.lower():
                    describes_behavior = False
                self.trail.step(
                    "research",
                    "%s reused from workspace (<%dd old, topic %s); saved web searches & LLM calls; related hunts: %s",
                    research_id,
                    self.settings.research_reuse_max_age_days,
                    clip(topic, 60),
                    ", ".join(related_hunts) if related_hunts else "none",
                )
            else:
                try:
                    log_payload_metrics(
                        "research", f"{topic}\n{research_context}", self.settings.hecate_llm_model
                    )
                    with self.metrics.measure("research") as measured:
                        research_result = self.hecate.research_new(
                            topic=topic,
                            technique=technique,
                            depth=self.settings.research_depth,
                            timeout_sec=self.settings.llm_timeout_sec,
                            web_search_enabled=intel_has_narrative,
                            source_context=research_context,
                        )
                        measured.set_usage(research_result.usage)
                except HecateError as exc:
                    log.error(
                        "hecate-agent research new failed (%s); refusing to generate without configured research context",
                        exc,
                    )
                    state.refund_draft()
                    return RunResult(
                        outcome="research_error", detail=str(exc), parked_count=parked_count
                    )

                if research_result.is_empty:
                    log.error(
                        "hecate-agent research new produced no research_id; refusing to generate without configured research context"
                    )
                    state.refund_draft()
                    return RunResult(outcome="research_empty", parked_count=parked_count)

                research_id = research_result.research_id
                related_hunts = research_result.related_hunts
                self._research_grounding = research_result.grounding
                self._research_grounding_label = research_result.grounding_label()
                describes_behavior = research_result.describes_behavior
                self.trail.step(
                    "research",
                    "%s done in %.0fs; context quality: %s; describes adversary behavior: %s; related hunts: %s",
                    research_id,
                    self.trail.elapsed - research_started,
                    self._research_grounding_label,
                    "yes" if describes_behavior else "NO",
                    listing(related_hunts),
                )
                if intel_has_narrative and research_result.grounding == "source-only":
                    log.warning(
                        "Research %s ran source-only (%s); it will not count as evidence for techniques or grounding.",
                        research_id,
                        research_result.web_search_note or "no web searches",
                    )
                    self.trail.step(
                        "research",
                        "SOURCE-ONLY: web search was requested but none succeeded; "
                        "research is not counted as evidence this cycle",
                    )

            if (
                self.settings.cti_triage == "park"
                and intel_has_narrative
                and not describes_behavior
            ):
                reason = (
                    f"research {research_id} found no adversary behavior to hunt in it "
                    "(commentary, product or opinion content)"
                )
                try:
                    park(self.settings.cti_queue_dir_resolved, item, reason)
                except OSError as exc:
                    log.warning("Could not park CTI item (%s); drafting it instead.", exc)
                else:
                    self.trail.step("research", "park: %s; draft slot refunded", reason)
                    log.info(
                        "Parking CTI item from %s (%s): %s",
                        item.source,
                        item.title[:60] or "untitled",
                        reason,
                    )
                    state.refund_draft()
                    self._advance_past(item)
                    return RunResult(
                        outcome="parked_after_research",
                        detail=reason,
                        research_id=research_id,
                        parked_count=parked_count + 1,
                    )

            log.info("Research %s is ready as background context", research_id)

        if sweep_inventory:
            log.info(
                "CTI is an indicator dump (%d indicators, %d type(s)); building a sweep "
                "draft directly instead of generating a behavioral hypothesis.",
                sum(sweep_inventory.values()),
                len(sweep_inventory),
            )
            hypothesis = build_indicator_sweep(item.content, title=item.title or None)
        else:
            self.trail.step(
                "hypothesis",
                "asking the model%s%s",
                f" (research context {research_id})" if research_id else " (no research context)",
                "" if intel_has_narrative else "; constrained to indicator presence",
            )
            hypothesis_started = self.trail.elapsed
            log_payload_metrics(
                "hypothesis_generation", primary_intel_context, self.settings.hecate_llm_model
            )
            try:
                with self.metrics.measure("hypothesis_generation") as measured:
                    hypothesis = self.hecate.hypothesis_generator(
                        threat_intel=primary_intel_context,
                        research_id=research_id,
                        timeout_sec=self.settings.llm_timeout_sec,
                        indicators_only=not intel_has_narrative,
                    )
                    measured.set_usage(hypothesis.usage)
                    if hypothesis.fallback:
                        measured.set_status("partial")
            except HecateError as exc:
                log.error("hecate hypothesis-generator failed: %s", exc)
                return self._handle_item_failure(
                    item, "hecate_error", str(exc), parked_count, state
                )

        repaired = _fill_empty_source_slot(hypothesis.hypothesis, item.title)
        if repaired != hypothesis.hypothesis:
            log.info("Filled empty [source] slot in indicator-sweep hypothesis from CTI title.")
            hypothesis.hypothesis = repaired

        if getattr(hypothesis, "indicator_records", None):
            from hecate_agent.core.provenance import IndicatorRecord, well_formed
            from hecate_agent.core.source_evidence import normalise

            evidence = self._source_evidence
            source_text = normalise(
                primary_intel_context + "\n" + (evidence.text if evidence is not None else "")
            )
            feed_values = {
                normalise(str(v))
                for values in (item.metadata.get("indicators") or {}).values()
                for v in values
            }
            added = 0
            unsourced: list[str] = []
            for r in hypothesis.indicator_records:
                try:
                    if "source" not in r:
                        r["source"] = "cti"
                    rec = IndicatorRecord.from_dict(r)
                    value = normalise(rec.value)
                    if not well_formed(rec.value, rec.type) or (
                        value not in feed_values and value not in source_text
                    ):
                        unsourced.append(rec.value)
                        continue
                    if _merge_indicator_record(self._indicator_records, rec):
                        added += 1
                except Exception as exc:
                    log.warning("Failed to parse indicator record from hypothesis: %s", exc)
            if unsourced:
                self.trail.step(
                    "hypothesis",
                    "dropped %d indicator(s) the source does not contain: %s",
                    len(unsourced),
                    listing(unsourced),
                )
            if added > 0:
                log.info("Appended %d structured indicator(s) from hypothesis extraction.", added)

        if not sweep_inventory:
            self.trail.step(
                "hypothesis",
                'done in %.0fs: "%s"',
                self.trail.elapsed - hypothesis_started,
                clip(hypothesis.hypothesis, 140),
            )
            if not hypothesis.is_threat_report:
                why = clip(hypothesis.low_confidence_reason, 120) or "no reason given"
                self.trail.step("hypothesis", "model judged this NOT a threat report: %s", why)

                if self.settings.cti_triage == "park":
                    reason = f"hypothesis model judged this NOT a threat report: {why}"
                    try:
                        park(self.settings.cti_queue_dir_resolved, item, reason)
                    except OSError as exc:
                        log.warning("Could not park CTI item (%s); drafting it instead.", exc)
                    else:
                        self.trail.step("hypothesis", "park: %s; draft slot refunded", reason)
                        log.info(
                            "Parking CTI item from %s (%s): %s",
                            item.source,
                            item.title[:60] or "untitled",
                            reason,
                        )
                        state.refund_draft()
                        self._advance_past(item)
                        return RunResult(
                            outcome="parked_after_hypothesis",
                            detail=reason,
                            research_id=research_id,
                            parked_count=parked_count + 1,
                        )
        model_techniques = list(hypothesis.techniques)

        if hypothesis.is_empty:
            log.warning("hecate returned empty hypothesis; refunding quota and leaving CTI.")
            state.refund_draft()
            return RunResult(outcome="empty_hypothesis", parked_count=parked_count)

        cti_techniques = [str(t) for t in (item.metadata.get("techniques") or [])]

        candidates: list[tuple[str, str]] = []
        self._wording_matched = []
        self._unevidenced_dropped = []
        if not sweep_inventory:
            with self.metrics.measure("technique_candidates"):
                candidates = self.hecate.candidate_techniques(self._technique_text(item))
            self.trail.step(
                "techniques",
                "matched in the intel's wording: %s",
                listing(f"{tid} {name}" for tid, name in candidates),
            )
        self._wording_matched = [tid for tid, _ in candidates]

        behaviour: list[Any] = []
        evidence_texts = self._evidence_texts(item, research_id)
        if not sweep_inventory:
            from hecate_agent.core.technique_evidence import map_behaviours

            behaviour = map_behaviours(evidence_texts)
            observed = [e.technique_id for e in behaviour if e.status == "observed"]
            self.trail.step(
                "techniques",
                "described behaviour observed: %s; capability only: %s",
                listing(observed),
                listing(e.technique_id for e in behaviour if e.status == "capability"),
            )
            self._wording_matched = list(dict.fromkeys([*self._wording_matched, *observed]))
        observed_ids = [e.technique_id for e in behaviour if e.status == "observed"]
        with self.metrics.measure("technique_validation"):
            hypothesis.techniques = merge_techniques(
                [*cti_techniques, *(tid for tid, _ in candidates), *observed_ids],
                hypothesis.techniques,
            )
        self.trail.step(
            "techniques",
            "model chose %s; CTI asserted %s -> merged %s",
            listing(model_techniques),
            listing(cti_techniques),
            listing(hypothesis.techniques),
        )
        with self.metrics.measure("technique_validation"):
            hypothesis.techniques = self._drop_unevidenced_techniques(
                hypothesis.techniques,
                protected=[*cti_techniques, *(tid for tid, _ in candidates), *observed_ids],
                cti_text=self._technique_text(item),
                research_text="",
            )

            if not sweep_inventory:
                hypothesis.techniques = self._gate_on_observed_use(
                    hypothesis.techniques,
                    cti_techniques,
                    behaviour,
                    evidence_texts,
                    item=item,
                )

        indicator_types = list((item.metadata.get("indicators") or {}).keys())
        for source in derive_data_sources(hypothesis.techniques, indicator_types):
            if source not in hypothesis.data_sources:
                hypothesis.data_sources.append(source)

        technique_facts: dict[str, TechniqueFact] = {}
        with self.metrics.measure("attack_lookup"):
            tactics, platforms = self._resolve_ttps(
                hypothesis.techniques,
                scope_text=" ".join([hypothesis.hypothesis, hypothesis.location]),
                facts=technique_facts,
                protected=[*cti_techniques, *(tid for tid, _ in candidates), *observed_ids],
                asserted=cti_techniques,
                intel_text=self._primary_evidence_text(item),
                specimen=self._specimen_platforms(item),
            )

        hypothesis.data_sources = platform_consistent_data_sources(
            hypothesis.data_sources, platforms
        )
        self.trail.step(
            "scope",
            "platforms %s; tactics %s; data sources %s",
            listing(platforms, "unscoped"),
            listing(tactics),
            listing(hypothesis.data_sources),
        )

        kept_observables = substantive_observables(hypothesis.observables)
        if kept_observables != hypothesis.observables:
            log.info(
                "Dropped %d observable(s) that restated a telemetry category or were templates",
                len(hypothesis.observables) - len(kept_observables),
            )
        hypothesis.observables = kept_observables or [_NO_OBSERVABLES]

        kept_techniques = [
            t
            for t in hypothesis.techniques
            if (t.upper() not in technique_facts or technique_facts[t.upper()].valid)
            and t.upper() not in self._platform_dropped
        ]
        unknown = [
            t
            for t in hypothesis.techniques
            if t not in kept_techniques and t.upper() not in self._platform_dropped
        ]
        if unknown:
            self.trail.step("techniques", "dropped IDs not in ATT&CK: %s", listing(unknown))
        hypothesis.techniques = kept_techniques
        self._technique_evidence = [
            e
            for e in self._technique_evidence
            if e.get("technique_id", "").upper() not in self._platform_dropped
        ]
        self._audit_claims(hypothesis, self._primary_evidence_text(item), platforms)

        if (
            self.settings.cti_triage == "park"
            and not hypothesis.techniques
            and not sweep_inventory
            and not (item.metadata.get("indicators") or {})
        ):
            reason = "no ATT&CK technique survived grounding and the intel names no indicators"
            try:
                park(self.settings.cti_queue_dir_resolved, item, reason)
            except OSError as exc:
                log.warning("Could not park CTI item (%s); drafting it instead.", exc)
            else:
                self.trail.step("techniques", "park: %s; draft slot refunded", reason)
                log.info(
                    "Parking CTI item from %s (%s): %s",
                    item.source,
                    item.title[:60] or "untitled",
                    reason,
                )
                state.refund_draft()
                self._advance_past(item)
                return RunResult(
                    outcome="parked_no_techniques",
                    detail=reason,
                    research_id=research_id,
                    parked_count=parked_count + 1,
                )

        if not hypothesis.actor.strip():
            attributed = attributed_actor(item.content)
            if attributed:
                self.trail.step("scope", "actor from the intel's attribution: %s", attributed)
                hypothesis.actor = attributed

        from hecate_runner.claim_provenance import verify_claim_citations

        self._claim_evidence = verify_claim_citations(
            hypothesis=hypothesis,
            citations=getattr(hypothesis, "evidence_citations", []),
            feed_text=item.content,
            primary_source_text=(
                self._source_evidence.text if self._source_evidence is not None else ""
            ),
            source_url=item.source_url,
            source_name=item.source,
        )
        quote_checks = Counter(row["status"] for row in self._claim_evidence)
        if self._claim_evidence:
            self.trail.step(
                "claim_evidence",
                "%d claim reference(s): %s",
                len(self._claim_evidence),
                ", ".join(f"{count} {status}" for status, count in sorted(quote_checks.items())),
            )

        if (
            not hypothesis.actor
            or not hypothesis.actor.strip()
            or hypothesis.actor == "[Review CTI and populate]"
        ):
            cve_match = re.search(r"CVE-\d{4}-\d{4,}", item.content, re.IGNORECASE)
            if cve_match:
                hypothesis.actor = f"Unattributed (threat actors exploiting {cve_match.group(0).upper()})"
            else:
                hypothesis.actor = "Unattributed"

        try:
            with hunt_id_lock(self.settings.hunts_root):
                hunt_id = next_hunt_id(self.settings.hunts_root)
                req = DraftHuntRequest(
                    hunt_id=hunt_id,
                    threat_intel=item.content,
                    hypothesis=hypothesis,
                    generated_at=datetime.now(UTC),
                    research_id=research_id,
                    tactics=tactics,
                    platforms=platforms,
                    source_url=item.source_url,
                    related_hunts=related_hunts,
                    source_evidence=(
                        self._source_evidence.to_dict() if self._source_evidence is not None else {}
                    ),
                    indicator_records=[r.to_dict() for r in self._indicator_records],
                    research_grounding=self._research_grounding_label,
                    technique_evidence=self._technique_evidence,
                    claim_audit=self._claim_audit,
                    claim_evidence=self._claim_evidence,
                    detection_guidance=self._detection_guidance,
                    enrichment_citations=list(self._enrichment_citations),
                )
                req.grounding_section = self._grounding_section(req, item, technique_facts)
                with self.metrics.measure("draft_write"):
                    path = write_draft(req, self.settings.hunts_root)
                clear_retry(self.settings.cti_queue_dir_resolved, item)
                self.trail.step("write", "%s written to %s", hunt_id, path)
        except OSError as exc:
            log.error("Failed to allocate/write draft hunt file: %s", exc)
            return self._handle_item_failure(item, "write_error", str(exc), parked_count, state)

        if research_id:
            try:
                self.hecate.link_research_to_hunt(
                    research_id, hunt_id, timeout_sec=self.settings.llm_timeout_sec
                )
            except HecateError as exc:
                log.warning(
                    "Could not link %s back to %s (%s); the hunt still records "
                    "spawned_from, so the forward reference is intact.",
                    hunt_id,
                    research_id,
                    exc,
                )

        try:
            self.cti.acknowledge(item)
            state.save(self.settings.state_file)
        except Exception as exc:  # isolate from the top-level guard
            log.warning(
                "Failed to acknowledge CTI item or save state after successfully drafting %s (%s); "
                "this item may be re-drafted under a new ID next cycle.",
                hunt_id,
                exc,
            )

        if self.settings.sigma_generation_enabled:
            self._attach_sigma_rules(req, path, item, technique_facts)

        log.info(
            "Draft %s created at %s (research=%s, drafts today: %d/%d)",
            hunt_id,
            path,
            research_id or "none",
            state.drafts_today,
            self.settings.max_drafts_per_day,
        )

        result = RunResult(
            outcome="draft_created",
            hunt_id=hunt_id,
            draft_path=path,
            research_id=research_id,
        )

        self._publish_github(hunt_id)
        self._publish_misp(hunt_id)
        self._notify_cycle(result)

        return result


# --- Factory ---------------------------------------------------------------


def build_default_orchestrator(settings: Settings, ignore_quota: bool = False) -> Orchestrator:
    """Wire up the standard orchestrator from settings alone."""
    if ignore_quota:
        settings = settings.model_copy(
            update={"max_drafts_per_day": 999999, "max_research_runs_per_day": 999999}
        )
    hecate = HecateClient(
        hecate_bin=settings.hecate_bin_resolved,
        workspace=settings.hecate_workspace,
        env_overrides=settings.env_for_hecate(),
        default_timeout_sec=settings.llm_timeout_sec,
    )
    cti = get_provider(settings.cti_provider, settings=settings)
    notify = functools.partial(notify_draft_created, settings)
    return Orchestrator(settings=settings, hecate=hecate, cti_provider=cti, notify=notify)


def build_orchestrator_for_item(
    settings: Settings, item: CTIItem, ignore_quota: bool = False
) -> Orchestrator:
    """The standard orchestrator, reading one supplied item in place of the configured feeds.

    Only intake differs from a scheduled cycle. Triage is off, since someone
    chose this item; the quotas, the drafting stages and every check after
    them are the cycle's own.
    """
    from hecate_runner.cti.single import SingleItemProvider

    updates: dict[str, Any] = {"cti_triage": "off"}
    if ignore_quota:
        updates["max_drafts_per_day"] = 999999
        updates["max_research_runs_per_day"] = 999999
    settings = settings.model_copy(update=updates)
    hecate = HecateClient(
        hecate_bin=settings.hecate_bin_resolved,
        workspace=settings.hecate_workspace,
        env_overrides=settings.env_for_hecate(),
        default_timeout_sec=settings.llm_timeout_sec,
    )
    cti = SingleItemProvider(item)
    notify = functools.partial(notify_draft_created, settings)
    return Orchestrator(settings=settings, hecate=hecate, cti_provider=cti, notify=notify)
