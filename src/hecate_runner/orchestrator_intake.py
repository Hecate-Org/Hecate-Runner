"""CTI intake, cursor navigation, deduplication, and dead-letter handling."""

from __future__ import annotations

import datetime
import logging
import re
from typing import TYPE_CHECKING, Any

from hecate_runner.cti import CTIItem
from hecate_runner.cti_triage import source_quality_verdict, triage
from hecate_runner.dead_letter import quarantine, record_failure
from hecate_runner.orchestrator_derivations import _MAX_SKIPS_PER_CYCLE, is_actionable
from hecate_runner.parked_store import park
from hecate_runner.trail import clip, counts, listing

if TYPE_CHECKING:
    from hecate_runner.orchestrator import RunResult
    from hecate_runner.state import OrchestratorState

log = logging.getLogger("hecate_runner.orchestrator")


class OrchestratorIntakeMixin:
    """Mixin handling CTI intake queue, deduplication, and dead-letter fault tolerance."""

    cti: Any
    settings: Any
    trail: Any

    def _advance_past(self, item: CTIItem) -> bool:
        """Acknowledge an item so the cursor moves; False if it could not.

        Without the advance the same item is returned by the next call, so a
        caller that keeps looping would spin on it forever.
        """
        try:
            self.cti.acknowledge(item)
        except Exception as exc:  # provider-specific cursor failures
            log.warning("Could not advance past CTI item (%s); stopping this cycle.", exc)
            return False
        return True

    def _drafted_from_same_source(self, item: CTIItem) -> str | None:
        """The hunt already drafted from this item's source link, or same CVE within 72h.

        H-0011 and H-0017 were both drafted from one MISP event (Kunai, open
        recursive DNS), a day apart, when the event reappeared on the feed.
        The second draft cost a research run and a review for nothing the
        first did not already say. The incremental index is refreshed from the
        actual hunt files, including manual edits, before looking up membership.
        """
        url = item.source_url.strip()
        needle = f"]({url})" if url else None

        cves: set[str] = set()
        for c in (item.metadata.get("indicators") or {}).get("cve", []):
            if isinstance(c, str) and c.strip():
                cves.add(c.strip().upper())
        for m in re.finditer(r"\bCVE-\d{4}-\d{4,7}\b", item.title or "", re.IGNORECASE):
            cves.add(m.group(0).upper())

        # A request-bearing template adds evidence that an earlier KEV/CVE inventory lacked.
        # Its pinned source URL still deduplicates the exact template revision.
        if item.source == "nuclei" and item.metadata.get("http_requests"):
            cves.clear()

        now = datetime.datetime.now(datetime.UTC)
        max_cve_age_sec = 3 * 86400  # 72 hours deduplication window

        if not needle and not cves:
            return None
        try:
            from hecate_agent.core.hunt_catalog import source_catalog
        except ImportError:
            # Core and Runner can be upgraded independently. Older Core builds
            # retain literal matching until the shared index becomes available.
            for path in sorted(self.settings.hunts_root.rglob("H-*.md"), reverse=True):
                try:
                    text = path.read_text(encoding="utf-8")
                    if needle and needle in text:
                        return str(path.stem)
                    if path.stat().st_mtime_ns >= int(
                        (now.timestamp() - max_cve_age_sec) * 1_000_000_000
                    ):
                        for cve in sorted(cves):
                            if cve in text:
                                return f"{path.stem} covering {cve} within 72h window"
                except (OSError, UnicodeError):
                    continue
            return None

        index = source_catalog(self.settings.hunts_root)
        url_matches = set(index.lookup("url", url)) if needle else set()
        cutoff = int((now.timestamp() - max_cve_age_sec) * 1_000_000_000)
        cve_matches = {
            path: cve for cve in sorted(cves) for path in index.lookup("cve", cve, since_ns=cutoff)
        }
        unusual = {cve for cve in cves if not re.fullmatch(r"CVE-\d{4}-\d{4,32}", cve)}
        if unusual:
            # Preserve legacy literal matching for malformed/custom feed values;
            # normal CVE lookups use the index without reading hunt bodies.
            for path in self.settings.hunts_root.rglob("H-*.md"):
                try:
                    if path.stat().st_mtime_ns >= cutoff:
                        text = path.read_text(encoding="utf-8")
                        for cve in sorted(unusual):
                            if cve in text:
                                cve_matches[path.absolute()] = cve
                except (OSError, UnicodeError):
                    continue
        for path in sorted(url_matches | cve_matches.keys(), reverse=True):
            if path in url_matches:
                return str(path.stem)
            return f"{path.stem} covering {cve_matches[path]} within 72h window"
        return None

    def _next_actionable_item(self) -> tuple[CTIItem | None, int, int]:
        """The next CTI item worth drafting, and how many were walked past, and how many parked.

        An item with neither narrative nor a parseable indicator inventory
        offers nothing to hunt. Drafted anyway it produced H-0630 --
        "Indicators published in Teaching AI to Reason Through Detection
        Triage appear in telemetry", a sweep for indicators that do not
        exist, off a vendor marketing post.

        Skipped items are acknowledged so the cursor advances past them
        instead of the same item being re-offered every cycle. This runs
        before the quota is reserved: walking past an item is not a draft and
        must not cost one.
        """
        skipped = 0
        parked_count = 0
        for _ in range(_MAX_SKIPS_PER_CYCLE + 1):
            item = self.cti.next_item()
            if item is None:
                self.trail.step("intake", "queue empty")
                return None, skipped, parked_count
            self.trail.step(
                "intake",
                '%s: "%s" (%d chars; indicators: %s; CTI techniques: %s)%s',
                item.source,
                clip(item.title or (item.content.splitlines() or [""])[0], 80),
                len(item.content),
                counts(item.metadata.get("indicators") or {}),
                listing(item.metadata.get("techniques") or []),
                (
                    f"; {item.metadata['backlog']} high-signal waiting in its backlog"
                    if "backlog" in item.metadata
                    else ""
                ),
            )
            if is_actionable(item.content):
                quality_verdict = source_quality_verdict(item)
                verdict = quality_verdict or (
                    triage(
                        item,
                        greynoise_api_key=self.settings.greynoise_api_key,
                        anti_noise_enabled=self.settings.anti_noise_triage,
                    )
                    if self.settings.cti_triage == "park"
                    else None
                )
                if verdict is not None and verdict.park:
                    reason = verdict.reason
                else:
                    earlier = (
                        self._drafted_from_same_source(item)
                        if (
                            self.settings.cti_triage == "park"
                            and not self.settings.campaign_clustering_enabled
                        )
                        else None
                    )
                    if earlier is None:
                        self.trail.step(
                            "triage",
                            "pass (%s)",
                            "triage off"
                            if verdict is None
                            else "no commentary category or title shape",
                        )
                        return item, skipped, parked_count
                    reason = (
                        f"already drafted as {earlier}"
                        if "(" in earlier
                        else f"already drafted as {earlier} from the same source ({item.source_url})"
                    )
                self.trail.step("triage", "park: %s", reason)
                # Held back, not dropped: the cursor has already moved past
                # this item, so the copy written here is the only one left.
                skipped += 1
                parked_count += 1
                log.info(
                    "Parking CTI item from %s (%s): %s",
                    item.source,
                    item.title[:60] or "untitled",
                    reason,
                )
                try:
                    import sys

                    orch_mod = sys.modules.get("hecate_runner.orchestrator")
                    park_fn = getattr(orch_mod, "park", park) if orch_mod else park
                    park_fn(self.settings.cti_queue_dir_resolved, item, reason)
                except OSError as exc:
                    # Parking is the whole safety net. If it cannot be written,
                    # draft the item rather than losing it.
                    log.warning("Could not park CTI item (%s); drafting it instead.", exc)
                    parked_count -= 1
                    return item, skipped - 1, parked_count
                if not self._advance_past(item):
                    return None, skipped, parked_count
                continue

            # Counted where the decision is made, not after the cursor moves:
            # an item we could not advance past was still found and rejected,
            # and reporting "no CTI in queue" for it would be untrue.
            skipped += 1
            self.trail.step("triage", "skip: no narrative, no indicator inventory, no prose")
            log.info(
                "Skipping CTI item from %s: no narrative, no parseable indicator "
                "inventory and no free-form prose, so there is nothing to hunt.",
                item.source,
            )
            if not self._advance_past(item):
                return None, skipped, parked_count

        log.info("Found %d non-actionable CTI items; stopping this cycle.", skipped)
        return None, skipped, parked_count

    def _handle_item_failure(
        self,
        item: CTIItem,
        outcome: str,
        error_msg: str,
        parked_count: int,
        state: OrchestratorState,
    ) -> RunResult:
        """Handle a fatal failure during CTI item processing with DLQ retry management."""
        from hecate_runner.orchestrator import RunResult

        state.refund_draft()

        queue_dir = self.settings.cti_queue_dir_resolved
        attempts = record_failure(queue_dir, item, error_msg)

        if attempts >= self.settings.cti_max_retries:
            dlq_path = quarantine(queue_dir, item, error_msg, attempts)
            self._advance_past(item)
            self.trail.step(
                "dead_letter",
                "item %s quarantined to %s after %d failures: %s",
                item.identifier or "unnamed",
                dlq_path.name,
                attempts,
                error_msg,
            )
            log.warning(
                "Quarantined poison-pill item %s to DLQ %s after %d failed attempts: %s",
                item.identifier,
                dlq_path.name,
                attempts,
                error_msg,
            )
            return RunResult(
                outcome="dead_letter",
                detail=f"Quarantined to DLQ after {attempts} attempts ({error_msg})",
                parked_count=parked_count,
            )

        log.warning(
            "CTI item %s failed (attempt %d/%d): %s",
            item.identifier,
            attempts,
            self.settings.cti_max_retries,
            error_msg,
        )
        return RunResult(outcome=outcome, detail=error_msg, parked_count=parked_count)
