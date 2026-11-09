"""Publishing and notification lifecycle stages for Hecate orchestrator."""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, Any

from hecate_runner.github_publisher import enqueue_hunt
from hecate_runner.misp_publisher import enqueue_misp_hunt

if TYPE_CHECKING:
    from hecate_runner.orchestrator import RunResult

log = logging.getLogger("hecate_runner.orchestrator")


class OrchestratorPublishingMixin:
    """Mixin providing post-draft publication to GitHub, MISP, and Slack."""

    settings: Any
    trail: Any
    notify: Any
    _indicator_records: list[Any]

    def _publish_github(self, hunt_id: str) -> None:
        """Snapshot publication for the independent GitHub maintenance worker."""
        if not self.settings.github_publishing_enabled:
            return

        orch_mod = sys.modules.get("hecate_runner.orchestrator")
        enqueue_fn = getattr(orch_mod, "enqueue_hunt", enqueue_hunt) if orch_mod else enqueue_hunt

        try:
            status = enqueue_fn(self.settings, hunt_id)
            log.info("Queued %s for GitHub publication (outbox status=%s)", hunt_id, status)
        except Exception as exc:
            log.warning("Could not queue %s for GitHub publication (%s)", hunt_id, exc)

    def _publish_misp(self, hunt_id: str) -> None:
        """Snapshot indicators for the independent MISP maintenance worker."""
        if not self.settings.misp_publishing_enabled:
            return

        orch_mod = sys.modules.get("hecate_runner.orchestrator")
        enqueue_fn = (
            getattr(orch_mod, "enqueue_misp_hunt", enqueue_misp_hunt)
            if orch_mod
            else enqueue_misp_hunt
        )

        try:
            enqueue_fn(
                self.settings,
                hunt_id,
                indicator_records=[record.to_dict() for record in self._indicator_records],
            )
            self.trail.step("misp_output", "%s queued for MISP storage", hunt_id)
        except Exception as exc:
            log.warning("Could not queue %s for MISP output (%s)", hunt_id, type(exc).__name__)

    def _notify_cycle(self, result: RunResult) -> None:
        """Deliver post-cycle notifications (best-effort, never raises)."""
        try:
            self.notify(result)
        except Exception as exc:  # notifications are best-effort, never fatal
            log.warning(
                "Draft-created notification failed (%s); draft %s was still created",
                exc,
                result.hunt_id,
            )
