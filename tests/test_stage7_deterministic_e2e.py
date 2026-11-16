"""Stage 7 Deterministic End-to-End Scenarios Test Suite.

Evaluation Plan Stage 7 Requirements:
- Run complete deterministic end-to-end scenarios combining built Core/Runner packages
  and a catalog snapshot.
- Cover intake through drafting, rules, approval, mock execution, evidence, retries,
  and publication previews.
- Success, rejection, and recovery paths behave correctly.
- Zero writes to real Slack, GitHub, MISP, or SIEM destinations.
- Test doubles must emulate failure behavior, not return success for everything.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from hecate_runner.bas.base import DetonationRequest, DetonationStage, DetonationTarget
from hecate_runner.bas.mock import MockBASProvider
from hecate_runner.config import Settings
from hecate_runner.cti import FileQueueProvider
from hecate_runner.hecate_client import HecateError, ResearchResult, SigmaResult
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.parked_store import list_parked
from hecate_runner.promotion_policy import evaluate_promotion, load_policy
from hecate_runner.query_execution import MockQueryProvider, ProposedQuery
from hecate_runner.state import OrchestratorState


# ==============================================================================
# Helper builders
# ==============================================================================


def _setup_promotion_policy(ws: Path, *, target_visibility: str = "public") -> None:
    policy = {
        "version": 1,
        "target_visibility": target_visibility,
        "publisher_login": "hecate-publisher[bot]",
        "auto_merge": {"enabled": True, "merge_method": "squash"},
        "review": {"minimum_approvals": 1, "allowed_associations": ["OWNER"]},
        "risk": {
            "missing_cti": "review",
            "missing_research": "review",
            "missing_sigma": "review",
            "incomplete_metadata": "review",
            "low_confidence_source": "review",
            "unsupported_claims": "review",
            "tlp_amber": "block" if target_visibility == "public" else "review",
            "tlp_red": "block",
            "unknown_tlp": "review" if target_visibility == "public" else "allow_private",
            "bas_failed": "block",
        },
    }
    (ws / "promotion-policy.yaml").write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")


# ==============================================================================
# 1. Full Deterministic Pipeline Success Path
# ==============================================================================


class TestDeterministicPipelineHappyPath:
    """Covers intake -> drafting -> rules -> mock execution -> approval -> publication preview."""

    def test_e2e_full_pipeline_to_publication_preview(
        self,
        settings: Settings,
        workspace: Path,
        mock_hecate: MagicMock,
    ) -> None:
        _setup_promotion_policy(workspace, target_visibility="public")

        # 1. Intake: Seed CTI in queue
        queue_dir = workspace / "cti_queue"
        queue_dir.mkdir(parents=True, exist_ok=True)
        raw_cti = """### Threat Intel Brief
Date: 2026-11-16
TLP:CLEAR
Adversaries dump LSASS memory via comsvcs.dll MiniDump (T1003.001).
Indicators:
- IPv4: 198.51.100.42
- URL: http://bad.c2/payload.ps1
- SHA256: 44d88612fea8a8f36de82e1278abb02f1a8e1047db7075b816283c48053fa3b4
"""
        (queue_dir / "next.txt").write_text(raw_cti, encoding="utf-8")

        # 2. Cycle Execution: Orchestrator intake and drafting
        provider = FileQueueProvider(queue_dir=queue_dir)
        provider.ensure_dirs()
        orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

        with patch(
            "hecate_agent.api.generate_enrichment_summary",
            return_value="Simulated enrichment summary for LSASS dump",
        ):
            result = orch.run_once()
        assert result.outcome == "draft_created"
        assert result.hunt_id == "H-0001"
        assert result.draft_path is not None
        assert result.draft_path.is_file()

        # Verify CTI queue moved item to processed
        assert not (queue_dir / "next.txt").exists()
        processed_files = list((queue_dir / "processed").glob("cti-*.txt"))
        assert len(processed_files) == 1

        # 3. Rules & Transpilation: Companion Sigma rule
        query_dir = workspace / "queries" / "H-0001"
        query_dir.mkdir(parents=True, exist_ok=True)
        sigma_file = query_dir / "H-0001-lsass.yml"
        sigma_content = (
            "title: LSASS Memory Dump via comsvcs\n"
            "status: experimental\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains:\n"
            "      - 'comsvcs.dll'\n"
            "      - 'MiniDump'\n"
            "  condition: selection\n"
        )
        sigma_file.write_text(sigma_content, encoding="utf-8")

        # 4. Mock SIEM Query Execution: Validate double behavior
        query_provider = MockQueryProvider(default_row_count=5)
        proposed = ProposedQuery(
            hunt_id="H-0001",
            data_source="windows_security",
            query_text="CommandLine=*comsvcs.dll* CommandLine=*MiniDump*",
            time_range_days=7,
            limit=50,
        )
        q_result = query_provider.execute(proposed)
        assert q_result.outcome == "executed"
        assert q_result.row_count > 0
        assert len(q_result.events) > 0

        # 5. Mock BAS Verification: Detonation & telemetry verification
        bas_provider = MockBASProvider()
        det_req = DetonationRequest(
            hunt_id="H-0001",
            technique_id="T1003.001",
            target=DetonationTarget(environment="staging", host="lab-01"),
        )
        bas_result = bas_provider.detonate(det_req)
        assert bas_result.success is True
        assert bas_result.stage == DetonationStage.COMPLETED
        assert bas_result.cleanup_success is True

        # 6. Companion Research Document: Grounding reference
        res_dir = workspace / "research"
        res_dir.mkdir(parents=True, exist_ok=True)
        (res_dir / "R-0001.md").write_text(
            "---\nresearch_id: R-0001\ntitle: LSASS Memory Dumping\ndate: 2026-11-16\n---\n"
            "# R-0001: LSASS Memory Dumping\n"
            "## Threat Context\nSource CTI names comsvcs.dll and MiniDump.\n",
            encoding="utf-8",
        )

        # 7. Analyst Approval & BAS True Positive Recording
        approved_hunt_content = (
            "---\n"
            "hunt_id: H-0001\n"
            "title: Adversaries dump LSASS memory via comsvcs\n"
            "status: active\n"
            "date: 2026-11-16\n"
            "review_decision: approved\n"
            "reviewed_by: analyst:lead\n"
            "reviewed_at: '2026-11-16T12:00:00+00:00'\n"
            "techniques:\n"
            "  - T1003.001\n"
            "platform:\n"
            "  - Windows\n"
            "data_sources:\n"
            "  - process_creation\n"
            "spawned_from: R-0001\n"
            "bas_verified: true\n"
            "bas_status: verified_true_positive\n"
            "---\n"
            "# H-0001: Adversaries dump LSASS memory via comsvcs\n\n"
            "> TLP:CLEAR - Threat intel brief\n\n"
            "## LEARN: Prepare the Hunt\n"
            "### Threat Context\n"
            "Source CTI:\n"
            "> Adversaries dump LSASS memory via comsvcs.dll MiniDump.\n\n"
            "## OBSERVE: Telemetry\n"
            "Endpoint process telemetry captures comsvcs.dll MiniDump command lines.\n\n"
            "## CHECK: Analyze\n"
            "Search for comsvcs invocations.\n\n"
            "## KEEP: Findings\n"
            "Rule generated in queries/H-0001/H-0001-lsass.yml.\n"
        )
        result.draft_path.write_text(approved_hunt_content, encoding="utf-8")

        # 8. Publication Promotion Preview: Validate deterministic promotion logic
        decision = evaluate_promotion(workspace, "H-0001")
        assert decision.eligible, f"Promotion preview failed: {decision.reasons}"
        assert not decision.review_required
        assert decision.tlp == "CLEAR"
        assert decision.unsupported_claims == 0


# ==============================================================================
# 2. Rejection Scenarios (TLP, Grounding, BAS)
# ==============================================================================


class TestDeterministicRejectionPaths:
    """Verifies that sensitive, ungrounded, or failed fixtures are deterministically blocked."""

    def test_tlp_red_material_hard_blocked_from_public_promotion(
        self,
        workspace: Path,
    ) -> None:
        """A hunt marked TLP:RED must be rejected by public promotion policy with an error."""
        _setup_promotion_policy(workspace, target_visibility="public")

        hunt_dir = workspace / "hunts" / "2026" / "Q4"
        hunt_dir.mkdir(parents=True, exist_ok=True)
        (workspace / "queries" / "H-0002").mkdir(parents=True, exist_ok=True)
        (workspace / "research").mkdir(parents=True, exist_ok=True)

        hunt_file = hunt_dir / "H-0002.md"
        hunt_file.write_text(
            "---\n"
            "hunt_id: H-0002\n"
            "title: Sensitive Operation\n"
            "status: planning\n"
            "date: 2026-11-16\n"
            "---\n"
            "# H-0002\n"
            "> TLP:RED - Strictly Classified Incident\n",
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="TLP:RED material cannot be published"):
            evaluate_promotion(workspace, "H-0002")

    def test_unsupported_grounding_claims_enforce_review(
        self,
        workspace: Path,
    ) -> None:
        """A hunt containing unevidenced fabricated assertions must enforce human review."""
        _setup_promotion_policy(workspace, target_visibility="public")

        hunt_dir = workspace / "hunts" / "2026" / "Q4"
        hunt_dir.mkdir(parents=True, exist_ok=True)
        (workspace / "queries" / "H-0003").mkdir(parents=True, exist_ok=True)
        (workspace / "queries" / "H-0003" / "rule.yml").write_text("title: Rule\n", encoding="utf-8")
        (workspace / "research").mkdir(parents=True, exist_ok=True)
        (workspace / "research" / "R-0003.md").write_text(
            "---\nresearch_id: R-0003\n---\n# Research\n", encoding="utf-8"
        )

        hunt_file = hunt_dir / "H-0003.md"
        hunt_file.write_text(
            "---\n"
            "hunt_id: H-0003\n"
            "title: Fabricated CVE Claims\n"
            "status: planning\n"
            "date: 2026-11-16\n"
            "techniques: [T1059.001]\n"
            "platform: [Windows]\n"
            "data_sources: [process_creation]\n"
            "spawned_from: R-0003\n"
            "---\n"
            "# H-0003\n"
            "> TLP:CLEAR\n"
            "### Threat Context\n"
            "Source CTI:\n"
            "> Valid source context.\n"
            "### Justification\n"
            "Threat actors exploited unevidenced vulnerability CVE-2029-88888 in the wild.\n",
            encoding="utf-8",
        )

        decision = evaluate_promotion(workspace, "H-0003")
        assert not decision.eligible
        assert decision.review_required
        assert decision.unsupported_claims > 0

    def test_failed_bas_verification_blocks_promotion(
        self,
        workspace: Path,
    ) -> None:
        """When live adversary emulation reports failure, promotion policy blocks auto-merge."""
        _setup_promotion_policy(workspace, target_visibility="public")

        hunt_dir = workspace / "hunts" / "2026" / "Q4"
        hunt_dir.mkdir(parents=True, exist_ok=True)
        (workspace / "queries" / "H-0004").mkdir(parents=True, exist_ok=True)
        (workspace / "queries" / "H-0004" / "rule.yml").write_text("title: Rule\n", encoding="utf-8")
        (workspace / "research").mkdir(parents=True, exist_ok=True)
        (workspace / "research" / "R-0004.md").write_text(
            "---\nresearch_id: R-0004\n---\n# Research\n", encoding="utf-8"
        )

        hunt_file = hunt_dir / "H-0004.md"
        hunt_file.write_text(
            "---\n"
            "hunt_id: H-0004\n"
            "title: BAS Failed Investigation\n"
            "status: planning\n"
            "date: 2026-11-16\n"
            "techniques: [T1059.001]\n"
            "platform: [Windows]\n"
            "data_sources: [process_creation]\n"
            "spawned_from: R-0004\n"
            "bas_verified: false\n"
            "bas_status: failed\n"
            "---\n"
            "# H-0004\n"
            "> TLP:CLEAR\n"
            "### Threat Context\n"
            "Source CTI: Some context.\n",
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="live adversary emulation verification failed"):
            evaluate_promotion(workspace, "H-0004")


# ==============================================================================
# 3. Fault Injection, Retries, and Recovery Paths
# ==============================================================================


class TestDeterministicFaultAndRecovery:
    """Verifies that transient errors trigger safe retries and do not lose state."""

    def test_transient_research_timeout_parks_item_and_recovers_on_retry(
        self,
        settings: Settings,
        workspace: Path,
        mock_hecate: MagicMock,
    ) -> None:
        """When HecateCore research fails transiently, item is parked and recovered on next cycle."""
        queue_dir = workspace / "cti_queue"
        queue_dir.mkdir(parents=True, exist_ok=True)
        raw_cti = """### Threat Intel Brief
Date: 2026-11-16
TLP:CLEAR
Adversary persistent rootkit campaign.
"""
        (queue_dir / "next.txt").write_text(raw_cti, encoding="utf-8")

        provider = FileQueueProvider(queue_dir=queue_dir)
        provider.ensure_dirs()
        orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

        # 1. First run: Simulate transient upstream timeout
        mock_hecate.research_new.side_effect = HecateError("LLM upstream 504 Gateway Timeout")

        with patch(
            "hecate_agent.api.generate_enrichment_summary",
            return_value="Simulated enrichment summary",
        ):
            fail_result = orch.run_once()
        assert fail_result.outcome == "research_error"
        assert fail_result.hunt_id is None

        # Verify item was safely preserved in queue for retry, not lost
        assert (queue_dir / "next.txt").exists()

        # 2. Recovery run: Restore upstream service
        mock_hecate.research_new.side_effect = None
        mock_hecate.research_new.return_value = ResearchResult(
            research_id="R-0005",
            recommended_hypothesis="Adversaries deploy rootkit modules.",
            related_hunts=[],
            raw_output="[deterministic research]",
            describes_behavior=True,
        )

        with patch(
            "hecate_agent.api.generate_enrichment_summary",
            return_value="Simulated enrichment summary",
        ):
            recovery_result = orch.run_once()
        assert recovery_result.outcome == "draft_created"
        assert recovery_result.hunt_id == "H-0001"
        assert recovery_result.draft_path.exists()

    def test_mock_bas_failure_emulation(self) -> None:
        """Test double must faithfully emulate adversary emulation detonation failures."""
        failing_bas = MockBASProvider(simulate_failure=True)
        req = DetonationRequest(
            hunt_id="H-0006",
            technique_id="T1059.001",
            target=DetonationTarget(environment="staging"),
        )
        res = failing_bas.detonate(req)
        assert res.success is False
        assert res.stage == DetonationStage.FAILED
        assert res.exit_code != 0
        assert "Simulated adversary detonation error" in res.stderr
