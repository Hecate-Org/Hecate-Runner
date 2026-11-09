"""Grounding, primary evidence collection, claim auditing, and technique validation."""

from __future__ import annotations

import logging
import re
from collections import Counter
from typing import TYPE_CHECKING, Any

from hecate_agent.core.grounding import (
    audit_draft,
    render_grounding_section,
    technique_lacks_evidence,
)

from hecate_runner.cti import CTIItem
from hecate_runner.hecate_client import HypothesisResult
from hecate_runner.hunt_writer import DraftHuntRequest, render_draft
from hecate_runner.metrics import LLMUsage
from hecate_runner.orchestrator_derivations import (
    _NO_OBSERVABLES,
    attributed_actor,
    platforms_named_in,
)
from hecate_runner.trail import clip, listing

if TYPE_CHECKING:
    from hecate_agent.core.grounding import TechniqueFact

log = logging.getLogger("hecate_runner.orchestrator")


class OrchestratorGroundingMixin:
    """Mixin providing primary-source evidence extraction, claim auditing, and grounding."""

    settings: Any
    hecate: Any
    trail: Any
    metrics: Any
    _source_evidence: Any
    _indicator_records: list[Any]
    _detection_guidance: list[dict[str, Any]]
    _specimen: list[str]
    _platform_evidence: dict[str, Any]
    _wording_matched: list[str]
    _technique_evidence: list[dict[str, str]]
    _unevidenced_dropped: list[str]
    _claim_audit: list[dict[str, str]]

    def _evidence_texts(self, item: CTIItem, research_id: str | None) -> list[tuple[str, str]]:
        """Primary-source texts that may evidence a technique, most authoritative first.

        Research can suggest what to investigate, but generated research is
        not evidence that this particular source reported a behavior.
        """
        texts = [("cti", item.content)]
        if self._source_evidence is not None and self._source_evidence.text:
            source = self._source_evidence.text
            if item.source == "github_poc":
                from hecate_agent.core.command_rules import without_tooling_sections

                source = re.sub(r"<[^>]+>", " ", without_tooling_sections(source))
            texts.append(("primary source", source))
        return texts

    def _technique_text(self, item: CTIItem) -> str:
        """The evidence texts as one, for matching technique names and phrases."""
        return "\n".join(text for _, text in self._evidence_texts(item, None))

    def _gate_on_observed_use(
        self,
        techniques: list[str],
        asserted: list[str],
        behaviour: list[Any],
        texts: list[tuple[str, str]],
        item: CTIItem | None = None,
    ) -> list[str]:
        """Keep techniques the sources show in use; record the passage for each."""
        from hecate_agent.core.technique_evidence import (
            TechniqueEvidence,
            _clip,
            actor_material_report,
            passage_status,
            sentences,
            technique_support,
        )

        by_id = {e.technique_id: e for e in behaviour}
        combined = "\n".join(text for _, text in texts)
        actor_material = any(actor_material_report(t) for _, t in texts)
        shielded = {t.upper() for t in asserted}
        is_otx_pulse = item is not None and (
            item.source == "otx" or bool(item.metadata.get("pulse_id"))
        )
        kept: list[str] = []
        evidence: list[dict[str, str]] = []
        dropped: list[str] = []
        unevidenced: list[str] = []

        for technique_id in techniques:
            upper = technique_id.upper()
            found = by_id.get(upper)
            if found is None:
                meta = self.hecate.lookup_technique(
                    upper, timeout_sec=self.settings.llm_timeout_sec
                )
                found = technique_support(
                    upper, [meta.name] if meta.found and meta.name else [], combined
                )
                parent = upper.split(".")[0]
                if (
                    found is None
                    and "." in upper
                    and parent in by_id
                    and by_id[parent].status == "observed"
                ):
                    self.trail.step(
                        "techniques", "%s unsupported; generalised to %s", upper, parent
                    )
                    upper, found = parent, by_id[parent]

            if found is None and upper in shielded:
                id_pattern = re.compile(rf"\b{re.escape(upper)}\b", re.IGNORECASE)
                if id_pattern.search(combined):
                    matching_sentence = ""
                    for s in sentences(combined):
                        if id_pattern.search(s):
                            matching_sentence = s
                            break
                    if matching_sentence:
                        status, passage = passage_status(
                            matching_sentence, 0, len(matching_sentence), actor_material
                        )
                        if status in ("capability", "negated", "context"):
                            dropped.append(upper)
                            evidence.append(
                                {
                                    "technique_id": upper,
                                    "status": status,
                                    "passage": _clip(passage),
                                    "source": "cti",
                                    "behaviour": "named by ID",
                                }
                            )
                            continue
                        found = TechniqueEvidence(
                            technique_id=upper,
                            status=status,
                            passage=_clip(passage),
                            source="cti",
                            behaviour="named by ID",
                        )
                    else:
                        m = id_pattern.search(combined)
                        assert m is not None
                        start = max(0, m.start() - 50)
                        end = min(len(combined), m.end() + 50)
                        found = TechniqueEvidence(
                            technique_id=upper,
                            status="observed",
                            passage=_clip(combined[start:end]),
                            source="cti",
                            behaviour="named by ID",
                        )
                elif is_otx_pulse:
                    unevidenced.append(upper)
                    continue
                else:
                    found = TechniqueEvidence(
                        technique_id=upper,
                        status="asserted",
                        passage="",
                        source="cti",
                        behaviour="named by ID",
                    )

            if (
                found is None
                and upper.startswith("T1059.")
                and any(
                    e.technique_id.startswith("T1059.") and e.status == "observed"
                    for e in behaviour
                )
            ):
                # A script host is not evidence for a second language. Keep
                # every language the source supports, without adding an
                # unsupported sibling proposed by a model/name matcher.
                unevidenced.append(upper)
                continue

            if found is not None and found.status in ("capability", "negated", "context"):
                dropped.append(upper)
                evidence.append({**found.to_dict(), "technique_id": upper, "status": found.status})
                continue

            if upper in kept:
                continue
            kept.append(upper)
            if found is not None:
                evidence.append({**found.to_dict(), "technique_id": upper})
            elif upper in shielded:
                evidence.append(
                    {
                        "technique_id": upper,
                        "status": "asserted",
                        "passage": "",
                        "source": "cti",
                        "behaviour": "named by ID",
                    }
                )

        if dropped:
            self.trail.step(
                "techniques", "dropped as capability only, not observed use: %s", listing(dropped)
            )
        if unevidenced:
            self.trail.step("techniques", "dropped unevidenced feed tags: %s", listing(unevidenced))
        self._technique_evidence = evidence
        return kept

    def _audit_claims(
        self,
        hypothesis: HypothesisResult,
        source_text: str = "",
        platforms: list[str] | None = None,
    ) -> None:
        """Remove observables that cannot be observed; soften capability stated as fact."""
        from hecate_agent.core.claim_audit import (
            audit_observables,
            audit_prose,
            prose_value_reasons,
        )

        findings = []
        observables = [o for o in hypothesis.observables if o != _NO_OBSERVABLES]
        unobservable = {
            **prose_value_reasons(
                [
                    *observables,
                    hypothesis.hypothesis,
                    hypothesis.justification,
                    hypothesis.behavior,
                    hypothesis.location,
                    hypothesis.evidence,
                ],
                source_text,
                platforms or [],
            ),
            **self._unobservable_values(),
        }
        hypothesis.observables, removed = audit_observables(
            observables, "observables", unobservable
        )
        findings += removed
        hypothesis.false_positives, removed = audit_observables(
            hypothesis.false_positives, "normal baseline"
        )
        findings += removed
        if not hypothesis.observables:
            hypothesis.observables = [_NO_OBSERVABLES]
        on_disk = any(
            r.role == "executable" and r.status != "historical" for r in self._indicator_records
        )
        prose, rewritten = audit_prose(
            {
                "hypothesis": hypothesis.hypothesis,
                "justification": hypothesis.justification,
                "behavior": hypothesis.behavior,
                "location": hypothesis.location,
                "evidence": hypothesis.evidence,
            },
            {t.upper() for t in hypothesis.techniques},
            on_disk,
            source_text=source_text,
            unobservable=unobservable,
        )
        hypothesis.hypothesis = prose["hypothesis"]
        hypothesis.justification = prose["justification"]
        hypothesis.behavior = prose["behavior"]
        hypothesis.location = prose["location"]
        hypothesis.evidence = prose["evidence"]
        findings += rewritten
        findings += self._unsupported_platform_claims(hypothesis)
        self._claim_audit = [f.to_dict() for f in findings]
        if findings:
            counts = Counter(f.action for f in findings)
            self.trail.step(
                "claims",
                "audit: %s",
                ", ".join(f"{n} {action}" for action, n in sorted(counts.items())),
            )

    def _unobservable_values(self) -> dict[str, str]:
        """Values the pipeline already knows no log can show, with the reason."""
        reasons = {
            "memory_only": "exists only in memory; no log records it as a file",
            "network_content": "is network content, not a file on disk; no file or process event carries it",
            "historical": "is historical infrastructure, not this intrusion",
            "non_file": "is a token, key or certificate fingerprint, not the hash of a file",
            "target": "is an address the actor targeted, not infrastructure a host connects to",
            "source_page": "is the source's own page, not an indicator",
            "placeholder": "is a documentation placeholder (example.com), not an indicator",
        }
        out: dict[str, str] = {}
        for record in self._indicator_records:
            why = reasons.get(record.role) or reasons.get(record.status)
            if why:
                out[record.value] = why
        evidence = self._source_evidence
        for artifact in getattr(evidence, "artifacts", []) or []:
            if artifact.status != "active":
                out.setdefault(
                    artifact.value,
                    f"the source does not tie it to this intrusion ({artifact.role or 'no role'})",
                )
        return out

    def _unsupported_platform_claims(self, hypothesis: HypothesisResult) -> list[Any]:
        """Prose naming a platform the specimen's evidence does not show; flagged, not rewritten."""
        from hecate_agent.core.claim_audit import ClaimFinding

        if not self._specimen:
            return []
        flagged = []
        for name, text in (
            ("location", hypothesis.location),
            ("hypothesis", hypothesis.hypothesis),
        ):
            extra = [p for p in platforms_named_in(text) if p not in self._specimen]
            if extra:
                flagged.append(
                    ClaimFinding(
                        name,
                        text,
                        "flagged",
                        f"names {listing(extra)}, but the specimen's evidence shows only "
                        f"{listing(self._specimen)}; the hunt is scoped to the evidence",
                    )
                )
        return flagged

    def _primary_evidence_text(self, item: CTIItem) -> str:
        """The feed item and fetched primary report, excluding generated enrichment."""
        base_text = (
            f"{item.content}\n{self._source_evidence.text}"
            if (self._source_evidence is not None and self._source_evidence.text)
            else item.content
        )
        return base_text

    def _command_text(self, item: CTIItem) -> str:
        """The text whose quoted commands may become process rules."""
        if item.source != "github_poc":
            return self._primary_evidence_text(item)
        from hecate_agent.core.command_rules import without_operator_sections

        evidence = self._source_evidence
        return str(without_operator_sections(evidence.text if evidence is not None else ""))

    def _demote_tooling_artifacts(self, item: CTIItem) -> None:
        """Take a PoC README's own files and test output out of the active evidence."""
        evidence = self._source_evidence
        if item.source != "github_poc" or evidence is None or not evidence.text:
            return
        from hecate_agent.core.command_rules import without_tooling_sections

        def squash(text: str) -> str:
            return " ".join(re.sub(r"[`*]", "", text).split())

        kept = squash(without_tooling_sections(evidence.text))
        demoted = []
        for artifact in evidence.artifacts:
            quote = squash(str(artifact.evidence or "")).rstrip("…").strip()[:80]
            if (
                artifact.status == "active"
                and (quote or artifact.value)
                and (quote or artifact.value) not in kept
            ):
                artifact.status = "unknown"
                if artifact.role == "unknown":
                    artifact.role = "attacker_tooling"
                demoted.append(artifact.value)
        if demoted:
            self.trail.step(
                "source",
                "%d artifact(s) only in the README's usage, lab or file sections: %s",
                len(demoted),
                listing(demoted),
            )

    def _evidence_research_text(self, research_id: str | None) -> str:
        """Return no research text for evidence checks."""
        return ""

    def _gather_source_evidence(self, item: CTIItem) -> None:
        """Fetch the item's report, extract verified evidence, and type its indicators."""
        indicators = dict(item.metadata.get("indicators") or {})
        if not self.settings.source_evidence_enabled:
            return
        if item.source in {
            "lolbas",
            "loldrivers",
            "gtfobins",
            "nuclei",
            "cisa_ics",
            "attack_deltas",
        } or (item.source == "cisa_advisories" and item.metadata.get("structured_document")):
            from hecate_agent.core.source_evidence import SourceArtifact, SourceEvidence

            artifacts = []
            for raw in item.metadata.get("source_artifacts", []):
                value = str(raw.get("value", ""))
                if value and value in item.content:
                    artifacts.append(
                        SourceArtifact(
                            value=value,
                            kind=str(raw.get("kind", "command_line")),
                            role=str(raw.get("role", "documented reference")),
                            status="unknown",
                            evidence=value,
                        )
                    )
            self._source_evidence = SourceEvidence(
                url=item.source_url or "",
                chars=len(item.content),
                chunks=1,
                artifacts=artifacts,
                text=item.content,
            )
            self.trail.step(
                "source",
                "retained structured primary source at revision %s; %d literal artifact(s)",
                str(item.metadata.get("source_revision", ""))[:40],
                len(artifacts),
            )
            return

        from hecate_agent.core.source_evidence import report_urls

        urls = report_urls(item.content, item.source_url)
        if not urls:
            self.trail.step("source", "no report link in the item; drafting from the feed text")
            return
        self.trail.step("source", "starting: reading %s", urls[0])
        started = self.trail.elapsed
        try:
            with self.metrics.measure("source_evidence") as measured:
                import concurrent.futures

                executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                future = executor.submit(self.hecate.source_evidence, urls[0])
                source_timeout_sec = max(900, getattr(self.settings, "llm_timeout_sec", 1500))
                try:
                    evidence = future.result(timeout=source_timeout_sec)
                except concurrent.futures.TimeoutError as exc:
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise TimeoutError(
                        f"Timed out after {source_timeout_sec} seconds reading {urls[0]}"
                    ) from exc

                self._source_evidence = evidence
                try:
                    if evidence.text:
                        self._indicator_records = self.hecate.indicator_records(
                            indicators, evidence
                        )
                finally:
                    metadata: Any = getattr(evidence, "usage_metadata", dict)()
                    if isinstance(metadata, dict) and metadata:
                        measured.set_usage(LLMUsage.from_metadata(metadata))
        except Exception as exc:  # evidence is an aid; never fatal
            log.warning("Source evidence failed for %s: %s", urls[0], exc)
            self.trail.step(
                "source", "failed for %s: %s; drafting from the feed text", urls[0], exc
            )
            return
        if evidence.error and not evidence.artifacts:
            self.trail.step(
                "source", "%s: %s; drafting from the feed text", urls[0], clip(evidence.error, 120)
            )
            return
        typed = [r for r in self._indicator_records if r.role != "unknown" or r.status != "unknown"]
        historical = [r.value for r in self._indicator_records if r.status == "historical"]
        self.trail.step(
            "source",
            "%s (%d chars, %d chunk(s)) in %.0fs: %d artifact(s) verified, %d dropped; "
            "%d/%d indicator(s) typed; historical: %s",
            urls[0],
            evidence.chars,
            evidence.chunks,
            self.trail.elapsed - started,
            len(evidence.artifacts),
            len(evidence.dropped),
            len(typed),
            len(self._indicator_records),
            listing(historical, "none"),
        )
        self._read_detection_guidance(evidence)

    def _observed_commands(self, item: CTIItem, platforms: list[str]) -> list[dict[str, Any]]:
        """Commands the source shows being run, each a process-rule candidate."""
        from hecate_agent.core.command_rules import command_candidates
        from hecate_agent.core.technique_evidence import extract_primary_actor

        primary_actor = (
            extract_primary_actor(self._primary_evidence_text(item))
            or attributed_actor(item.content)
            or None
        )
        candidates: list[dict[str, Any]] = list(
            command_candidates(self._command_text(item), platforms, primary_actor=primary_actor)
        )
        if candidates:
            self.trail.step(
                "sigma",
                "%d command(s) the source shows being run: %s",
                len(candidates),
                listing([str(c.get("title", "")) for c in candidates]),
            )
        return candidates

    def _source_artifacts(self) -> list[dict[str, Any]]:
        """The primary source's verified artifacts, for two-pass Sigma generation."""
        from dataclasses import asdict

        if self._source_evidence is None:
            return []
        return [asdict(a) for a in getattr(self._source_evidence, "artifacts", []) or []]

    def _specimen_platforms(self, item: CTIItem) -> list[str]:
        """Platforms the item and its primary source show in observed activity."""
        from hecate_agent.core.platform_evidence import platform_evidence

        evidence = platform_evidence([self._primary_evidence_text(item)])
        self._platform_evidence = evidence.to_dict()
        supported: list[str] = list(evidence.supported)
        if supported:
            self.trail.step(
                "scope",
                "the specimen's evidence shows %s: %s",
                listing(supported),
                "; ".join(
                    f"{p} ({', '.join(m['marker'] for m in evidence.markers[p][:6])})"
                    for p in supported
                ),
            )
        elif evidence.markers:
            self.trail.step(
                "scope",
                "platform evidence too thin to scope on: %s",
                listing(sorted(evidence.markers)),
            )
        self._specimen = supported
        return supported

    def _read_detection_guidance(self, evidence: Any) -> None:
        """Extract the report's own detection guidance and log where each item can run."""
        from hecate_agent.core.detection_guidance import extract_guidance

        items = extract_guidance(
            getattr(evidence, "text", "") or "", getattr(evidence, "url", "") or ""
        )
        self._detection_guidance = [g.to_dict() for g in items]
        if not items:
            self.trail.step("guidance", "the source publishes no detection guidance section")
            return
        routes = Counter(g.route for g in items)
        candidates = sum(len(g.candidates) for g in items)
        self.trail.step(
            "guidance",
            "%d item(s) from the source: %s; %d Sigma candidate(s)",
            len(items),
            ", ".join(f"{n} {route}" for route, n in sorted(routes.items())),
            candidates,
        )

    def _grounding_section(
        self,
        req: DraftHuntRequest,
        item: CTIItem,
        technique_facts: dict[str, TechniqueFact] | None = None,
    ) -> str:
        """Audit the draft as it currently stands and render the result."""
        previous_section, req.grounding_section = req.grounding_section, ""
        try:
            draft_text = render_draft(req)
        finally:
            req.grounding_section = previous_section

        try:
            with self.metrics.measure("grounding_audit"):
                report = audit_draft(
                    draft_text=draft_text,
                    cti_text=self._primary_evidence_text(item),
                    research_text=self._evidence_research_text(req.research_id),
                    cti_techniques=[str(t) for t in (item.metadata.get("techniques") or [])],
                    technique_facts=technique_facts,
                    hunt_platforms=list(req.platforms),
                    matched_techniques=self._wording_matched,
                )
        except Exception as exc:
            log.warning("Grounding audit failed for %s (%s); section left empty.", req.hunt_id, exc)
            return ""

        tally = report.counts
        self.trail.step(
            "grounding",
            "%s: %d asserted by CTI, %d externally corroborated, %d inferred, %d UNSUPPORTED%s",
            req.hunt_id,
            tally.get("asserted", 0),
            tally.get("corroborated", 0),
            tally.get("derived", 0),
            tally.get("unsupported", 0),
            f" ({listing(c.value for c in report.unsupported)})" if report.unsupported else "",
        )
        if report.unsupported:
            log.warning(
                "%s carries %d claim(s) that trace to no source: %s",
                req.hunt_id,
                len(report.unsupported),
                ", ".join(c.value for c in report.unsupported),
            )
        section: str = render_grounding_section(report)
        if self._unevidenced_dropped:
            section += (
                "\n> Dropped before drafting, because the model proposed them and nothing "
                "in the CTI or research describes them: "
                + ", ".join(f"`{t}`" for t in self._unevidenced_dropped)
                + "\n"
            )
        return section

    def _drop_unevidenced_techniques(
        self,
        techniques: list[str],
        protected: list[str],
        cti_text: str,
        research_text: str,
    ) -> list[str]:
        """Remove model-picked techniques that no source describes."""
        shielded = {t.upper() for t in protected}
        kept: list[str] = []
        self._unevidenced_dropped = []
        for technique_id in techniques:
            upper = technique_id.upper()
            if upper in shielded or upper.split(".")[0] in shielded:
                kept.append(technique_id)
                continue
            meta = self.hecate.lookup_technique(
                technique_id, timeout_sec=self.settings.llm_timeout_sec
            )
            names = tuple(n for n in (meta.name, meta.parent_name) if n)
            if meta.found and technique_lacks_evidence(upper, names, cti_text, research_text):
                self._unevidenced_dropped.append(f"{upper} {meta.name}".strip())
            else:
                kept.append(technique_id)
        if self._unevidenced_dropped:
            self.trail.step(
                "techniques",
                "dropped model picks no source describes: %s",
                listing(self._unevidenced_dropped),
            )
        return kept

    def _research_text(self, research_id: str | None) -> str:
        """Load the linked research document for context or diagnostics only."""
        if not research_id:
            return ""
        path = self.settings.hecate_workspace / "research" / f"{research_id}.md"
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return ""
