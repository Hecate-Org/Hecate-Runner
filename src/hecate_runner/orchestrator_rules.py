"""Sigma rule generation, review gap synthesis, and native SIEM deployment."""

from __future__ import annotations

import logging
import re
import uuid
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from hecate_agent.core.command_rules import command_candidates
from hecate_agent.core.sigma_semantics import repair_sigma_semantics, semantic_problem

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.context_metrics import log_payload_metrics
from hecate_runner.cti import CTIItem
from hecate_runner.cti.reference_rules import reference_candidates
from hecate_runner.hecate_client import HecateError
from hecate_runner.hunt_writer import DraftHuntRequest, render_draft
from hecate_runner.native_queries import transpile_and_write_native
from hecate_runner.orchestrator_derivations import _RULE_IOC_RE
from hecate_runner.trail import clip, listing

if TYPE_CHECKING:
    from hecate_agent.core.grounding import TechniqueFact

log = logging.getLogger("hecate_runner.orchestrator")


class OrchestratorRulesMixin:
    """Mixin for multi-pass Sigma rule generation, reviewer gap synthesis, and deployment."""

    settings: Any
    hecate: Any
    trail: Any
    metrics: Any
    _indicator_records: list[Any]
    _source_evidence: Any
    _detection_guidance: list[dict[str, Any]]

    # Provided by OrchestratorGroundingMixin / Orchestrator
    _primary_evidence_text: Any
    _command_text: Any
    _unobservable_values: Any
    _source_artifacts: Any
    _observed_commands: Any
    _grounding_section: Any
    _run_purple_team_validation: Any
    _run_bas_validation: Any

    def _log_query_literals(self, artifacts: list[dict[str, Any]], platforms: list[str]) -> None:
        """Pass one of rule generation: the exact values rules may match."""
        from hecate_agent.core.query_literals import literals_from_artifacts

        literals = literals_from_artifacts(artifacts, platforms)
        if literals:
            self.trail.step(
                "sigma",
                "pass 1: %d exact value(s) from the source rules may match: %s",
                len(literals),
                listing([lit.sigma for lit in literals]),
            )
        else:
            self.trail.step(
                "sigma", "pass 1: no verified source values; model rules are not held to a list"
            )

    def _log_rule_review(self, rules: list[dict[str, Any]], gaps: list[dict[str, str]]) -> None:
        """A2: what the reviewer said about each model rule, and what no rule covers."""
        if not self.settings.sigma_review_enabled:
            return

        verdicts: list[str] = []
        for rule in rules:
            try:
                review = (yaml.safe_load(str(rule.get("rule_yaml", ""))) or {}).get("hecate_review")
            except yaml.YAMLError:
                continue
            if review:
                verdicts.append(f"{rule.get('title', 'untitled')}: {review.get('verdict')}")
        self.trail.step(
            "review",
            "%d model rule(s) reviewed%s; %d uncovered behaviour(s)%s",
            len(verdicts),
            f" ({'; '.join(verdicts)})" if verdicts else "",
            len(gaps),
            f": {listing([g.get('behaviour', '') for g in gaps])}" if gaps else "",
        )

    def _audit_rule_provenance(self, rules: list[dict[str, Any]]) -> None:
        """Every address and hash a rule matches must say where it came from.

        Rules carry a ``hecate_provenance`` list (role, status, source and the
        typing passage per indicator). The generator already rejects invented
        indicators; an address or hash with no entry here means one slipped
        through, and the reviewer is told which.
        """
        import ipaddress

        rfc1918_nets = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
        )

        traced = 0
        untraced: list[str] = []
        for rule in rules:
            try:
                document = yaml.safe_load(str(rule.get("rule_yaml", ""))) or {}
            except yaml.YAMLError:
                continue
            known = {
                str(e.get("value", "")).lower() for e in document.get("hecate_provenance") or []
            }
            traced += len(known)
            category = str((document.get("logsource") or {}).get("category", "")).lower()
            text = yaml.safe_dump(document.get("detection") or {}).lower()
            for value in set(_RULE_IOC_RE.findall(text)):
                # In host events (such as process_creation command lines), private RFC 1918
                # IPs represent internal target hosts, not external threat infrastructure.
                try:
                    ip_obj = ipaddress.ip_address(value)
                    if category != "network_connection" and any(
                        ip_obj in net for net in rfc1918_nets
                    ):
                        continue
                except ValueError:
                    pass
                if not any(value in k or k in value for k in known if k):
                    untraced.append(f"{value} ({rule.get('title', 'untitled')})")
        if untraced:
            self.trail.step(
                "provenance", "untraced indicator(s) in rules: %s", listing(sorted(untraced))
            )
            log.warning(
                "Sigma rules match indicators with no provenance: %s", ", ".join(sorted(untraced))
            )
        else:
            self.trail.step(
                "provenance",
                "%d indicator(s) across %d rule(s), each traced to its source",
                traced,
                len(rules),
            )

    def _generate_pass2_uncovered_rules(
        self,
        req: DraftHuntRequest,
        gaps: list[dict[str, str]],
        item: CTIItem,
        out_dir: Path,
        existing_rules: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Pass 2 (Iterative Uncovered Behavior Pass).

        Extracts unmapped commands, utilities, and concrete observables from
        the review gaps (uncovered behaviors) and synthesizes targeted Sigma rules.
        """
        pass2_rules: list[dict[str, Any]] = []
        covered_titles = {str(r.get("title", "")).lower() for r in existing_rules}

        # Gather text from all uncovered gaps
        gap_texts = [f"{g.get('behaviour', '')} {g.get('quote', '')}".strip() for g in gaps]
        combined_gap_text = "\n".join(gap_texts)
        if not combined_gap_text.strip():
            return []

        # Find command candidates from gap text or primary text that match the gaps
        candidates = list(command_candidates(combined_gap_text, platforms=req.platforms))
        primary_candidates = list(
            command_candidates(self._command_text(item), platforms=req.platforms)
        )
        for cand in primary_candidates:
            prog = cand.get("title", "").split()[0].lower()
            if prog in combined_gap_text.lower() and not any(
                c.get("title") == cand.get("title") for c in candidates
            ):
                candidates.append(cand)

        for candidate in candidates:
            title = str(candidate.get("title", "")).strip()
            if not title:
                continue
            full_title = f"Command the source shows being run: {title}"
            if full_title.lower() in covered_titles or title.lower() in covered_titles:
                continue

            detection = dict(candidate.get("detection") or {})
            detection, _ = repair_sigma_semantics(detection)
            cat = str(candidate.get("category", "process_creation"))
            problem = semantic_problem(detection, cat, title)
            if problem:
                continue

            # Determine product (linux vs windows)
            cand_platform = candidate.get("platform")
            if not cand_platform:
                sel = detection.get("selection") or {}
                img = str(sel.get("Image|endswith", ""))
                cmd_val = str(candidate.get("command", ""))
                if img.startswith("/") or any(
                    u in cmd_val or u in img for u in ("nsenter", "bpftool", "bash", "sh", "kprobe")
                ):
                    cand_platform = "linux"

            logsource: dict[str, str] = {"category": cat}
            if cand_platform in ("linux", "unix"):
                logsource["product"] = "linux"
            elif cand_platform == "windows":
                logsource["product"] = "windows"

            techs = list(req.hypothesis.techniques)
            document = {
                "title": full_title[:120],
                "id": str(uuid.uuid4()),
                "status": "experimental",
                "description": (
                    f"Pass 2 rule auto-generated for uncovered behavior: "
                    f'The source shows this command being run: "{candidate.get("command", "")}".'
                ),
                "references": [item.source_url] if item.source_url else [],
                "author": "hecate (auto-generated pass 2 from uncovered review behaviors - requires analyst review)",
                "date": date.today().isoformat(),
                "tags": [f"attack.{t.lower()}" for t in techs],
                "logsource": logsource,
                "detection": detection,
                "falsepositives": ["Legitimate administration or automation matching the command"],
                "level": str(candidate.get("level", "medium")),
            }
            if req.hunt_id:
                document["hunt_id"] = req.hunt_id

            rule_yaml = yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=100)

            # Write rule to out_dir
            out_dir.mkdir(parents=True, exist_ok=True)
            slug = "".join(c if c.isalnum() else "_" for c in full_title.lower())
            slug = "_".join(part for part in slug.split("_") if part)[:60]
            base_fname = f"{cat}__{slug or 'rule'}.yml"
            rule_path = out_dir / base_fname
            counter = 2
            while rule_path.exists():
                rule_path = out_dir / f"{base_fname[:-4]}_{counter}.yml"
                counter += 1

            try:
                # Defer native transpile to the single post-purple/BAS pass in
                # ``_attach_sigma_rules`` so each rule converts once.
                rule_path.write_text(rule_yaml, encoding="utf-8")
            except OSError as exc:
                log.warning("Failed to write Pass 2 rule to %s: %s", rule_path, exc)
                continue

            pass2_rules.append(
                {
                    "logsource_category": cat,
                    "title": full_title[:120],
                    "level": document["level"],
                    "techniques": techs,
                    "rule_yaml": rule_yaml,
                    "path": str(rule_path),
                }
            )
            covered_titles.add(full_title.lower())
            covered_titles.add(title.lower())

        # Extract unmapped file path candidates from gaps and artifacts
        primary_text = self._primary_evidence_text(item)
        file_path_candidates: set[str] = set()

        # Artifacts from source evidence
        if self._source_evidence and self._source_evidence.artifacts:
            for art in self._source_evidence.artifacts:
                if (
                    getattr(art, "kind", "") == "file_path"
                    and getattr(art, "status", "") == "active"
                    and getattr(art, "role", "") != "attacker-side"
                ):
                    val = str(getattr(art, "value", "") or "").strip()
                    if val:
                        file_path_candidates.add(val)

        # Regex patterns for concrete Linux & Windows paths
        linux_paths = re.findall(
            r"(?:/etc/(?:cron[^\s\"';<>]+|systemd[^\s\"';<>]+)|/dev/shm/[^\s\"';<>]+|/sys/fs/bpf/[^\s\"';<>]+|/tmp/[^\s\"';<>]+|/var/tmp/[^\s\"';<>]+|/usr/local/bin/[^\s\"';<>]+)",
            combined_gap_text + "\n" + primary_text,
        )
        windows_paths = re.findall(
            r"(?:[A-Za-z]:\\[A-Za-z0-9_.\-\\]+|\\Tasks\\[A-Za-z0-9_.\-\\]+)",
            combined_gap_text + "\n" + primary_text,
        )
        for p in linux_paths + windows_paths:
            cleaned_p = p.strip(".,;:\"'()[]`")
            if cleaned_p and len(cleaned_p) > 5 and not cleaned_p.endswith(("/", "\\")):
                file_path_candidates.add(cleaned_p)

        gap_lower = combined_gap_text.lower()
        file_gap_keywords = (
            "file",
            "cron",
            "script",
            "staged",
            "persist",
            "driver",
            "drop",
            "directory",
            "delete",
            "remove",
            "elf",
            "payload",
            "temporary",
            "bastion",
            "stage",
        )
        has_file_gap = any(k in gap_lower for k in file_gap_keywords)

        def is_path_covered(fp: str) -> bool:
            fp_low = fp.lower()
            for r in existing_rules:
                if fp_low in str(r.get("title", "")).lower():
                    return True
                ryaml = str(r.get("rule_yaml", "")).lower()
                if "targetfilename" in ryaml and fp_low in ryaml:
                    return True
            for r in pass2_rules:
                if fp_low in str(r.get("title", "")).lower():
                    return True
                ryaml = str(r.get("rule_yaml", "")).lower()
                if "targetfilename" in ryaml and fp_low in ryaml:
                    return True
            return False

        if has_file_gap:
            blocked_values = {value.lower() for value in self._unobservable_values()}
            for path_cand in sorted(file_path_candidates):
                p_lower = path_cand.lower()
                if p_lower in blocked_values:
                    continue  # Pass 2 must preserve the primary source's exclusions.

                # Check relevance to gap: exact match in gap text or semantic match with gap concepts
                relevant = (
                    p_lower in gap_lower
                    or ("cron" in gap_lower and "cron" in p_lower)
                    or (
                        any(k in gap_lower for k in ("elf", "staged", "remove", "delete"))
                        and any(ext in p_lower for ext in (".o", "/dev/shm", "/tmp"))
                    )
                    or (
                        any(k in gap_lower for k in ("staging", "bastion", "temporary", "stage"))
                        and any(k in p_lower for k in ("stage", "tmp"))
                    )
                    or (
                        any(k in gap_lower for k in ("driver", "byovd", "service"))
                        and ".sys" in p_lower
                    )
                )

                if not relevant or is_path_covered(path_cand):
                    continue

                full_title = f"File event for uncovered artifact path: {path_cand}"
                if full_title.lower() in covered_titles:
                    continue

                cat = "file_event"
                if path_cand.startswith("/"):
                    cand_product = "linux"
                elif "\\" in path_cand:
                    cand_product = "windows"
                else:
                    scoped = {p.lower() for p in req.platforms}
                    if len(scoped) != 1 or not scoped <= {"linux", "windows", "macos"}:
                        continue  # A bare filename cannot determine the endpoint OS.
                    cand_product = next(iter(scoped))
                logsource_block: dict[str, str] = {"category": cat, "product": cand_product}

                detection = {
                    "selection": {"TargetFilename|contains": path_cand},
                    "condition": "selection",
                }
                detection, _ = repair_sigma_semantics(detection)
                problem = semantic_problem(detection, cat, full_title)
                if problem:
                    continue

                techs = list(req.hypothesis.techniques)
                if "cron" in p_lower and "T1053.003" not in techs:
                    techs.append("T1053.003")
                elif ".sys" in p_lower and "T1068" not in techs:
                    techs.append("T1068")

                document = {
                    "title": full_title[:120],
                    "id": str(uuid.uuid4()),
                    "status": "experimental",
                    "description": (
                        f"Pass 2 rule auto-generated for uncovered behavior: "
                        f"Detects file creation, modification, or artifact staging at '{path_cand}'."
                    ),
                    "references": [item.source_url] if item.source_url else [],
                    "author": "hecate (auto-generated pass 2 from uncovered review behaviors - requires analyst review)",
                    "date": date.today().isoformat(),
                    "tags": [f"attack.{t.lower()}" for t in techs],
                    "logsource": logsource_block,
                    "detection": detection,
                    "falsepositives": [
                        "Legitimate system administration or authorized tool activity matching the path"
                    ],
                    "level": "high",
                }
                if req.hunt_id:
                    document["hunt_id"] = req.hunt_id

                rule_yaml = yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=100)

                out_dir.mkdir(parents=True, exist_ok=True)
                slug = "".join(c if c.isalnum() else "_" for c in path_cand.lower())
                slug = "_".join(part for part in slug.split("_") if part)[:60]
                base_fname = f"{cat}__{slug or 'rule'}.yml"
                rule_path = out_dir / base_fname
                counter = 2
                while rule_path.exists():
                    rule_path = out_dir / f"{base_fname[:-4]}_{counter}.yml"
                    counter += 1

                try:
                    # Defer native transpile to the single post-purple/BAS pass.
                    rule_path.write_text(rule_yaml, encoding="utf-8")
                except OSError as exc:
                    log.warning("Failed to write Pass 2 rule to %s: %s", rule_path, exc)
                    continue

                pass2_rules.append(
                    {
                        "logsource_category": cat,
                        "title": full_title[:120],
                        "level": document["level"],
                        "techniques": techs,
                        "rule_yaml": rule_yaml,
                        "path": str(rule_path),
                    }
                )
                covered_titles.add(full_title.lower())

        return pass2_rules

    def _attach_sigma_rules(
        self,
        req: DraftHuntRequest,
        path: Path,
        item: CTIItem,
        technique_facts: dict[str, TechniqueFact] | None = None,
    ) -> None:
        """Draft Sigma rules for the hunt and rewrite the draft to include them."""
        import json

        techniques = list(req.hypothesis.techniques)
        indicators = dict(item.metadata.get("indicators") or {})
        from hecate_agent.core.provenance import mark_placeholders, mark_source_pages

        own = mark_source_pages(
            self._indicator_records,
            [item.source_url, getattr(self._source_evidence, "url", "")],
        )
        if own:
            self.trail.step("sigma", "no rules for the source's own pages: %s", listing(own))
        placeholders = mark_placeholders(self._indicator_records)
        if placeholders:
            self.trail.step(
                "sigma", "no rules for documentation placeholders: %s", listing(placeholders)
            )
        records = [r.to_dict() for r in self._indicator_records]
        if records:
            # The model may only use indicators a rule can observe; historical
            # hosts and in-memory hashes are then rejected as invented.
            from hecate_agent.core.provenance import routable_indicators

            indicators = routable_indicators(self._indicator_records)
        # Artifacts on the actor's own machine are not something this hunt can observe.
        source_observables = (
            [a.value for a in self._source_evidence.behaviours if a.role != "attacker-side"]
            if self._source_evidence is not None
            else []
        )
        out_dir = self.settings.hecate_workspace / "queries" / req.hunt_id

        payload = {
            "hunt_id": req.hunt_id,
            "threat_intel": item.content,
            "hypothesis": req.hypothesis.hypothesis,
            "justification": req.hypothesis.justification,
            "techniques": techniques,
            "platforms": req.platforms,
            "indicators": indicators,
            "references": [item.source_url] if item.source_url else [],
            "observables": [
                o
                for o in [*req.hypothesis.observables, req.hypothesis.evidence, *source_observables]
                if o and o.strip()
            ],
            "indicator_records": records,
            "detection_guidance": self._detection_guidance,
            "source_artifacts": self._source_artifacts(),
            "review_rules": self.settings.sigma_review_enabled,
            "observed_commands": []
            if item.metadata.get("reference_only")
            else self._observed_commands(item, req.platforms),
            "reference_candidates": reference_candidates(item.metadata),
        }

        payload_str = json.dumps(payload)
        log_payload_metrics("sigma_generation", payload_str, self.settings.hecate_llm_model)

        self._log_query_literals(self._source_artifacts(), req.platforms)
        self.trail.step(
            "sigma",
            "drafting rules from techniques %s, indicator types %s, platforms %s",
            listing(techniques),
            listing(indicators.keys()),
            listing(req.platforms, "unscoped"),
        )
        sigma_started = self.trail.elapsed
        try:
            with self.metrics.measure("sigma_generation") as measured:
                result = self.hecate.sigma_generator(
                    payload, out_dir, timeout_sec=self.settings.sigma_timeout_sec
                )
                measured.set_usage(result.usage)
                if not result.success or not result.rules:
                    measured.set_status("partial")
        except HecateError as exc:
            self.trail.step(
                "sigma",
                "no rules after %.0fs: %s",
                self.trail.elapsed - sigma_started,
                clip(str(exc), 160),
            )
            log.warning(
                "Sigma drafting failed for %s (%s); draft keeps its placeholder query section.",
                req.hunt_id,
                exc,
            )
            return

        real_rejections = [
            r for r in result.rejected if "no rule returned" not in r and "unsupported" not in r
        ]
        omitted = getattr(result, "omitted", []) or [
            r for r in result.rejected if "no rule returned" in r or "unsupported" in r
        ]
        for reason in real_rejections:
            self.trail.step("sigma", "rejected %s", clip(reason, 160))
            log.info("Sigma rule rejected for %s: %s", req.hunt_id, reason)
        for note in omitted:
            log.debug("Sigma log source omitted for %s: %s", req.hunt_id, note)

        self.trail.step(
            "sigma",
            "done in %.0fs: %d rule(s) kept (%s), %d rejected",
            self.trail.elapsed - sigma_started,
            len(result.rules or []),
            listing(sorted({str(r.get("logsource_category")) for r in result.rules or []})),
            len(real_rejections),
        )

        self._audit_rule_provenance(result.rules or [])
        self._log_rule_review(result.rules or [], result.review_gaps)

        if not result.success or not result.rules:
            log.warning(
                "Sigma drafting produced no usable rules for %s (%s); draft keeps its placeholder query section.",
                req.hunt_id,
                result.error or "no rules returned",
            )
            return

        if result.review_gaps:
            pass2_rules = self._generate_pass2_uncovered_rules(
                req, result.review_gaps, item, out_dir, result.rules
            )
            if pass2_rules:
                result.rules.extend(pass2_rules)
                self.trail.step(
                    "sigma",
                    "pass 2: generated %d rule(s) for uncovered behaviors: %s",
                    len(pass2_rules),
                    listing([str(r.get("title", "")) for r in pass2_rules]),
                )

        if self.settings.purple_team_validation_enabled:
            self._run_purple_team_validation(req, result.rules, out_dir, item)

        if getattr(self.settings, "bas_enabled", False):
            self._run_bas_validation(req, result.rules, out_dir, item)

        for warning in result.warnings:
            if "no rule returned" in warning or "unsupported" in warning:
                log.debug("Sigma drafting note for %s: %s", req.hunt_id, warning)
            else:
                log.info("Sigma drafting note for %s: %s", req.hunt_id, warning)

        self.metrics.sigma_rules_produced += len(result.rules)
        req.sigma_rules = result.rules
        req.review_gaps = result.review_gaps

        # Single native transpile pass after purple/BAS may have tuned YAML.
        for r_entry in result.rules:
            r_yaml = r_entry.get("rule_yaml")
            r_path_str = r_entry.get("path")
            r_path = Path(r_path_str) if r_path_str else None
            if not r_path or not r_path.is_file():
                cat = str(r_entry.get("logsource_category", "rule"))
                title = str(r_entry.get("title", "rule"))
                slug = "".join(c if c.isalnum() else "_" for c in title.lower())
                slug = "_".join(part for part in slug.split("_") if part)[:60]
                r_path = out_dir / f"{cat}__{slug or 'rule'}.yml"
            if r_yaml and r_path.parent.exists():
                try:
                    r_entry["_transpile"] = transpile_and_write_native(r_path, r_yaml)
                except Exception as t_err:
                    log.debug("Native EDR query generation for %s skipped (%s)", r_path.name, t_err)

        if getattr(self.settings, "siem_deploy_enabled", False):
            req.siem_deployments = self._deploy_native_queries(req, result.rules, out_dir)
        if getattr(self.settings, "lab_hit_probe_enabled", True):
            req.lab_probe = self._probe_lab_hits(req, out_dir)
        try:
            req.sigma_rule_dir = str(out_dir.relative_to(self.settings.hecate_workspace))
        except ValueError:  # out_dir outside the workspace -- show it whole
            req.sigma_rule_dir = str(out_dir)

        # Re-audit: the rules just added are themselves claims, and a rule
        # matching a C2 domain no source mentions is exactly what the audit
        # exists to surface.
        req.grounding_section = self._grounding_section(req, item, technique_facts)
        try:
            atomic_write_text(path, render_draft(req))
        except OSError as exc:
            log.warning(
                "Generated %d Sigma rule(s) for %s but could not rewrite the draft (%s); "
                "the rule files are still at %s.",
                len(result.rules),
                req.hunt_id,
                exc,
                out_dir,
            )
            return

        log.info(
            "Attached %d Sigma rule(s) to %s covering %s",
            len(result.rules),
            req.hunt_id,
            ", ".join(sorted({str(r.get("logsource_category")) for r in result.rules})),
        )

    def _probe_lab_hits(self, req: DraftHuntRequest, out_dir: Path) -> dict[str, Any]:
        """Run drafted native queries against the configured lab SIEM (COUNT-FIRST)."""
        from hecate_runner.lab_hits import probe_lab_hits

        try:
            report = probe_lab_hits(
                req.hunt_id,
                out_dir,
                provider_name=self.settings.query_provider,
                hecate_bin=self.settings.hecate_bin_resolved,
                workspace=self.settings.hecate_workspace,
                max_time_range_days=self.settings.max_query_time_range_days,
                max_limit=self.settings.max_query_limit,
                env_overrides=self.settings.query_provider_env(),
                window_days=getattr(self.settings, "lab_hit_probe_window_days", 1),
                max_auto_fetch=getattr(self.settings, "auto_hunt_max_fetch", 200),
            )
        except Exception as exc:
            log.warning("Lab hit probe skipped for %s (%s)", req.hunt_id, exc)
            return {
                "provider": self.settings.query_provider,
                "window_days": getattr(self.settings, "lab_hit_probe_window_days", 1),
                "status": "error",
                "total_hits": 0,
                "queries_run": 0,
                "detail": str(exc)[:240],
                "results": [],
            }

        self.trail.step(
            "lab",
            "probe on %s: %s (%s)",
            report.provider,
            report.status,
            report.detail or "no detail",
        )
        return report.to_dict()

    def _deploy_native_queries(
        self,
        req: DraftHuntRequest,
        rules: list[dict[str, Any]],
        out_dir: Path,
    ) -> list[dict[str, Any]]:
        """Deploy or simulate deployment of transpiled queries to target SIEM/EDR platforms."""
        from hecate_agent.api import deploy_transpiled_query

        deploy_results = []
        is_dry_run = getattr(self.settings, "siem_deploy_dry_run", True)

        for rule in rules:
            r_yaml = rule.get("rule_yaml")
            title = str(rule.get("title") or req.hunt_id)
            if not r_yaml:
                continue

            try:
                trans_queries = rule.get("_transpile")
                if not isinstance(trans_queries, dict):
                    from hecate_agent.api import transpile_sigma_rule

                    trans_queries = transpile_sigma_rule(r_yaml)
                for target, t_res in trans_queries.items():
                    if getattr(t_res, "success", False) and getattr(t_res, "query", None):
                        res = deploy_transpiled_query(
                            target=target,
                            query=t_res.query,
                            hunt_id=req.hunt_id,
                            title=title,
                            description=f"Auto-generated query for {req.hunt_id}",
                            techniques=rule.get("techniques") or [],
                            dry_run=is_dry_run,
                        )
                        deploy_results.append(res)
            except Exception as d_err:
                log.warning("Query deployment skipped for %s (%s)", title, d_err)

        if deploy_results:
            statuses = [f"{r.get('target')}:{r.get('status')}" for r in deploy_results]
            self.trail.step(
                "deploy", "processed %d query(s): %s", len(deploy_results), listing(statuses)
            )
            log.info("SIEM/EDR query deployment for %s: %s", req.hunt_id, ", ".join(statuses))

        return deploy_results
