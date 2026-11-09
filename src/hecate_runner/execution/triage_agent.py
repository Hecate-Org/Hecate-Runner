"""Autonomous Finding Triage Agent for live hunt execution telemetry.

Ingests normalized SIEM events, evaluates alignment with the hunt hypothesis,
performs noise reduction and heuristic scoring, runs optional LLM evaluation,
and produces a structured FindingTriageReport.
"""

from __future__ import annotations

import json
import logging
import math
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from hecate_agent.core.hunting_knowledge import (
    EVIDENCE_RULES,
    load_environment_context,
    load_stage_guidance,
)

from hecate_runner.config import Settings
from hecate_runner.execution.normalizer import NormalizedEvent, extract_entities_from_events

log = logging.getLogger(__name__)

# Known interactive shells and scripting interpreters
_INTERPRETERS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
    }
)

# Known web servers, daemons, and application runtimes
_SERVER_PARENTS = frozenset(
    {
        "node",
        "node-red",
        "w3wp.exe",
        "httpd",
        "nginx",
        "apache",
        "apache2",
        "tomcat",
        "java",
        "php",
        "php-fpm",
        "gunicorn",
        "uwsgi",
        "mysqld",
        "postgres",
    }
)

# Known Living-off-the-Land Binaries (LOLBins)
_LOLBINS = frozenset(
    {
        "certutil.exe",
        "wmic.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "bitsadmin.exe",
        "curl",
        "wget",
        "nc",
        "netcat",
        "socat",
        "ssh",
        "scp",
    }
)

# Highly suspicious argument patterns
_SUSPICIOUS_CLI_PATTERNS = [
    # Lookbehind: `-enc` is not a word char, so `\b` before the dash never matches.
    re.compile(r"(?<![\w-])(-enc|-encodedcommand)\b", re.IGNORECASE),
    re.compile(r"\b(downloadstring|downloadfile|invoke-expression|\biex\b)\b", re.IGNORECASE),
    re.compile(r"curl\s+-[a-zA-Z]*f.*\|\s*(bash|sh)", re.IGNORECASE),
    re.compile(r"wget\s+-[a-zA-Z]*O.*\|\s*(bash|sh)", re.IGNORECASE),
    re.compile(r"(/dev/shm|/dev/tcp/|/tmp/|\bchmod\s+\+x\b)", re.IGNORECASE),
    re.compile(r"\b(base64\s+-d|certutil\s+-urlcache)\b", re.IGNORECASE),
    re.compile(r"\b(whoami|id|uname\s+-a|cat\s+/etc/shadow|net\s+user)\b", re.IGNORECASE),
]


@dataclass
class FindingTriageReport:
    """Outcome of triaging live telemetry hits against a hunt's hypothesis."""

    hunt_id: str
    sweep_id: str
    target_siem: str
    verdict: str  # "true_positive" | "suspicious" | "benign_noise" | "inconclusive"
    confidence: float  # Uncalibrated 0.0-1.0 assessment/routing score, not a probability
    summary: str
    rationale: str
    technique_matches: list[str] = field(default_factory=list)
    extracted_entities: dict[str, list[str]] = field(default_factory=dict)
    recommended_action: str = "pivot"  # "escalate_to_soc" | "pivot" | "tune_rule" | "ignore"
    event_count: int = 0
    triaged_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    finding_id: str = ""
    confidence_kind: str = "uncalibrated_assessment"
    reviewed_event_count: int = 0
    assessment_source: str = "heuristic"

    @property
    def is_threat(self) -> bool:
        """True if the finding is considered actionable adversary activity."""
        return self.verdict in ("true_positive", "suspicious")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FindingTriageAgent:
    """Evaluates telemetry matches against hunt hypotheses using heuristics & LLM."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()

    def triage(
        self,
        hunt_id: str,
        sweep_id: str,
        target_siem: str,
        events: list[NormalizedEvent],
        *,
        hypothesis: str = "",
        techniques: list[str] | None = None,
    ) -> FindingTriageReport:
        """Perform triage assessment on a set of normalized telemetry events."""
        if not events:
            return FindingTriageReport(
                hunt_id=hunt_id,
                sweep_id=sweep_id,
                target_siem=target_siem,
                verdict="inconclusive",
                confidence=0.0,
                summary="No telemetry events provided for triage.",
                rationale="Empty event list.",
                recommended_action="pivot",
                event_count=0,
            )

        entities = extract_entities_from_events(events)
        target_techniques = list(techniques or [])

        # 1. Deterministic heuristic pre-assessment
        heuristic_report = self._evaluate_heuristics(
            hunt_id=hunt_id,
            sweep_id=sweep_id,
            target_siem=target_siem,
            events=events,
            entities=entities,
            hypothesis=hypothesis,
            known_techniques=target_techniques,
        )

        # 2. If LLM is available and confident enough to refine, try LLM triage
        try:
            llm_report = self._evaluate_llm(
                hunt_id=hunt_id,
                sweep_id=sweep_id,
                target_siem=target_siem,
                events=events,
                entities=entities,
                hypothesis=hypothesis,
                known_techniques=target_techniques,
            )
            if llm_report is not None:
                merged_techniques = sorted(
                    set(llm_report.technique_matches).union(heuristic_report.technique_matches)
                )
                llm_report.technique_matches = merged_techniques
                return llm_report
        except Exception as exc:
            log.debug("LLM triage evaluation skipped or failed (%s); using heuristics", exc)

        return heuristic_report

    def _evaluate_heuristics(
        self,
        hunt_id: str,
        sweep_id: str,
        target_siem: str,
        events: list[NormalizedEvent],
        entities: dict[str, list[str]],
        hypothesis: str,
        known_techniques: list[str],
    ) -> FindingTriageReport:
        """Deterministic heuristic rule evaluation."""
        suspicious_cli_hits = 0
        interpreter_hits = 0
        lolbin_hits = 0
        server_command_hits = 0
        matched_techniques = set(known_techniques)

        for e in events:
            proc_base = (e.process_name.split("/")[-1].split("\\")[-1]).lower()
            parent_base = (e.parent_process.split("/")[-1].split("\\")[-1]).lower()

            server_parent = parent_base in _SERVER_PARENTS
            if any(proc_base == interp for interp in _INTERPRETERS):
                interpreter_hits += 1
                if proc_base in ("sh", "bash", "zsh"):
                    matched_techniques.add("T1059.004")
                elif "powershell" in proc_base or proc_base == "pwsh.exe":
                    matched_techniques.add("T1059.001")
                elif proc_base == "cmd.exe":
                    matched_techniques.add("T1059.003")

            if any(proc_base == lol for lol in _LOLBINS):
                lolbin_hits += 1

            for pat in _SUSPICIOUS_CLI_PATTERNS:
                if pat.search(e.command_line):
                    suspicious_cli_hits += 1
                    if server_parent:
                        server_command_hits += 1
                    break

        total_ev = len(events)

        # A same-event server/command association is a lead, not proof of exploit
        # success or initial access. Never combine unrelated events to assert it.
        if server_command_hits > 0:
            return FindingTriageReport(
                hunt_id=hunt_id,
                sweep_id=sweep_id,
                target_siem=target_siem,
                verdict="suspicious",
                confidence=0.85,
                summary=(
                    "Suspicious application runtime activity: "
                    f"{', '.join(entities.get('parent_processes', [])[:2])} "
                    "is associated with a suspicious command pattern; authorization and outcome need verification."
                ),
                rationale=(
                    f"Detected {server_command_hits} event(s) linking a server parent and suspicious command. "
                    "Heuristics do not establish malicious intent, the entry vector or successful exploitation. "
                    f"Evaluate the hypothesis and benign alternatives: '{hypothesis[:100]}'."
                ),
                technique_matches=sorted(matched_techniques),
                extracted_entities=entities,
                recommended_action="escalate_to_soc",
                event_count=total_ev,
                reviewed_event_count=total_ev,
            )

        # Moderate Confidence: Suspicious commands or LOLBins in environment
        if suspicious_cli_hits > 0 or (interpreter_hits > 0 and lolbin_hits > 0):
            return FindingTriageReport(
                hunt_id=hunt_id,
                sweep_id=sweep_id,
                target_siem=target_siem,
                verdict="suspicious",
                confidence=0.75,
                summary=(
                    f"Suspicious activity detected: {suspicious_cli_hits} event(s) contain "
                    f"adversary command-line patterns or scripting LOLBins."
                ),
                rationale=(
                    f"Command telemetry matches known TTP patterns ({', '.join(sorted(matched_techniques)[:3])}). "
                    f"Pivoting recommended to confirm initial access vector."
                ),
                technique_matches=sorted(matched_techniques),
                extracted_entities=entities,
                recommended_action="pivot",
                event_count=total_ev,
                reviewed_event_count=total_ev,
            )

        # No heuristic match cannot establish a benign baseline or exclude abuse.
        return FindingTriageReport(
            hunt_id=hunt_id,
            sweep_id=sweep_id,
            target_siem=target_siem,
            verdict="inconclusive",
            confidence=0.0,
            summary="No configured heuristic identified suspicious activity; intent remains unverified.",
            rationale=(
                f"Reviewed {total_ev} event(s) without a configured heuristic match. "
                "This does not establish authorized behavior or rule out techniques outside heuristic coverage."
            ),
            technique_matches=sorted(matched_techniques),
            extracted_entities=entities,
            recommended_action="pivot",
            event_count=total_ev,
            reviewed_event_count=total_ev,
        )

    def _evaluate_llm(
        self,
        hunt_id: str,
        sweep_id: str,
        target_siem: str,
        events: list[NormalizedEvent],
        entities: dict[str, list[str]],
        hypothesis: str,
        known_techniques: list[str],
    ) -> FindingTriageReport | None:
        """Call LLM provider to evaluate findings against the hypothesis."""
        try:
            from hecate_agent.core.llm_router import create_router

            provider = create_router()
            # Spread a bounded sample across returned events, while explicitly
            # retaining the fact that it is not a representative population test.
            sample = (
                events
                if len(events) <= 5
                else [events[i * (len(events) - 1) // 4] for i in range(5)]
            )
            sample_data = [
                {
                    "event_id": ev.event_id,
                    "timestamp": ev.timestamp,
                    "host": ev.host,
                    "user": ev.user,
                    "process": ev.process_name,
                    "parent": ev.parent_process,
                    "command_line": ev.command_line,
                    "ip": ev.ip,
                }
                for ev in sample
            ]
            workspace = self.settings.hecate_workspace
            system = (
                f"Evidence rules:\n{EVIDENCE_RULES}\n\n"
                f"{load_stage_guidance('triage', workspace=workspace)}\n\n"
                f"{load_environment_context(workspace=workspace)}"
            )

            prompt = f"""You are an expert Threat Hunter and Incident Responder analyzing live SIEM detection events.

HUNT DETAILS:
- Hunt ID: {hunt_id}
- Hypothesis Statement: {hypothesis}
- MITRE Techniques: {", ".join(known_techniques)}
- SIEM Backend: {target_siem}

SAMPLE TELEMETRY EVENTS ({len(sample)} reviewed of {len(events)} returned events;
upstream population completeness is unverified; this sample is not statistically representative):
{json.dumps(sample_data, ensure_ascii=True)}

Evaluate whether these events corroborate the threat hypothesis or represent benign operational noise.
Only cite supplied event IDs and observed facts. Describe missing context and contrary evidence.
Do not infer malicious success from a command, or benignness from missing heuristic matches.
Do not generalize a benign sample to unreviewed events. Confidence is an uncalibrated
assessment score, not a probability. Any observed technique matches are candidate mappings.
Respond ONLY with a valid JSON object matching this schema:
{{
  "verdict": "true_positive" | "suspicious" | "benign_noise" | "inconclusive",
  "confidence": 0.0 to 1.0,
  "summary": "1-2 sentence executive characterization of the finding",
  "rationale": "Detailed forensic explanation of why this is malicious or benign",
  "technique_matches": ["Txxxx", ...],
  "recommended_action": "escalate_to_soc" | "pivot" | "tune_rule" | "ignore"
}}
"""
            resp = provider.complete(
                [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
                max_tokens=1024,
                temperature=0.1,
                capability="finding_triage",
            )
            text = resp.text.strip()
            # Find JSON object in response
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1:
                data = json.loads(text[start : end + 1])
                verdict = data.get("verdict", "inconclusive")
                action = data.get("recommended_action", "pivot")
                score = float(data.get("confidence", 0.0))
                if verdict not in {"true_positive", "suspicious", "benign_noise", "inconclusive"}:
                    return None
                if action not in {
                    "escalate_to_soc",
                    "pivot",
                    "tune_rule",
                    "ignore",
                } or not math.isfinite(score):
                    return None
                rationale = str(data.get("rationale", ""))
                rationale += (
                    f" Reviewed {len(sample)} of {len(events)} returned events; "
                    "upstream population completeness is unverified. The assessment score is uncalibrated."
                )
                if len(sample) < len(events) and verdict == "benign_noise":
                    verdict = "inconclusive"
                    action = "pivot"
                    rationale += " Only a partial sample was reviewed; unreviewed events cannot be classified as benign."
                return FindingTriageReport(
                    hunt_id=hunt_id,
                    sweep_id=sweep_id,
                    target_siem=target_siem,
                    verdict=verdict,
                    confidence=max(0.0, min(score, 1.0)),
                    summary=str(data.get("summary", "")),
                    rationale=rationale,
                    technique_matches=list(data.get("technique_matches", known_techniques)),
                    extracted_entities=entities,
                    recommended_action=action,
                    event_count=len(events),
                    reviewed_event_count=len(sample),
                    assessment_source="llm",
                )
        except Exception:
            return None
        return None
