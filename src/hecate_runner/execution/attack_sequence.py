"""Correlated Attack-Sequence Engine for Composite Hunt Sweeps.

Classifies hunting detection queries into kill-chain attack stages,
executes composite multi-stage sweeps, and correlates cross-source
telemetry events into coherent attack chains across temporal windows.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hecate_runner.execution.normalizer import NormalizedEvent

log = logging.getLogger(__name__)


class AttackStage(str, Enum):
    """Normalized MITRE ATT&CK kill-chain progression stages."""

    RECON_DELIVERY = "recon_delivery"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE_EVASION = "persistence_evasion"
    COMMAND_AND_CONTROL = "command_and_control"
    DISCOVERY_CREDENTIALS = "discovery_credentials"

    @property
    def order(self) -> int:
        """Sequential ordering across an attack progression."""
        _ORDER = {
            AttackStage.RECON_DELIVERY: 1,
            AttackStage.INITIAL_ACCESS: 2,
            AttackStage.EXECUTION: 3,
            AttackStage.PERSISTENCE_EVASION: 4,
            AttackStage.COMMAND_AND_CONTROL: 5,
            AttackStage.DISCOVERY_CREDENTIALS: 6,
        }
        return _ORDER.get(self, 99)

    @property
    def label(self) -> str:
        """Human-readable display label."""
        _LABELS = {
            AttackStage.RECON_DELIVERY: "Recon & Delivery",
            AttackStage.INITIAL_ACCESS: "Initial Access & Exploitation",
            AttackStage.EXECUTION: "Process Execution & Tool Transfer",
            AttackStage.PERSISTENCE_EVASION: "Persistence & Defense Evasion",
            AttackStage.COMMAND_AND_CONTROL: "Command & Control / Exfiltration",
            AttackStage.DISCOVERY_CREDENTIALS: "Discovery & Credential Access",
        }
        return _LABELS.get(self, self.value)


# Rules to classify queries by filename pattern or detection keywords.
# Note: Specific technique behaviors (persistence, discovery, C2) are evaluated before
# generic log sources (process_creation, file_event) so that commands like
# process_creation__whoami_discovery are correctly categorized as DISCOVERY.
_STAGE_PATTERNS: list[tuple[re.Pattern, AttackStage]] = [
    # Specific Behavioral Techniques
    (re.compile(r"keychain|shadow|sam_|whoami|system_profiler|ioreg_|credential|discovery", re.IGNORECASE), AttackStage.DISCOVERY_CREDENTIALS),
    (re.compile(r"launchagent|launchdaemon|launchctl|cron_|cron\.d|systemd|registry_|startup|plist|chmod_|xattr_|persistence", re.IGNORECASE), AttackStage.PERSISTENCE_EVASION),
    (re.compile(r"c2_|beacon|outbound_|connect_to", re.IGNORECASE), AttackStage.COMMAND_AND_CONTROL),
    (re.compile(r"exploit|cve_|cve-|\/v2\/|\/flows", re.IGNORECASE), AttackStage.INITIAL_ACCESS),
    (re.compile(r"phish|email|attachment|spearphish", re.IGNORECASE), AttackStage.RECON_DELIVERY),
    (re.compile(r"curl_|wget_|bash_|sh_|powershell|cmd_|exec_|shell_process", re.IGNORECASE), AttackStage.EXECUTION),

    # Log Source Categories (if no specific technique matched)
    (re.compile(r"dns_query|dns_lookup|domain_named|proxy", re.IGNORECASE), AttackStage.RECON_DELIVERY),
    (re.compile(r"webserver|http_request", re.IGNORECASE), AttackStage.INITIAL_ACCESS),
    (re.compile(r"network_connection", re.IGNORECASE), AttackStage.COMMAND_AND_CONTROL),
    (re.compile(r"file_event|file_creation", re.IGNORECASE), AttackStage.PERSISTENCE_EVASION),
    (re.compile(r"process_creation", re.IGNORECASE), AttackStage.EXECUTION),
]


def classify_query_stage(query_file: str, query_text: str = "") -> AttackStage:
    """Classify a query into an attack progression stage.

    Uses query filename conventions first, then query syntax keywords.
    """
    clean_name = Path(query_file).name.lower()
    for pattern, stage in _STAGE_PATTERNS:
        if pattern.search(clean_name):
            return stage

    # Fallback to query body keywords
    text_lower = query_text.lower()
    for pattern, stage in _STAGE_PATTERNS:
        if pattern.search(text_lower):
            return stage

    return AttackStage.EXECUTION


def sort_and_group_queries(query_files: list[Path]) -> list[dict[str, Any]]:
    """Sort and stage queries in chronological kill-chain progression order.

    Deduplicates rules with the same stem across dialect extensions (e.g. .spl vs .kql).
    """
    stages: list[dict[str, Any]] = []
    seen_stems: set[str] = set()

    for qf in query_files:
        if qf.stem in seen_stems:
            continue
        seen_stems.add(qf.stem)

        try:
            q_text = qf.read_text(encoding="utf-8").strip()
        except Exception:
            q_text = ""

        stage = classify_query_stage(qf.name, q_text)
        stages.append(
            {
                "query_file": qf.name,
                "query_text": q_text,
                "path": str(qf.resolve()),
                "stage": stage.value,
                "stage_label": stage.label,
                "stage_order": stage.order,
            }
        )

    # Sort primarily by stage progression order, secondarily by query filename
    stages.sort(key=lambda s: (s["stage_order"], s["query_file"]))
    return stages


def build_composite_query_preview(stage_items: list[dict[str, Any]]) -> str:
    """Build a multi-stage summary preview string for CLI and notifications."""
    if not stage_items:
        return "No queries staged."

    lines = [f"[Composite Attack Sequence: {len(stage_items)} Stages]"]
    for idx, item in enumerate(stage_items, 1):
        lines.append(f"  {idx}. [{item.get('stage_label', 'Stage')}] {item.get('query_file')}")
    return "\n".join(lines)


@dataclass
class CorrelatedSequenceStep:
    """One observed event step in an attack sequence."""

    stage: str
    stage_label: str
    timestamp: str
    delta_seconds: float
    description: str
    event_id: str
    raw_query_file: str = ""


@dataclass
class CorrelatedSequence:
    """A verified multi-stage attack sequence correlating telemetry across stages."""

    hunt_id: str
    entity_type: str  # "host", "user", "ip"
    entity_value: str
    stages: list[str]
    steps: list[CorrelatedSequenceStep]
    total_span_seconds: float
    is_confirmed_sequence: bool
    confidence_boost: float = 0.0

    @property
    def distinct_stages_count(self) -> int:
        return len(set(self.stages))


def _parse_event_dt(ts_str: str) -> datetime | None:
    """Safely parse diverse timestamp strings into a datetime object."""
    if not ts_str:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            # Normalize trailing 'Z' if present
            clean = ts_str.replace("Z", "+00:00") if "Z" in ts_str else ts_str
            return datetime.fromisoformat(clean)
        except Exception:
            continue
    return None


def correlate_events_into_sequences(
    events: list[NormalizedEvent],
    *,
    max_window_sec: int = 3600,
) -> list[CorrelatedSequence]:
    """Group normalized events by shared entity and evaluate multi-stage correlation.

    An attack sequence is confirmed when an entity exhibits events across
    two or more distinct kill-chain stages within ``max_window_sec``.
    """
    if not events:
        return []

    # 1. Group events by primary entity (host preferred, user/ip fallback)
    entity_groups: dict[tuple[str, str], list[NormalizedEvent]] = {}
    for ev in events:
        group_key: tuple[str, str] | None = None
        if ev.host:
            group_key = ("host", ev.host)
        elif ev.user and ev.user not in ("root", "system", "administrator"):
            group_key = ("user", ev.user)
        elif ev.ip and not ev.ip.startswith(("127.", "0.", "169.254.")):
            group_key = ("ip", ev.ip)

        if group_key is not None:
            entity_groups.setdefault(group_key, []).append(ev)

    confirmed_sequences: list[CorrelatedSequence] = []

    for (ent_type, ent_val), ev_list in entity_groups.items():
        # Sort chronologically
        parsed_events: list[tuple[datetime, NormalizedEvent]] = []
        for e in ev_list:
            dt = _parse_event_dt(e.timestamp) or datetime.min
            parsed_events.append((dt, e))

        parsed_events.sort(key=lambda t: t[0])

        steps: list[CorrelatedSequenceStep] = []
        stages_seen: list[str] = []
        first_dt: datetime | None = None

        for dt, e in parsed_events:
            stage_val = ""
            if e.stage:
                stage_val = e.stage.value if isinstance(e.stage, AttackStage) else str(e.stage).lower()
            elif e.query_file:
                stage_val = classify_query_stage(e.query_file).value

            if not stage_val or stage_val not in AttackStage._value2member_map_:
                continue

            stage_enum = AttackStage(stage_val)

            if first_dt is None and dt != datetime.min:
                first_dt = dt
            delta_sec = (dt - first_dt).total_seconds() if (first_dt and dt != datetime.min) else 0.0

            # Construct step summary
            detail_desc = ""
            if e.command_line:
                detail_desc = f"{e.process_name or 'process'}: {e.command_line[:65]}"
            elif e.file_path:
                detail_desc = f"File created/modified: {e.file_path}"
            elif e.ip:
                detail_desc = f"Network connection to {e.ip}"
            else:
                detail_desc = f"{stage_enum.label} activity ({e.event_id})"

            steps.append(
                CorrelatedSequenceStep(
                    stage=stage_enum.value,
                    stage_label=stage_enum.label,
                    timestamp=e.timestamp,
                    delta_seconds=max(0.0, delta_sec),
                    description=detail_desc,
                    event_id=e.event_id,
                    raw_query_file=e.query_file,
                )
            )
            stages_seen.append(stage_enum.value)

        distinct_stages = set(stages_seen)
        total_span = steps[-1].delta_seconds if steps else 0.0

        # Sequence criteria: >= 2 distinct attack stages within window
        is_seq = len(distinct_stages) >= 2 and total_span <= max_window_sec

        if is_seq:
            # 3+ stages gives highest confidence boost (0.95), 2 stages gives (0.88)
            boost = 0.95 if len(distinct_stages) >= 3 else 0.88
            confirmed_sequences.append(
                CorrelatedSequence(
                    hunt_id=ev_list[0].hunt_id,
                    entity_type=ent_type,
                    entity_value=ent_val,
                    stages=stages_seen,
                    steps=steps,
                    total_span_seconds=total_span,
                    is_confirmed_sequence=True,
                    confidence_boost=boost,
                )
            )

    return confirmed_sequences


def format_sequence_timeline(seq: CorrelatedSequence) -> str:
    """Format an ASCII attack sequence timeline for markdown & forensic reports."""
    lines = [
        f"Correlated Attack Sequence on {seq.entity_type} '{seq.entity_value}' "
        f"({seq.distinct_stages_count} stages across {seq.total_span_seconds:.1f}s):"
    ]
    seen_labels: set[str] = set()
    step_num = 1

    for step in seq.steps:
        # Group repeated identical descriptions to avoid clutter
        prefix = "┌─" if step_num == 1 else ("└─" if step_num == len(seq.steps) else "├─")
        indent = "  " * (step_num - 1)
        delta_str = f"Δt={step.delta_seconds:.0f}s" if step.delta_seconds > 0 else "initial"
        lines.append(f"{indent}{prefix} [{step.stage_label}] {step.description} ({delta_str})")
        step_num += 1

    return "\n".join(lines)
