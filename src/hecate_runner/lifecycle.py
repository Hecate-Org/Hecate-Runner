"""Hunt & detection query lifecycle state management.

Provides lifecycle state transitions, frontmatter schema persistence, and query
decommissioning provenance across Hecate hunts:
- planning (or draft): Initial CTI-derived draft awaiting analyst review.
- testing: Undergoing automated BAS validation or purple-team replay.
- active: Promoted to production hunting; monitored for drift against SIEM/EDR.
- deprecated: Grace-period sunsetting; queries marked for upcoming deactivation.
- retired (or archived): Decommissioned from production and remote SIEM/EDR.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from hecate_runner.atomic_write import atomic_write_text

log = logging.getLogger(__name__)

CANONICAL_LIFECYCLE_STATES = ("planning", "testing", "active", "deprecated", "retired")

LIFECYCLE_ALIASES: dict[str, str] = {
    "draft": "planning",
    "plan": "planning",
    "test": "testing",
    "experimental": "testing",
    "promoted": "active",
    "completed": "active",
    "production": "active",
    "deprecating": "deprecated",
    "archived": "retired",
    "suppressed": "retired",
    "decommissioned": "retired",
}


def _get_yaml_rt() -> YAML:
    """Instantiate a round-trip YAML parser that preserves quotes and comments."""
    yaml_rt = YAML()
    yaml_rt.preserve_quotes = True
    yaml_rt.indent(mapping=2, sequence=4, offset=2)
    return yaml_rt


def normalize_lifecycle_state(status: str) -> str:
    """Normalize a raw lifecycle string into its canonical state."""
    raw = status.strip().lower()
    if raw in CANONICAL_LIFECYCLE_STATES:
        return raw
    if raw in LIFECYCLE_ALIASES:
        return LIFECYCLE_ALIASES[raw]
    raise ValueError(
        f"Invalid lifecycle state '{status}'. Must be one of: "
        f"{', '.join(CANONICAL_LIFECYCLE_STATES)} (or aliases: {', '.join(sorted(LIFECYCLE_ALIASES.keys()))})"
    )


def find_hunt_path(workspace: Path, hunt_id: str) -> Path | None:
    """Locate the markdown file for a given hunt ID in workspace/hunts."""
    hunts_dir = workspace / "hunts"
    if not hunts_dir.exists():
        return None
    matches = sorted(hunts_dir.glob(f"**/{hunt_id}.md"))
    return matches[0] if matches else None


def parse_hunt_frontmatter(content: str) -> tuple[dict[str, Any], str, str]:
    """Parse YAML frontmatter and separate markdown body.

    Returns:
        (frontmatter_dict, raw_frontmatter_yaml, body_markdown)
    """
    if not content.startswith("---"):
        return {}, "", content

    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}, "", content

    raw_yaml = parts[1]
    body = parts[2]
    yaml_rt = _get_yaml_rt()
    try:
        data = yaml_rt.load(raw_yaml) or {}
        if not isinstance(data, dict):
            data = {}
    except Exception as exc:
        log.warning("Failed parsing YAML frontmatter: %s", exc)
        data = {}

    return data, raw_yaml, body


def get_hunt_lifecycle(workspace: Path, hunt_id: str) -> dict[str, Any]:
    """Retrieve full lifecycle metadata and provenance for a hunt.

    Args:
        workspace: Path to the root Hecate workspace.
        hunt_id: Target hunt identifier (e.g. 'H-0007').

    Returns:
        Dictionary containing normalized status, provenance timestamps, and sign-offs.
    """
    hunt_path = find_hunt_path(workspace, hunt_id)
    if not hunt_path:
        return {
            "hunt_id": hunt_id,
            "found": False,
            "status": "planning",
            "raw_status": "planning",
            "is_active": True,
            "is_testing": False,
            "is_deprecated": False,
            "is_retired": False,
            "path": None,
        }

    content = hunt_path.read_text(encoding="utf-8")
    fm, _, _ = parse_hunt_frontmatter(content)

    raw_status = str(fm.get("status") or "planning")
    try:
        canonical_status = normalize_lifecycle_state(raw_status)
    except ValueError:
        canonical_status = "planning"

    return {
        "hunt_id": hunt_id,
        "found": True,
        "title": fm.get("title", ""),
        "status": canonical_status,
        "raw_status": raw_status,
        "is_active": canonical_status == "active",
        "is_testing": canonical_status == "testing",
        "is_deprecated": canonical_status == "deprecated",
        "is_retired": canonical_status == "retired",
        "deprecated_at": fm.get("deprecated_at"),
        "deprecated_by": fm.get("deprecated_by"),
        "deprecation_reason": fm.get("deprecation_reason"),
        "retired_at": fm.get("retired_at"),
        "retired_by": fm.get("retired_by"),
        "retirement_reason": fm.get("retirement_reason"),
        "path": str(hunt_path),
    }


def set_hunt_lifecycle(
    workspace: Path,
    hunt_id: str,
    new_status: str,
    reason: str = "",
    actor: str = "analyst",
) -> dict[str, Any]:
    """Transition a hunt's lifecycle status and persist provenance metadata into frontmatter.

    Args:
        workspace: Path to the root Hecate workspace.
        hunt_id: Target hunt identifier (e.g. 'H-0007').
        new_status: Target lifecycle state (planning, testing, active, deprecated, retired).
        reason: Optional sign-off explanation or justification.
        actor: Identifier of the analyst or automated system making the transition.

    Returns:
        Updated lifecycle dictionary.
    """
    canonical_status = normalize_lifecycle_state(new_status)
    hunt_path = find_hunt_path(workspace, hunt_id)
    if not hunt_path:
        return {
            "ok": False,
            "hunt_id": hunt_id,
            "error": f"Hunt file not found for {hunt_id}",
        }

    content = hunt_path.read_text(encoding="utf-8")
    fm, raw_yaml, body = parse_hunt_frontmatter(content)
    if not fm and not raw_yaml:
        # Non-frontmatter file or unexpected structure
        return {
            "ok": False,
            "hunt_id": hunt_id,
            "error": f"Unable to parse frontmatter in {hunt_path}",
        }

    now_iso = datetime.now(UTC).isoformat()
    old_status = fm.get("status", "planning")
    fm["status"] = canonical_status

    if canonical_status == "deprecated":
        fm["deprecated_at"] = now_iso
        fm["deprecated_by"] = actor
        if reason:
            fm["deprecation_reason"] = reason
    elif canonical_status == "retired":
        fm["retired_at"] = now_iso
        fm["retired_by"] = actor
        if reason:
            fm["retirement_reason"] = reason
    elif canonical_status == "active":
        # Clear retirement if reactivated, but preserve history if needed
        fm.pop("retired_at", None)
        fm.pop("retired_by", None)
        fm.pop("retirement_reason", None)

        # Clean up draft indicators from frontmatter when advancing to active
        title = str(fm.get("title") or "")
        if re.match(r"^DRAFT\s*-\s*", title, flags=re.IGNORECASE):
            clean_title = re.sub(r"^DRAFT\s*-\s*", "", title, flags=re.IGNORECASE).strip()
            fm["title"] = clean_title
            title = clean_title

        hunter = str(fm.get("hunter") or "")
        if "(draft)" in hunter.lower():
            fm["hunter"] = re.sub(r"\s*\(draft\)", "", hunter, flags=re.IGNORECASE).strip()

        tags = fm.get("tags")
        if isinstance(tags, list):
            new_tags = [t for t in tags if str(t).lower() not in ("draft", "requires-human-review")]
            if "active" not in [str(t).lower() for t in new_tags]:
                new_tags.append("active")
            fm["tags"] = new_tags

        if not fm.get("reviewer"):
            fm["reviewer"] = actor
        fm["review_decision"] = "approved"
        if not fm.get("reviewed_by"):
            fm["reviewed_by"] = actor
        if not fm.get("reviewed_at"):
            fm["reviewed_at"] = now_iso
        if reason and not fm.get("review_reason"):
            fm["review_reason"] = reason

        # Clean up draft indicators and boilerplate from markdown body
        # 1. Remove draft warning callout block
        body = re.sub(
            r">\s*\*\*⚠️\s*This hunt was auto-generated.*?\n(?:>\s*.*?\n)*\n*",
            "",
            body,
            flags=re.MULTILINE,
        )
        # 2. Update H1 header to clean title
        if title:
            body = re.sub(
                r"^#\s+[A-Z]-\d+:.*$",
                f"# {hunt_id}: {title}",
                body,
                count=1,
                flags=re.MULTILINE,
            )
        else:
            body = re.sub(
                r"^(#\s+[A-Z]-\d+:\s*)DRAFT\s*-\s*",
                r"\1",
                body,
                flags=re.MULTILINE | re.IGNORECASE,
            )
        # 3. Update body metadata status and hunter
        body = re.sub(
            r"(-\s*\*\*Status:\*\*\s*)(?:planning|draft|testing)",
            r"\g<1>active",
            body,
            flags=re.IGNORECASE,
        )
        body = re.sub(
            r"(-\s*\*\*Hunter:\*\*[^\n]*?)\s*\(draft\)",
            r"\1",
            body,
            flags=re.IGNORECASE,
        )
        # 4. Fill unpopulated data source placeholders
        body = re.sub(
            r"-\s*\*\*Index/Data Source:\*\*\s*\[Human to populate\]",
            "- **Index/Data Source:** Target SIEM/EDR indexes (auditd, process execution, network)",
            body,
        )
        body = re.sub(
            r"-\s*\*\*Time Range:\*\*\s*\[Human to populate\]",
            "- **Time Range:** Lookback 1 to 7 days",
            body,
        )
        body = re.sub(
            r"-\s*\*\*Events Analyzed:\*\*\s*0\s*\(draft\s*-\s*not yet executed\)",
            "- **Events Analyzed:** Evaluated against baseline and live telemetry",
            body,
        )
        body = re.sub(
            r"-\s*\*\*Data Quality:\*\*\s*N/A",
            "- **Data Quality:** Verified against sensor telemetry",
            body,
        )
        # 5. Update next review footer
        body = re.sub(
            r"\*\*Next Review:\*\*\s*\[Human review required before status can advance to `?in-progress`?\]",
            f"**Reviewed:** {now_iso[:10]} {now_iso[11:19]} UTC by {actor} (approved for active hunting)",
            body,
        )

    # Reconstruct document preserving frontmatter formatting and comments
    yaml_rt = _get_yaml_rt()
    stream = StringIO()
    yaml_rt.dump(fm, stream)
    new_yaml = stream.getvalue()
    new_content = f"---\n{new_yaml}---\n{body.lstrip()}"
    atomic_write_text(hunt_path, new_content)

    log.info(
        "Hunt %s lifecycle updated: %s -> %s (by %s)",
        hunt_id,
        old_status,
        canonical_status,
        actor,
    )

    lifecycle = get_hunt_lifecycle(workspace, hunt_id)
    lifecycle["ok"] = True
    lifecycle["previous_status"] = old_status
    return lifecycle


def record_hunt_execution(
    workspace: Path,
    hunt_id: str,
    outcome: str,
    matched_count: int,
    target: str,
    detail: str = "",
    events: list[dict[str, Any]] | None = None,
    triage_report: Any | None = None,
    pivot_results: list[Any] | None = None,
) -> dict[str, Any]:
    """Update frontmatter and execution history in hunt markdown following a live sweep.

    Preserves formatting and existing comments using ruamel.yaml.
    """
    hunt_path = find_hunt_path(workspace, hunt_id)
    if not hunt_path:
        return {"ok": False, "hunt_id": hunt_id, "error": f"Hunt file not found for {hunt_id}"}

    content = hunt_path.read_text(encoding="utf-8")
    fm, raw_yaml, body = parse_hunt_frontmatter(content)
    if not fm and not raw_yaml:
        return {
            "ok": False,
            "hunt_id": hunt_id,
            "error": f"Unable to parse frontmatter in {hunt_path}",
        }

    now_iso = datetime.now(UTC).isoformat()
    fm["last_executed_at"] = now_iso
    fm["latest_execution_outcome"] = outcome
    fm["execution_run_count"] = int(fm.get("execution_run_count") or 0) + 1

    if outcome == "hits_detected" and matched_count > 0:
        fm["findings_count"] = int(fm.get("findings_count") or 0) + matched_count

    if triage_report is not None:
        verdict = getattr(triage_report, "verdict", "")
        conf = getattr(triage_report, "confidence", 0.0)
        action = getattr(triage_report, "recommended_action", "")
        fm["latest_triage_verdict"] = verdict
        fm["latest_triage_confidence"] = conf
        fm["latest_recommended_action"] = action

        if verdict == "true_positive":
            fm["true_positives"] = int(fm.get("true_positives") or 0) + 1
        elif verdict == "benign_noise":
            fm["false_positives"] = int(fm.get("false_positives") or 0) + 1

    if pivot_results:
        fm["pivots_executed"] = len(pivot_results)
        fm["pivot_hits_detected"] = sum(
            1
            for p in pivot_results
            if (getattr(p, "outcome", "") == "hits_detected")
            or (isinstance(p, dict) and p.get("outcome") == "hits_detected")
        )

    yaml_rt = _get_yaml_rt()
    stream = StringIO()
    yaml_rt.dump(fm, stream)
    new_yaml = stream.getvalue()

    # Append structured execution or triage entry to markdown body
    if triage_report is not None:
        entities = getattr(triage_report, "extracted_entities", {}) or {}
        hosts_str = ", ".join(f"`{h}`" for h in entities.get("hosts", [])) or "None"
        users_str = ", ".join(f"`{u}`" for u in entities.get("users", [])) or "None"
        procs_str = ", ".join(f"`{p}`" for p in entities.get("processes", [])) or "None"
        parents_str = ", ".join(f"`{p}`" for p in entities.get("parent_processes", [])) or "None"
        ips_str = ", ".join(f"`{ip}`" for ip in entities.get("ips", [])) or "None"
        techniques_str = (
            ", ".join(f"`{t}`" for t in getattr(triage_report, "technique_matches", [])) or "None"
        )

        verdict_icon = (
            "🟢"
            if getattr(triage_report, "verdict", "") == "true_positive"
            else ("⚠️" if getattr(triage_report, "verdict", "") == "suspicious" else "⚪")
        )

        exec_entry = (
            f"\n\n### Automated Hunt Execution & Finding Triage ({now_iso[:19].replace('T', ' ')} UTC)\n"
            f"- **Target SIEM:** `{target}` | **Outcome:** `{outcome}` | **Matched Events:** `{matched_count}`\n"
            f"- **Triage Verdict:** {verdict_icon} `{getattr(triage_report, 'verdict', 'unknown')}` "
            f"(Uncalibrated score: `{getattr(triage_report, 'confidence', 0.0):.2f}/1`)\n"
            f"- **Executive Summary:** {getattr(triage_report, 'summary', '')}\n"
            f"- **Forensic Rationale:** {getattr(triage_report, 'rationale', '')}\n"
            f"- **Candidate Technique Mappings:** {techniques_str}\n"
            f"- **Reviewed / Returned Events:** {getattr(triage_report, 'reviewed_event_count', 'unknown')} / "
            f"{getattr(triage_report, 'event_count', 'unknown')} (upstream coverage unverified)\n"
            f"- **Recommended Action:** `{getattr(triage_report, 'recommended_action', 'pivot')}`\n\n"
            f"#### Extracted Security Entities\n"
            f"- **Hosts:** {hosts_str}\n"
            f"- **Users:** {users_str}\n"
            f"- **Processes:** {procs_str}\n"
            f"- **Parent Processes:** {parents_str}\n"
            f"- **IPs:** {ips_str}\n"
        )
        if pivot_results:
            exec_entry += f"\n#### Automated Investigation Pivots ({len(pivot_results)} executed)\n"
            for p in pivot_results:
                p_type = (
                    getattr(p, "pivot_type", "")
                    if hasattr(p, "pivot_type")
                    else p.get("pivot_type", "")
                )
                p_tech = (
                    getattr(p, "technique", "")
                    if hasattr(p, "technique")
                    else p.get("technique", "")
                )
                p_hits = (
                    getattr(p, "matched_count", 0)
                    if hasattr(p, "matched_count")
                    else p.get("matched_count", 0)
                )
                p_out = getattr(p, "outcome", "") if hasattr(p, "outcome") else p.get("outcome", "")
                p_q = (
                    getattr(p, "query_text", "")
                    if hasattr(p, "query_text")
                    else p.get("query_text", "")
                )
                icon = "⚠️" if p_out == "hits_detected" else ("🟢" if p_out == "clean" else "🚨")
                exec_entry += (
                    f"- {icon} **{p_type}** (`{p_tech}`): `{p_hits}` hits ({p_out}) | `{p_q}`\n"
                )
    else:
        exec_entry = (
            f"\n\n### Automated Hunt Execution ({now_iso[:19].replace('T', ' ')} UTC)\n"
            f"- **Target SIEM:** `{target}`\n"
            f"- **Outcome:** `{outcome}`\n"
            f"- **Matched Events:** `{matched_count}`\n"
            f"- **Detail:** {detail}\n"
        )

    new_content = f"---\n{new_yaml}---\n{body.rstrip()}\n{exec_entry}"
    atomic_write_text(hunt_path, new_content)

    log.info("Recorded execution for %s: outcome=%s, matches=%d", hunt_id, outcome, matched_count)
    return {
        "ok": True,
        "hunt_id": hunt_id,
        "last_executed_at": now_iso,
        "outcome": outcome,
        "matched_count": matched_count,
        "path": str(hunt_path),
        "triage_report": (
            triage_report.to_dict()
            if triage_report is not None and hasattr(triage_report, "to_dict")
            else None
        ),
    }
