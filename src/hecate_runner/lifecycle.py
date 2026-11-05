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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

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
    try:
        data = yaml.safe_load(raw_yaml) or {}
        if not isinstance(data, dict):
            data = {}
    except yaml.YAMLError as exc:
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

    # Reconstruct document preserving frontmatter formatting
    new_yaml = yaml.dump(fm, default_flow_style=False, sort_keys=False, allow_unicode=True)
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
