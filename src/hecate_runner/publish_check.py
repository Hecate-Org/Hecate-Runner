"""Load a saved hunt's rules and run the publish check."""

from __future__ import annotations

import json
from pathlib import Path

from hecate_agent.core.publish_check import Finding, PublishReport, evaluate_hunt, fenced_sigma


def rules_for_hunt(workspace: Path, hunt_id: str, hunt_text: str) -> list[tuple[str, str]]:
    """Query files for the hunt, or the Sigma fenced in its body when there are none."""
    query_dir = workspace / "queries" / hunt_id
    files = (
        sorted(query_dir.glob("*.yml")) + sorted(query_dir.glob("*.yaml"))
        if query_dir.is_dir()
        else []
    )
    loaded = [(path.name, path.read_text(encoding="utf-8")) for path in files]
    return loaded or fenced_sigma(hunt_text)


def evaluate_saved_hunt(workspace: Path, hunt_id: str, hunt_text: str) -> PublishReport:
    return evaluate_hunt(hunt_text, rules_for_hunt(workspace, hunt_id, hunt_text))


def findings_json(report: PublishReport) -> str:
    return json.dumps([item.to_dict() for item in report.findings], ensure_ascii=False)


def blocking_summary(findings: list[Finding], limit: int = 6) -> str:
    lines = [f"• `{item.target or item.check}` {item.message}" for item in findings[:limit]]
    if len(findings) > limit:
        lines.append(f"• {len(findings) - limit} more")
    return "\n".join(lines)
