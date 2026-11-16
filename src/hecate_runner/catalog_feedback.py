"""Production → catalog fidelity writeback.

Closes the loop between live SIEM verification, FP triage / applied tunes, and
hunt markdown frontmatter (TPs/FPs, BAS fields, tune/filter provenance, optional
Sigma level nudge under FP pressure).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

import yaml

from hecate_runner.bas.approved import confirms_technique, result_status
from hecate_runner.lifecycle import find_hunt_path, parse_hunt_frontmatter
from hecate_runner.workspace_paths import (
    normalize_hunt_id,
    query_directory,
    read_artifact,
    write_artifact,
)

log = logging.getLogger(__name__)

_LEVEL_DOWN: dict[str, str] = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "informational": "informational",
    "low": "low",
}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _safe_int(value: Any, default: int = 0) -> int:
    """Coerce frontmatter counters without raising on corrupt YAML scalars."""
    if value is None or value is False:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    if not text:
        return default
    try:
        return int(text)
    except (TypeError, ValueError):
        try:
            return int(float(text))
        except (TypeError, ValueError):
            return default


def _safe_float(value: Any) -> float | None:
    """Coerce latency-like fields; return None when absent or unparseable."""
    if value is None or value is False or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_hunt_id_or_error(value: Any) -> tuple[str | None, str | None]:
    raw = str(value or "").strip()
    if not raw:
        return None, "missing hunt_id"
    try:
        return normalize_hunt_id(raw), None
    except ValueError as exc:
        return None, str(exc) or "Invalid hunt ID"


def _dump_frontmatter(fm: dict[str, Any]) -> str:
    from hecate_runner.lifecycle import _get_yaml_rt

    stream = StringIO()
    _get_yaml_rt().dump(fm, stream)
    return stream.getvalue()


def patch_hunt_frontmatter(
    workspace: Path,
    hunt_id: str,
    updates: Mapping[str, Any],
    *,
    body_append: str | None = None,
    remove_keys: list[str] | None = None,
) -> dict[str, Any]:
    """Merge ``updates`` into hunt YAML frontmatter; optionally append body text."""
    norm_hunt_id, err = _normalize_hunt_id_or_error(hunt_id)
    if err or not norm_hunt_id:
        return {"ok": False, "hunt_id": str(hunt_id or ""), "error": err or "missing hunt_id"}
    hunt_path = find_hunt_path(workspace, norm_hunt_id)
    if not hunt_path:
        return {
            "ok": False,
            "hunt_id": norm_hunt_id,
            "error": f"Hunt file not found for {norm_hunt_id}",
        }

    content = read_artifact(hunt_path, workspace)
    fm, raw_yaml, body = parse_hunt_frontmatter(content)
    if not fm and not raw_yaml:
        return {
            "ok": False,
            "hunt_id": norm_hunt_id,
            "error": f"Unable to parse frontmatter in {hunt_path}",
        }

    for key in remove_keys or ():
        fm.pop(key, None)
    for key, value in updates.items():
        if value is None:
            fm.pop(key, None)
        else:
            fm[key] = value

    new_body = body.rstrip()
    if body_append:
        new_body = f"{new_body}\n{body_append.rstrip()}\n"

    new_content = f"---\n{_dump_frontmatter(fm)}---\n{new_body.lstrip()}"
    write_artifact(hunt_path, new_content, workspace)
    return {
        "ok": True,
        "hunt_id": norm_hunt_id,
        "path": str(hunt_path),
        "updates": dict(updates),
    }


def _as_mapping(payload: Any) -> dict[str, Any]:
    if isinstance(payload, Mapping):
        return dict(payload)
    if hasattr(payload, "to_dict"):
        return dict(payload.to_dict())
    data: dict[str, Any] = {}
    for key in (
        "hunt_id",
        "status",
        "bas_provider",
        "provider",
        "siem_backend",
        "backend",
        "rule_triggered",
        "telemetry_arrived",
        "detection_latency_sec",
        "query_match_latency_sec",
        "matched_events_count",
        "search_job_id",
        "siem_alert_fired",
        "alert_search_id",
        "alert_name",
        "alert_time_utc",
        "verification_scope",
        "fidelity_scope",
        "technique_id",
        "ability_id",
        "run_id",
        "notes",
    ):
        if hasattr(payload, key):
            data[key] = getattr(payload, key)
    return data


def record_siem_verification_feedback(
    workspace: Path,
    payload: Any,
    *,
    increment_outcomes: bool = True,
    extra_updates: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Write SIEM/BAS verification outcomes into hunt frontmatter.

    When ``increment_outcomes`` is True:
    - behavioral ``verified_true_positive`` → ``true_positives += 1``
    - ``detection_miss`` → ``detection_miss_count += 1``
    """
    data = _as_mapping(payload)
    hunt_id, err = _normalize_hunt_id_or_error(data.get("hunt_id"))
    if err or not hunt_id:
        return {"ok": False, "error": err or "missing hunt_id"}

    # Normalize status so StrEnum / value-bearing objects compare correctly.
    raw_status = data.get("status")
    if raw_status is not None and not isinstance(raw_status, str):
        data["status"] = str(getattr(raw_status, "value", raw_status))

    hunt_path = find_hunt_path(workspace, hunt_id)
    if not hunt_path:
        return {"ok": False, "hunt_id": hunt_id, "error": f"Hunt file not found for {hunt_id}"}

    content = read_artifact(hunt_path, workspace)
    fm, raw_yaml, body = parse_hunt_frontmatter(content)
    if not fm and not raw_yaml:
        return {
            "ok": False,
            "hunt_id": hunt_id,
            "error": f"Unable to parse frontmatter in {hunt_path}",
        }

    now = _now_iso()
    status = result_status(data)
    confirmed = confirms_technique(data)
    provider = data.get("bas_provider") or data.get("provider") or ""
    backend = data.get("siem_backend") or data.get("backend") or ""

    fm["last_siem_verified_at"] = now
    fm["last_siem_verification_status"] = status
    fm["bas_verified"] = confirmed
    fm["bas_status"] = status
    fm["bas_provider"] = provider
    fm["bas_backend"] = backend
    fm["bas_detection_triggered"] = bool(data.get("rule_triggered"))
    fm["bas_siem_alert_fired"] = bool(data.get("siem_alert_fired"))
    fm["bas_fidelity_scope"] = data.get("fidelity_scope") or fm.get("bas_fidelity_scope") or ""
    fm["bas_verification_scope"] = (
        data.get("verification_scope") or fm.get("bas_verification_scope") or ""
    )

    latency = _safe_float(data.get("detection_latency_sec"))
    if latency is not None:
        fm["bas_detection_latency_sec"] = round(latency, 3)
    else:
        fm.pop("bas_detection_latency_sec", None)

    q_latency = _safe_float(data.get("query_match_latency_sec"))
    if q_latency is not None:
        fm["bas_query_match_latency_sec"] = round(q_latency, 3)
    else:
        fm.pop("bas_query_match_latency_sec", None)

    if data.get("search_job_id"):
        fm["bas_search_job_id"] = data.get("search_job_id")
    else:
        fm.pop("bas_search_job_id", None)

    if data.get("siem_alert_fired"):
        fm["bas_alert_search_id"] = data.get("alert_search_id")
        fm["bas_alert_name"] = data.get("alert_name")
        fm["bas_alert_time_utc"] = data.get("alert_time_utc")
    else:
        for key in ("bas_alert_search_id", "bas_alert_name", "bas_alert_time_utc"):
            fm.pop(key, None)

    # Snapshot counters before metadata merge so extra_updates cannot reset them.
    prior_tp = _safe_int(fm.get("true_positives"))
    prior_miss = _safe_int(fm.get("detection_miss_count"))

    if extra_updates:
        for key, value in extra_updates.items():
            if value is None:
                fm.pop(key, None)
            else:
                fm[key] = value

    outcome_bumped: str | None = None
    if increment_outcomes:
        if confirmed:
            fm["true_positives"] = prior_tp + 1
            outcome_bumped = "true_positive"
        elif status == "detection_miss":
            fm["detection_miss_count"] = prior_miss + 1
            outcome_bumped = "detection_miss"

    new_content = f"---\n{_dump_frontmatter(fm)}---\n{body.lstrip()}"
    write_artifact(hunt_path, new_content, workspace)
    log.info(
        "Catalog SIEM feedback for %s: status=%s confirmed=%s bumped=%s",
        hunt_id,
        status,
        confirmed,
        outcome_bumped,
    )
    return {
        "ok": True,
        "hunt_id": hunt_id,
        "path": str(hunt_path),
        "status": status,
        "bas_verified": confirmed,
        "outcome_bumped": outcome_bumped,
        "true_positives": fm.get("true_positives"),
        "detection_miss_count": fm.get("detection_miss_count"),
    }


def infer_tune_action_kind(instruction: str, summary: str = "") -> str:
    """Classify a tune as exclude / include / other from instruction or summary."""
    blob = f"{instruction} {summary}".lower()
    if any(
        tok in blob
        for tok in (
            "exclude",
            "exclusion",
            "filter out",
            "filtered out",
            "suppress",
            "omit",
            "ignore",
        )
    ):
        return "exclude"
    if any(tok in blob for tok in ("broaden", "expand", "include", "add ")):
        return "include"
    return "other"


def _nudge_sigma_level(rule_path: Path, workspace: Path) -> str | None:
    """Lower Sigma ``level`` one notch. Returns new level or None if unchanged."""
    try:
        text = read_artifact(rule_path, workspace)
    except Exception:
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    current = str(data.get("level") or "").strip().lower().strip("\"'")
    if not current or current not in _LEVEL_DOWN:
        return None
    new_level = _LEVEL_DOWN[current]
    if new_level == current:
        return None
    # Preserve document formatting where possible via line replace (quoted/commented).
    pattern = re.compile(
        rf"(?im)^(\s*level\s*:\s*)(['\"]?){re.escape(current)}\2(\s*(?:#.*)?)?\s*$"
    )
    if pattern.search(text):
        updated = pattern.sub(rf"\g<1>\g<2>{new_level}\g<2>\g<3>", text, count=1)
    else:
        data["level"] = new_level
        updated = yaml.dump(data, sort_keys=False)
    write_artifact(rule_path, updated if updated.endswith("\n") else updated + "\n", workspace)
    return new_level


def record_rule_tune_feedback(
    workspace: Path,
    hunt_id: str,
    *,
    summary: str,
    instruction: str = "",
    action_kind: str | None = None,
    rule_file: Path | str | None = None,
    transpiled_targets: list[str] | None = None,
    body_note: bool = False,
) -> dict[str, Any]:
    """Persist applied tune outcomes into hunt frontmatter (and optional level nudge)."""
    norm_hunt_id, err = _normalize_hunt_id_or_error(hunt_id)
    if err or not norm_hunt_id:
        return {"ok": False, "hunt_id": str(hunt_id or ""), "error": err or "missing hunt_id"}
    hunt_path = find_hunt_path(workspace, norm_hunt_id)
    if not hunt_path:
        return {
            "ok": False,
            "hunt_id": norm_hunt_id,
            "error": f"Hunt file not found for {norm_hunt_id}",
        }

    content = read_artifact(hunt_path, workspace)
    fm, raw_yaml, body = parse_hunt_frontmatter(content)
    if not fm and not raw_yaml:
        return {
            "ok": False,
            "hunt_id": norm_hunt_id,
            "error": f"Unable to parse frontmatter in {hunt_path}",
        }

    kind = action_kind or infer_tune_action_kind(instruction, summary)
    now = _now_iso()
    fm["last_tuned_at"] = now
    fm["last_tune_summary"] = summary
    fm["last_tune_instruction"] = (instruction or "")[:240]
    fm["last_tune_action"] = kind
    fm["tune_count"] = _safe_int(fm.get("tune_count")) + 1
    if transpiled_targets:
        fm["last_tune_targets"] = list(transpiled_targets)

    if kind == "exclude":
        fm["filters_applied_count"] = _safe_int(fm.get("filters_applied_count")) + 1
        fm["last_detection_filter"] = summary

    level_adjusted: str | None = None
    tp = _safe_int(fm.get("true_positives"))
    fp = _safe_int(fm.get("false_positives"))
    # Under FP pressure, an applied exclusion should also quiet the Sigma level.
    if kind == "exclude" and fp > tp:
        rule_path: Path | None = Path(rule_file) if rule_file else None
        if rule_path is None:
            try:
                from hecate_runner.bas.rule_selection import select_primary_sigma_rule

                selected = select_primary_sigma_rule(query_directory(workspace, norm_hunt_id))
                rule_path = selected.path if selected else None
            except Exception:
                rule_path = None
        if rule_path and rule_path.exists():
            level_adjusted = _nudge_sigma_level(rule_path, workspace)
            if level_adjusted:
                fm["detection_level"] = level_adjusted
                fm["detection_level_adjusted_at"] = now
                fm["detection_level_reason"] = "fp_pressure_after_exclude_tune"

    append = ""
    if body_note:
        append = (
            f"\n\n### Catalog Tune Writeback ({now[:19].replace('T', ' ')} UTC)\n"
            f"- **Action:** `{kind}`\n"
            f"- **Summary:** {summary}\n"
        )
        if level_adjusted:
            append += f"- **Level nudged:** `{level_adjusted}` (FP pressure)\n"

    new_body = body.rstrip()
    if append:
        new_body = f"{new_body}\n{append}"

    new_content = f"---\n{_dump_frontmatter(fm)}---\n{new_body.lstrip()}"
    write_artifact(hunt_path, new_content, workspace)
    log.info(
        "Catalog tune feedback for %s: kind=%s level=%s tune_count=%s",
        norm_hunt_id,
        kind,
        level_adjusted,
        fm.get("tune_count"),
    )
    return {
        "ok": True,
        "hunt_id": norm_hunt_id,
        "path": str(hunt_path),
        "action_kind": kind,
        "tune_count": fm.get("tune_count"),
        "filters_applied_count": fm.get("filters_applied_count"),
        "level_adjusted": level_adjusted,
        "detection_level": fm.get("detection_level"),
    }
