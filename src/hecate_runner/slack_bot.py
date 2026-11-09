"""Slack Socket Mode bot service and interactive Action Handlers for Hecate.

Enables bidirectional human-in-the-loop (HITL) SecOps operations:
- Approve & Promote planning drafts to active status
- Deploy hunt queries to target SIEM and EDR platforms
- Replay purple-team emulation in the local sandbox
- Park or suppress non-actionable intelligence items
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.config import Settings
from hecate_runner.slack_blocks import (
    build_approve_hunt_modal,
    build_pending_hunts_card,
    build_reject_hunt_modal,
    build_runner_status_card,
    build_slash_help_card,
)

log = logging.getLogger(__name__)


def deploy_queries_for_hunt(
    workspace: Path,
    hunt_id: str,
    dry_run: bool = True,
    target: str | None = None,
) -> list[dict[str, Any]]:
    """Deploy or simulate deployment of hunt queries to target SIEM/EDR platforms."""
    try:
        from dotenv import load_dotenv

        load_dotenv(override=False)
        load_dotenv(workspace / ".env", override=False)
    except ImportError:
        pass

    query_dir = workspace / "queries" / hunt_id
    if not query_dir.exists():
        log.warning("Query directory not found for %s at %s", hunt_id, query_dir)
        return []

    from hecate_agent.api import deploy_transpiled_query

    query_exts = {
        ".kql": "sentinel_kql",
        ".cql": "crowdstrike_cql",
        ".leql": "rapid7_leql",
        ".s1ql": "sentinelone_s1ql",
        ".spl": "splunk_spl",
        ".eql": "elastic_eql",
    }

    results: list[dict[str, Any]] = []
    for q_file in sorted(query_dir.iterdir()):
        tgt = query_exts.get(q_file.suffix.lower())
        if not tgt:
            continue
        if target and target.lower() != tgt.lower():
            continue

        q_text = q_file.read_text(encoding="utf-8").strip()
        title = q_file.stem.replace("__", " - ").replace("_", " ").title()
        res = deploy_transpiled_query(
            target=tgt,
            query=q_text,
            hunt_id=hunt_id,
            title=title,
            dry_run=dry_run,
        )
        results.append(
            {
                "file": q_file.name,
                "target": tgt,
                "status": res.get("status"),
                "ok": res.get("ok", False),
                "remote_id": res.get("remote_id"),
                "detail": res.get("detail", ""),
                "request_summary": res.get("request_summary", {}),
            }
        )

    return results


def undeploy_queries_for_hunt(
    workspace: Path,
    hunt_id: str,
    dry_run: bool = True,
    target: str | None = None,
) -> list[dict[str, Any]]:
    """Undeploy or simulate teardown of hunt queries from target SIEM/EDR platforms."""
    try:
        from dotenv import load_dotenv

        load_dotenv(override=False)
        load_dotenv(workspace / ".env", override=False)
    except ImportError:
        pass

    query_dir = workspace / "queries" / hunt_id
    if not query_dir.exists():
        log.warning("Query directory not found for %s at %s", hunt_id, query_dir)
        return []

    from hecate_agent.api import undeploy_transpiled_query

    query_exts = {
        ".kql": "sentinel_kql",
        ".cql": "crowdstrike_cql",
        ".leql": "rapid7_leql",
        ".s1ql": "sentinelone_s1ql",
        ".spl": "splunk_spl",
        ".eql": "elastic_eql",
    }

    results: list[dict[str, Any]] = []
    for q_file in sorted(query_dir.iterdir()):
        tgt = query_exts.get(q_file.suffix.lower())
        if not tgt:
            continue
        if target and target.lower() != tgt.lower():
            continue

        q_text = q_file.read_text(encoding="utf-8").strip()
        title = q_file.stem.replace("__", " - ").replace("_", " ").title()
        res = undeploy_transpiled_query(
            target=tgt,
            hunt_id=hunt_id,
            title=title,
            query=q_text,
            dry_run=dry_run,
        )
        results.append(
            {
                "file": q_file.name,
                "target": tgt,
                "status": res.get("status"),
                "ok": res.get("ok", False),
                "remote_id": res.get("remote_id"),
                "detail": res.get("detail", ""),
                "request_summary": res.get("request_summary", {}),
            }
        )

    return results


def sync_queries_for_hunt(
    workspace: Path,
    hunt_id: str,
    dry_run: bool = True,
    target: str | None = None,
) -> list[dict[str, Any]]:
    """Verify synchronization and detect drift for hunt queries against target SIEM/EDR."""
    try:
        from dotenv import load_dotenv

        load_dotenv(override=False)
        load_dotenv(workspace / ".env", override=False)
    except ImportError:
        pass

    query_dir = workspace / "queries" / hunt_id
    if not query_dir.exists():
        log.warning("Query directory not found for %s at %s", hunt_id, query_dir)
        return []

    from hecate_agent.api import sync_transpiled_query

    query_exts = {
        ".kql": "sentinel_kql",
        ".cql": "crowdstrike_cql",
        ".leql": "rapid7_leql",
        ".s1ql": "sentinelone_s1ql",
        ".spl": "splunk_spl",
        ".eql": "elastic_eql",
    }

    results: list[dict[str, Any]] = []
    for q_file in sorted(query_dir.iterdir()):
        tgt = query_exts.get(q_file.suffix.lower())
        if not tgt:
            continue
        if target and target.lower() != tgt.lower():
            continue

        q_text = q_file.read_text(encoding="utf-8").strip()
        title = q_file.stem.replace("__", " - ").replace("_", " ").title()
        res = sync_transpiled_query(
            target=tgt,
            query=q_text,
            hunt_id=hunt_id,
            title=title,
            dry_run=dry_run,
        )
        results.append(
            {
                "file": q_file.name,
                "target": tgt,
                "status": res.get("status"),
                "ok": res.get("ok", False),
                "remote_id": res.get("remote_id"),
                "detail": res.get("detail", ""),
                "local_query": res.get("local_query", ""),
                "remote_query": res.get("remote_query"),
                "drift_diff": res.get("drift_diff"),
                "request_summary": res.get("request_summary", {}),
            }
        )

    return results


def promote_hunt(workspace: Path, hunt_id: str) -> dict[str, Any]:
    """Promote a planning hunt to active status in the workspace."""
    matches = sorted((workspace / "hunts").glob(f"**/{hunt_id}.md"))
    if not matches:
        return {"ok": False, "hunt_id": hunt_id, "error": f"Hunt file not found for {hunt_id}"}

    hunt_path = matches[0]
    content = hunt_path.read_text(encoding="utf-8")

    if re.search(r"^status:\s*(active|promoted|completed)\s*$", content, re.MULTILINE):
        return {
            "ok": True,
            "hunt_id": hunt_id,
            "status": "active",
            "already_promoted": True,
            "path": str(hunt_path),
        }

    updated_content, count = re.subn(
        r"^status:\s*planning\s*$",
        "status: active",
        content,
        flags=re.MULTILINE,
    )
    if count == 0:
        updated_content, count = re.subn(
            r"^status:.*$",
            "status: active",
            content,
            flags=re.MULTILINE,
        )

    atomic_write_text(hunt_path, updated_content)
    log.info("Hunt %s promoted to active in %s", hunt_id, hunt_path)
    return {
        "ok": True,
        "hunt_id": hunt_id,
        "status": "active",
        "already_promoted": False,
        "path": str(hunt_path),
    }


def park_hunt(
    workspace: Path, hunt_id: str, reason: str = "Analyst suppressed via Slack"
) -> dict[str, Any]:
    """Mark a hunt bundle as suppressed / parked in the workspace."""
    matches = sorted((workspace / "hunts").glob(f"**/{hunt_id}.md"))
    if not matches:
        return {"ok": False, "hunt_id": hunt_id, "error": f"Hunt file not found for {hunt_id}"}

    hunt_path = matches[0]
    content = hunt_path.read_text(encoding="utf-8")

    updated_content = _update_frontmatter(content, {"status": "suppressed"})
    if updated_content is None:
        return {"ok": False, "hunt_id": hunt_id, "error": f"No frontmatter in {hunt_path}"}
    atomic_write_text(hunt_path, updated_content)
    log.info("Hunt %s suppressed in %s", hunt_id, hunt_path)
    return {
        "ok": True,
        "hunt_id": hunt_id,
        "status": "suppressed",
        "reason": reason,
        "path": str(hunt_path),
    }


def _update_frontmatter(content: str, values: dict[str, str]) -> str | None:
    """Set top-level frontmatter keys without touching the body.

    Hunt bodies embed Sigma rules with their own `status:` lines, so edits must
    stay between the opening and closing `---`. Returns None without frontmatter.
    """
    lines = content.split("\n")
    if not lines or lines[0].strip() != "---":
        return None
    end = next((i for i, line in enumerate(lines[1:], 1) if line.strip() == "---"), None)
    if end is None:
        return None

    remaining = dict(values)
    head = lines[1:end]
    for i, line in enumerate(head):
        key = line.split(":", 1)[0]
        if ":" in line and key in remaining:
            head[i] = f"{key}: {remaining.pop(key)}"
    head.extend(f"{key}: {value}" for key, value in remaining.items())
    return "\n".join([lines[0], *head, *lines[end:]])


#: Tags that describe an unreviewed draft and stop being true once a reviewer approves it.
_DRAFT_ONLY_TAGS = frozenset({"draft", "requires-human-review"})


def _finalize_approved_body(
    content: str, hunt_id: str, title: str, reviewer: str, reviewed_at: datetime
) -> str:
    """Remove the body's draft markers from an approved hunt.

    H-0021 was approved and published still headed "DRAFT - Automated Hunt Draft",
    with a banner saying not to run its queries and its body status `planning`.
    """
    replacements = {
        f"# {hunt_id}: DRAFT - Automated Hunt Draft\n": f"# {hunt_id}: {title}\n",
        "> **⚠️ This hunt was auto-generated by hecate-runner.**\n"
        "> **Do not execute queries until a human reviews the Learn/Observe sections "
        "and advances the status.**\n": "",
        "- **Hunter:** hecate-runner orchestrator (draft)\n": "- **Hunter:** hecate-runner orchestrator\n",
        "- **Status:** planning\n": "- **Status:** active\n",
        "**Next Review:** [Human review required before status can advance to `in-progress`]": (
            f"**Reviewed:** {reviewed_at.strftime('%Y-%m-%d %H:%M:%S UTC')} by {reviewer}"
        ),
    }
    for old, new in replacements.items():
        content = content.replace(old, new, 1)
    return content


def list_pending_hunts(workspace: Path) -> list[dict[str, Any]]:
    """Hunts whose frontmatter status is `planning`, oldest ID first."""
    from hecate_runner.lifecycle import parse_hunt_frontmatter

    pending = []
    for path in sorted((workspace / "hunts").glob("**/H-*.md")):
        try:
            fm, _, _ = parse_hunt_frontmatter(path.read_text(encoding="utf-8"))
        except OSError as exc:
            log.warning("Could not read hunt %s: %s", path, exc)
            continue
        if str(fm.get("status") or "").strip().lower() != "planning":
            continue
        techniques = fm.get("techniques") or []
        pending.append(
            {
                "hunt_id": str(fm.get("hunt_id") or path.stem),
                "title": str(fm.get("title") or ""),
                "date": str(fm.get("date") or ""),
                "techniques": [str(t) for t in techniques] if isinstance(techniques, list) else [],
                "research_id": str(fm.get("spawned_from") or ""),
                "path": str(path),
                "publish_check": str(fm.get("publish_check") or ""),
                "publish_blocking": _blocking_count(fm.get("publish_findings")),
                "lab_probe": str(fm.get("lab_probe") or ""),
                "lab_probe_provider": _frontmatter_scalar(fm.get("lab_probe_provider")),
                "lab_probe_window_days": fm.get("lab_probe_window_days") or 0,
                "lab_probe_hits": fm.get("lab_probe_hits") or 0,
            }
        )
    return pending


def _frontmatter_scalar(raw: Any) -> str:
    """JSON-encoded frontmatter scalars decode to a plain string."""
    if raw is None:
        return ""
    if isinstance(raw, str):
        text = raw.strip()
        if text.startswith('"') or text.startswith("'"):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                return text.strip("\"'")
            return str(parsed) if parsed is not None else ""
        return text
    return str(raw)


def _blocking_count(raw: Any) -> int:
    findings = raw if isinstance(raw, list) else []
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = []
        findings = parsed if isinstance(parsed, list) else []
    return sum(1 for item in findings if isinstance(item, dict) and item.get("severity") == "block")


def review_hunt(
    workspace: Path,
    hunt_id: str,
    *,
    approve: bool,
    reviewer: str,
    reason: str = "",
    override: str = "",
) -> dict[str, Any]:
    """Approve (active) or reject (suppressed) a planning hunt and record the reviewer.

    Refuses hunts that are no longer `planning`, so a stale Slack button cannot
    reverse a decision someone else already made. Approval also refuses a hunt
    whose publish check has a blocking finding, unless the reviewer supplies an
    override that is stored with their name.
    """
    from hecate_runner.lifecycle import find_hunt_path, parse_hunt_frontmatter
    from hecate_runner.publish_check import evaluate_saved_hunt, findings_json

    hunt_path = find_hunt_path(workspace, hunt_id)
    if hunt_path is None:
        return {"ok": False, "hunt_id": hunt_id, "error": f"Hunt file not found for {hunt_id}"}

    content = hunt_path.read_text(encoding="utf-8")
    fm, _, _ = parse_hunt_frontmatter(content)
    current = str(fm.get("status") or "").strip()
    if current.lower() != "planning":
        return {
            "ok": False,
            "hunt_id": hunt_id,
            "error": f"{hunt_id} is `{current or 'unknown'}`, not awaiting review",
        }

    report = evaluate_saved_hunt(workspace, hunt_id, content)
    blocking = report.blocking()
    override_text = override.strip()
    if approve and blocking and len(override_text) < 12:
        shown = "; ".join(item.message for item in blocking[:3])
        return {
            "ok": False,
            "hunt_id": hunt_id,
            "needs_override": True,
            "findings": [item.to_dict() for item in blocking],
            "error": f"{hunt_id} has {len(blocking)} blocking publish finding(s): {shown}",
        }

    status = "active" if approve else "suppressed"
    reviewed_at = datetime.now(UTC)
    values = {
        "status": status,
        "review_decision": "approved" if approve else "rejected",
        "reviewed_by": json.dumps(reviewer),
        "reviewed_at": json.dumps(reviewed_at.isoformat(timespec="seconds")),
        "review_reason": json.dumps(reason.strip()),
        "publish_check": report.verdict,
        "publish_findings": findings_json(report),
    }
    if approve and blocking:
        values["publish_override"] = json.dumps(override_text)
        values["publish_override_by"] = json.dumps(reviewer)
    title = str(fm.get("title") or "")
    if approve:
        title = title.removeprefix("DRAFT - ")
        values["title"] = json.dumps(title, ensure_ascii=False)
        values["hunter"] = str(fm.get("hunter") or "").removesuffix(" (draft)")
        tags = [t for t in fm.get("tags") or [] if t not in _DRAFT_ONLY_TAGS]
        values["tags"] = json.dumps(tags)
    updated = _update_frontmatter(content, values)
    if updated is not None and approve:
        updated = _finalize_approved_body(updated, hunt_id, title, reviewer, reviewed_at)
    if updated is None:
        return {"ok": False, "hunt_id": hunt_id, "error": f"No frontmatter in {hunt_path}"}
    atomic_write_text(hunt_path, updated)
    log.info("Hunt %s %s via Slack by %s", hunt_id, status, reviewer)
    return {"ok": True, "hunt_id": hunt_id, "status": status, "path": str(hunt_path)}


def publish_reviewed_hunt(
    settings: Settings, hunt_id: str, *, reviewer: str, rights_note: str
) -> dict[str, Any]:
    """Record the release sign-off for the hunt's current snapshot and open its PR.

    The sign-off is bound to the snapshot's digest, so it must be taken after
    the review decision is written into the hunt's frontmatter.
    """
    from hecate_runner.github_publisher import _snapshot_bundle, enqueue_hunt, sync_outbox
    from hecate_runner.public_review import approve_public_review, prepare_public_review

    try:
        files, _ = _snapshot_bundle(settings, hunt_id)
        approve_public_review(
            settings,
            files,
            expected_digest=prepare_public_review(settings, files)["digest"],
            reviewer=reviewer,
            rights_note=rights_note,
            privacy_checked=True,
            redistribution_checked=True,
        )
        if enqueue_hunt(settings, hunt_id) == "awaiting_review":
            return {"ok": False, "error": "the release sign-off did not match the queued snapshot"}
        result = next((r for r in sync_outbox(settings) if r.hunt_id == hunt_id), None)
    except Exception as exc:
        log.warning("Publishing %s after review failed: %s", hunt_id, exc)
        return {"ok": False, "error": str(exc)}
    if result is None or not result.pr_url:
        return {"ok": False, "error": "queued, but the publisher has not opened a pull request yet"}
    return {"ok": True, "pr_url": result.pr_url, "pr_number": result.pr_number}


def replay_hunt_purple_team(workspace: Path, hunt_id: str) -> dict[str, Any]:
    """Replay Sigma rules for a hunt against synthetic adversary telemetry."""
    query_dir = workspace / "queries" / hunt_id
    sigma_files = (
        list(query_dir.glob("*.yml")) + list(query_dir.glob("*.yaml")) if query_dir.exists() else []
    )

    if not sigma_files:
        return {
            "ok": False,
            "hunt_id": hunt_id,
            "error": f"No Sigma rules found in queries/{hunt_id}",
        }

    from hecate_runner.purple_team import replay_rule

    sample_events = [
        {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc AAAA",
        }
    ]
    replayed = 0
    passed = 0
    for s_file in sigma_files:
        rule_yaml = s_file.read_text(encoding="utf-8")
        res = replay_rule(rule_yaml, sample_events, baseline=[])
        replayed += 1
        if res.matched:
            passed += 1

    return {
        "ok": True,
        "hunt_id": hunt_id,
        "total_rules": replayed,
        "passed_rules": passed,
        "fidelity": f"{(passed / replayed * 100):.0f}%" if replayed else "0%",
        "sample_events_count": len(sample_events),
    }


def execute_adhoc_hunt(
    settings: Settings,
    topic: str,
    content: str | None = None,
    dry_run: bool = False,
) -> Any:
    """Trigger an immediate ad-hoc hunt cycle for a given topic or CVE."""
    from datetime import UTC, datetime

    from hecate_runner.cti.base import CTIItem
    from hecate_runner.orchestrator import build_orchestrator_for_item

    item_content = (
        content
        or f"Ad-hoc threat intelligence hunt request for {topic}. Analyze recent exploitation, threat actor tradecraft, TTPs, and detection opportunities."
    )
    item = CTIItem(
        content=item_content,
        source="slack_command",
        received_at=datetime.now(UTC),
        identifier=f"slack_{topic.replace(' ', '_')}",
        title=topic,
    )
    orch = build_orchestrator_for_item(settings, item, ignore_quota=True)
    return orch.run_once(dry_run=dry_run)


class SlackBotService:
    """Manages Slack Socket Mode event handlers, interactive actions, and commands."""

    def __init__(self, settings: Settings | None = None, app: Any = None):
        self.settings = settings or Settings()
        self._app = app
        self._handler: Any = None
        self._thread_hunt_map: dict[str, str] = {}

        if self._app is None and self.is_configured:
            self._init_app()

        if self._app is not None:
            self._register_handlers()

    def register_thread_hunt(self, thread_ts: str, hunt_id: str) -> None:
        """Register a notification thread timestamp to its associated hunt ID."""
        self._thread_hunt_map[thread_ts] = hunt_id

    @property
    def is_configured(self) -> bool:
        """True when both Slack Bot and App tokens are present."""
        return bool(self.settings.slack_bot_token and self.settings.slack_app_token)

    @property
    def app(self) -> Any:
        return self._app

    def _init_app(self) -> None:
        try:
            from slack_bolt import App

            bot_tok = self.settings.slack_bot_token or ""
            self._app = App(token=bot_tok, token_verification_enabled=False)
        except Exception as exc:
            log.warning("Failed to initialize Slack Bolt App: %s", exc)
            self._app = None

    def _register_handlers(self) -> None:
        if self._app is None:
            return

        @self._app.action("hecate_approve_hunt")
        def handle_approve(ack: Any, body: dict[str, Any], client: Any) -> None:
            ack()
            hunt_id = str(body.get("actions", [{}])[0].get("value") or "").strip()
            message = body.get("message", {})
            metadata = {
                "hunt_id": hunt_id,
                "channel": (body.get("channel") or {}).get("id"),
                "thread_ts": message.get("ts") or body.get("container", {}).get("message_ts"),
            }
            _open_approve_modal(client, body["trigger_id"], hunt_id, metadata)

        @self._app.action("hecate_deploy_queries")
        def handle_deploy(ack: Any, body: dict[str, Any], say: Any) -> None:
            ack()
            action = body.get("actions", [{}])[0]
            hunt_id = str(action.get("value") or "").strip()
            thread_ts = body.get("message", {}).get("ts") or body.get("container", {}).get(
                "message_ts"
            )
            user_info = body.get("user", {})
            user_name = user_info.get("username") or user_info.get("name") or "analyst"

            is_dry_run = getattr(self.settings, "siem_deploy_dry_run", True)
            mode_str = "Simulated (Dry-Run)" if is_dry_run else "Live API Push"
            log.info(
                "Slack HITL action: deploy queries for %s by %s (mode=%s)",
                hunt_id,
                user_name,
                mode_str,
            )

            deployments = deploy_queries_for_hunt(
                self.settings.hecate_workspace,
                hunt_id,
                dry_run=is_dry_run,
            )

            if not deployments:
                say(
                    text=f"⚠️ *No transpiled query files found for `{hunt_id}`* under `queries/{hunt_id}`.",
                    thread_ts=thread_ts,
                )
                return

            rows = []
            for d in deployments:
                status_icon = "✅" if d.get("ok") else "❌"
                target = d.get("target")
                status = d.get("status")
                rem_id = f" (`{d.get('remote_id')}`)" if d.get("remote_id") else ""
                rows.append(f"{status_icon} *{target}:* `{status}`{rem_id}")

            rows_text = "\n".join(rows)
            msg = (
                f"🔍 *SIEM & EDR Query Deployment for `{hunt_id}`*\n"
                f"*Mode:* `{mode_str}` | *Initiated by:* <@{user_info.get('id', user_name)}>\n\n"
                f"{rows_text}"
            )
            say(text=msg, thread_ts=thread_ts)

        @self._app.action("hecate_reconcile_drift")
        def handle_reconcile_drift(ack: Any, body: dict[str, Any], say: Any) -> None:
            ack()
            action = body.get("actions", [{}])[0]
            hunt_id = str(action.get("value") or "").strip()
            thread_ts = body.get("message", {}).get("ts") or body.get("container", {}).get(
                "message_ts"
            )
            user_info = body.get("user", {})
            user_name = user_info.get("username") or user_info.get("name") or "analyst"

            is_dry_run = getattr(self.settings, "siem_deploy_dry_run", True)
            mode_str = "Simulated (Dry-Run)" if is_dry_run else "Live Push"
            log.info(
                "Slack HITL action: reconcile SIEM drift for %s by %s (mode=%s)",
                hunt_id,
                user_name,
                mode_str,
            )

            from hecate_runner.siem_drift import reconcile_hunt_queries

            results = reconcile_hunt_queries(
                self.settings.hecate_workspace,
                hunt_id,
                dry_run=is_dry_run,
                actor=f"slack:{user_name}",
            )

            if not results:
                say(
                    text=f"ℹ️ *No drifted queries to reconcile for `{hunt_id}`* (already in sync).",  # noqa: RUF001
                    thread_ts=thread_ts,
                )
                return

            rows = []
            for r in results:
                icon = "✅" if r.get("ok") else "❌"
                target = r.get("target")
                fname = r.get("file")
                rem_id = f" (`{r.get('remote_id')}`)" if r.get("remote_id") else ""
                prev = r.get("previous_status")
                st = r.get("status")
                rows.append(f"{icon} *{target}* (`{fname}`): `{prev}` ➔ `{st}`{rem_id}")

            rows_text = "\n".join(rows)
            msg = (
                f"🔄 *SIEM Detection Reconciliation for `{hunt_id}`*\n"
                f"*Mode:* `{mode_str}` | *Initiated by:* <@{user_info.get('id', user_name)}>\n\n"
                f"{rows_text}"
            )
            say(text=msg, thread_ts=thread_ts)

        @self._app.action("hecate_rerun_purple")
        def handle_purple(ack: Any, body: dict[str, Any], say: Any) -> None:
            ack()
            action = body.get("actions", [{}])[0]
            hunt_id = str(action.get("value") or "").strip()
            thread_ts = body.get("message", {}).get("ts") or body.get("container", {}).get(
                "message_ts"
            )
            user_info = body.get("user", {})
            user_name = user_info.get("username") or user_info.get("name") or "analyst"

            log.info("Slack HITL action: purple team replay for %s by %s", hunt_id, user_name)
            res = replay_hunt_purple_team(self.settings.hecate_workspace, hunt_id)
            if res.get("ok"):
                msg = (
                    f"🧪 *Purple Team Replay for `{hunt_id}` Completed*\n"
                    f"• *Requested by:* <@{user_info.get('id', user_name)}>\n"
                    f"• *Rules Tested:* {res.get('total_rules')}\n"
                    f"• *Rules Validated:* {res.get('passed_rules')}\n"
                    f"• *Detection Fidelity:* {res.get('fidelity')}\n"
                    f"• *Sandbox Telemetry:* {res.get('sample_events_count')} events evaluated"
                )
            else:
                msg = f"❌ *Purple Team Replay failed for `{hunt_id}`:* {res.get('error')}"

            say(text=msg, thread_ts=thread_ts)

        @self._app.action("hecate_park_hunt")
        def handle_park(ack: Any, body: dict[str, Any], say: Any) -> None:
            ack()
            action = body.get("actions", [{}])[0]
            hunt_id = str(action.get("value") or "").strip()
            thread_ts = body.get("message", {}).get("ts") or body.get("container", {}).get(
                "message_ts"
            )
            user_info = body.get("user", {})
            user_name = user_info.get("username") or user_info.get("name") or "analyst"

            log.info("Slack HITL action: park hunt %s by %s", hunt_id, user_name)
            res = park_hunt(self.settings.hecate_workspace, hunt_id)
            if res.get("ok"):
                msg = (
                    f"⏸️ *Hunt `{hunt_id}` Parked / Suppressed*\n"
                    f"• *Suppressed by:* <@{user_info.get('id', user_name)}>\n"
                    f"• *Status:* `suppressed`\n"
                    f"• Marked as commentary / un-actionable intelligence."
                )
            else:
                msg = f"❌ *Failed to park `{hunt_id}`:* {res.get('error')}"

            say(text=msg, thread_ts=thread_ts)

        @self._app.action("hecate_approve_sweep")
        def handle_approve_sweep(ack: Any, body: dict[str, Any], say: Any) -> None:
            ack()
            action = body.get("actions", [{}])[0]
            sweep_id = str(action.get("value") or "").strip()
            thread_ts = body.get("message", {}).get("ts") or body.get("container", {}).get(
                "message_ts"
            )
            user_info = body.get("user", {})
            user_name = user_info.get("username") or user_info.get("name") or "analyst"
            user_id = str(user_info.get("id") or "unknown")

            log.info("Slack HITL action: approve sweep %s by %s", sweep_id, user_name)
            from hecate_runner.execution.scheduler import HuntExecutionScheduler

            scheduler = HuntExecutionScheduler(settings=self.settings)
            res = scheduler.execute_sweep(sweep_id, approver=f"slack:{user_id} ({user_name})")

            icon = "🟢" if res.outcome == "clean" else ("⚠️" if res.outcome == "hits_detected" else "🚨")
            msg = (
                f"{icon} *Hunt Sweep Executed by <@{user_id}>*\n"
                f"• *Hunt ID:* `{res.hunt_id}`\n"
                f"• *Target SIEM:* `{res.target}`\n"
                f"• *Outcome:* `{res.outcome}`\n"
                f"• *Matched Events:* `{res.matched_count}`\n"
                f"• *Detail:* {res.detail}"
            )
            say(text=msg, thread_ts=thread_ts)

        @self._app.action("hecate_reject_sweep")
        def handle_reject_sweep(ack: Any, body: dict[str, Any], say: Any) -> None:
            ack()
            action = body.get("actions", [{}])[0]
            sweep_id = str(action.get("value") or "").strip()
            thread_ts = body.get("message", {}).get("ts") or body.get("container", {}).get(
                "message_ts"
            )
            user_info = body.get("user", {})
            user_name = user_info.get("username") or user_info.get("name") or "analyst"
            user_id = str(user_info.get("id") or "unknown")

            log.info("Slack HITL action: reject sweep %s by %s", sweep_id, user_name)
            from hecate_runner.execution.scheduler import HuntExecutionScheduler

            scheduler = HuntExecutionScheduler(settings=self.settings)
            scheduler.reject_sweep(
                sweep_id, reason=f"Rejected via Slack by {user_name}", actor=f"slack:{user_id}"
            )
            msg = f"⏹️ *Hunt Sweep `{sweep_id}` Skipped / Cancelled* by <@{user_id}>"
            say(text=msg, thread_ts=thread_ts)

        @self._app.action("hecate_tune_finding")
        def handle_tune_finding(ack: Any, body: dict[str, Any], say: Any) -> None:
            ack()
            action = body.get("actions", [{}])[0]
            finding_id = str(action.get("value") or "").strip()
            thread_ts = body.get("message", {}).get("ts") or body.get("container", {}).get(
                "message_ts"
            )
            user_info = body.get("user", {})
            user_name = user_info.get("username") or user_info.get("name") or "analyst"
            user_id = str(user_info.get("id") or "unknown")

            log.info(
                "Slack HITL action: auto-tune rule for finding %s by %s",
                finding_id,
                user_name,
            )
            from hecate_runner.execution.watermark_store import WatermarkStore
            from hecate_runner.rule_tuner import RuleTuner

            store = WatermarkStore(db_path=self.settings.hunt_executions_db)
            finding = store.get_finding(finding_id)
            if not finding:
                say(text=f"❌ *Finding `{finding_id}` not found in ledger.*", thread_ts=thread_ts)
                return

            tuner = RuleTuner(workspace=self.workspace)
            res = tuner.auto_tune_from_finding(finding)

            if res.ok:
                store.update_finding_tuning(
                    finding_id=finding_id,
                    status="tuned",
                    instruction="Auto-derived from finding",
                    summary=res.action_summary,
                )
                diff_snip = f"```diff\n{res.diff[:600]}\n```" if res.diff else ""
                msg = (
                    f"🛠️ *Sigma Detection Rule Tuned by <@{user_id}>*\n"
                    f"• *Hunt ID:* `{res.hunt_id}`\n"
                    f"• *Finding:* `{finding_id}`\n"
                    f"• *Action:* {res.action_summary}\n"
                    f"• *Re-transpiled Dialects:* {', '.join(f'`{t}`' for t in res.transpiled_targets)}\n"
                    f"{diff_snip}"
                )
            else:
                msg = f"⚠️ *Rule Tuning Failed for `{res.hunt_id}`:* {res.error}"

            say(text=msg, thread_ts=thread_ts)

        def _reviewer(user: dict[str, Any]) -> str:
            name = user.get("username") or user.get("name") or ""
            return f"slack:{user.get('id', 'unknown')}" + (f" ({name})" if name else "")

        def _review_notice(res: dict[str, Any], user_id: str) -> str:
            if not res.get("ok"):
                return f"⚠️ {res.get('error')}"
            verb = "approved" if res.get("status") == "active" else "rejected"
            return (
                f"{'✅' if verb == 'approved' else '🚫'} `{res['hunt_id']}` {verb} by <@{user_id}>"
            )

        def _open_approve_modal(
            client: Any, trigger_id: str, hunt_id: str, metadata: dict[str, Any]
        ) -> None:
            destination = (
                self.settings.github_publishing_repository
                if self.settings.github_publishing_enabled
                else None
            )
            from hecate_runner.lifecycle import find_hunt_path
            from hecate_runner.publish_check import evaluate_saved_hunt

            hunt_path = find_hunt_path(self.settings.hecate_workspace, hunt_id)
            findings: list[dict[str, Any]] = []
            lab_probe: dict[str, Any] | None = None
            if hunt_path is not None:
                content = hunt_path.read_text(encoding="utf-8")
                report = evaluate_saved_hunt(
                    self.settings.hecate_workspace,
                    hunt_id,
                    content,
                )
                findings = [item.to_dict() for item in report.blocking()]
                from hecate_runner.lifecycle import parse_hunt_frontmatter
                from hecate_runner.slack_blocks import _frontmatter_lab_probe

                fm, _, _ = parse_hunt_frontmatter(content)
                lab_probe = _frontmatter_lab_probe(fm)
            client.views_open(
                trigger_id=trigger_id,
                view=build_approve_hunt_modal(
                    hunt_id,
                    json.dumps(metadata),
                    destination=destination,
                    findings=findings,
                    lab_probe=lab_probe,
                ),
            )

        @self._app.action("hecate_pending_approve")
        def handle_pending_approve(ack: Any, body: dict[str, Any], client: Any) -> None:
            ack()
            hunt_id = str(body.get("actions", [{}])[0].get("value") or "").strip()
            metadata = {"hunt_id": hunt_id, "response_url": body.get("response_url")}
            _open_approve_modal(client, body["trigger_id"], hunt_id, metadata)

        @self._app.view("hecate_approve_hunt_modal")
        def handle_approve_submission(
            ack: Any, body: dict[str, Any], view: dict[str, Any], client: Any
        ) -> None:
            metadata = json.loads(view.get("private_metadata") or "{}")
            hunt_id = str(metadata.get("hunt_id") or "")
            values = view.get("state", {}).get("values", {})
            publishing = self.settings.github_publishing_enabled
            rights = ""
            if publishing:
                checked = {
                    option.get("value")
                    for option in values.get("release_checks", {})
                    .get("checks", {})
                    .get("selected_options")
                    or []
                }
                rights = str(
                    values.get("release_rights", {}).get("rights", {}).get("value") or ""
                ).strip()
                errors = {}
                if checked != {"privacy", "redistribution"}:
                    errors["release_checks"] = "Both checks are required to publish."
                if len(rights) < 20:
                    errors["release_rights"] = "Say why the source can be republished."
                if errors:
                    ack(response_action="errors", errors=errors)
                    return

            user = body.get("user", {})
            reviewer = _reviewer(user)
            override = str(
                values.get("publish_override", {}).get("override", {}).get("value") or ""
            ).strip()
            res = review_hunt(
                self.settings.hecate_workspace,
                hunt_id,
                approve=True,
                reviewer=reviewer,
                override=override,
            )
            if not res.get("ok"):
                if res.get("needs_override") and "publish_override" in values:
                    ack(
                        response_action="errors",
                        errors={"publish_override": str(res.get("error"))[:150]},
                    )
                elif publishing:
                    ack(response_action="errors", errors={"release_checks": str(res.get("error"))[:150]})
                else:
                    ack()
                    _post_review_result(client, metadata, f"⚠️ {res.get('error')}")
                return
            ack()

            notice = _review_notice(res, str(user.get("id", "")))
            if publishing:
                published = publish_reviewed_hunt(
                    self.settings, hunt_id, reviewer=reviewer, rights_note=rights
                )
                if published["ok"]:
                    notice += (
                        f"\n*Step 2:* approve <{published['pr_url']}|PR #{published['pr_number']}>"
                        " on GitHub to publish it."
                    )
                else:
                    notice += (
                        f"\n⚠️ Not published: {published['error']}. "
                        f"Retry with `hecate-runner publish {hunt_id}`."
                    )
            _post_review_result(client, metadata, notice)

        def _post_review_result(client: Any, metadata: dict[str, Any], notice: str) -> None:
            if response_url := metadata.get("response_url"):
                from slack_sdk.webhook import WebhookClient

                WebhookClient(response_url).send(
                    replace_original=True,
                    attachments=build_pending_hunts_card(
                        list_pending_hunts(self.settings.hecate_workspace), notice=notice
                    ),
                )
            elif metadata.get("channel"):
                client.chat_postMessage(
                    channel=metadata["channel"], thread_ts=metadata.get("thread_ts"), text=notice
                )

        @self._app.action("hecate_pending_reject")
        def handle_pending_reject(ack: Any, body: dict[str, Any], client: Any) -> None:
            ack()
            hunt_id = str(body.get("actions", [{}])[0].get("value") or "").strip()
            metadata = json.dumps({"hunt_id": hunt_id, "response_url": body.get("response_url")})
            client.views_open(
                trigger_id=body["trigger_id"], view=build_reject_hunt_modal(hunt_id, metadata)
            )

        @self._app.view("hecate_reject_hunt_modal")
        def handle_reject_submission(ack: Any, body: dict[str, Any], view: dict[str, Any]) -> None:
            metadata = json.loads(view.get("private_metadata") or "{}")
            hunt_id = str(metadata.get("hunt_id") or "")
            reason = str(
                view.get("state", {})
                .get("values", {})
                .get("reject_reason", {})
                .get("reason", {})
                .get("value")
                or ""
            ).strip()
            if not reason:
                ack(response_action="errors", errors={"reject_reason": "Give a reason."})
                return

            user = body.get("user", {})
            res = review_hunt(
                self.settings.hecate_workspace,
                hunt_id,
                approve=False,
                reviewer=_reviewer(user),
                reason=reason,
            )
            if not res.get("ok"):
                ack(response_action="errors", errors={"reject_reason": str(res.get("error"))})
                return
            ack()

            response_url = metadata.get("response_url")
            if response_url:
                from slack_sdk.webhook import WebhookClient

                WebhookClient(response_url).send(
                    replace_original=True,
                    attachments=build_pending_hunts_card(
                        list_pending_hunts(self.settings.hecate_workspace),
                        notice=_review_notice(res, str(user.get("id", ""))),
                    ),
                )

        @self._app.command("/hecate")
        def handle_hecate_command(ack: Any, body: dict[str, Any], respond: Any) -> None:
            ack()
            text = str(body.get("text") or "").strip()
            tokens = text.split()
            subcmd = tokens[0].lower() if tokens else "help"
            user_id = str(body.get("user_id") or "analyst")
            channel_id = str(body.get("channel_id") or "")

            log.info("Slack slash command /hecate '%s' from %s in %s", text, user_id, channel_id)

            if subcmd in {"help", "-h", "--help"}:
                card = build_slash_help_card()
                respond(attachments=card)
                return

            if subcmd == "status":
                card = build_runner_status_card(self.settings)
                respond(attachments=card)
                return

            if subcmd in {"pending", "review"}:
                hunts = list_pending_hunts(self.settings.hecate_workspace)
                respond(attachments=build_pending_hunts_card(hunts))
                return

            if subcmd == "deploy":
                if len(tokens) < 2:
                    respond(
                        text=(
                            "⚠️ *Usage:* `/hecate deploy <hunt_id> [target]`\n"
                            "• Example: `/hecate deploy H-0868`\n"
                            "• Example: `/hecate deploy H-0868 sentinel_kql`"
                        )
                    )
                    return

                hunt_id = tokens[1].upper()
                target = tokens[2].lower() if len(tokens) > 2 else None
                is_dry_run = getattr(self.settings, "siem_deploy_dry_run", True)
                mode_str = "Simulated (Dry-Run)" if is_dry_run else "Live API Push"

                deployments = deploy_queries_for_hunt(
                    self.settings.hecate_workspace,
                    hunt_id,
                    dry_run=is_dry_run,
                    target=target,
                )
                if not deployments:
                    respond(text=f"⚠️ *No queries found for `{hunt_id}`* under `queries/{hunt_id}`.")
                    return

                rows = []
                for d in deployments:
                    icon = "✅" if d.get("ok") else "❌"
                    tgt = d.get("target")
                    st = d.get("status")
                    rem_id = f" (`{d.get('remote_id')}`)" if d.get("remote_id") else ""
                    rows.append(f"{icon} *{tgt}:* `{st}`{rem_id}")

                rows_text = "\n".join(rows)
                msg = (
                    f"🔍 *SIEM & EDR Query Deployment for `{hunt_id}`*\n"
                    f"*Mode:* `{mode_str}` | *Initiated by:* <@{user_id}>\n\n"
                    f"{rows_text}"
                )
                respond(text=msg)
                return

            if subcmd == "undeploy":
                if len(tokens) < 2:
                    respond(
                        text=(
                            "⚠️ *Usage:* `/hecate undeploy <hunt_id> [target]`\n"
                            "• Example: `/hecate undeploy H-0868`\n"
                            "• Example: `/hecate undeploy H-0868 splunk_spl`"
                        )
                    )
                    return

                hunt_id = tokens[1].upper()
                target = tokens[2].lower() if len(tokens) > 2 else None
                is_dry_run = getattr(self.settings, "siem_deploy_dry_run", True)
                mode_str = "Simulated (Dry-Run)" if is_dry_run else "Live Teardown"

                undeployments = undeploy_queries_for_hunt(
                    self.settings.hecate_workspace,
                    hunt_id,
                    dry_run=is_dry_run,
                    target=target,
                )
                if not undeployments:
                    respond(text=f"⚠️ *No queries found for `{hunt_id}`* under `queries/{hunt_id}`.")
                    return

                rows = []
                for d in undeployments:
                    icon = "✅" if d.get("ok") else "❌"
                    tgt = d.get("target")
                    st = d.get("status")
                    rem_id = f" (`{d.get('remote_id')}`)" if d.get("remote_id") else ""
                    rows.append(f"{icon} *{tgt}:* `{st}`{rem_id}")

                rows_text = "\n".join(rows)
                msg = (
                    f"🗑️ *SIEM & EDR Query Undeployment for `{hunt_id}`*\n"
                    f"*Mode:* `{mode_str}` | *Initiated by:* <@{user_id}>\n\n"
                    f"{rows_text}"
                )
                respond(text=msg)
                return

            if subcmd == "sync":
                if len(tokens) < 2:
                    respond(
                        text=(
                            "⚠️ *Usage:* `/hecate sync <hunt_id> [target]`\n"
                            "• Example: `/hecate sync H-0868`\n"
                            "• Example: `/hecate sync H-0868 splunk_spl`"
                        )
                    )
                    return

                hunt_id = tokens[1].upper()
                target = tokens[2].lower() if len(tokens) > 2 else None
                is_dry_run = getattr(self.settings, "siem_deploy_dry_run", True)
                mode_str = "Simulated (Dry-Run)" if is_dry_run else "Live API Sync"

                syncs = sync_queries_for_hunt(
                    self.settings.hecate_workspace,
                    hunt_id,
                    dry_run=is_dry_run,
                    target=target,
                )
                if not syncs:
                    respond(text=f"⚠️ *No queries found for `{hunt_id}`* under `queries/{hunt_id}`.")
                    return

                rows = []
                for s in syncs:
                    icon = (
                        "✅"
                        if s.get("status") in {"in_sync", "dry_run"}
                        else ("⚠️" if s.get("status") == "drift_detected" else "❌")
                    )
                    tgt = s.get("target")
                    st = s.get("status")
                    rem_id = f" (`{s.get('remote_id')}`)" if s.get("remote_id") else ""
                    rows.append(f"{icon} *{tgt}:* `{st}`{rem_id}")

                rows_text = "\n".join(rows)
                msg = (
                    f"🔄 *SIEM & EDR Query Synchronization & Drift Check for `{hunt_id}`*\n"
                    f"*Mode:* `{mode_str}` | *Initiated by:* <@{user_id}>\n\n"
                    f"{rows_text}"
                )
                respond(text=msg)
                return

            if subcmd in {"reconcile", "reconcile-queries"}:
                if len(tokens) < 2:
                    respond(
                        text=(
                            "⚠️ *Usage:* `/hecate reconcile <hunt_id> [target]`\n"
                            "• Example: `/hecate reconcile H-0007`\n"
                            "• Example: `/hecate reconcile H-0007 splunk_spl`"
                        )
                    )
                    return

                hunt_id = tokens[1].upper()
                target = tokens[2].lower() if len(tokens) > 2 else None
                is_dry_run = getattr(self.settings, "siem_deploy_dry_run", True)
                mode_str = "Simulated (Dry-Run)" if is_dry_run else "Live Push"

                from hecate_runner.siem_drift import reconcile_hunt_queries

                results = reconcile_hunt_queries(
                    self.settings.hecate_workspace,
                    hunt_id,
                    target=target,
                    dry_run=is_dry_run,
                    actor=f"slack:{user_id}",
                )
                reconciled = [r for r in results if r.get("ok")]
                rows = [
                    f"• `{r.get('target')}` ({r.get('file')}): `{r.get('previous_status')}` ➔ `in_sync`"
                    for r in reconciled
                ]
                rows_text = "\n".join(rows) if rows else "No drifted or missing queries found."

                msg = (
                    f"🔄 *SIEM Reconciliation for `{hunt_id}`*\n"
                    f"*Mode:* `{mode_str}` | *Initiated by:* <@{user_id}>\n\n"
                    f"{rows_text}"
                )
                respond(text=msg)
                return

            if subcmd in {"audit-siem", "siem-audit"}:
                target = tokens[1].lower() if len(tokens) > 1 else None
                is_dry_run = getattr(self.settings, "siem_deploy_dry_run", True)
                mode_str = "Simulated (Dry-Run)" if is_dry_run else "Live API"

                from hecate_runner.siem_drift import audit_workspace_queries

                report = audit_workspace_queries(
                    self.settings.hecate_workspace,
                    target=target,
                    dry_run=is_dry_run,
                    trigger=f"slack:{user_id}",
                )
                msg = (
                    f"🔍 *SIEM & EDR Detection-as-Code Audit*\n"
                    f"*Mode:* `{mode_str}` | *Initiated by:* <@{user_id}>\n\n"
                    f"• *Hunts Audited:* `{report.get('total_hunts', 0)}`\n"
                    f"• *Total Queries:* `{report.get('total_queries', 0)}`\n"
                    f"• *In-Sync:* `{report.get('in_sync_count', 0)}`\n"
                    f"• *Drifted:* `{report.get('drifted_count', 0)}`\n"
                    f"• *Missing in SIEM:* `{report.get('missing_count', 0)}`\n"
                )
                respond(text=msg)
                return

            if subcmd in {"siem-status", "siem"}:
                from hecate_runner.siem_drift import get_drift_history, get_siem_drift_metrics
                from hecate_runner.slack_blocks import build_siem_status_card

                metrics = get_siem_drift_metrics(self.settings.hecate_workspace, days=7)
                recent_history = get_drift_history(self.settings.hecate_workspace, limit=5)
                card = build_siem_status_card(self.settings, metrics, recent_history)
                respond(attachments=card)
                return

            if subcmd in {"history", "drift-history"}:
                history_hunt = tokens[1].upper() if len(tokens) > 1 else None
                from hecate_runner.siem_drift import get_drift_history
                from hecate_runner.slack_blocks import build_siem_history_card

                history = get_drift_history(
                    self.settings.hecate_workspace, hunt_id=history_hunt, limit=10
                )
                card = build_siem_history_card(history_hunt, history)
                respond(attachments=card)
                return

            if subcmd == "rerun":
                if len(tokens) < 2:
                    respond(
                        text="⚠️ *Usage:* `/hecate rerun <hunt_id>` (e.g. `/hecate rerun H-0868`)"
                    )
                    return

                hunt_id = tokens[1].upper()
                res = replay_hunt_purple_team(self.settings.hecate_workspace, hunt_id)
                if res.get("ok"):
                    msg = (
                        f"🧪 *Purple Team Replay for `{hunt_id}` Completed*\n"
                        f"• *Requested by:* <@{user_id}>\n"
                        f"• *Rules Tested:* {res.get('total_rules')}\n"
                        f"• *Rules Validated:* {res.get('passed_rules')}\n"
                        f"• *Detection Fidelity:* {res.get('fidelity')}\n"
                        f"• *Sandbox Telemetry:* {res.get('sample_events_count')} events evaluated"
                    )
                else:
                    msg = f"❌ *Purple Team Replay failed for `{hunt_id}`:* {res.get('error')}"
                respond(text=msg)
                return

            if subcmd == "hunt":
                if len(tokens) < 2:
                    respond(
                        text=(
                            "⚠️ *Usage:* `/hecate hunt <topic_or_cve>`\n"
                            "• Example: `/hecate hunt Akira Ransomware`\n"
                            "• Example: `/hecate hunt CVE-2024-38077`"
                        )
                    )
                    return

                topic = " ".join(tokens[1:])
                respond(
                    text=(
                        f"🚀 *Ad-hoc Hunt Initiated:* Launching autonomous research & hypothesis pipeline for *{topic}*...\n"
                        f"_Processing within workspace `{self.settings.hecate_workspace.name}`..._"
                    )
                )
                try:
                    res = execute_adhoc_hunt(self.settings, topic=topic)
                    if getattr(res, "ok", False) and getattr(res, "hunt_id", None):
                        finish_msg = (
                            f"✅ *Ad-hoc Hunt Completed: `{res.hunt_id}`*\n"
                            f"• *Topic:* {topic}\n"
                            f"• *Draft Path:* `{res.draft_path}`\n"
                            f"• *Research ID:* `{res.research_id or 'none'}`"
                        )
                    else:
                        outcome = getattr(res, "outcome", "error")
                        detail = getattr(res, "detail", "")
                        finish_msg = f"⚠️ *Ad-hoc Hunt finished with status `{outcome}`:* {detail}"
                except Exception as h_err:
                    finish_msg = f"❌ *Ad-hoc Hunt failed for `{topic}`:* {h_err}"

                respond(text=finish_msg)
                return

            if subcmd == "tune":
                if len(tokens) < 3:
                    respond(
                        text=(
                            "⚠️ *Usage:* `/hecate tune <hunt_id> <instruction>`\n"
                            "• Example: `/hecate tune H-0868 exclude svchost.exe with parent services.exe`\n"
                            "• Example: `/hecate tune H-0868 filter path C:\\Program Files\\AdminTools`"
                        )
                    )
                    return

                hunt_id = tokens[1].upper()
                instruction = " ".join(tokens[2:])
                from hecate_runner.rule_tuner import RuleTuner

                tuner = RuleTuner(self.settings.hecate_workspace)
                tune_res = tuner.tune_hunt_rule(hunt_id, instruction)
                if tune_res.ok:
                    purple_res = replay_hunt_purple_team(self.settings.hecate_workspace, hunt_id)
                    fidelity = purple_res.get("fidelity", "100%") if purple_res.get("ok") else "N/A"
                    passed = purple_res.get("passed_rules", 0) if purple_res.get("ok") else 0
                    total = purple_res.get("total_rules", 0) if purple_res.get("ok") else 0
                    purple_summary = f"{passed}/{total} rules passed ({fidelity} fidelity)"

                    gh_summary = ""
                    if self.settings.github_publishing_enabled:
                        try:
                            from hecate_runner.github_publisher import enqueue_hunt, sync_outbox

                            enqueue_hunt(self.settings, hunt_id)
                            pub_results = sync_outbox(self.settings)
                            for pr in pub_results:
                                if pr.hunt_id == hunt_id:
                                    if pr.pr_url:
                                        gh_summary = f"\n• *GitHub Pull Request:* <{pr.pr_url}|PR #{pr.pr_number}> updated (`{pr.digest[:8]}`)"
                                    else:
                                        gh_summary = f"\n• *GitHub Outbox:* Enqueued revision (`{pr.digest[:8]}`)"
                                    break
                        except Exception as gh_err:
                            log.warning("Failed to sync GitHub PR for %s: %s", hunt_id, gh_err)
                            gh_summary = f"\n• *GitHub PR Sync:* Warning: {gh_err}"

                    targets_str = ", ".join(f"`{t}`" for t in tune_res.transpiled_targets) or "None"
                    sub_warn_str = ""
                    if tune_res.subsumption_warnings:
                        sub_warn_str = (
                            f"\n⚠️ *Subsumption Warning:* {'; '.join(tune_res.subsumption_warnings)}"
                        )

                    msg = (
                        f"🛠️ *Sigma Rule Tuned & Autonomous Validation Completed for `{hunt_id}`*\n"
                        f"• *Analyst Instruction:* _{instruction}_\n"
                        f"• *Action Taken:* {tune_res.action_summary}\n"
                        f"• *Updated Telemetry Targets:* {targets_str}\n"
                        f"• *Purple-Team Validation:* {purple_summary}"
                        f"{gh_summary}"
                        f"{sub_warn_str}\n\n"
                        f"```diff\n{tune_res.diff}\n```"
                    )
                else:
                    msg = f"❌ *Rule tuning failed for `{hunt_id}`:* {tune_res.error}"

                respond(text=msg)
                return

            respond(
                text=f"❓ Unknown command `/hecate {subcmd}`. Type `/hecate help` for available commands."
            )

        @self._app.event("app_mention")
        def handle_app_mention(body: dict[str, Any], say: Any, client: Any = None) -> None:
            handle_thread_message(body, say, client=client)

        @self._app.event("message")
        def handle_thread_message(body: dict[str, Any], say: Any, client: Any = None) -> None:
            event = body.get("event", {})
            if event.get("subtype") or event.get("bot_id"):
                return
            is_mention = event.get("type") == "app_mention"
            thread_ts = event.get("thread_ts")
            if not thread_ts:
                if is_mention:
                    thread_ts = event.get("ts")
                else:
                    return

            text = str(event.get("text") or "").strip()
            if not text:
                return

            user_id = str(event.get("user") or "analyst")

            # Resolve hunt ID
            hunt_id = self._thread_hunt_map.get(thread_ts)
            if not hunt_id:
                h_match = re.search(r"(?i)\b(H-\d+)\b", text)
                if h_match:
                    hunt_id = h_match.group(1).upper()

            if not hunt_id and client:
                try:
                    channel = event.get("channel")
                    resp = client.conversations_replies(channel=channel, ts=thread_ts, limit=1)
                    messages = resp.get("messages", [])
                    if messages:
                        parent_text = messages[0].get("text", "")
                        h_match = re.search(r"(?i)\b(H-\d+)\b", parent_text)
                        if h_match:
                            hunt_id = h_match.group(1).upper()
                            self._thread_hunt_map[thread_ts] = hunt_id
                except Exception as c_err:
                    log.debug("Thread parent lookup failed: %s", c_err)

            if not hunt_id:
                if is_mention:
                    say(
                        text=(
                            "⚠️ *Could not identify hunt ID for tuning.* "
                            "Please specify the hunt ID (e.g. `@hecate tune H-0700 exclude svchost.exe with parent services.exe`) "
                            "or reply in an active hunt notification thread."
                        ),
                        thread_ts=thread_ts,
                    )
                return

            log.info("Conversational HITL rule tuning for %s from %s: '%s'", hunt_id, user_id, text)
            from hecate_runner.rule_tuner import RuleTuner

            tuner = RuleTuner(self.settings.hecate_workspace)
            res = tuner.tune_hunt_rule(hunt_id, text)

            if res.ok:
                purple_res = replay_hunt_purple_team(self.settings.hecate_workspace, hunt_id)
                fidelity = purple_res.get("fidelity", "100%") if purple_res.get("ok") else "N/A"
                passed = purple_res.get("passed_rules", 0) if purple_res.get("ok") else 0
                total = purple_res.get("total_rules", 0) if purple_res.get("ok") else 0
                purple_summary = f"{passed}/{total} rules passed ({fidelity} fidelity)"

                gh_summary = ""
                if self.settings.github_publishing_enabled:
                    try:
                        from hecate_runner.github_publisher import enqueue_hunt, sync_outbox

                        enqueue_hunt(self.settings, hunt_id)
                        pub_results = sync_outbox(self.settings)
                        for pr in pub_results:
                            if pr.hunt_id == hunt_id:
                                if pr.pr_url:
                                    gh_summary = f"\n• *GitHub Pull Request:* <{pr.pr_url}|PR #{pr.pr_number}> updated (`{pr.digest[:8]}`)"
                                else:
                                    gh_summary = f"\n• *GitHub Outbox:* Enqueued revision (`{pr.digest[:8]}`)"
                                break
                    except Exception as gh_err:
                        log.warning(
                            "Failed to sync GitHub PR for %s after tuning: %s", hunt_id, gh_err
                        )
                        gh_summary = f"\n• *GitHub PR Sync:* Warning: {gh_err}"

                targets_str = ", ".join(f"`{t}`" for t in res.transpiled_targets) or "None"
                msg = (
                    f"🛠️ *Sigma Rule Tuned & Re-Transpiled for `{hunt_id}`*\n"
                    f"• *Analyst Instruction:* _{text}_\n"
                    f"• *Action Taken:* {res.action_summary}\n"
                    f"• *Updated Telemetry Targets:* {targets_str}\n"
                    f"• *Purple-Team Validation:* {purple_summary}"
                    f"{gh_summary}\n\n"
                    f"```diff\n{res.diff}\n```"
                )
            else:
                msg = (
                    f"⚠️ *Rule Tuning Note for `{hunt_id}`:* {res.error}\n"
                    f"_Try instructions like 'Exclude svchost.exe', 'Filter out CommandLine /update', or 'Add Image pwsh.exe'._"
                )

            say(text=msg, thread_ts=thread_ts)

    def start(self) -> None:
        """Start the Socket Mode handler loop."""
        if not self.is_configured or self._app is None:
            log.warning("Slack Bot not configured with valid tokens; start() is a no-op.")
            return

        from slack_bolt.adapter.socket_mode import SocketModeHandler

        app_tok = self.settings.slack_app_token or ""
        self._handler = SocketModeHandler(self._app, app_tok)
        log.info("Starting Hecate Slack Socket Mode Bot...")
        self._handler.start()

    def close(self) -> None:
        """Close the Socket Mode connection."""
        if self._handler:
            self._handler.close()
            self._handler = None
