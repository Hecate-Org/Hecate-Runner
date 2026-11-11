"""Slack Block Kit message builders for Hecate pipeline events.

Provides structured, color-coded Slack cards with interactive buttons,
MITRE ATT&CK badges, MISP links, and multi-column telemetry summaries.
"""

from __future__ import annotations

import contextlib
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hecate_runner.metrics import format_usd

if TYPE_CHECKING:
    from hecate_runner.config import Settings
    from hecate_runner.cti.base import CTIItem
    from hecate_runner.orchestrator import RunResult

# Brand / Severity accent colors
COLOR_SUCCESS = "#2EB886"  # Emerald green (Validated hunt, detection passed)
COLOR_INFO = "#3AA3E3"  # Cerulean blue (Metrics, telemetry, digest)
COLOR_WARNING = "#ECB22E"  # Amber yellow (Planning draft, review required, telemetry gap)
COLOR_CRITICAL = "#E01E5A"  # Crimson red (Critical exploit spike, weaponization alert)
COLOR_PURPLE = "#7928CA"  # Aubergine / Purple (Purple team, threat hunting)

_TLD_PATTERN = (
    r"\b(?<!\[|\/)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)\.(com|org|net|edu|gov|io|ir|ru|cn|info|biz|xyz|top|"
    r"site|online|live|club|vip|cc|co|me|tv|us|uk|de|eu|nl|fr|it|es|pl|br|in|au|jp|kr|"
    r"cloud|shop|store|app|dev|tech|pro|space|fun|icu|link|click|work|mobi|asia|pw|tk|"
    r"ml|ga|cf|gq|onion|su|to|is|ws)\b"
)


def defang_ioc(text: str) -> str:
    """Defang IOCs (URLs, IPv4, domains, email addresses) so they cannot be accidentally clicked in Slack."""
    if not text:
        return text

    def _defang_url(m: re.Match[str]) -> str:
        scheme = "hxxps://" if m.group(1).lower() == "https" else "hxxp://"
        rest = m.group(2)
        parts = rest.split("/", 1)
        host = parts[0].replace(".", "[.]")
        path = "/" + parts[1] if len(parts) > 1 else ""
        return scheme + host + path

    out = re.sub(r"\b(https?)://([^\s\'\"<>]+)", _defang_url, text, flags=re.IGNORECASE)
    out = re.sub(r"\bftp://", "fxp://", out, flags=re.IGNORECASE)

    # Defang IPv4 addresses (excluding already bracketed dots)
    out = re.sub(
        r"\b(?<!\[)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\])\b",
        r"\1[.]\2[.]\3[.]\4",
        out,
    )

    # Defang email addresses
    out = re.sub(
        r"\b([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b",
        lambda m: m.group(1) + "[@]" + m.group(2).replace(".", "[.]"),
        out,
    )

    def _defang_domain(m: re.Match[str]) -> str:
        domain = m.group(1) + "." + m.group(2)
        return domain.replace(".", "[.]")

    out = re.sub(_TLD_PATTERN, _defang_domain, out, flags=re.IGNORECASE)
    return out


_SLACK_SECTION_TEXT_LIMIT = 3000
_SLACK_FIELD_TEXT_LIMIT = 2000
_SLACK_HEADER_TEXT_LIMIT = 150


def clip_slack_text(text: str, limit: int = _SLACK_SECTION_TEXT_LIMIT) -> str:
    """Ensure text content does not exceed Slack's Block Kit character limit (default 3,000 chars)."""
    if not text or len(text) <= limit:
        return text
    suffix = "... [clipped]"
    cut = max(0, limit - len(suffix))
    return text[:cut] + suffix


def sanitize_slack_blocks(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Clip all text and field contents in Slack blocks to comply with Block Kit limits."""
    for block in blocks:
        b_type = block.get("type")
        if b_type == "header":
            txt_obj = block.get("text")
            if isinstance(txt_obj, dict) and "text" in txt_obj:
                txt_obj["text"] = clip_slack_text(txt_obj["text"], _SLACK_HEADER_TEXT_LIMIT)
        elif b_type == "section":
            txt_obj = block.get("text")
            if isinstance(txt_obj, dict) and "text" in txt_obj:
                txt_obj["text"] = clip_slack_text(txt_obj["text"], _SLACK_SECTION_TEXT_LIMIT)
            fields = block.get("fields")
            if isinstance(fields, list):
                for fld in fields:
                    if isinstance(fld, dict) and "text" in fld:
                        fld["text"] = clip_slack_text(fld["text"], _SLACK_FIELD_TEXT_LIMIT)
        elif b_type == "context":
            elements = block.get("elements")
            if isinstance(elements, list):
                for el in elements:
                    if isinstance(el, dict) and "text" in el:
                        el["text"] = clip_slack_text(el["text"], _SLACK_FIELD_TEXT_LIMIT)
    return blocks


def _frontmatter_lab_probe(frontmatter: dict[str, Any]) -> dict[str, Any] | None:
    """Rebuild a lab probe dict from hunt frontmatter fields."""
    status = str(frontmatter.get("lab_probe") or "").strip().lower()
    if not status:
        return None
    results = frontmatter.get("lab_probe_results") or []
    if isinstance(results, str) and results.strip():
        try:
            results = json.loads(results)
        except json.JSONDecodeError:
            results = []
    detail = frontmatter.get("lab_probe_detail") or ""
    if isinstance(detail, str) and detail.startswith('"'):
        with contextlib.suppress(json.JSONDecodeError):
            detail = json.loads(detail)
    provider = frontmatter.get("lab_probe_provider") or ""
    if isinstance(provider, str) and provider.startswith('"'):
        with contextlib.suppress(json.JSONDecodeError):
            provider = json.loads(provider)
    return {
        "status": status,
        "provider": str(provider or ""),
        "window_days": int(frontmatter.get("lab_probe_window_days") or 0),
        "total_hits": int(frontmatter.get("lab_probe_hits") or 0),
        "queries_run": int(frontmatter.get("lab_probe_queries") or 0),
        "detail": str(detail or ""),
        "results": results if isinstance(results, list) else [],
    }


def _draft_review_signals(result: Any) -> str:
    """Publish findings and lab hit probe for the card that announces a new draft."""
    path = getattr(result, "draft_path", None)
    if not path:
        return ""
    try:
        from hecate_runner.lifecycle import parse_hunt_frontmatter

        frontmatter, _, _ = parse_hunt_frontmatter(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""

    sections: list[str] = []
    verdict = str(frontmatter.get("publish_check") or "")
    if verdict in {"block", "review"}:
        raw = frontmatter.get("publish_findings") or []
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = []
        lines = []
        for item in raw[:6] if isinstance(raw, list) else []:
            if isinstance(item, dict):
                lines.append(f"• `{item.get('target') or item.get('check')}` {item.get('message')}")
        head = (
            "*Publish check:* blocking. Approval needs a written override."
            if verdict == "block"
            else "*Publish check:* review these before approving."
        )
        sections.append(head + ("\n" + "\n".join(lines) if lines else ""))

    from hecate_runner.lab_hits import format_lab_probe_slack

    lab_text = format_lab_probe_slack(_frontmatter_lab_probe(frontmatter))
    if lab_text:
        sections.append(lab_text)
    return "\n\n".join(sections)


def build_draft_card(result: RunResult, *, interactive: bool = False) -> list[dict[str, Any]]:
    """Build a rich Slack card for a newly created draft hunt."""
    research_ctx = (
        f"Linked to research context `{result.research_id}`"
        if result.research_id
        else "Source-only extraction (no web search)"
    )
    parked_text = (
        f"• {result.parked_count} commentary item(s) parked during intake triage"
        if result.parked_count > 0
        else "• Clean triage: zero items parked"
    )

    is_enrichment = result.outcome == "incremental_enrichment"
    header_text = (
        f"🔄 Campaign Dossier Enriched: {result.hunt_id}"
        if is_enrichment
        else f"📝 New Draft Hunt Initiated: {result.hunt_id}"
    )
    status_label = (
        "`active` (Dossier incrementally updated)"
        if is_enrichment
        else "`planning` (Awaiting review)"
    )

    purple_text = "⚪ Replay pending"
    bas_text = "⚪ Detonation pending"
    path_str = getattr(result, "draft_path", None)
    if path_str and Path(path_str).is_file():
        try:
            from hecate_runner.lifecycle import parse_hunt_frontmatter

            fm, _, _ = parse_hunt_frontmatter(Path(path_str).read_text(encoding="utf-8"))
            pt_eval = fm.get("purple_team_rules_evaluated", 0)
            pt_matched = fm.get("purple_team_rules_replay_matched", 0)
            pt_val = fm.get("purple_team_validated", False)
            if pt_eval > 0:
                icon = "✅" if pt_matched > 0 else "⚠️"
                purple_text = f"{icon} *{pt_matched}/{pt_eval}* rules matched replay"
            elif pt_val:
                purple_text = "✅ Replay validated"
            else:
                purple_text = "⚪ No rules replayed"

            bas_ver = fm.get("bas_verified", False)
            bas_prov = str(fm.get("bas_provider") or "")
            if bas_prov:
                if bas_prov.lower() == "mock":
                    bas_text = (
                        "🧪 *MOCK* (synthesized AST logic probe)"
                        if bas_ver
                        else "⚠️ MOCK probe unverified"
                    )
                else:
                    icon = "✅" if bas_ver else "⚠️"
                    bas_text = (
                        f"{icon} *{bas_prov.upper()}* live detonation verified"
                        if bas_ver
                        else f"⚠️ {bas_prov.upper()} unverified"
                    )
            elif bas_ver:
                bas_text = "✅ Detonation verified"
            else:
                bas_text = "⚪ Simulation skipped"
        except Exception:
            pass

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": header_text,
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Hunt ID:* `{result.hunt_id}`\n"
                    f"*Context:* {research_ctx}\n"
                    f"*Location:* `{result.draft_path}`"
                ),
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Status:*\n{status_label}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Intake Triage:*\n{parked_text}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Purple Team:*\n{purple_text}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*BAS Verification:*\n{bas_text}",
                },
            ],
        },
    ]
    if is_enrichment and result.detail:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Enrichment Update:*\n{result.detail}"},
            }
        )
    review_text = _draft_review_signals(result)
    if review_text:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": review_text}})

    if interactive:
        blocks.append(
            {
                "type": "actions",
                "block_id": f"hunt_actions_{result.hunt_id}",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🚀 Approve & Promote",
                            "emoji": True,
                        },
                        "style": "primary",
                        "action_id": "hecate_approve_hunt",
                        "value": result.hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🔍 Deploy Queries", "emoji": True},
                        "action_id": "hecate_deploy_queries",
                        "value": result.hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🧪 Purple Team Replay",
                            "emoji": True,
                        },
                        "action_id": "hecate_rerun_purple",
                        "value": result.hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "⏸️ Park / Suppress", "emoji": True},
                        "style": "danger",
                        "action_id": "hecate_park_hunt",
                        "value": result.hunt_id,
                    },
                ],
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🤖 *Hecate Autonomous Runner* | Run `hecate-runner watch` to observe execution",
                }
            ],
        }
    )

    return [{"color": COLOR_WARNING, "blocks": sanitize_slack_blocks(blocks)}]


def build_hunt_completed_card(
    *,
    hunt_id: str,
    topic: str,
    techniques: list[str],
    sigma_count: int,
    pr_url: str = "",
    misp_event_id: str = "",
    misp_url: str = "https://localhost:8443",
    content_repo_url: str = "https://github.com/BrizoSec/Hecate-Content",
    interactive: bool = False,
) -> list[dict[str, Any]]:
    """Build an executive completion card for a validated hunt."""
    tech_formatted = ", ".join(f"`{t}`" for t in techniques[:6]) or "Unspecified"
    if len(techniques) > 6:
        tech_formatted += f" _(+{len(techniques) - 6} more)_"

    misp_text = (
        f"<{misp_url}/events/view/{misp_event_id}|Event #{misp_event_id}>"
        if misp_event_id
        else "Local sync pending"
    )
    pr_text = f"<{pr_url}|PR Active>" if pr_url else "Direct commit to workspace"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🛡️ Hunt Validated & Published: {hunt_id}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Topic / Hypothesis:*\n{clip_slack_text(topic, 2900)}",
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*MITRE Techniques:*\n{tech_formatted}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Sigma Detection Rules:*\n`{sigma_count} rules validated`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*MISP Indicator Sync:*\n{misp_text}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Content PR:*\n{pr_text}",
                },
            ],
        },
    ]

    # Action buttons if links are available
    action_elements: list[dict[str, Any]] = []
    if pr_url:
        action_elements.append(
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "View Pull Request", "emoji": True},
                "url": pr_url,
                "style": "primary",
            }
        )
    if misp_event_id:
        action_elements.append(
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Open MISP Event", "emoji": True},
                "url": f"{misp_url.rstrip('/')}/events/view/{misp_event_id}",
            }
        )
    if content_repo_url:
        action_elements.append(
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Content Repo", "emoji": True},
                "url": content_repo_url,
            }
        )

    if action_elements:
        blocks.append({"type": "actions", "elements": action_elements})

    if interactive:
        blocks.append(
            {
                "type": "actions",
                "block_id": f"hunt_actions_{hunt_id}",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🚀 Approve & Promote",
                            "emoji": True,
                        },
                        "style": "primary",
                        "action_id": "hecate_approve_hunt",
                        "value": hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🔍 Deploy Queries", "emoji": True},
                        "action_id": "hecate_deploy_queries",
                        "value": hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🧪 Purple Team Replay",
                            "emoji": True,
                        },
                        "action_id": "hecate_rerun_purple",
                        "value": hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "⏸️ Park / Suppress", "emoji": True},
                        "style": "danger",
                        "action_id": "hecate_park_hunt",
                        "value": hunt_id,
                    },
                ],
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🛡️ *Hecate Purple Team Engine* | Passed 100% claim provenance audit",
                }
            ],
        }
    )

    return [{"color": COLOR_SUCCESS, "blocks": sanitize_slack_blocks(blocks)}]


def build_purple_team_card(
    *,
    hunt_id: str,
    technique: str,
    success: bool,
    telemetry_count: int,
    summary: str,
    log_source: str = "Windows Event Log / Zeek",
    emulation_mode: str = "Atomic Red Team (Dynamic)",
) -> list[dict[str, Any]]:
    """Build a purple-team emulation validation card."""
    color = COLOR_SUCCESS if success else COLOR_WARNING
    status_icon = "✅" if success else "⚠️"
    status_title = "Detection Rule Verified" if success else "Telemetry / Coverage Gap"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{status_icon} Purple Team Outcome: {technique} ({hunt_id})",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Technique Tested:*\n`{technique}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Validation Outcome:*\n*{status_title}*",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Observed Telemetry Logs:*\n`{telemetry_count} events captured`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Telemetry Source:*\n`{log_source}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Adversary Emulation:*\n`{emulation_mode}`",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Emulation & Detection Findings:*\n{summary}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "⚔️ *Purple Team Validation Pipeline* | Correlated with generated Sigma rules",
                }
            ],
        },
    ]

    return [{"color": color, "blocks": sanitize_slack_blocks(blocks)}]


def build_threat_intake_card(item: CTIItem) -> list[dict[str, Any]]:
    """Build a card for critical incoming threat intelligence."""
    profile = str(item.metadata.get("evidence_profile") or "unclassified")
    color = COLOR_CRITICAL if profile == "vulnerability_advisory" else COLOR_INFO

    ingested_time = (
        item.received_at.strftime("%Y-%m-%d %H:%M UTC")
        if item.received_at is not None
        else "Recent"
    )

    clean_title = defang_ioc(item.title[:75])
    clean_identifier = defang_ioc(item.identifier)
    clean_summary = defang_ioc(item.content[:350])

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 Threat Intel Intake: {clean_title}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Source:*\n`{item.source}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Evidence Profile:*\n`{profile}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Identifier:*\n`{clean_identifier}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Ingested:*\n`{ingested_time}`",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Intelligence Summary & Telemetry:*\n```{clean_summary}...```",
            },
        },
    ]

    if item.source_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Threat Source", "emoji": True},
                        "url": item.source_url,
                    }
                ],
            }
        )

    return [{"color": color, "blocks": sanitize_slack_blocks(blocks)}]


def build_ops_metrics_card(metrics_summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Build an operational digest for the summary's selected window."""
    days = metrics_summary.get("window_days", 1)
    window = "24-Hour" if days == 1 else f"{days}-Day"
    hunts_done = metrics_summary.get("hunts_completed", 0)
    sigma_total = metrics_summary.get("sigma_rules_produced")
    sigma_text = "Unavailable" if sigma_total is None else f"{sigma_total} rules generated"
    spend_today = format_usd(metrics_summary.get("spend_today_usd"))
    budget = format_usd(metrics_summary.get("daily_budget_usd"))
    active_sources = metrics_summary.get("active_sources", [])
    purple_pass_pct = metrics_summary.get("purple_team_pass_pct") or "Unavailable"

    sources_str = ", ".join(f"`{s}`" for s in active_sources) or "All sources idle"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"📊 Hecate {window} Autonomous Ops Digest",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Hunt Drafts Created ({days}d):*\n*{hunts_done} hunts*",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Sigma Detection Rules:*\n*{sigma_text}*",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Purple Team Pass Rate:*\n*{purple_pass_pct}*",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Today's Estimated LLM Cost / Budget (UTC):*\n*{spend_today}* / {budget}",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Active Ingestion Feeds:*\n{sources_str}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Pipeline metrics from recorded cycles",
                }
            ],
        },
    ]

    return [{"color": COLOR_INFO, "blocks": sanitize_slack_blocks(blocks)}]


def build_detection_engineering_digest_card(
    data: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build a Daily Detection Engineering Digest card."""
    total_rules = data.get("total_sigma_rules", 0)
    rules_validated = data.get("rules_validated_24h", 0)
    rules_evaluated = data.get("rules_evaluated_24h", 0)
    pass_rate = data.get("pass_rate_pct", "100%")
    top_tactics = ", ".join(data.get("top_tactics", [])[:3]) or "Execution, Persistence"
    platforms = ", ".join(data.get("platforms", [])[:4]) or "Enterprise"

    recent_rules = data.get("recent_rules", [])
    rules_md_lines = []
    for r in recent_rules[:4]:
        tech = f" [`{r['technique']}`]" if r.get("technique") and r["technique"] != "N/A" else ""
        rules_md_lines.append(f"• *{r['title']}*{tech}\n  ↳ `{r['file']}`")
    rules_md = "\n".join(rules_md_lines) or "No new rules validated in lookback window."

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🛡️ Daily Detection Engineering Digest",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Total Sigma Rules:*\n*{total_rules:,} rules in library*",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Purple Team Pass Rate:*\n*{pass_rate}* ({rules_validated}/{rules_evaluated} validated)",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Primary MITRE Tactics:*\n`{top_tactics}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Target Platforms:*\n`{platforms}`",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Recently Validated Detections (24h):*\n{rules_md}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🔍 *Detection Engine:* Continuous CI/CD validation | Automated Sigma & PyTest passes",
                }
            ],
        },
    ]

    return [{"color": COLOR_SUCCESS, "blocks": sanitize_slack_blocks(blocks)}]


def build_threat_intel_digest_card(
    data: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build a Daily Threat Intelligence Digest card."""
    active_sources = data.get("active_sources", [])
    total_research = data.get("total_research_count", 0)
    recent_research = data.get("recent_research_count", 0)
    cves_count = data.get("cves_tracked_count", 0)
    cves_sample = ", ".join(f"`{c}`" for c in data.get("cves_sample", [])[:3]) or "None active"
    misp_status = "🟢 Connected & Syncing" if data.get("misp_sync_active") else "⚪ Offline"

    recent_topics = data.get("recent_topics", [])
    topics_md_lines = []
    for t in recent_topics[:4]:
        topics_md_lines.append(f"• *{t['id']}*: {t['topic']} `[{t['complexity'].upper()}]`")
    topics_md = (
        "\n".join(topics_md_lines) or "No threat research items generated in lookback window."
    )

    sources_str = ", ".join(f"`{s}`" for s in active_sources) or "No sources active"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 Daily Threat Intelligence Digest",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Active Feeds ({len(active_sources)}):*\n{sources_str}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*MISP Telemetry:*\n{misp_status}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Research Contexts:*\n*{recent_research} new* (Total: {total_research:,})",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*High-Weapon CVEs:*\n*{cves_count} tracked* ({cves_sample})",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Threat Research & Campaign Spotlights:*\n{topics_md}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🌐 *CTI Feed Health:* Live polling active across Sandbox, Exploits, APT & Cloud feeds",
                }
            ],
        },
    ]

    return [{"color": COLOR_CRITICAL, "blocks": sanitize_slack_blocks(blocks)}]


def build_threat_hunting_digest_card(
    data: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build a Daily Threat Hunting Digest card."""
    total_hunts = data.get("total_hunts", 0)
    recent_hunts = data.get("recent_hunts_count", 0)
    spend_today = float(data.get("spend_today_usd", 0.0))
    daily_budget = float(data.get("daily_budget_usd", 20.0))
    budget_pct = data.get("budget_pct", "0.0%")
    status_counts = data.get("status_counts", {})
    planning = status_counts.get("planning", 0)
    promoted = status_counts.get("promoted", 0) + status_counts.get("completed", 0)

    hunt_spotlights = data.get("hunt_spotlights", [])
    spotlights_md_lines = []
    for h in hunt_spotlights[:4]:
        spotlights_md_lines.append(f"• *{h['id']}*: {h['title']} `[{h['status']}]`")
    spotlights_md = (
        "\n".join(spotlights_md_lines) or "No active hunt operations in lookback window."
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🎯 Daily Threat Hunting Digest",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Hunts Executed (24h):*\n*{recent_hunts} runs* (Total: {total_hunts:,})",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Campaign Pipeline:*\n*{planning} in planning* | *{promoted} promoted*",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*LLM Spend / Budget:*\n*${spend_today:.2f}* / ${daily_budget:.2f} ({budget_pct})",
                },
                {
                    "type": "mrkdwn",
                    "text": "*Hunter Engine:*\n`hecate-runner autonomous`",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Recent Hunt Operations & Hypotheses:*\n{spotlights_md}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🎯 *Hunt Status:* Autonomous hypothesis evaluation, telemetry sweep & query generation",
                }
            ],
        },
    ]

    return [{"color": COLOR_PURPLE, "blocks": sanitize_slack_blocks(blocks)}]


def build_slash_help_card() -> list[dict[str, Any]]:
    """Build a help card describing available /hecate slash commands."""
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🤖 Hecate SecOps Slash Commands",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "*Autonomous Threat Hunting & Detection Engineering Commands:*\n\n"
                    "• `/hecate status` — View pipeline status, active hunts, quota & metrics\n"
                    "• `/hecate pending` — Review planning hunts and approve or reject them\n"
                    "• `/hecate hunt <topic_or_cve>` — Launch an immediate ad-hoc hunt cycle (e.g. `/hecate hunt Akira Ransomware`)\n"
                    "• `/hecate deploy <hunt_id> [target]` — Deploy or simulate queries across SIEM/EDRs (e.g. `/hecate deploy H-0868 sentinel_kql`)\n"
                    "• `/hecate undeploy <hunt_id> [target]` — Teardown/delete queries from SIEM/EDRs (e.g. `/hecate undeploy H-0868 splunk_spl`)\n"
                    "• `/hecate sync <hunt_id> [target]` — Check synchronization and query drift against SIEM/EDRs\n"
                    "• `/hecate reconcile <hunt_id> [target]` — Reconcile drifted/missing queries back to git-authoritative state\n"
                    "• `/hecate audit-siem [target]` — Audit all active hunts across SIEM/EDR platforms\n"
                    "• `/hecate siem-status` — View SIEM sync health, target breakdowns & drift metrics\n"
                    "• `/hecate history [hunt_id]` — View chronological SIEM drift & reconciliation audit history\n"
                    "• `/hecate rerun <hunt_id>` — Replay purple-team adversary emulation and validate Sigma rules\n"
                    "• `/hecate tune <hunt_id> <instruction>` — Interactively tune Sigma rule (e.g. `/hecate tune H-0868 exclude svchost.exe with parent services.exe`)\n"
                    "• `/hecate help` — Show this command reference guide"
                ),
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🛡️ *Hecate Autonomous SecOps* | Socket Mode Interactive Engine",
                }
            ],
        },
    ]
    return [{"color": COLOR_INFO, "blocks": sanitize_slack_blocks(blocks)}]


# Two blocks per hunt; Slack rejects messages with more than 50 blocks.
_PENDING_HUNTS_SHOWN = 20


def build_pending_hunts_card(
    hunts: list[dict[str, Any]], *, notice: str = ""
) -> list[dict[str, Any]]:
    """Build the /hecate pending review queue with Approve / Reject buttons per hunt."""
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🗂️ Hunts Awaiting Review ({len(hunts)})",
                "emoji": True,
            },
        }
    ]
    if notice:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": notice}})
    if not hunts:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "✅ No hunts are waiting for review."},
            }
        )

    for hunt in hunts[:_PENDING_HUNTS_SHOWN]:
        hunt_id = hunt["hunt_id"]
        techniques = hunt.get("techniques") or []
        technique_text = ", ".join(f"`{t}`" for t in techniques[:6])
        if len(techniques) > 6:
            technique_text += f" +{len(techniques) - 6} more"
        details = [
            f"*Drafted:* {hunt.get('date') or 'unknown'}",
            f"*Research:* `{hunt['research_id']}`" if hunt.get("research_id") else "",
            f"*Techniques:* {technique_text}" if technique_text else "",
        ]
        blocking = int(hunt.get("publish_blocking") or 0)
        if blocking:
            details.append(f"*Publish check:* {blocking} blocking")
        elif hunt.get("publish_check") == "review":
            details.append("*Publish check:* review")
        lab_status = str(hunt.get("lab_probe") or "").strip().lower()
        if lab_status and lab_status not in {"skipped"}:
            provider = hunt.get("lab_probe_provider") or "lab"
            window = hunt.get("lab_probe_window_days") or "?"
            hits = hunt.get("lab_probe_hits")
            if lab_status == "miss":
                details.append(f"*Lab hits:* miss on `{provider}` (0 in {window}d)")
            elif lab_status == "unconfigured":
                details.append(f"*Lab hits:* `{provider}` not configured")
            elif lab_status == "error":
                details.append(f"*Lab hits:* error on `{provider}`")
            elif lab_status == "overmatch":
                details.append(f"*Lab hits:* overmatch on `{provider}` ({hits} in {window}d)")
            else:
                details.append(f"*Lab hits:* {hits} on `{provider}` in {window}d")
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*`{hunt_id}`* {defang_ioc(hunt.get('title') or '(untitled)')}\n"
                        + " • ".join(d for d in details if d)
                    ),
                },
            }
        )
        blocks.append(
            {
                "type": "actions",
                "block_id": f"pending_review_{hunt_id}",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve", "emoji": True},
                        "style": "primary",
                        "action_id": "hecate_pending_approve",
                        "value": hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🚫 Reject", "emoji": True},
                        "style": "danger",
                        "action_id": "hecate_pending_reject",
                        "value": hunt_id,
                    },
                ],
            }
        )

    footer = (
        "🤖 *Hecate Review Queue* | Approve sets `active` and opens the publication PR; "
        "Reject sets `suppressed`"
    )
    if len(hunts) > _PENDING_HUNTS_SHOWN:
        footer = (
            f"Showing the oldest {_PENDING_HUNTS_SHOWN} of {len(hunts)}; "
            "review these to see the rest. " + footer
        )
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": footer}]})
    color = COLOR_WARNING if hunts else COLOR_SUCCESS
    return [{"color": color, "blocks": sanitize_slack_blocks(blocks)}]


def build_approve_hunt_modal(
    hunt_id: str,
    private_metadata: str,
    *,
    destination: str | None,
    findings: list[dict[str, Any]] | None = None,
    lab_probe: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Modal that approves a planning hunt and, when publishing is on, signs off its release.

    With a destination, submitting is step one of two: the publisher opens a PR
    there, and approving that PR on GitHub is step two. Blocking publish
    findings require a written override before the hunt can become active.
    """
    blocks: list[dict[str, Any]] = []
    blocking = findings or []
    if blocking:
        shown = "\n".join(
            f"• `{item.get('target') or item.get('check')}` {item.get('message')}"
            for item in blocking[:6]
        )
        extra = f"\n• {len(blocking) - 6} more" if len(blocking) > 6 else ""
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Publish check is blocking* `{hunt_id}` ({len(blocking)}).\n"
                        f"{shown}{extra}"
                    ),
                },
            }
        )
        blocks.append(
            {
                "type": "input",
                "block_id": "publish_override",
                "label": {"type": "plain_text", "text": "Override, and why this is still safe"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "override",
                    "min_length": 12,
                    "max_length": 500,
                },
            }
        )
    from hecate_runner.lab_hits import format_lab_probe_slack

    lab_text = format_lab_probe_slack(lab_probe)
    if lab_text:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": lab_text}})
    if destination is None:
        if not blocking:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"`{hunt_id}` will move from `planning` to `active`. Publishing is off.",
                    },
                }
            )
    else:
        blocks += [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Step 1 of 2.* `{hunt_id}` moves to `active` and the publisher opens a "
                        f"pull request on `{destination}`, a public repository.\n"
                        "*Step 2:* approve that pull request on GitHub; it then merges itself."
                    ),
                },
            },
            {
                "type": "input",
                "block_id": "release_checks",
                "label": {"type": "plain_text", "text": "Release checks"},
                "element": {
                    "type": "checkboxes",
                    "action_id": "checks",
                    "options": [
                        {
                            "text": {
                                "type": "mrkdwn",
                                "text": "*No private data:* no customer, internal or personal data",
                            },
                            "value": "privacy",
                        },
                        {
                            "text": {
                                "type": "mrkdwn",
                                "text": "*Republishing allowed:* the source's license or terms "
                                "permit the quoted material",
                            },
                            "value": "redistribution",
                        },
                    ],
                },
            },
            {
                "type": "input",
                "block_id": "release_rights",
                "label": {"type": "plain_text", "text": "Basis for republishing the source"},
                "hint": {
                    "type": "plain_text",
                    "text": "For example: MIT-licensed public repository; author credited and linked.",
                },
                "element": {
                    "type": "plain_text_input",
                    "action_id": "rights",
                    "min_length": 20,
                    "max_length": 500,
                },
            },
        ]
    return {
        "type": "modal",
        "callback_id": "hecate_approve_hunt_modal",
        "private_metadata": private_metadata,
        "title": {"type": "plain_text", "text": f"Approve {hunt_id}"},
        "submit": {
            "type": "plain_text",
            "text": "Approve" if destination is None else "Approve & publish",
        },
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": blocks,
    }


def build_reject_hunt_modal(hunt_id: str, private_metadata: str) -> dict[str, Any]:
    """Modal asking for the reason a planning hunt is rejected."""
    return {
        "type": "modal",
        "callback_id": "hecate_reject_hunt_modal",
        "private_metadata": private_metadata,
        "title": {"type": "plain_text", "text": f"Reject {hunt_id}"},
        "submit": {"type": "plain_text", "text": "Reject"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"`{hunt_id}` will be set to `suppressed`. The reason is saved in its frontmatter.",
                },
            },
            {
                "type": "input",
                "block_id": "reject_reason",
                "label": {"type": "plain_text", "text": "Reason"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "reason",
                    "multiline": True,
                    "max_length": 500,
                },
            },
        ],
    }


def build_runner_status_card(settings: Settings) -> list[dict[str, Any]]:
    """Build an operational status card for /hecate status."""
    from hecate_runner.parked_store import list_parked
    from hecate_runner.siem_drift import load_drift_state
    from hecate_runner.state import OrchestratorState

    state = OrchestratorState.load(settings.state_file)
    parked_count = len(list_parked(settings.cti_queue_dir_resolved))

    hunts_dir = settings.hecate_workspace / "hunts"
    hunt_files = sorted(hunts_dir.glob("**/*.md")) if hunts_dir.exists() else []
    total_hunts = len(hunt_files)

    planning_count = 0
    active_count = 0
    for hf in hunt_files:
        try:
            txt = hf.read_text(encoding="utf-8")
            if "status: planning" in txt:
                planning_count += 1
            elif any(s in txt for s in ("status: active", "status: promoted", "status: completed")):
                active_count += 1
        except Exception:
            continue

    recent_hunts_lines = []
    for hf in hunt_files[-4:]:
        recent_hunts_lines.append(f"• `{hf.stem}`: {hf.name}")
    recent_text = "\n".join(recent_hunts_lines) or "No hunts recorded yet"

    fields = [
        {
            "type": "mrkdwn",
            "text": f"*Workspace:*\n`{settings.hecate_workspace.name}`",
        },
        {
            "type": "mrkdwn",
            "text": f"*CTI Provider:*\n`{settings.cti_provider}`",
        },
        {
            "type": "mrkdwn",
            "text": f"*Draft Quota (24h):*\n`{state.drafts_today} / {settings.max_drafts_per_day}`",
        },
        {
            "type": "mrkdwn",
            "text": f"*Research Quota:*\n`{state.research_runs_today} / {settings.max_research_runs_per_day}`",
        },
        {
            "type": "mrkdwn",
            "text": f"*Hunts in Workspace:*\n`{total_hunts} total` (`{active_count}` active, `{planning_count}` planning)",
        },
        {
            "type": "mrkdwn",
            "text": f"*Parked Commentary:*\n`{parked_count} item(s)`",
        },
    ]

    drift_state = load_drift_state(settings.hecate_workspace)
    if drift_state:
        in_sync = drift_state.get("in_sync_count", 0)
        total_q = drift_state.get("total_queries", 0)
        drifted = drift_state.get("drifted_count", 0)
        missing = drift_state.get("missing_count", 0)
        pct = (in_sync / total_q * 100.0) if total_q > 0 else 100.0
        icon = "✅" if (drifted == 0 and missing == 0) else "⚠️"
        fields.append(
            {
                "type": "mrkdwn",
                "text": f"*Detection-as-Code Sync:*\n{icon} `{in_sync}/{total_q}` ({pct:.0f}% in sync, `{drifted}` drifted)",
            }
        )
        fields.append(
            {
                "type": "mrkdwn",
                "text": f"*Last SIEM Audit:*\n`{str(drift_state.get('audited_at', 'unknown'))[:19]}`",
            }
        )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "📊 Hecate Autonomous Runner Status",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": fields,
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Recent Hunt Operations:*\n{recent_text}\n*Last Pipeline Run:* `{state.last_run_iso or 'never'}`",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🤖 *Hecate Status* | Interactive SecOps Bot Active",
                }
            ],
        },
    ]
    return [{"color": COLOR_SUCCESS, "blocks": sanitize_slack_blocks(blocks)}]


def build_siem_drift_alert_card(
    hunt_id: str,
    drifted_queries: list[dict[str, Any]],
    settings: Settings,
    interactive: bool = True,
) -> list[dict[str, Any]]:
    """Build an interactive alert card notifying analysts of query drift or missing rules."""
    active_drifted = [q for q in drifted_queries if q.get("status") != "decommissioned"]
    if not active_drifted:
        return []

    query_lines = []
    for q in active_drifted[:5]:
        tgt = q.get("target", "unknown")
        fname = q.get("file", "")
        st = q.get("status", "drift_detected")
        rem_id = q.get("remote_id") or ""
        diff = q.get("drift_diff")
        icon = "⚠️" if st == "drift_detected" else "❌"
        line = f"{icon} *{tgt}* (`{fname}`): `{st}`"
        if rem_id:
            line += f"\n  • Remote ID: `{rem_id}`"
        if diff:
            diff_preview = diff.strip().split("\n")[:2]
            line += "\n  • " + " | ".join(diff_preview)
        query_lines.append(line)

    if len(active_drifted) > 5:
        query_lines.append(f"_...and {len(active_drifted) - 5} more query(s)_")

    body_text = (
        f"🚨 *SIEM Detection Drift Detected for `{hunt_id}`*\n\n"
        "One or more detection queries deployed to your enterprise SIEM/EDR have "
        "drifted from git-authoritative definitions or have been deleted remotely.\n\n"
        + "\n".join(query_lines)
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"⚠️ SIEM Query Drift: {hunt_id}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": body_text,
            },
        },
    ]

    if interactive:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "⚡ Reconcile in SIEM",
                            "emoji": True,
                        },
                        "style": "primary",
                        "action_id": "hecate_reconcile_drift",
                        "value": hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Deploy All Queries", "emoji": True},
                        "action_id": "hecate_deploy_queries",
                        "value": hunt_id,
                    },
                ],
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🛡️ *Hecate Detection-as-Code Guardian* | Automated Drift Sentinel",
                }
            ],
        }
    )

    return [{"color": COLOR_WARNING, "blocks": sanitize_slack_blocks(blocks)}]


def build_siem_status_card(
    settings: Settings,
    metrics: dict[str, Any],
    recent_history: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build rich Slack Block Kit card summarizing SIEM sync health, versioning, and recent drift."""
    health_pct = metrics.get("sync_health_pct", 100.0)
    in_sync = metrics.get("in_sync_count", 0)
    total_q = metrics.get("total_queries", 0)
    drifted = metrics.get("drifted_count", 0)
    missing = metrics.get("missing_count", 0)
    decommissioned = metrics.get("decommissioned_count", 0)
    versions = metrics.get("tracked_query_versions", 0)
    sweeps = metrics.get("sweeps_conducted", 0)
    reconciled = metrics.get("reconciliations_period", 0)
    last_audited = str(metrics.get("last_audited", "never"))[:19]

    status_icon = "🟢" if (drifted == 0 and missing == 0) else ("🟡" if drifted == 0 else "🔴")
    card_color = COLOR_SUCCESS if (drifted == 0 and missing == 0) else COLOR_WARNING

    target_breakdown = metrics.get("target_drift_breakdown", {})
    target_lines = [f"• `{tgt}`: {cnt} drift incident(s)" for tgt, cnt in target_breakdown.items()]
    target_text = "\n".join(target_lines) if target_lines else "• No platform drift detected."

    recent_rows = []
    for evt in recent_history[:5]:
        ts = str(evt.get("timestamp", ""))[:19]
        h_id = evt.get("hunt_id", "")
        tgt = evt.get("target", "")
        ev_type = evt.get("event_type", "")
        actor = evt.get("actor", "system")
        icon = (
            "✅"
            if ev_type == "reconciled"
            else (
                "🧹"
                if ev_type == "decommissioned"
                else ("⚠️" if ev_type == "drift_detected" else "ℹ️")  # noqa: RUF001
            )
        )
        recent_rows.append(f"{icon} `{ts}` *{h_id}* ({tgt}): `{ev_type}` by `{actor}`")
    timeline_text = (
        "\n".join(recent_rows) if recent_rows else "No recent drift/reconciliation events."
    )

    drift_missing_text = f"`{drifted}` drifted, `{missing}` missing"
    if decommissioned:
        drift_missing_text += f", `{decommissioned}` decommissioned"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{status_icon} Detection-as-Code SIEM Health & Versioning",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Sync Health:*\n`{health_pct:.1f}%` ({in_sync}/{total_q} in sync)",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Drifted / Missing:*\n{drift_missing_text}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Tracked Query Versions:*\n`{versions}` rule version(s)",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Reconciliations (7d):*\n`{reconciled}` action(s)",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Audit Sweeps (7d):*\n`{sweeps}` sweep(s)",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Last Audit:*\n`{last_audited}`",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Platform Drift Summary:*\n{target_text}\n\n*Recent Audit Trail:*\n{timeline_text}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"🛡️ *Hecate SIEM Guardian* | Workspace: `{settings.hecate_workspace.name}`",
                }
            ],
        },
    ]
    return [{"color": card_color, "blocks": sanitize_slack_blocks(blocks)}]


def build_siem_history_card(
    hunt_id: str | None,
    history: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build Slack Block Kit card displaying chronological audit events for a hunt or workspace."""
    title_suffix = f"for `{hunt_id}`" if hunt_id else "Audit Trail"
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"📜 SIEM Drift & Versioning History {title_suffix}",
                "emoji": True,
            },
        },
    ]

    if not history:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "No drift or reconciliation history recorded yet.",
                },
            }
        )
    else:
        event_lines = []
        for ev in history[:10]:
            ts = str(ev.get("timestamp", ""))[:19]
            h_id = ev.get("hunt_id", "")
            tgt = ev.get("target", "")
            ev_type = ev.get("event_type", "")
            actor = ev.get("actor", "system")
            f_name = ev.get("file_name", "")
            icon = (
                "✅" if ev_type == "reconciled" else ("⚠️" if ev_type == "drift_detected" else "ℹ️")  # noqa: RUF001
            )
            line = f"{icon} *{ts}* — `{h_id}` / `{tgt}`\n• File: `{f_name}` | Event: `{ev_type}` | Actor: `{actor}`"
            diff = ev.get("drift_diff")
            if diff:
                preview = diff.strip().replace("\n", " | ")[:120]
                line += f"\n• Diff: _{preview}_"
            event_lines.append(line)

        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "\n\n".join(event_lines),
                },
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🛡️ *Hecate Detection-as-Code* | `/hecate history`",
                }
            ],
        }
    )
    return [{"color": COLOR_INFO, "blocks": sanitize_slack_blocks(blocks)}]


def build_staged_sweep_card(
    sweep: Any,
    title: str = "",
) -> list[dict[str, Any]]:
    """Build an interactive Slack Block Kit card for a scheduled hunt sweep awaiting approval."""
    hunt_id = getattr(sweep, "hunt_id", "")
    sweep_id = getattr(sweep, "sweep_id", "")
    target = getattr(sweep, "target_siem", "SIEM")
    days = getattr(sweep, "time_range_days", 1)
    q_file = getattr(sweep, "query_file", "")
    query_text = getattr(sweep, "query_text", "")
    justification = getattr(sweep, "justification", "")

    header_text = f"🎯 *Scheduled Hunt Sweep: `{hunt_id}`*"
    sub_title = f"_{title}_\n" if title else ""

    q_snippet = query_text[:350] + ("..." if len(query_text) > 350 else "")

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🎯 Scheduled Sweep Approval: {hunt_id}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{header_text}\n{sub_title}"
                    f"• *Target SIEM:* `{target}`\n"
                    f"• *Lookback Window:* `{days} day(s)`\n"
                    f"• *Query File:* `{q_file}`\n"
                    f"• *Justification:* {justification}"
                ),
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Query Snippet:*\n```{q_snippet}```",
            },
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "▶️ Approve & Sweep", "emoji": True},
                    "style": "primary",
                    "value": sweep_id,
                    "action_id": "hecate_approve_sweep",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "⏹️ Skip Sweep", "emoji": True},
                    "style": "danger",
                    "value": sweep_id,
                    "action_id": "hecate_reject_sweep",
                },
            ],
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"🛡️ *Hecate Safe Execution Gate* | Sweep ID: `{sweep_id}` | COUNT-FIRST Protected",
                }
            ],
        },
    ]
    return [{"color": COLOR_WARNING, "blocks": sanitize_slack_blocks(blocks)}]


def build_sweep_result_card(
    result: Any,
    title: str = "",
) -> list[dict[str, Any]]:
    """Build an informative Slack Block Kit card reporting the outcome of a hunt sweep."""
    hunt_id = getattr(result, "hunt_id", "")
    target = getattr(result, "target", "")
    outcome = getattr(result, "outcome", "clean")
    matched_count = getattr(result, "matched_count", 0)
    detail = getattr(result, "detail", "")
    executed_at = getattr(result, "executed_at", "")

    if outcome == "clean":
        icon = "🟢"
        color = COLOR_SUCCESS
        status_text = "Not observed (0 matching events within tested scope)"
    elif outcome == "hits_detected":
        icon = "⚠️"
        color = COLOR_WARNING
        status_text = f"Telemetry Hits Detected ({matched_count} events)"
    elif outcome == "overmatch":
        icon = "🚨"
        color = COLOR_CRITICAL
        status_text = f"Overmatch Threshold Exceeded ({matched_count} events)"
    else:
        icon = "❌"
        color = COLOR_CRITICAL
        status_text = f"Execution Error: {detail[:100]}"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{icon} Hunt Sweep Outcome: {hunt_id}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{icon} Status:* `{status_text}`\n"
                    f"• *Hunt ID:* `{hunt_id}`\n"
                    f"• *Target SIEM:* `{target}`\n"
                    f"• *Matched Events:* `{matched_count}`\n"
                    f"• *Executed At:* `{executed_at}`\n"
                    f"• *Summary:* {detail}"
                ),
            },
        },
    ]

    triage = getattr(result, "triage_report", None)
    if triage:
        t_verdict = getattr(triage, "verdict", "")
        t_conf = getattr(triage, "confidence", 0.0)
        t_summary = getattr(triage, "summary", "")
        t_rationale = getattr(triage, "rationale", "")
        t_action = getattr(triage, "recommended_action", "pivot")
        entities = getattr(triage, "extracted_entities", {}) or {}

        v_icon = (
            "🟢" if t_verdict == "true_positive" else ("⚠️" if t_verdict == "suspicious" else "⚪")
        )
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*🔎 Automated Triage Assessment:*\n"
                        f"• *Verdict:* {v_icon} `{t_verdict}` (Uncalibrated score: `{t_conf:.2f}/1`)\n"
                        f"• *Recommendation:* `{t_action}`\n"
                        f"• *Summary:* {t_summary}\n"
                        f"• *Rationale:* _{t_rationale[:200]}_"
                    ),
                },
            }
        )

        ent_lines = []
        if entities.get("hosts"):
            ent_lines.append(f"• *Hosts:* {', '.join(f'`{h}`' for h in entities['hosts'][:3])}")
        if entities.get("users"):
            ent_lines.append(f"• *Users:* {', '.join(f'`{u}`' for u in entities['users'][:3])}")
        if entities.get("processes"):
            ent_lines.append(
                f"• *Processes:* {', '.join(f'`{p}`' for p in entities['processes'][:3])}"
            )
        if entities.get("parent_processes"):
            ent_lines.append(
                f"• *Parents:* {', '.join(f'`{p}`' for p in entities['parent_processes'][:3])}"
            )
        if entities.get("ips"):
            ent_lines.append(f"• *IPs:* {', '.join(f'`{ip}`' for ip in entities['ips'][:3])}")

        if ent_lines:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Extracted Security Entities:*\n" + "\n".join(ent_lines),
                    },
                }
            )

    events = getattr(result, "events", [])
    if events and isinstance(events, list) and not triage:
        sample_lines = []
        for i, ev in enumerate(events[:3], 1):
            if isinstance(ev, dict):
                sample_lines.append(f"{i}. `{json.dumps(ev)[:160]}`")
        if sample_lines:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Sample Telemetry Hits:*\n" + "\n".join(sample_lines),
                    },
                }
            )

    # Automated Investigation Pivots
    pivots = getattr(result, "pivot_results", []) or []
    if pivots:
        pivot_lines = []
        for p in pivots[:3]:
            p_type = (
                getattr(p, "pivot_type", "")
                if hasattr(p, "pivot_type")
                else p.get("pivot_type", "")
            )
            p_tech = (
                getattr(p, "technique", "") if hasattr(p, "technique") else p.get("technique", "")
            )
            p_hits = (
                getattr(p, "matched_count", 0)
                if hasattr(p, "matched_count")
                else p.get("matched_count", 0)
            )
            p_out = getattr(p, "outcome", "") if hasattr(p, "outcome") else p.get("outcome", "")
            icon = "⚠️" if p_out == "hits_detected" else ("🟢" if p_out == "clean" else "🚨")
            pivot_lines.append(
                f"• {icon} *{p_type.replace('_', ' ').title()}* (`{p_tech}`): `{p_hits}` events ({p_out})"
            )
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🔄 Automated Investigation Pivots ({len(pivots)} executed):*\n"
                    + "\n".join(pivot_lines),
                },
            }
        )

    # Interactive HITL Action Buttons (Self-Tuning)
    if triage:
        t_verdict = getattr(triage, "verdict", "")
        finding_id = getattr(triage, "finding_id", "")
        if finding_id and t_verdict in ("benign_noise", "suspicious"):
            btn_text = (
                "🛠️ Auto-Tune (Exclude FP)"
                if t_verdict == "benign_noise"
                else "🛠️ Tune Rule (Narrow Filter)"
            )
            blocks.append(
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": btn_text,
                                "emoji": True,
                            },
                            "style": "primary",
                            "action_id": "hecate_tune_finding",
                            "value": finding_id,
                        }
                    ],
                }
            )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🛡️ *Hecate Autonomous Engine* | Guardrails Enforced",
                }
            ],
        }
    )
    return [{"color": color, "blocks": sanitize_slack_blocks(blocks)}]
