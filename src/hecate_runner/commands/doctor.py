"""Deployment health checks and diagnostics."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Annotated, Any, cast

import typer
from dotenv import dotenv_values
from rich.console import Console

from hecate_runner.config import Settings

console = Console()


def _get_settings() -> Settings:
    cli_mod = sys.modules.get("hecate_runner.cli")
    if cli_mod and hasattr(cli_mod, "Settings"):
        return cast(Settings, cli_mod.Settings())
    return Settings()


def _check_module_available(name: str) -> bool:
    cli_mod = sys.modules.get("hecate_runner.cli")
    if cli_mod and hasattr(cli_mod, "_module_available"):
        return cast(bool, cli_mod._module_available(name))
    return _module_available(name)


def _check_stix_data_available() -> bool:
    cli_mod = sys.modules.get("hecate_runner.cli")
    if cli_mod and hasattr(cli_mod, "_stix_data_available"):
        return cast(bool, cli_mod._stix_data_available())
    return _stix_data_available()


def _get_effective_model(settings: Settings) -> str:
    cli_mod = sys.modules.get("hecate_runner.cli")
    if cli_mod and hasattr(cli_mod, "_effective_model"):
        return cast(str, cli_mod._effective_model(settings))
    return _effective_model(settings)


def doctor(
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit deployment health check as JSON.")
    ] = False,
) -> None:
    """Sanity-check the deployment. Non-zero exit code if anything is off."""
    settings = _get_settings()
    problems: list[str] = []
    checks: list[dict[str, Any]] = []

    def check(condition: bool, label: str, remediation: str) -> None:
        checks.append(
            {
                "name": label,
                "status": "pass" if condition else "fail",
                "severity": "error",
                "remediation": remediation if not condition else None,
            }
        )
        if not json_output:
            status_mark = "[green]✓[/green]" if condition else "[red]✗[/red]"
            console.print(f"{status_mark} {label}")
            if not condition:
                console.print(f"    [yellow]fix:[/yellow] {remediation}")
        if not condition:
            problems.append(label)

    def warn(condition: bool, label: str, remediation: str) -> None:
        """Like `check`, but doesn't fail the command or set a non-zero exit."""
        checks.append(
            {
                "name": label,
                "status": "pass" if condition else "warn",
                "severity": "warning",
                "remediation": remediation if not condition else None,
            }
        )
        if not json_output:
            status_mark = "[green]✓[/green]" if condition else "[yellow]![/yellow]"
            console.print(f"{status_mark} {label}")
            if not condition:
                console.print(f"    [yellow]note:[/yellow] {remediation}")

    check(
        settings.hecate_workspace.exists(),
        f"Hecate workspace exists: {settings.hecate_workspace}",
        "Set HECATE_WORKSPACE to the Hecate-Core checkout",
    )
    check(
        settings.hecate_bin_resolved.exists(),
        f"hecate-agent CLI at {settings.hecate_bin_resolved}",
        "Install Hecate inside a venv and set HECATE_BIN if not at default location",
    )
    check(
        settings.hunts_root.exists() or settings.hecate_workspace.exists(),
        f"Hunts root writable: {settings.hunts_root}",
        "Create it with `hecate-agent hunt new` inside the workspace",
    )
    check(
        _has_write(settings.log_dir),
        f"Log dir writable: {settings.log_dir}",
        f"chmod +w {settings.log_dir}",
    )
    check(
        _has_write(settings.cti_queue_dir_resolved) or not settings.cti_queue_dir_resolved.exists(),
        f"CTI queue dir writable: {settings.cti_queue_dir_resolved}",
        f"mkdir -p and chmod +w {settings.cti_queue_dir_resolved}",
    )
    if settings.cti_provider == "multi":
        multi_names = settings.cti_multi_provider_names
        check(
            bool(multi_names) and "multi" not in multi_names,
            f"HECATE_RUNNER_CTI_MULTI_PROVIDERS valid ({', '.join(multi_names) or 'empty'})",
            "Set HECATE_RUNNER_CTI_MULTI_PROVIDERS to a comma-separated list from: "
            "file, otx, rss, misp, cisa_kev, abuse_ch.",
        )
    else:
        multi_names = []
    active_cti_providers = (
        multi_names if settings.cti_provider == "multi" else [settings.cti_provider]
    )

    if "otx" in active_cti_providers:
        check(
            bool(settings.otx_api_key),
            "OTX_API_KEY set (required — cti_provider includes 'otx')",
            "Set OTX_API_KEY in .env — get a free-tier key at https://otx.alienvault.com",
        )
    if "misp" in active_cti_providers:
        check(
            bool(settings.misp_base_url) and bool(settings.misp_api_key),
            "MISP_BASE_URL / MISP_API_KEY set (required — cti_provider includes 'misp')",
            "Set both in .env — use a dedicated automation key, not a personal user's key.",
        )
    # Checked unconditionally (not gated on cti_provider == "rss") because
    # `rss-poll` runs independently, same as `otx-poll` — most deployments
    # run the main loop on cti_provider=file and feed it via a poller timer.
    check(
        bool(settings.rss_feed_urls),
        f"RSS feed URLs configured ({len(settings.rss_feed_urls)} feeds)",
        "Set HECATE_RUNNER_RSS_FEED_URLS to a comma-separated list of feed URLs.",
    )

    # --- Agent capabilities ------------------------------------------------
    check(
        _check_module_available("mitreattack"),
        "mitreattack-python importable (ATT&CK technique lookup)",
        "Reinstall the runner with `uv sync` — hecate-agent[all] carries it.",
    )
    check(
        _check_stix_data_available(),
        "ATT&CK STIX data present (technique validation and enrichment)",
        "Run `hecate-agent attack update` to download the STIX bundle.",
    )
    check(
        _check_module_available("sklearn"),
        "scikit-learn importable (related-hunt similarity)",
        "Reinstall the runner with `uv sync` — hecate-agent[all] carries it.",
    )
    check(
        _check_module_available("sigma"),
        "pySigma importable (Sigma rule validation)",
        "Reinstall the runner with `uv sync` — without it generated rules are "
        "only structurally checked, never validated as Sigma.",
    )
    if settings.research_enabled:
        check(
            _check_module_available("tavily"),
            "tavily-python importable (research web search)",
            "Reinstall the runner with `uv sync` — without it research runs without web-search context.",
        )
        check(
            _tavily_key_available(settings),
            "TAVILY_API_KEY set (research web search is mandatory-when-enabled)",
            "Set TAVILY_API_KEY in the Hecate workspace .env. Get a free-tier "
            "key at https://tavily.com, or set HECATE_RUNNER_RESEARCH_ENABLED=false "
            "to run drafts without research context deliberately.",
        )
    warn(
        bool(settings.slack_bot_token or settings.slack_webhook_url),
        "SLACK_BOT_TOKEN or HECATE_RUNNER_SLACK_WEBHOOK_URL set (Slack alerts)",
        "Optional — without it, drafts land silently in hunts/ with no alert.",
    )
    if settings.query_provider == "splunk":
        check(
            _env_key_available(settings, "SPLUNK_HOST")
            and _env_key_available(settings, "SPLUNK_TOKEN"),
            "SPLUNK_HOST / SPLUNK_TOKEN set (required for HECATE_RUNNER_QUERY_PROVIDER=splunk)",
            "Set both in the Hecate workspace .env — see `hecate-agent splunk test` to verify connectivity "
            "before running `hecate-runner approve` against it.",
        )
    else:
        checks.append(
            {
                "name": f"Query provider is '{settings.query_provider}'",
                "status": "info",
                "severity": "info",
                "remediation": None,
            }
        )
        if not json_output:
            console.print(
                f"[dim]i Query provider is '{settings.query_provider}' — `hecate-runner approve` cannot touch a real "
                "system yet. Set HECATE_RUNNER_QUERY_PROVIDER=splunk once real access exists.[/dim]"
            )

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "ok": len(problems) == 0,
                    "problems": problems,
                    "checks": checks,
                },
                indent=2,
            )
        )
        if problems:
            raise typer.Exit(code=1)
        return

    if problems:
        console.print(f"\n[red]{len(problems)} problem(s) found[/red]")
        raise typer.Exit(code=1)
    console.print("\n[green]All checks passed.[/green]")


def _effective_model(settings: Settings) -> str:
    """Render the LLM the hecate subprocess will actually use."""
    provider = settings.hecate_llm_provider or _workspace_env_value(settings, "HECATE_LLM_PROVIDER")
    model = settings.hecate_llm_model or _workspace_env_value(settings, "HECATE_LLM_MODEL")
    if not provider and not model:
        return "(hecate autodetects — none set here or in the workspace .env)"
    suffix = (
        "" if (settings.hecate_llm_provider or settings.hecate_llm_model) else "  (from workspace)"
    )
    return f"{provider or '?'}:{model or '?'}{suffix}"


def _workspace_env_value(settings: Settings, key_name: str) -> str:
    """Read one key from the Hecate workspace's own .env, or "" if absent."""
    if os.getenv(key_name):
        return os.environ[key_name]
    workspace_env = settings.hecate_workspace / ".env"
    if workspace_env.exists():
        return dotenv_values(workspace_env).get(key_name) or ""
    return ""


def _env_key_available(settings: Settings, key_name: str) -> bool:
    """Check both places an Hecate-subprocess-only env var could actually be set."""
    if os.getenv(key_name):
        return True
    workspace_env = settings.hecate_workspace / ".env"
    if workspace_env.exists():
        return bool(dotenv_values(workspace_env).get(key_name))
    return False


def _tavily_key_available(settings: Settings) -> bool:
    return _env_key_available(settings, "TAVILY_API_KEY")


def _module_available(name: str) -> bool:
    """True if `name` can be imported in *this* interpreter."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _stix_data_available() -> bool:
    """True if ATT&CK lookups are backed by live STIX data, not the fallback."""
    try:
        from hecate_agent.core.attack_matrix import is_using_stix

        return bool(is_using_stix())
    except Exception:
        return False


def _has_write(path: Path) -> bool:
    """Return True if the path (or its nearest existing parent) is writable."""
    check_target = path
    while not check_target.exists():
        check_target = check_target.parent
    return os.access(check_target, os.W_OK)
