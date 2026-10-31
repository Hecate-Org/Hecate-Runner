"""Slack integration, digest, and bot commands."""

from __future__ import annotations

import signal
import sys
from typing import Annotated, Any, cast

import httpx
import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from hecate_runner.config import Settings
from hecate_runner.digests import (
    collect_detection_engineering_metrics,
    collect_threat_hunting_metrics,
    collect_threat_intel_metrics,
)
from hecate_runner.metrics import MetricsStore
from hecate_runner.notifications import (
    notify_detection_digest,
    notify_ops_metrics,
    notify_threat_hunting_digest,
    notify_threat_intel_digest,
    send_test_all_channels,
    send_test_notification,
)

console = Console()


def _get_settings() -> Settings:
    cli_mod = sys.modules.get("hecate_runner.cli")
    if cli_mod and hasattr(cli_mod, "Settings"):
        return cast(Settings, cli_mod.Settings())
    return Settings()


def slack_channels() -> None:
    """List configured Slack channels and their mapped threat intelligence feeds."""
    settings = _get_settings()
    table = Table(title="Hecate Slack Multi-Channel Architecture", box=box.ROUNDED)
    table.add_column("Tier", style="dim")
    table.add_column("Channel", style="bold cyan")
    table.add_column("Feed Type", style="green")
    table.add_column("Mapped Threat Sources / Triggers", style="white")

    table.add_row(
        "Tier 1",
        settings.slack_channel_ops_metrics,
        "Ops & Spend Metrics",
        "Daily summary, Sigma rules count, LLM token budget, uptime",
    )
    table.add_row(
        "Tier 1",
        settings.slack_channel_hunts_exec,
        "Executive Hunts",
        "Validated hunts, PR merges, MISP sync events",
    )
    table.add_row(
        "Tier 1",
        settings.slack_channel_purple_team,
        "Purple Team Feed",
        "Adversary emulation validation, detection firing rates",
    )
    table.add_row(
        "Tier 1",
        settings.slack_channel_detection_engineering,
        "Detection Eng Digest",
        "Rules authored, syntax valid %, test-fired %, platforms",
    )
    table.add_row(
        "Tier 1",
        settings.slack_channel_threat_intel,
        "Threat Intel Digest",
        "IOCs harvested, CVE coverage, fresh CTI items triaged",
    )
    table.add_row(
        "Tier 1",
        settings.slack_channel_threat_hunting,
        "Threat Hunting Digest",
        "Top techniques, hunts completed, active campaigns",
    )
    table.add_row(
        "Tier 2",
        settings.slack_channel_c2,
        "C2 Infrastructure",
        "Censys C2, Certstream, Shadowserver botnet feeds",
    )
    table.add_row(
        "Tier 2",
        settings.slack_channel_sandbox,
        "Sandbox & Malware",
        "MalwareBazaar, VX-Underground, Any.run execution",
    )
    table.add_row(
        "Tier 2",
        settings.slack_channel_apt,
        "APT Campaigns",
        "DFIR Report, OpenCTI, MISP campaigns, OTX pulses",
    )
    table.add_row(
        "Tier 2",
        settings.slack_channel_cloud,
        "Cloud & Identity Threat",
        "Cloud threat feeds, Azure/AWS identity incidents",
    )
    table.add_row(
        "Tier 2",
        settings.slack_channel_exploits,
        "Exploits & EPSS",
        "CISA KEV, GitHub PoC, VulnCheck, MSRC advisories",
    )
    console.print(table)
    mode = (
        "[bold green]Bot Token (Direct Channel Routing)[/bold green]"
        if settings.slack_bot_token
        else (
            "[bold yellow]Incoming Webhook (Single Channel Fallback)[/bold yellow]"
            if settings.slack_webhook_url
            else "[bold red]Unconfigured (No SLACK_BOT_TOKEN or webhook)[/bold red]"
        )
    )
    console.print(f"Current Delivery Mode: {mode}")


def slack_test(
    channel: Annotated[
        str | None,
        typer.Option(
            "--channel", "-c", help="Specific channel to test (requires SLACK_BOT_TOKEN)."
        ),
    ] = None,
    test_all: Annotated[
        bool,
        typer.Option("--all", "-a", help="Test connectivity to all 8 configured Slack channels."),
    ] = False,
) -> None:
    """Send a test alert to the configured Slack incoming webhook or Bot Token channels."""
    settings = _get_settings()
    if not settings.slack_bot_token and not settings.slack_webhook_url:
        console.print(
            "[red]Neither SLACK_BOT_TOKEN nor HECATE_RUNNER_SLACK_WEBHOOK_URL is set in .env[/red]"
        )
        raise typer.Exit(code=1)

    if test_all:
        console.print("[dim]Testing delivery across all configured Slack channels...[/dim]")
        results = send_test_all_channels(settings)
        failed = False
        for ch, (success, msg) in results.items():
            if success:
                console.print(f"[green]✓ {ch}: {msg}[/green]")
            else:
                console.print(f"[red]✗ {ch}: {msg}[/red]")
                failed = True
        if failed:
            raise typer.Exit(code=1)
        return

    target = channel or settings.slack_channel_hunts_exec
    console.print(f"[dim]Sending test notification to {target}...[/dim]")
    success, msg = send_test_notification(settings, channel=channel)
    if success:
        console.print(f"[green]✓ {msg}[/green]")
    else:
        console.print(f"[red]✗ {msg}[/red]")
        raise typer.Exit(code=1)


def ops_digest(
    channel: Annotated[
        str | None,
        typer.Option("--channel", "-c", help="Override destination Slack channel."),
    ] = None,
    post: Annotated[
        bool,
        typer.Option(
            "--post/--no-post",
            help="Actually post the ops digest to Slack (default true; --no-post displays locally).",
        ),
    ] = True,
    days: Annotated[
        int,
        typer.Option("--days", "-d", help="Number of past days to summarize."),
    ] = 7,
) -> None:
    """Generate and optionally post an executive operational and cost metrics digest."""
    settings = _get_settings()
    store = MetricsStore(settings.metrics_file)
    metrics_summary = store.summary(days=days)

    table = Table(title=f"Hecate SecOps Operational Digest ({days}-Day Summary)", box=box.ROUNDED)
    table.add_column("Metric", style="dim")
    table.add_column("Value", style="bold cyan")

    table.add_row("Total Pipeline Cycles", str(metrics_summary["completed_cycles"]))
    table.add_row("Estimated Spend", f"${metrics_summary['total_cost_usd']:.2f}")
    table.add_row("Total LLM Calls", f"{metrics_summary['total_llm_calls']:,}")
    table.add_row("Total Prompt Tokens", f"{metrics_summary['total_input_tokens']:,}")
    table.add_row("Total Completion Tokens", f"{metrics_summary['total_output_tokens']:,}")
    console.print(table)

    if metrics_summary["stages"]:
        stage_table = Table(title="LLM Cost Breakdown by Orchestrator Stage", box=box.SIMPLE)
        stage_table.add_column("Stage", style="bold")
        stage_table.add_column("Calls", justify="right")
        stage_table.add_column("Prompt Tokens", justify="right")
        stage_table.add_column("Comp Tokens", justify="right")
        stage_table.add_column("Cost (USD)", justify="right", style="green")

        for stage, data in sorted(
            metrics_summary["stages"].items(), key=lambda x: x[1]["cost_usd"], reverse=True
        ):
            stage_table.add_row(
                stage,
                f"{data['calls']:,}",
                f"{data['input_tokens']:,}",
                f"{data['output_tokens']:,}",
                f"${data['cost_usd']:.4f}",
            )
        console.print(stage_table)

    if post:
        if not settings.slack_bot_token and not settings.slack_webhook_url:
            console.print("[dim]Slack unconfigured; digest not posted.[/dim]")
            return
        target = channel or settings.slack_channel_ops_metrics
        console.print(f"[dim]Posting visual ops digest to {target}...[/dim]")
        notify_ops_metrics(settings, metrics_summary, channel=target)
        console.print(f"[green]✓ Ops digest posted to {target} successfully.[/green]")


def setup_slack_channels() -> None:
    """Verify or attempt creation of Detection Engineering, Threat Intel, and Threat Hunting Slack channels."""
    settings = _get_settings()
    if not settings.slack_bot_token:
        console.print(
            "[red]SLACK_BOT_TOKEN is required to check or configure Slack channels.[/red]"
        )
        raise typer.Exit(code=1)

    target_channels = [
        # Specialized Threat Feeds
        ("Threat C2 Infrastructure", settings.slack_channel_c2),
        ("Threat Sandbox Malware", settings.slack_channel_sandbox),
        ("Threat APT Campaigns", settings.slack_channel_apt),
        ("Threat Cloud & Identity", settings.slack_channel_cloud),
        ("Threat Exploits & EPSS", settings.slack_channel_exploits),
        # Daily Digests & Engineering
        ("Detection Engineering", settings.slack_channel_detection_engineering),
        ("Threat Intel Digest", settings.slack_channel_threat_intel),
        ("Threat Hunting Digest", settings.slack_channel_threat_hunting),
        # Operations, Validation & Fallback
        ("Executive Hunts", settings.slack_channel_hunts_exec),
        ("Ops & Cost Metrics", settings.slack_channel_ops_metrics),
        ("Purple Team Feed", settings.slack_channel_purple_team),
        ("Global Fallback Feed", "#all-hecate-hunt"),
    ]

    console.print("[dim]Querying workspace public channels...[/dim]")
    headers = {"Authorization": f"Bearer {settings.slack_bot_token}"}
    existing_channels: dict[str, str] = {}
    try:
        resp = httpx.get(
            "https://slack.com/api/conversations.list",
            headers=headers,
            params={"types": "public_channel", "limit": 200},
            timeout=10.0,
        )
        data = resp.json()
        if data.get("ok"):
            for ch in data.get("channels", []):
                existing_channels[ch["name"].lower()] = ch["id"]
        else:
            console.print(f"[yellow]Warning: Could not list channels: {data.get('error')}[/yellow]")
    except Exception as exc:
        console.print(f"[yellow]Warning: conversations.list failed: {exc}[/yellow]")

    table = Table(title="Hecate Specialized Slack Channels Status", box=box.ROUNDED)
    table.add_column("Domain", style="bold cyan")
    table.add_column("Channel Name", style="white")
    table.add_column("Status", style="green")
    table.add_column("Channel ID / Note", style="dim")

    needs_manual_creation = []

    for domain, ch_raw in target_channels:
        ch_name = ch_raw.lstrip("#").lower()
        if ch_name in existing_channels:
            table.add_row(domain, f"#{ch_name}", "✓ Online (Exists)", existing_channels[ch_name])
        else:
            create_resp = httpx.post(
                "https://slack.com/api/conversations.create",
                headers=headers,
                json={"name": ch_name},
                timeout=10.0,
            )
            create_data = create_resp.json()
            if create_data.get("ok"):
                new_id = create_data.get("channel", {}).get("id", "Created")
                table.add_row(domain, f"#{ch_name}", "✓ Created Successfully", new_id)
            else:
                err = create_data.get("error", "unknown")
                if err == "name_taken":
                    table.add_row(domain, f"#{ch_name}", "✓ Online (Exists)", "Name taken")
                elif err == "missing_scope":
                    table.add_row(
                        domain, f"#{ch_name}", "⚠️ Needs Creation", "Missing channels:manage"
                    )
                    needs_manual_creation.append(f"#{ch_name}")
                else:
                    table.add_row(domain, f"#{ch_name}", f"⚠️ {err}", "Create failed")
                    needs_manual_creation.append(f"#{ch_name}")

    console.print(table)

    if needs_manual_creation:
        console.print()
        console.print(
            "[bold yellow]To activate specialized channel feeds, choose either option:[/bold yellow]"
        )
        console.print(
            "  [bold cyan]Option A (Quickest):[/bold cyan] In your Slack desktop or web client, create public channels:"
        )
        console.print(f"  [bold green]{', '.join(needs_manual_creation)}[/bold green]")
        console.print(
            "  [dim](Because the Bot Token has `chat:write.public`, it will immediately post to them without needing an invite).[/dim]"
        )
        console.print()
        console.print(
            "  [bold cyan]Option B (Automated via API):[/bold cyan] In your Slack App Settings (api.slack.com/apps):"
        )
        console.print(
            "  Add the [bold]channels:write[/bold] scope under Bot Token Scopes, reinstall the app to workspace, and re-run this command."
        )


def daily_digest(
    domain: Annotated[
        str,
        typer.Option(
            "--domain",
            "-d",
            help="Domain to digest: 'all', 'detection', 'intel', or 'hunting'.",
        ),
    ] = "all",
    channel: Annotated[
        str | None,
        typer.Option("--channel", "-c", help="Override destination Slack channel."),
    ] = None,
    hours: Annotated[
        int,
        typer.Option("--hours", "-h", help="Lookback window in hours (default 24)."),
    ] = 24,
    post: Annotated[
        bool,
        typer.Option(
            "--post/--no-post",
            help="Actually post to Slack (default true; --no-post displays locally).",
        ),
    ] = True,
) -> None:
    """Generate and optionally post daily digests for Detection Eng, Threat Intel, and Threat Hunting."""
    settings = _get_settings()
    domain = domain.lower().strip()

    if domain not in ("all", "detection", "intel", "hunting"):
        console.print(
            f"[red]Invalid domain '{domain}'. Choose 'all', 'detection', 'intel', or 'hunting'.[/red]"
        )
        raise typer.Exit(code=1)

    # 1. Detection Engineering
    if domain in ("all", "detection"):
        det_data = collect_detection_engineering_metrics(settings, hours=hours)
        table = Table(title=f"Detection Engineering Digest ({hours}h Window)", box=box.ROUNDED)
        table.add_column("Metric", style="dim")
        table.add_column("Value", style="bold cyan")
        table.add_row("Sigma Rules Authored", str(det_data["rules_authored"]))
        table.add_row("Syntax Valid %", f"{det_data['syntax_valid_pct']:.1f}%")
        table.add_row("Test-Fired %", f"{det_data['test_fired_pct']:.1f}%")
        table.add_row("Target Platforms", ", ".join(det_data["target_platforms"]) or "None")
        console.print(table)
        if post and (settings.slack_bot_token or settings.slack_webhook_url):
            target = channel or settings.slack_channel_detection_engineering
            console.print(f"[dim]Posting Detection Engineering digest to {target}...[/dim]")
            success, msg = notify_detection_digest(settings, det_data, channel=target)
            if success:
                console.print(f"[green]✓ Detection Eng digest delivered. ({msg})[/green]")
            else:
                console.print(f"[yellow]⚠️ Detection Eng digest post note: {msg}[/yellow]")

    # 2. Threat Intel
    if domain in ("all", "intel"):
        intel_data = collect_threat_intel_metrics(settings, hours=hours)
        table = Table(title=f"Threat Intelligence Digest ({hours}h Window)", box=box.ROUNDED)
        table.add_column("Metric", style="dim")
        table.add_column("Value", style="bold green")
        table.add_row("CTI Items Triaged", str(intel_data["items_triaged"]))
        table.add_row("IOCs Harvested", str(intel_data["iocs_harvested"]))
        table.add_row("CVEs Covered", str(intel_data["cves_covered"]))
        table.add_row("Active Feeds", ", ".join(intel_data["active_feeds"]) or "None")
        console.print(table)
        if post and (settings.slack_bot_token or settings.slack_webhook_url):
            target = channel or settings.slack_channel_threat_intel
            console.print(f"[dim]Posting Threat Intel digest to {target}...[/dim]")
            success, msg = notify_threat_intel_digest(settings, intel_data, channel=target)
            if success:
                console.print(f"[green]✓ Threat Intel digest delivered. ({msg})[/green]")
            else:
                console.print(f"[yellow]⚠️ Threat Intel digest post note: {msg}[/yellow]")

    # 3. Threat Hunting
    if domain in ("all", "hunting"):
        hunt_data = collect_threat_hunting_metrics(settings, hours=hours)
        table = Table(title=f"Threat Hunting Digest ({hours}h Window)", box=box.ROUNDED)
        table.add_column("Metric", style="dim")
        table.add_column("Value", style="bold magenta")
        table.add_row("Hunts Completed", str(hunt_data["hunts_completed"]))
        table.add_row("Hypotheses Formulated", str(len(hunt_data["hypotheses_formulated"])))
        table.add_row("Top ATT&CK Techniques", ", ".join(hunt_data["top_techniques"]) or "None")
        table.add_row("Active Campaigns", ", ".join(hunt_data["active_campaigns"]) or "None")
        console.print(table)
        if post and (settings.slack_bot_token or settings.slack_webhook_url):
            target = channel or settings.slack_channel_threat_hunting
            console.print(f"[dim]Posting Threat Hunting digest to {target}...[/dim]")
            success, msg = notify_threat_hunting_digest(settings, hunt_data, channel=target)
            if success:
                console.print(f"[green]✓ Threat Hunting digest delivered. ({msg})[/green]")
            else:
                console.print(f"[yellow]⚠️ Threat Hunting digest post note: {msg}[/yellow]")


def slack_bot_cmd(
    simulate: Annotated[
        bool,
        typer.Option(
            "--simulate",
            "-s",
            help="Run interactive offline simulation harness without Slack connection.",
        ),
    ] = False,
    execute_sim: Annotated[
        str | None,
        typer.Option(
            "--execute-sim",
            "-e",
            help="Execute a single simulation command headlessly and print output.",
        ),
    ] = None,
) -> None:
    """Start the Slack Socket Mode interactive bot daemon or offline simulation harness."""
    settings = _get_settings()

    if execute_sim:
        from hecate_runner.slack_sim import SlackBotSimulator

        sim = SlackBotSimulator(settings=settings)
        out = sim.execute_sim_line(execute_sim)
        console.print(out)
        return

    if simulate:
        from hecate_runner.slack_sim import SlackBotSimulator

        sim = SlackBotSimulator(settings=settings)
        sim.run_repl(console=console)
        return

    # Check configuration
    if not (settings.slack_bot_token and settings.slack_app_token):
        console.print(
            Panel(
                "[bold red]Slack Interactive Socket Mode Bot is not fully configured.[/bold red]\n\n"
                "Missing required tokens in your environment or `.env`:\n"
                f"• `SLACK_BOT_TOKEN`: {'[green]Configured[/green]' if settings.slack_bot_token else '[red]Missing (xoxb-...)[/red]'}\n"
                f"• `SLACK_APP_TOKEN`: {'[green]Configured[/green]' if settings.slack_app_token else '[red]Missing (xapp-...)[/red]'}\n\n"
                "[bold yellow]How to set up:[/bold yellow]\n"
                "1. Go to your Slack App Settings -> Basic Information -> App-Level Tokens.\n"
                "2. Generate a token named `SocketMode` with scope [cyan]connections:write[/cyan].\n"
                "3. Set `SLACK_APP_TOKEN=xapp-...` in `Hecate-Workspace/.env`.\n"
                "4. Under Socket Mode in your app settings, toggle [bold]Enable Socket Mode[/bold] to ON.\n"
                "5. Ensure `SLACK_BOT_TOKEN=xoxb-...` has `chat:write` and `commands` scopes.\n\n"
                "[dim]Tip: You can test all bot functionality offline using:[/dim]\n"
                "[bold cyan]hecate-runner slack-bot --simulate[/bold cyan]",
                title="❌ Configuration Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    from hecate_runner.slack_bot import SlackBotService

    service = SlackBotService(settings=settings)
    if not service.is_configured:
        console.print("[red]Slack Bot initialization failed.[/red]")
        raise typer.Exit(code=1)

    console.print(
        Panel(
            "[bold green]Starting Hecate Interactive Slack Bot (Socket Mode)...[/bold green]\n"
            f"• Workspace: [cyan]{settings.hecate_workspace}[/cyan]\n"
            f"• Threat Hunting: [cyan]{settings.slack_channel_threat_hunting}[/cyan]\n"
            f"• Detection Eng: [cyan]{settings.slack_channel_detection_engineering}[/cyan]\n"
            f"• Interactive HITL: [green]Enabled[/green]\n"
            f"• Slash Commands: [cyan]/hecate status, /hecate hunt, /hecate deploy, /hecate rerun[/cyan]\n\n"
            "[dim]Press Ctrl+C to stop.[/dim]",
            title="🤖 Hecate SecOps Bot",
            border_style="green",
        )
    )

    def _sig_handler(sig: int, frame: Any) -> None:
        console.print("\n[dim]Received shutdown signal, terminating Socket Mode...[/dim]")
        service.close()
        raise typer.Exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    try:
        service.start()
    except Exception as exc:
        console.print(f"[red]Slack Bot stopped with error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
