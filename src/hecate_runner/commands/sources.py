"""CTI sources and MISP outbox CLI commands."""

from __future__ import annotations

import datetime
import json
import os
import sys
from pathlib import Path
from typing import Annotated, cast

import typer
from rich.console import Console
from rich.table import Table

from hecate_runner.config import Settings

sources_app = typer.Typer(help="Manage CTI sources (list, enable, disable, reset).")
misp_app = typer.Typer(help="Store completed pipeline artifacts in MISP independently of intake.")

console = Console()


def _get_settings() -> Settings:
    cli_mod = sys.modules.get("hecate_runner.cli")
    if cli_mod and hasattr(cli_mod, "Settings"):
        return cast(Settings, cli_mod.Settings())
    return Settings()


@misp_app.command("enable")
def enable_misp_output() -> None:
    settings = _get_settings()
    if not (settings.misp_base_url and (settings.misp_output_api_key or settings.misp_api_key)):
        console.print("[red]MISP_BASE_URL and a MISP writer API key are required.[/red]")
        raise typer.Exit(1)
    _update_env_key("HECATE_RUNNER_MISP_PUBLISHING_ENABLED", "true")
    console.print(
        "MISP output enabled: organization-only draft events; intake is configured separately."
    )


@misp_app.command("disable")
def disable_misp_output() -> None:
    _update_env_key("HECATE_RUNNER_MISP_PUBLISHING_ENABLED", "false")
    console.print("MISP output disabled.")


@misp_app.command("publish")
def publish_to_misp(hunt_id: str) -> None:
    """Queue one existing hunt and verify its artifacts were stored in MISP."""
    from hecate_runner.misp_publisher import (
        enqueue_misp_hunt,
        misp_publication_status,
        sync_misp_outbox,
    )

    settings = _get_settings()
    try:
        enqueue_misp_hunt(settings, hunt_id)
        sync_misp_outbox(settings)
    except Exception as exc:
        console.print(f"[red]Could not export hunt ({type(exc).__name__}).[/red]")
        raise typer.Exit(1) from exc
    row = next(row for row in misp_publication_status(settings) if row["hunt_id"] == hunt_id)
    if row["status"] != "confirmed":
        console.print(
            f"[yellow]{hunt_id} remains queued: {row['last_error'] or row['status']}[/yellow]"
        )
        raise typer.Exit(1)
    console.print(
        f"{hunt_id}: confirmed MISP event #{row['event_id']} ({settings.misp_base_url}/events/view/{row['event_id']})"
    )


@misp_app.command("sync")
def sync_misp_output() -> None:
    """Retry due output records without drafting or consuming CTI."""
    from hecate_runner.misp_publisher import sync_misp_outbox

    settings = _get_settings()
    if not settings.misp_publishing_enabled:
        console.print("MISP output is disabled. Run hecate-runner misp enable first.")
        raise typer.Exit(1)
    results = sync_misp_outbox(settings)
    console.print(f"Confirmed {len(results)} MISP export(s).")


@misp_app.command("status")
def misp_output_status(json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    from hecate_runner.misp_publisher import misp_publication_status

    settings = _get_settings()
    rows = misp_publication_status(settings)
    if json_output:
        typer.echo(
            json.dumps({"enabled": settings.misp_publishing_enabled, "exports": rows}, indent=2)
        )
        return
    console.print(f"MISP output: {'enabled' if settings.misp_publishing_enabled else 'disabled'}")
    table = Table("Hunt", "Status", "MISP event", "Last error")
    for row in rows:
        table.add_row(row["hunt_id"], row["status"], row["event_id"] or "--", row["last_error"])
    console.print(table)


@sources_app.command("check")
def check_sources() -> None:
    """Confirm read-only connectivity and record monitor health (no hunts or messages)."""
    from hecate_runner.integration_checks import check_integrations

    results = check_integrations(_get_settings())
    table = Table(title="Confirmed integration health")
    table.add_column("Integration")
    table.add_column("Status")
    table.add_column("Detail")
    for name, result in sorted(results.items()):
        status = (
            "[green]confirmed[/green]"
            if result["healthy"] and result["enabled"]
            else "[magenta]reachable; disabled[/magenta]"
            if result["healthy"]
            else "[red]unavailable[/red]"
        )
        table.add_row("misp_intake" if name == "misp" else name, status, result["detail"])
    Console().print(table)


@sources_app.command("list")
def list_sources() -> None:
    """List all CTI sources, their configuration status, and active state."""
    settings = _get_settings()
    console = Console()

    table = Table(title="CTI Sources Configuration")
    table.add_column("Provider", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Credentials / Configured", style="dim")
    table.add_column("Cursor State")

    is_multi = settings.cti_provider == "multi"
    active_sources = settings.cti_multi_provider_names if is_multi else [settings.cti_provider]

    def format_active(name: str) -> str:
        return "[green]Active[/green]" if name in active_sources else "[dim]Disabled[/dim]"

    def cursor_status(path: Path) -> str:
        if path.exists():
            mtime = os.path.getmtime(path)
            dt = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
            return f"Exists (last updated {dt})"
        return "None"

    for name in (
        "lolbas",
        "loldrivers",
        "gtfobins",
        "nuclei",
        "cisa_advisories",
        "cisa_ics",
        "attack_deltas",
    ):
        table.add_row(
            name,
            format_active(name),
            "Public repository / dedicated feed",
            cursor_status(settings.hecate_workspace / ".cursors" / f"{name}_cursor.json"),
        )

    # OTX
    otx_cred = "API Key present" if settings.otx_api_key else "Missing API Key"
    table.add_row("otx", format_active("otx"), otx_cred, cursor_status(settings.otx_cursor_file))

    # MISP
    misp_cred = (
        "Configured" if settings.misp_base_url and settings.misp_api_key else "Missing Config"
    )
    table.add_row(
        "misp", format_active("misp"), misp_cred, cursor_status(settings.misp_cursor_file)
    )

    # RSS
    rss_cred = f"{len(settings.rss_feed_urls)} feeds" if settings.rss_feed_urls else "No feeds"
    table.add_row("rss", format_active("rss"), rss_cred, cursor_status(settings.rss_cursor_file))

    # CISA KEV
    cisa_cursor = settings.hecate_workspace / ".cursors" / "cisa_kev_cursor.json"
    table.add_row(
        "cisa_kev", format_active("cisa_kev"), "Built-in (Public)", cursor_status(cisa_cursor)
    )

    # abuse_ch
    table.add_row(
        "abuse_ch",
        format_active("abuse_ch"),
        "ThreatFox (Public JSON)",
        cursor_status(settings.abuse_ch_cursor_file),
    )

    # certstream
    table.add_row(
        "certstream",
        format_active("certstream"),
        "Live CTL Stream (Public)",
        cursor_status(settings.certstream_cursor_file),
    )

    # github_poc
    gh_cred = "Token present" if settings.github_token else "Keyless / Public"
    table.add_row(
        "github_poc",
        format_active("github_poc"),
        gh_cred,
        cursor_status(settings.github_poc_cursor_file),
    )

    # malwarebazaar
    mb_cred = "API Key present" if settings.abusech_api_key else "Keyless / Public CSV"
    table.add_row(
        "malwarebazaar",
        format_active("malwarebazaar"),
        mb_cred,
        cursor_status(settings.malwarebazaar_cursor_file),
    )

    # vxunderground
    vx_cred = "Token present" if settings.github_token else "Keyless / Public Atom"
    table.add_row(
        "vxunderground",
        format_active("vxunderground"),
        vx_cred,
        cursor_status(settings.vxunderground_cursor_file),
    )

    # dfir_report
    table.add_row(
        "dfir_report",
        format_active("dfir_report"),
        "Public Feed / Procedural",
        cursor_status(settings.dfir_report_cursor_file),
    )

    # triage
    triage_cred = "API Key present" if settings.triage_api_key else "Missing API Key"
    table.add_row(
        "triage",
        format_active("triage"),
        triage_cred,
        cursor_status(settings.triage_cursor_file),
    )

    # vulncheck
    vc_cred = "API Key present" if settings.vulncheck_api_key else "Missing API Key"
    table.add_row(
        "vulncheck",
        format_active("vulncheck"),
        vc_cred,
        cursor_status(settings.vulncheck_cursor_file),
    )

    # censys_c2
    censys_cred = "Token present" if settings.censys_api_token else "Missing Token"
    table.add_row(
        "censys_c2",
        format_active("censys_c2"),
        censys_cred,
        cursor_status(settings.censys_c2_cursor_file),
    )

    # shadowserver
    ss_cred = (
        "API Key/Secret present"
        if settings.shadowserver_api_key and settings.shadowserver_api_secret
        else "Missing API key/secret"
    )
    table.add_row(
        "shadowserver",
        format_active("shadowserver"),
        ss_cred,
        cursor_status(settings.shadowserver_cursor_file),
    )

    # msrc
    table.add_row(
        "msrc",
        format_active("msrc"),
        "Public API (Keyless)",
        cursor_status(settings.msrc_cursor_file),
    )

    # cloud_threat
    ct_cred = (
        f"{len(settings.cloud_threat_feed_urls)} feeds"
        if settings.cloud_threat_feed_urls
        else "No feeds"
    )
    table.add_row(
        "cloud_threat",
        format_active("cloud_threat"),
        ct_cred,
        cursor_status(settings.cloud_threat_cursor_file),
    )

    # first_org
    table.add_row(
        "first_org",
        format_active("first_org"),
        f"EPSS >= {settings.first_org_min_epss:.0%}",
        cursor_status(settings.first_org_cursor_file),
    )

    # anyrun
    ar_cred = "API Key present" if settings.anyrun_api_key else "Public Feed / Keyless"
    table.add_row(
        "anyrun",
        format_active("anyrun"),
        ar_cred,
        cursor_status(settings.anyrun_cursor_file),
    )

    # opencti
    octi_cred = (
        "GraphQL Client"
        if settings.opencti_url and settings.opencti_token
        else "Test STIX fallback; no instance"
    )
    table.add_row(
        "opencti",
        format_active("opencti"),
        octi_cred,
        cursor_status(settings.opencti_cursor_file),
    )

    # File Queue
    file_queue_dir = settings.cti_queue_dir_resolved
    file_status = (
        f"{len(list(file_queue_dir.glob('*.txt')))} items"
        if file_queue_dir.exists()
        else "Missing dir"
    )
    table.add_row("file", format_active("file"), file_status, "N/A")

    console.print(table)

    if is_multi:
        console.print(
            f"\n[dim]Multi-provider round-robin cursor:[/dim] {cursor_status(settings.multi_cursor_file)}\n"
        )


def _find_canonical_env_file() -> Path:
    try:
        settings = _get_settings()
        ws_env = settings.hecate_workspace / ".env"
        if ws_env.is_file():
            return ws_env
    except Exception:
        pass
    if Path(".env").is_file():
        return Path(".env")
    default_ws = Path.home() / "betas" / "Hecate-Workspace" / ".env"
    if default_ws.is_file():
        return default_ws
    return Path(".env")


def _update_env_key(key: str, value: str) -> None:
    from dotenv import set_key

    env_path = _find_canonical_env_file()
    if not env_path.exists():
        env_path.touch()
    set_key(str(env_path), key, value)


@sources_app.command("enable")
def enable_source(name: str) -> None:
    """Enable a CTI source in the .env configuration."""
    settings = _get_settings()
    console = Console()

    valid = {
        "otx",
        "rss",
        "misp",
        "cisa_kev",
        "abuse_ch",
        "certstream",
        "github_poc",
        "malwarebazaar",
        "vxunderground",
        "dfir_report",
        "triage",
        "vulncheck",
        "censys_c2",
        "shadowserver",
        "msrc",
        "cloud_threat",
        "first_org",
        "anyrun",
        "opencti",
        "lolbas",
        "loldrivers",
        "gtfobins",
        "nuclei",
        "cisa_advisories",
        "cisa_ics",
        "attack_deltas",
        "file",
    }
    if name not in valid:
        console.print(
            f"[red]Error:[/red] Unknown source '{name}'. Valid sources are: {', '.join(valid)}"
        )
        raise typer.Exit(1)

    active = (
        settings.cti_multi_provider_names
        if settings.cti_provider == "multi"
        else [settings.cti_provider]
    )
    if name in active:
        console.print(f"Source [cyan]{name}[/cyan] is already enabled.")
        return

    if settings.cti_provider == "file" and name != "file":
        new_active = [name] if settings.cti_provider == "file" else [*active, name]
    else:
        new_active = [*active, name]

    if len(new_active) > 1:
        _update_env_key("HECATE_RUNNER_CTI_PROVIDER", "multi")
        _update_env_key("HECATE_RUNNER_CTI_MULTI_PROVIDERS", ",".join(new_active))
        console.print(f"Enabled [cyan]{name}[/cyan] (Mode: multi, Active: {','.join(new_active)})")
    else:
        _update_env_key("HECATE_RUNNER_CTI_PROVIDER", name)
        console.print(f"Enabled [cyan]{name}[/cyan] as the primary CTI provider.")


@sources_app.command("disable")
def disable_source(name: str) -> None:
    """Disable a CTI source in the .env configuration."""
    settings = _get_settings()
    console = Console()

    if settings.cti_provider != "multi":
        if settings.cti_provider == name:
            console.print(
                "[yellow]Cannot disable the only active source.[/yellow] Set a new primary source first, or enable another."
            )
            raise typer.Exit(1)
        else:
            console.print(f"Source [cyan]{name}[/cyan] is already disabled.")
            return

    active = settings.cti_multi_provider_names
    if name not in active:
        console.print(f"Source [cyan]{name}[/cyan] is already disabled.")
        return

    new_active = [a for a in active if a != name]

    if len(new_active) == 1:
        _update_env_key("HECATE_RUNNER_CTI_PROVIDER", new_active[0])
        console.print(
            f"Disabled [cyan]{name}[/cyan]. Reverted to single provider mode: {new_active[0]}"
        )
    else:
        _update_env_key("HECATE_RUNNER_CTI_MULTI_PROVIDERS", ",".join(new_active))
        console.print(f"Disabled [cyan]{name}[/cyan]. Remaining active: {','.join(new_active)}")


@sources_app.command("reset")
def reset_cursor(name: str) -> None:
    """Reset source state; delta sources establish a fresh baseline on their next poll."""
    settings = _get_settings()
    console = Console()

    cursors = {
        "otx": settings.otx_cursor_file,
        "misp": settings.misp_cursor_file,
        "rss": settings.rss_cursor_file,
        "multi": settings.multi_cursor_file,
        "cisa_kev": settings.hecate_workspace / ".cursors" / "cisa_kev_cursor.json",
        "abuse_ch": settings.abuse_ch_cursor_file,
        "certstream": settings.certstream_cursor_file,
        "github_poc": settings.github_poc_cursor_file,
        "malwarebazaar": settings.malwarebazaar_cursor_file,
        "vxunderground": settings.vxunderground_cursor_file,
        "dfir_report": settings.dfir_report_cursor_file,
        "triage": settings.triage_cursor_file,
        "vulncheck": settings.vulncheck_cursor_file,
        "censys_c2": settings.censys_c2_cursor_file,
        "shadowserver": settings.shadowserver_cursor_file,
        "msrc": settings.msrc_cursor_file,
        "cloud_threat": settings.cloud_threat_cursor_file,
        "first_org": settings.first_org_cursor_file,
        "anyrun": settings.anyrun_cursor_file,
        "opencti": settings.opencti_cursor_file,
    }

    for source in (
        "lolbas",
        "loldrivers",
        "gtfobins",
        "nuclei",
        "cisa_advisories",
        "cisa_ics",
        "attack_deltas",
    ):
        cursors[source] = settings.hecate_workspace / ".cursors" / f"{source}_cursor.json"
    if name == "cisa_advisories":
        (settings.hecate_workspace / ".cursors" / "cisa_narrative_feed.json").unlink(
            missing_ok=True
        )

    if name not in cursors:
        console.print(f"[red]Error:[/red] Unknown source or source without cursor '{name}'.")
        raise typer.Exit(1)

    cursor_path = cursors[name]
    if cursor_path.exists():
        try:
            os.remove(cursor_path)
            console.print(f"[green]Successfully reset cursor for {name}.[/green]")
        except Exception as e:
            console.print(f"[red]Failed to delete cursor:[/red] {e}")
            raise typer.Exit(1) from e
    else:
        console.print(f"No cursor found for [cyan]{name}[/cyan] at {cursor_path}")
