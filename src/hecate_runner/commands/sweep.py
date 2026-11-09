"""CLI commands for autonomous hunt sweep execution, staging, and approvals."""

from __future__ import annotations

import logging
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from hecate_runner.config import Settings
from hecate_runner.execution.scheduler import HuntExecutionScheduler

log = logging.getLogger(__name__)
console = Console()

sweep_app = typer.Typer(
    help="Autonomous hunt sweep scheduling, COUNT-FIRST safe execution, and approvals.",
    no_args_is_help=True,
)


@sweep_app.command("list")
def sweep_list(
    force: Annotated[bool, typer.Option("--force", "-f", help="Show all active hunts regardless of cadence")] = False,
) -> None:
    """List active hunts, target SIEM queries, execution watermarks, and sweep eligibility."""
    settings = Settings()
    scheduler = HuntExecutionScheduler(settings=settings)
    active = scheduler.discover_active_hunts()

    if not active:
        console.print("[yellow]No active hunts found with transpiled queries in workspace.[/yellow]")
        return

    table = Table(
        title=f"Active Hunt Execution Cadence (Target: {scheduler.provider.name.upper()})",
        box=box.ROUNDED,
    )
    table.add_column("Hunt ID", style="bold cyan")
    table.add_column("Title", style="white")
    table.add_column("Query File", style="dim")
    table.add_column("Last Executed", style="magenta")
    table.add_column("Outcome", style="green")
    table.add_column("Matches", justify="right")
    table.add_column("Eligible?", justify="center")

    for h in active:
        wm = h.get("watermark")
        eligible = scheduler.check_eligibility(h, force=force)
        q_files = h.get("query_files", [])
        q_name = q_files[0].name if q_files else "[red]none[/red]"

        last_run = wm.last_executed_at[:16].replace("T", " ") if wm else "[dim]never[/dim]"
        outcome = wm.last_outcome if wm else "[dim]none[/dim]"
        matched = str(wm.last_matched_count) if wm else "0"
        elig_icon = "[green]✓ Yes[/green]" if eligible else "[dim]No[/dim]"

        table.add_row(
            h["hunt_id"],
            (h["title"][:38] + "...") if len(h["title"]) > 38 else h["title"],
            q_name,
            last_run,
            outcome,
            matched,
            elig_icon,
        )

    console.print(table)


@sweep_app.command("pending")
def sweep_pending() -> None:
    """List staged hunt sweeps awaiting human approval."""
    settings = Settings()
    scheduler = HuntExecutionScheduler(settings=settings)
    staged = scheduler.store.list_staged_sweeps(status="pending_approval")

    if not staged:
        console.print("[dim]No hunt sweeps pending approval.[/dim]")
        return

    table = Table(title="Hunt Sweeps Awaiting Approval", box=box.ROUNDED)
    table.add_column("Sweep ID", style="bold cyan")
    table.add_column("Hunt ID", style="bold yellow")
    table.add_column("Target", style="magenta")
    table.add_column("Window", justify="right")
    table.add_column("Staged At", style="dim")
    table.add_column("Query Snippet", style="white")

    for s in staged:
        table.add_row(
            s.sweep_id,
            s.hunt_id,
            s.target_siem,
            f"{s.time_range_days}d",
            s.staged_at[:16].replace("T", " "),
            (s.query_text[:40] + "...") if len(s.query_text) > 40 else s.query_text,
        )

    console.print(table)
    console.print(
        "\n[dim]Approve execution with:[/dim] `hecate-runner sweep approve <SWEEP_ID>`\n"
        "[dim]Reject sweep with:[/dim] `hecate-runner sweep reject <SWEEP_ID>`"
    )


@sweep_app.command("stage")
def sweep_stage(
    hunt_id: Annotated[str | None, typer.Option("--hunt-id", "-h", help="Stage sweep for a specific hunt only")] = None,
    force: Annotated[bool, typer.Option("--force", "-f", help="Stage sweep regardless of scheduled cadence")] = False,
    days: Annotated[int, typer.Option("--days", "-d", help="Lookback window in days")] = 1,
) -> None:
    """Stage scheduled sweeps for eligible active hunts (generates approval cards)."""
    settings = Settings()
    scheduler = HuntExecutionScheduler(settings=settings)
    staged = scheduler.stage_sweeps(hunt_id=hunt_id, force=force, time_range_days=days)

    if not staged:
        console.print("[yellow]No eligible hunts to stage. Use --force to stage immediately.[/yellow]")
        return

    console.print(f"[green]✓[/green] Staged {len(staged)} hunt sweep(s) for approval:")
    for s in staged:
        console.print(
            f"  • [bold cyan]{s.sweep_id}[/bold cyan] for [bold]{s.hunt_id}[/bold] "
            f"({s.target_siem}, window={s.time_range_days}d)"
        )
    console.print(
        "\n[dim]Run `hecate-runner sweep approve <SWEEP_ID>` or approve via Slack card to execute.[/dim]"
    )


@sweep_app.command("approve")
def sweep_approve(
    sweep_id_or_hunt_id: Annotated[str, typer.Argument(help="Sweep ID (SWEEP-...) or Hunt ID (H-...)")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt")] = False,
) -> None:
    """Execute a staged sweep through the COUNT-FIRST Safe Execution Gate."""
    settings = Settings()
    scheduler = HuntExecutionScheduler(settings=settings)
    staged = scheduler.store.get_staged_sweep(sweep_id_or_hunt_id)

    if not staged:
        console.print(
            f"[red]No pending sweep found for '{sweep_id_or_hunt_id}'.[/red] "
            "Run `hecate-runner sweep pending` to see what is staged."
        )
        raise typer.Exit(code=1)

    console.print(f"[bold]Hunt:[/bold] {staged.hunt_id} (Sweep ID: {staged.sweep_id})")
    console.print(f"[bold]Target SIEM:[/bold] {staged.target_siem}")
    console.print(f"[bold]Time Range:[/bold] {staged.time_range_days} day(s)")
    console.print(f"[bold]Query File:[/bold] {staged.query_file}")
    console.print(f"[bold]Query:[/bold] {staged.query_text}")

    if not yes and not typer.confirm("\nExecute this hunt sweep through the COUNT-FIRST gate?"):
        console.print("[yellow]Cancelled — sweep remains staged for approval.[/yellow]")
        raise typer.Exit(code=1)

    console.print("\n[dim]Running COUNT-FIRST pre-flight and safe execution...[/dim]")
    res = scheduler.execute_sweep(staged.sweep_id, approver="cli:analyst")

    if res.outcome == "clean":
        console.print(f"[green]✓ Clean Sweep![/green] 0 events matched on {res.target}.")
    elif res.outcome == "hits_detected":
        console.print(
            f"[yellow]⚠️ Telemetry Hits Detected![/yellow] {res.matched_count} event(s) matched on {res.target}."
        )
    elif res.outcome == "overmatch":
        console.print(
            f"[red]🚨 Overmatch Warning![/red] {res.matched_count} event(s) matched (exceeded auto-fetch ceiling)."
        )
    else:
        console.print(f"[red]✗ Sweep Execution Failed:[/red] {res.detail}")

    console.print(f"[dim]Recorded outcome: {res.outcome} in hunt markdown and watermarks.[/dim]")
    raise typer.Exit(code=0 if res.ok else 1)


@sweep_app.command("reject")
def sweep_reject(
    sweep_id_or_hunt_id: Annotated[str, typer.Argument(help="Sweep ID (SWEEP-...) or Hunt ID (H-...)")],
    reason: Annotated[str, typer.Option("--reason", "-r", help="Reason for rejecting sweep")] = "Rejected via CLI",
) -> None:
    """Reject and cancel a staged sweep."""
    settings = Settings()
    scheduler = HuntExecutionScheduler(settings=settings)
    staged = scheduler.reject_sweep(sweep_id_or_hunt_id, reason=reason, actor="cli:analyst")

    if not staged:
        console.print(f"[red]No pending sweep found for '{sweep_id_or_hunt_id}'.[/red]")
        raise typer.Exit(code=1)

    console.print(f"[yellow]✓ Sweep {staged.sweep_id} for {staged.hunt_id} rejected.[/yellow] ({reason})")


@sweep_app.command("run")
def sweep_run(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID to sweep (e.g. H-0021)")],
    days: Annotated[int, typer.Option("--days", "-d", help="Lookback window in days")] = 1,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt")] = False,
    force_raw: Annotated[bool, typer.Option("--force-raw", help="Bypass COUNT-FIRST check")] = False,
) -> None:
    """Stage and immediately execute a sweep for an active hunt."""
    settings = Settings()
    scheduler = HuntExecutionScheduler(settings=settings)

    if not yes and not typer.confirm(f"Execute sweep for active hunt {hunt_id}?"):
        console.print("[yellow]Cancelled.[/yellow]")
        raise typer.Exit(code=1)

    staged_list = scheduler.stage_sweeps(hunt_id=hunt_id, force=True, time_range_days=days)
    if not staged_list:
        console.print(f"[red]Could not stage sweep for '{hunt_id}'. Verify hunt is active with queries.[/red]")
        raise typer.Exit(code=1)

    staged = staged_list[0]
    res = scheduler.execute_sweep(staged.sweep_id, approver="cli:analyst", force_raw=force_raw)

    if res.outcome == "clean":
        console.print(f"[green]✓ Clean Sweep![/green] 0 events matched on {res.target}.")
    elif res.outcome == "hits_detected":
        console.print(
            f"[yellow]⚠️ Telemetry Hits Detected![/yellow] {res.matched_count} event(s) matched on {res.target}."
        )
    elif res.outcome == "overmatch":
        console.print(
            f"[red]🚨 Overmatch Warning![/red] {res.matched_count} event(s) matched (exceeded auto-fetch ceiling)."
        )
    else:
        console.print(f"[red]✗ Sweep Execution Failed:[/red] {res.detail}")

    raise typer.Exit(code=0 if res.ok else 1)
