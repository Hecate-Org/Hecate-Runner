"""CLI commands for SIEM & EDR query drift detection, reconciliation, versioning, and auditing."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Annotated, Any, cast

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from hecate_runner import drift_alerts, notifications, siem_drift
from hecate_runner.config import Settings
from hecate_runner.workspace_paths import normalize_hunt_id, query_directory

log = logging.getLogger(__name__)
console = Console()


def _get_settings() -> Settings:
    cli_mod = sys.modules.get("hecate_runner.cli")
    if cli_mod and hasattr(cli_mod, "Settings"):
        return cast(Settings, cli_mod.Settings())
    return Settings()


def _require_hunt_id(hunt_id: str) -> str:
    try:
        return normalize_hunt_id(hunt_id)
    except ValueError:
        console.print(f"[red]Invalid hunt ID:[/red] {hunt_id!r}")
        raise typer.Exit(code=1) from None


def _append_github_step_summary(markdown: str) -> None:
    summary_env = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_env:
        return
    summary_path = Path(summary_env)
    try:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with summary_path.open("a", encoding="utf-8") as f:
            f.write(markdown if markdown.endswith("\n") else markdown + "\n")
    except OSError as exc:
        log.warning("Could not write GITHUB_STEP_SUMMARY (%s): %s", summary_path, exc)
        console.print(
            f"[yellow]Warning:[/yellow] could not write GITHUB_STEP_SUMMARY ({summary_path}): {exc}"
        )


def _print_jsonable(data: Any) -> None:
    try:
        console.print_json(data=data)
    except (TypeError, ValueError):
        try:
            console.print_json(json.dumps(data, default=str))
        except Exception:
            console.print(str(data))


def audit_siem_cmd(
    target: Annotated[
        str | None,
        typer.Option("--target", help="Specific target platform (e.g. splunk_spl, sentinel_kql)."),
    ] = None,
    reconcile: Annotated[
        bool,
        typer.Option(
            "--reconcile/--no-reconcile",
            help="Automatically reconcile any drifted or missing queries to match local git repository.",
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run/--live",
            help="Simulate audit (default) or query/mutate live SIEM APIs.",
        ),
    ] = True,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table, markdown, or json."),
    ] = "table",
    output_markdown: Annotated[
        Path | None,
        typer.Option(
            "--output-markdown", "-o", help="Write GitHub Flavored Markdown report to a file."
        ),
    ] = None,
    github_step_summary: Annotated[
        bool,
        typer.Option(
            "--github-step-summary",
            help="Append GitHub Flavored Markdown report to GITHUB_STEP_SUMMARY environment variable.",
        ),
    ] = False,
    fail_on_drift: Annotated[
        bool,
        typer.Option(
            "--fail-on-drift",
            help="Exit with non-zero exit code 1 if query drift or missing queries are detected (useful for PR gating).",
        ),
    ] = False,
    alert_slack: Annotated[
        bool,
        typer.Option(
            "--alert-slack/--no-alert-slack",
            help="Send Slack alert card if query drift is detected.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show full query drift diffs."),
    ] = False,
) -> None:
    """Audit all workspace hunting queries across SIEM & EDR platforms for detection drift."""
    settings = _get_settings()

    mode_str = "simulated (dry-run)" if dry_run else "live"
    if format != "markdown" and format != "json":
        console.print(
            f"[bold cyan]Auditing detection-as-code queries across {settings.hecate_workspace.name}...[/bold cyan]"
        )

    report = siem_drift.audit_workspace_queries(
        settings.hecate_workspace, target=target, dry_run=dry_run
    )

    in_sync = report.get("in_sync_count", 0)
    decommissioned = report.get("decommissioned_count", 0)
    pending_decom = report.get("pending_decommission_count", 0)
    drifted = report.get("drifted_count", 0)
    missing = report.get("missing_count", 0)
    total_q = report.get("total_queries", 0)
    total_h = report.get("total_hunts", 0)

    md_report = siem_drift.build_siem_markdown_report(report)

    if format == "markdown":
        console.print(md_report)
    elif format == "json":
        _print_jsonable(report)
    else:
        table = Table(
            title=f"SIEM & EDR Detection-as-Code Audit ({mode_str})",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Hunt ID")
        table.add_column("File")
        table.add_column("Target")
        table.add_column("Status")
        table.add_column("Remote ID")

        for hunt_id, results in report.get("hunts", {}).items():
            for res in results:
                status = res.get("status", "")
                if status in {"in_sync", "dry_run"}:
                    status_color = "green" if status == "in_sync" else "blue"
                elif status == "decommissioned":
                    status_color = "cyan"
                elif status == "pending_decommission" or status == "drift_detected":
                    status_color = "yellow"
                elif status == "missing_remote":
                    status_color = "magenta"
                else:
                    status_color = "red"

                table.add_row(
                    hunt_id,
                    str(res.get("file", "")),
                    str(res.get("target", "")),
                    f"[{status_color}]{status}[/{status_color}]",
                    str(res.get("remote_id") or ""),
                )

        console.print(table)
        decom_str = f", [cyan]{decommissioned} decommissioned[/cyan]" if decommissioned > 0 else ""
        pending_str = (
            f", [yellow]{pending_decom} pending decommission[/yellow]" if pending_decom > 0 else ""
        )
        console.print(
            f"\n[bold]Audit Summary:[/bold] {total_h} hunt(s), {total_q} queries evaluated "
            f"([green]{in_sync} in sync[/green]{decom_str}{pending_str}, "
            f"[yellow]{drifted} drifted[/yellow], "
            f"[magenta]{missing} missing[/magenta])."
        )

        if verbose or drifted > 0:
            for hunt_id, drifted_list in report.get("drifted_by_hunt", {}).items():
                for res in drifted_list:
                    diff = res.get("drift_diff")
                    if diff:
                        console.print(
                            f"\n[bold yellow]── Query Drift Detected: {hunt_id} / {res.get('target')} ({res.get('file')}) ──[/bold yellow]"
                        )
                        console.print(diff)

    if output_markdown:
        output_markdown.write_text(md_report, encoding="utf-8")
        if format != "markdown" and format != "json":
            console.print(f"[green]Markdown report written to:[/green] {output_markdown}")

    if github_step_summary and "GITHUB_STEP_SUMMARY" in os.environ:
        _append_github_step_summary(md_report + "\n")

    if alert_slack and (drifted > 0 or missing > 0):
        for hunt_id, problems in drift_alerts.drift_alert_groups(report).items():
            notifications.notify_siem_drift(settings, hunt_id, problems)
        if format != "markdown" and format != "json":
            console.print("[green]Slack drift alert notification cards dispatched.[/green]")

    if reconcile and (drifted > 0 or missing > 0):
        if format != "markdown" and format != "json":
            console.print(
                f"\n[bold yellow]Triggering automated reconciliation ({mode_str})...[/bold yellow]"
            )
        rec_summary = siem_drift.reconcile_all_drifted_queries(
            settings.hecate_workspace, target=target, dry_run=dry_run
        )
        if format != "markdown" and format != "json":
            console.print(
                f"[bold green]Reconciliation complete:[/bold green] {rec_summary.get('total_reconciled', 0)} reconciled, "
                f"{rec_summary.get('total_failed', 0)} failed."
            )

    if fail_on_drift and (drifted > 0 or missing > 0 or pending_decom > 0):
        if format != "markdown" and format != "json":
            console.print(
                "[bold red]CI Gate Failed: Detection query drift, missing remote queries, or pending decommissioning detected.[/bold red]"
            )
        raise typer.Exit(code=1)


def reconcile_queries_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID (e.g. H-0007) to reconcile queries for.")],
    target: Annotated[
        str | None,
        typer.Option("--target", help="Specific target platform (e.g. splunk_spl, sentinel_kql)."),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run/--live",
            help="Simulate reconciliation (default) or push live updates to SIEM.",
        ),
    ] = True,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Force redeploy all queries regardless of current sync status.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show full request details."),
    ] = False,
) -> None:
    """Reconcile drifted or missing SIEM/EDR queries back to git-authoritative definitions."""
    settings = _get_settings()
    clean_id = _require_hunt_id(hunt_id)
    query_dir = query_directory(settings.hecate_workspace, clean_id)
    if not query_dir.exists():
        console.print(f"[red]Query directory not found:[/red] {query_dir}")
        raise typer.Exit(code=1)

    table = Table(
        title=f"SIEM & EDR Query Reconciliation for {clean_id}",
        show_header=True,
        header_style="bold green",
    )
    table.add_column("File")
    table.add_column("Target")
    table.add_column("Previous Status")
    table.add_column("New Status")
    table.add_column("Remote ID")
    table.add_column("Detail")

    results = siem_drift.reconcile_hunt_queries(
        settings.hecate_workspace,
        clean_id,
        target=target,
        dry_run=dry_run,
        force=force,
    )

    if not results:
        console.print(f"[green]All queries for {clean_id} are already in sync.[/green]")
        return

    reconciled_count = 0
    for res in results:
        status_color = "green" if res.get("ok") else "red"
        table.add_row(
            str(res.get("file", "")),
            str(res.get("target", "")),
            str(res.get("previous_status", "")),
            f"[{status_color}]{res.get('status')}[/{status_color}]",
            str(res.get("remote_id") or ""),
            str(res.get("detail", "")),
        )
        if res.get("ok"):
            reconciled_count += 1

    console.print(table)
    mode_str = "simulated (dry-run)" if dry_run else "live"
    console.print(
        f"[bold]{reconciled_count} / {len(results)}[/bold] query(s) reconciled in {mode_str} mode."
    )

    if verbose:
        for res in results:
            summary = res.get("request_summary")
            if summary:
                console.print(
                    f"\n[bold cyan]── Reconciliation Request: {res.get('target')} ({res.get('file')}) ──[/bold cyan]"
                )
                _print_jsonable(summary)


def drift_history_cmd(
    hunt_id: Annotated[
        str | None,
        typer.Option("--hunt-id", "-h", help="Filter by hunt ID (e.g. H-0007)."),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option("--target", "-t", help="Filter by target platform (e.g. splunk_spl)."),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", help="Maximum entries to display."),
    ] = 25,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show full query drift diffs."),
    ] = False,
) -> None:
    """View chronological SIEM Detection-as-Code drift and reconciliation audit history."""
    settings = _get_settings()
    clean_hunt = _require_hunt_id(hunt_id) if hunt_id else None
    if limit < 0:
        console.print(f"[red]Invalid --limit:[/red] {limit} (must be >= 0).")
        raise typer.Exit(code=1)

    events = siem_drift.get_drift_history(
        settings.hecate_workspace, hunt_id=clean_hunt, target=target, limit=limit
    )
    if not events:
        console.print("[dim]No drift or reconciliation events found in audit history.[/dim]")
        return

    table = Table(
        title="SIEM Detection-as-Code Drift & Reconciliation History",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Timestamp")
    table.add_column("Hunt ID")
    table.add_column("Target")
    table.add_column("Event")
    table.add_column("File")
    table.add_column("Actor")
    table.add_column("Detail")

    for ev in events:
        ev_type = ev.get("event_type", "")
        if ev_type == "reconciled":
            color = "green"
        elif ev_type == "decommissioned":
            color = "cyan"
        elif ev_type == "pending_decommission" or ev_type == "drift_detected":
            color = "yellow"
        elif ev_type == "missing_remote":
            color = "magenta"
        elif ev_type == "deploy_failed":
            color = "red"
        else:
            color = "blue"

        ts = str(ev.get("timestamp", ""))[:19].replace("T", " ")
        table.add_row(
            ts,
            str(ev.get("hunt_id", "")),
            str(ev.get("target", "")),
            f"[{color}]{ev_type}[/{color}]",
            str(ev.get("file_name", "")),
            str(ev.get("actor", "system")),
            str(ev.get("detail", "") or "")[:60],
        )

    console.print(table)

    if verbose:
        for ev in events:
            diff = ev.get("drift_diff")
            if diff:
                console.print(
                    f"\n[bold yellow]── Query Diff: {ev.get('hunt_id')} / {ev.get('target')} ({ev.get('file_name')}) at {ev.get('timestamp')} ──[/bold yellow]"
                )
                console.print(diff)


def siem_status_cmd(
    days: Annotated[
        int,
        typer.Option("--days", "-d", help="Lookback window in days for metrics."),
    ] = 7,
) -> None:
    """Display comprehensive SIEM Detection-as-Code health, sync metrics, and audit summary."""
    settings = _get_settings()
    if days < 1:
        console.print(f"[red]Invalid --days:[/red] {days} (must be >= 1).")
        raise typer.Exit(code=1)

    metrics = siem_drift.get_siem_drift_metrics(settings.hecate_workspace, days=days)
    history = siem_drift.get_drift_history(settings.hecate_workspace, limit=5)

    health_pct = metrics.get("sync_health_pct", 100.0)
    in_sync = metrics.get("in_sync_count", 0)
    total_q = metrics.get("total_queries", 0)
    drifted = metrics.get("drifted_count", 0)
    missing = metrics.get("missing_count", 0)
    versions = metrics.get("tracked_query_versions", 0)
    sweeps = metrics.get("sweeps_conducted", 0)
    reconciled = metrics.get("reconciliations_period", 0)
    last_audited = str(metrics.get("last_audited", "never")).replace("T", " ")[:19]

    health_color = (
        "green" if (drifted == 0 and missing == 0) else ("yellow" if drifted == 0 else "red")
    )
    day_label = f"{days}-Day" if days != 1 else "1-Day"

    summary_text = (
        f"[bold]Sync Health:[/bold] [{health_color}]{health_pct:.1f}%[/{health_color}] "
        f"([green]{in_sync}[/green] in sync, [yellow]{drifted}[/yellow] drifted, [magenta]{missing}[/magenta] missing / {total_q} total)\n"
        f"[bold]Tracked Query Versions:[/bold] [cyan]{versions}[/cyan] rule version(s)\n"
        f"[bold]Last Audit Sweep:[/bold] {last_audited}\n"
        f"[bold]{day_label} Audit Sweeps:[/bold] {sweeps} | [bold]Reconciliations:[/bold] [green]{reconciled}[/green]"
    )

    console.print(
        Panel(
            summary_text,
            title="[bold cyan]SIEM Detection-as-Code Status Dashboard[/bold cyan]",
            border_style="cyan",
        )
    )

    target_breakdown = metrics.get("target_drift_breakdown", {})
    if target_breakdown:
        tb_table = Table(
            title=f"Drift Incidents by Target Platform (Past {days} Day{'s' if days != 1 else ''})",
            show_header=True,
        )
        tb_table.add_column("Target Platform")
        tb_table.add_column("Drift Incidents", justify="right")
        for tgt, count in sorted(target_breakdown.items(), key=lambda x: -x[1]):
            tb_table.add_row(tgt, f"[yellow]{count}[/yellow]")
        console.print(tb_table)

    if history:
        hist_table = Table(title="Recent Drift & Reconciliation Activity", show_header=True)
        hist_table.add_column("Timestamp")
        hist_table.add_column("Hunt ID")
        hist_table.add_column("Target")
        hist_table.add_column("Event")
        hist_table.add_column("Actor")
        for ev in history:
            ev_type = ev.get("event_type", "")
            ev_color = (
                "green"
                if ev_type == "reconciled"
                else ("yellow" if ev_type == "drift_detected" else "blue")
            )
            ts = str(ev.get("timestamp", ""))[:19].replace("T", " ")
            hist_table.add_row(
                ts,
                str(ev.get("hunt_id", "")),
                str(ev.get("target", "")),
                f"[{ev_color}]{ev_type}[/{ev_color}]",
                str(ev.get("actor", "system")),
            )
        console.print(hist_table)


def query_versions_cmd(
    hunt_id: Annotated[
        str | None,
        typer.Argument(help="Optional hunt ID (e.g. H-0007) to inspect versions for."),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option("--target", "-t", help="Filter by target platform (e.g. splunk_spl)."),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", help="Maximum entries to display."),
    ] = 25,
) -> None:
    """View deployed SIEM query versions, content hashes, and deployment history."""
    settings = _get_settings()
    clean_hunt = _require_hunt_id(hunt_id) if hunt_id else None
    if limit < 0:
        console.print(f"[red]Invalid --limit:[/red] {limit} (must be >= 0).")
        raise typer.Exit(code=1)

    versions = siem_drift.get_query_versions(
        settings.hecate_workspace, hunt_id=clean_hunt, target=target, limit=limit
    )
    if not versions:
        console.print("[dim]No query versions recorded in database yet.[/dim]")
        return

    table = Table(
        title=f"SIEM Query Versions {f'for {clean_hunt}' if clean_hunt else ''}",
        show_header=True,
        header_style="bold blue",
    )
    table.add_column("Hunt ID")
    table.add_column("Target")
    table.add_column("File")
    table.add_column("Ver", justify="right")
    table.add_column("SHA256 Hash")
    table.add_column("Deployed At")
    table.add_column("Deployed By")
    table.add_column("Status")

    for v in versions:
        ts = str(v.get("deployed_at", ""))[:19].replace("T", " ")
        q_hash = str(v.get("query_hash", ""))[:12] + "…"
        st = str(v.get("status", "active"))
        if st == "active":
            st_color = "green"
        elif st in ("decommissioned", "retired"):
            st_color = "cyan"
        elif st == "deprecated":
            st_color = "yellow"
        else:
            st_color = "dim"

        table.add_row(
            str(v.get("hunt_id", "")),
            str(v.get("target", "")),
            str(v.get("file_name", "")),
            f"[bold cyan]v{v.get('version', 1)}[/bold cyan]",
            q_hash,
            ts,
            str(v.get("deployed_by", "system")),
            f"[{st_color}]{st}[/{st_color}]",
        )

    console.print(table)
