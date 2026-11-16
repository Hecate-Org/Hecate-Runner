"""CLI commands for SIEM & EDR query deployment, synchronization, decommissioning, and hunt lifecycle."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated, Any, cast

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from hecate_runner.config import Settings
from hecate_runner.lifecycle import get_hunt_lifecycle, set_hunt_lifecycle
from hecate_runner.siem_drift import decommission_hunt_queries, record_query_version
from hecate_runner.slack_bot import deploy_queries_for_hunt, sync_queries_for_hunt

console = Console()


def _get_settings() -> Settings:
    cli_mod = sys.modules.get("hecate_runner.cli")
    if cli_mod and hasattr(cli_mod, "Settings"):
        return cast(Settings, cli_mod.Settings())
    return Settings()


def deploy_queries_cmd(
    hunt_id: Annotated[
        str, typer.Argument(help="Hunt ID (e.g. H-0868) or 'all' to deploy all hunt queries.")
    ],
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run/--live", help="Simulate deployment (default) or push live via API."
        ),
    ] = True,
    target: Annotated[
        str | None,
        typer.Option("--target", help="Specific target platform (e.g. sentinel_kql, splunk_spl)."),
    ] = None,
    github_step_summary: Annotated[
        bool,
        typer.Option(
            "--github-step-summary",
            help="Append deployment summary to GITHUB_STEP_SUMMARY.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose", "-v", help="Show full contract payload schemas and HTTP endpoints."
        ),
    ] = False,
) -> None:
    """Deploy or simulate deployment of hunt queries to target SIEM and EDR platforms."""
    settings = _get_settings()
    queries_root = settings.hecate_workspace / "queries"
    if not queries_root.exists():
        console.print(f"[red]Queries root directory not found:[/red] {queries_root}")
        raise typer.Exit(code=1)

    target_hunts: list[str] = []
    if hunt_id.lower() == "all":
        target_hunts = sorted(
            [d.name for d in queries_root.iterdir() if d.is_dir() and d.name.startswith("H-")]
        )
    else:
        target_dir = queries_root / hunt_id
        if not target_dir.exists():
            console.print(f"[red]Query directory not found:[/red] {target_dir}")
            raise typer.Exit(code=1)
        target_hunts = [hunt_id]

    table = Table(
        title="SIEM & EDR Query Deployment (All Hunts)"
        if hunt_id.lower() == "all"
        else f"SIEM & EDR Query Deployment for {hunt_id}",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Hunt ID")
    table.add_column("File")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Remote ID")
    table.add_column("Detail")

    total_deployed = 0
    total_processed = 0
    all_deployments: list[tuple[str, dict[str, Any]]] = []

    for h_id in target_hunts:
        deployments = deploy_queries_for_hunt(
            settings.hecate_workspace,
            h_id,
            dry_run=dry_run,
            target=target,
        )
        for res in deployments:
            total_processed += 1
            all_deployments.append((h_id, res))
            status_color = "green" if res.get("ok") else "red"
            table.add_row(
                h_id,
                str(res.get("file", "")),
                str(res.get("target", "")),
                f"[{status_color}]{res.get('status')}[/{status_color}]",
                str(res.get("remote_id") or ""),
                str(res.get("detail", "")),
            )
            if res.get("ok"):
                total_deployed += 1
                if not dry_run:
                    q_file = settings.hecate_workspace / "queries" / h_id / str(res.get("file", ""))
                    q_content = q_file.read_text(encoding="utf-8") if q_file.exists() else ""
                    if q_content:
                        record_query_version(
                            settings.hecate_workspace,
                            hunt_id=h_id,
                            target=str(res.get("target", "")),
                            file_name=str(res.get("file", "")),
                            query_content=q_content,
                            remote_id=str(res.get("remote_id") or ""),
                            deployed_by="cli",
                        )

    console.print(table)
    mode_str = "simulated (dry-run)" if dry_run else "live"
    console.print(
        f"[bold]{total_deployed}/{total_processed}[/bold] query(s) processed across {len(target_hunts)} hunt(s) in {mode_str} mode."
    )

    if verbose:
        for h_id, res in all_deployments:
            summary = res.get("request_summary")
            if summary:
                console.print(
                    f"\n[bold cyan]── Contract Payload: {h_id} / {res.get('target')} ({res.get('file')}) ──[/bold cyan]"
                )
                console.print_json(data=summary)

    if github_step_summary and "GITHUB_STEP_SUMMARY" in os.environ:
        summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"])
        md_lines = [
            f"## 🚀 SIEM Detection-as-Code Deployment ({mode_str})",
            "",
            f"> **Processed:** `{total_deployed}/{total_processed}` queries across `{len(target_hunts)}` hunt(s).",
            "",
            "| Hunt ID | File | Target | Status | Remote ID |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for h_id, res in all_deployments[:30]:
            st = "✅ " + str(res.get("status")) if res.get("ok") else "❌ " + str(res.get("status"))
            md_lines.append(
                f"| `{h_id}` | `{res.get('file')}` | `{res.get('target')}` | {st} | `{(res.get('remote_id') or '')[:25]}` |"
            )
        if len(all_deployments) > 30:
            md_lines.append(
                f"| ... | *({len(all_deployments) - 30} additional queries deployed)* | | | |"
            )
        md_lines.append("")
        with summary_path.open("a", encoding="utf-8") as f:
            f.write("\n".join(md_lines) + "\n")


def decommission_queries_cmd(
    hunt_id: Annotated[
        str, typer.Argument(help="Hunt ID (e.g. H-0011) to decommission queries for, or 'all'.")
    ],
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run/--live",
            help="Simulate decommissioning (default) or delete live from remote SIEM APIs.",
        ),
    ] = True,
    target: Annotated[
        str | None,
        typer.Option("--target", help="Specific target platform (e.g. sentinel_kql, splunk_spl)."),
    ] = None,
    reason: Annotated[
        str,
        typer.Option(
            "--reason", "-r", help="Analyst rationale and sign-off for query decommissioning."
        ),
    ] = "Decommissioned via Query Lifecycle Management",
    actor: Annotated[
        str,
        typer.Option(
            "--actor", "-a", help="Analyst or system identifier signing off on decommissioning."
        ),
    ] = "analyst",
    retire_hunt: Annotated[
        bool,
        typer.Option(
            "--retire-hunt/--no-retire-hunt",
            help="Also transition hunt frontmatter lifecycle status to 'retired'.",
        ),
    ] = True,
    github_step_summary: Annotated[
        bool,
        typer.Option(
            "--github-step-summary",
            help="Append decommissioning summary to GITHUB_STEP_SUMMARY.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show full HTTP request summaries."),
    ] = False,
) -> None:
    """Decommission and undeploy hunt queries from target SIEM & EDR platforms with audit provenance."""
    settings = _get_settings()
    summary = decommission_hunt_queries(
        workspace=settings.hecate_workspace,
        hunt_id=hunt_id,
        dry_run=dry_run,
        target=target,
        reason=reason,
        actor=actor,
        retire_hunt=retire_hunt,
    )

    table = Table(
        title=f"SIEM Detection Query Decommissioning ({'All Hunts' if hunt_id.lower() == 'all' else hunt_id})",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Hunt ID")
    table.add_column("File")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Remote ID")
    table.add_column("Provenance & Detail")

    for res in summary.get("results", []):
        st = str(res.get("status", ""))
        status_color = "green" if res.get("ok") else "red"
        table.add_row(
            str(res.get("hunt_id", "")),
            str(res.get("file", "")),
            str(res.get("target", "")),
            f"[{status_color}]{st}[/{status_color}]",
            str(res.get("remote_id") or ""),
            str(res.get("detail", "") or res.get("reason", "")),
        )

    console.print(table)
    mode_str = "simulated (dry-run)" if dry_run else "live"
    console.print(
        f"[bold]{summary.get('total_decommissioned', 0)}/{summary.get('total_queries', 0)}[/bold] query(s) "
        f"decommissioned across {summary.get('total_hunts', 1)} hunt(s) in {mode_str} mode "
        f"(sign-off: [cyan]{actor}[/cyan] — '{reason}')."
    )
    if retire_hunt:
        console.print("[bold green]✔ Hunt lifecycle status transitioned to 'retired'.[/bold green]")

    if verbose:
        for res in summary.get("results", []):
            req_sum = res.get("request_summary")
            if req_sum:
                console.print(
                    f"\n[bold red]── Teardown Contract: {res.get('target')} ({res.get('file')}) ──[/bold red]"
                )
                console.print_json(data=req_sum)

    if github_step_summary and "GITHUB_STEP_SUMMARY" in os.environ:
        summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"])
        md_lines = [
            f"## 🧹 SIEM Detection Query Decommissioning ({mode_str})",
            "",
            f"> **Sign-off:** `{actor}` | **Reason:** {reason} | **Retired Hunt:** `{retire_hunt}`",
            "",
            "| Hunt ID | File | Target | Status | Remote ID |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for res in summary.get("results", [])[:30]:
            st = "✅ " + str(res.get("status")) if res.get("ok") else "❌ " + str(res.get("status"))
            md_lines.append(
                f"| `{res.get('hunt_id')}` | `{res.get('file')}` | `{res.get('target')}` | {st} | `{(res.get('remote_id') or '')[:25]}` |"
            )
        md_lines.append("")
        with summary_path.open("a", encoding="utf-8") as f:
            f.write("\n".join(md_lines) + "\n")


def undeploy_queries_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID (e.g. H-0868) to undeploy queries for.")],
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run/--live", help="Simulate undeployment (default) or delete live via API."
        ),
    ] = True,
    target: Annotated[
        str | None,
        typer.Option("--target", help="Specific target platform (e.g. sentinel_kql, splunk_spl)."),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show full HTTP request summaries."),
    ] = False,
) -> None:
    """Undeploy/delete hunt queries from target SIEM and EDR platforms."""
    settings = _get_settings()
    summary = decommission_hunt_queries(
        workspace=settings.hecate_workspace,
        hunt_id=hunt_id,
        dry_run=dry_run,
        target=target,
        reason="Undeployed via CLI command",
        actor="cli",
        retire_hunt=False,
    )

    table = Table(
        title=f"SIEM & EDR Query Undeployment for {hunt_id}",
        show_header=True,
        header_style="bold red",
    )
    table.add_column("File")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Remote ID")
    table.add_column("Detail")

    for res in summary.get("results", []):
        status = str(res.get("status", ""))
        if status in {"undeployed", "not_found", "dry_run"}:
            status_color = (
                "green" if status == "undeployed" else ("cyan" if status == "not_found" else "blue")
            )
        else:
            status_color = "red"
        table.add_row(
            str(res.get("file", "")),
            str(res.get("target", "")),
            f"[{status_color}]{status}[/{status_color}]",
            str(res.get("remote_id") or ""),
            str(res.get("detail", "")),
        )

    console.print(table)
    mode_str = "simulated (dry-run)" if dry_run else "live"
    console.print(
        f"[bold]{summary.get('total_decommissioned', 0)}[/bold] query(s) processed in {mode_str} mode."
    )

    if verbose:
        for res in summary.get("results", []):
            req_sum = res.get("request_summary")
            if req_sum:
                console.print(
                    f"\n[bold red]── Teardown Contract: {res.get('target')} ({res.get('file')}) ──[/bold red]"
                )
                console.print_json(data=req_sum)


def hunt_lifecycle_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID (e.g. H-0011).")],
    status: Annotated[
        str | None,
        typer.Argument(
            help="Optional new lifecycle state: planning, testing, active, deprecated, retired."
        ),
    ] = None,
    reason: Annotated[
        str,
        typer.Option("--reason", "-r", help="Reason for lifecycle transition."),
    ] = "",
    actor: Annotated[
        str,
        typer.Option("--actor", "-a", help="Analyst or engineer performing transition."),
    ] = "analyst",
) -> None:
    """View or transition hunt lifecycle state (planning, testing, active, deprecated, retired)."""
    settings = _get_settings()

    if status:
        res = set_hunt_lifecycle(
            workspace=settings.hecate_workspace,
            hunt_id=hunt_id,
            new_status=status,
            reason=reason,
            actor=actor,
        )
        if not res.get("ok"):
            console.print(f"[bold red]Lifecycle update failed:[/bold red] {res.get('error')}")
            raise typer.Exit(code=1)
        console.print(
            f"[bold green]✔ Hunt {hunt_id} transitioned:[/bold green] "
            f"[dim]{res.get('previous_status')}[/dim] -> [bold cyan]{res.get('status')}[/bold cyan] "
            f"(by {actor}{f' — {reason}' if reason else ''})"
        )
        return

    # View current lifecycle
    lc = get_hunt_lifecycle(settings.hecate_workspace, hunt_id)
    if not lc.get("found"):
        console.print(f"[bold red]Hunt not found:[/bold red] {hunt_id}")
        raise typer.Exit(code=1)

    table = Table(
        title=f"Hunt Lifecycle Metadata: {hunt_id}",
        show_header=False,
        box=box.ROUNDED,
    )
    table.add_column("Property", style="bold cyan", width=22)
    table.add_column("Value")

    st = lc.get("status", "planning")
    if st == "active":
        st_color = "bold green"
    elif st == "retired":
        st_color = "bold cyan"
    elif st == "deprecated":
        st_color = "bold yellow"
    else:
        st_color = "bright_white"

    table.add_row("Hunt ID", hunt_id)
    table.add_row("Title", str(lc.get("title", "")))
    table.add_row("Lifecycle Status", f"[{st_color}]{st}[/{st_color}]")
    table.add_row("Frontmatter Raw Status", str(lc.get("raw_status", "")))
    table.add_row("File Path", str(lc.get("path", "")))

    if lc.get("deprecated_at"):
        table.add_row("Deprecated At", str(lc.get("deprecated_at")))
        table.add_row("Deprecated By", str(lc.get("deprecated_by") or ""))
        table.add_row("Deprecation Reason", str(lc.get("deprecation_reason") or ""))

    if lc.get("retired_at"):
        table.add_row("Retired At", str(lc.get("retired_at")))
        table.add_row("Retired By", str(lc.get("retired_by") or ""))
        table.add_row("Retirement Reason", str(lc.get("retirement_reason") or ""))

    console.print(table)


def sync_queries_cmd(
    hunt_id: Annotated[
        str, typer.Argument(help="Hunt ID (e.g. H-0868) to sync check queries for.")
    ],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run/--live", help="Simulate sync check (default) or query live SIEM."),
    ] = True,
    target: Annotated[
        str | None,
        typer.Option("--target", help="Specific target platform (e.g. sentinel_kql, splunk_spl)."),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show query drift diffs and full summaries."),
    ] = False,
) -> None:
    """Check synchronization and detect query drift against target SIEM and EDR platforms."""
    settings = _get_settings()
    query_dir = settings.hecate_workspace / "queries" / hunt_id
    if not query_dir.exists():
        console.print(f"[red]Query directory not found:[/red] {query_dir}")
        raise typer.Exit(code=1)

    table = Table(
        title=f"SIEM & EDR Query Synchronization & Drift for {hunt_id}",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("File")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Remote ID")
    table.add_column("Detail")

    syncs = sync_queries_for_hunt(
        settings.hecate_workspace,
        hunt_id,
        dry_run=dry_run,
        target=target,
    )
    in_sync_count = 0
    drift_count = 0
    missing_count = 0

    for res in syncs:
        status = res.get("status", "")
        if status in {"in_sync", "dry_run"}:
            status_color = "green" if status == "in_sync" else "blue"
            if status == "in_sync":
                in_sync_count += 1
        elif status == "drift_detected":
            status_color = "yellow"
            drift_count += 1
        elif status == "missing_remote":
            status_color = "magenta"
            missing_count += 1
        else:
            status_color = "red"

        table.add_row(
            str(res.get("file", "")),
            str(res.get("target", "")),
            f"[{status_color}]{status}[/{status_color}]",
            str(res.get("remote_id") or ""),
            str(res.get("detail", "")),
        )

    console.print(table)
    mode_str = "simulated (dry-run)" if dry_run else "live"
    console.print(
        f"[bold]{len(syncs)}[/bold] query(s) evaluated in {mode_str} mode "
        f"([green]{in_sync_count} in sync[/green], "
        f"[yellow]{drift_count} drifted[/yellow], "
        f"[magenta]{missing_count} missing[/magenta])."
    )

    if verbose or drift_count > 0:
        for res in syncs:
            drift_diff = res.get("drift_diff")
            if drift_diff:
                console.print(
                    f"\n[bold yellow]── Query Drift Detected: {res.get('target')} ({res.get('file')}) ──[/bold yellow]"
                )
                console.print(drift_diff)
            elif verbose:
                summary = res.get("request_summary")
                if summary:
                    console.print(
                        f"\n[bold cyan]── Sync Request: {res.get('target')} ({res.get('file')}) ──[/bold cyan]"
                    )
                    console.print_json(data=summary)
