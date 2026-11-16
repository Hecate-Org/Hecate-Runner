"""CLI command for resident perpetual daemon worker loop."""

from __future__ import annotations

import logging
import signal
import sys
import threading
import time
from typing import Annotated, Any, cast

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel

from hecate_runner.config import Settings
from hecate_runner.orchestrator import RunResult

log = logging.getLogger(__name__)
console = Console()


def _get_settings() -> Settings:
    cli_mod = sys.modules.get("hecate_runner.cli")
    if cli_mod and hasattr(cli_mod, "Settings"):
        return cast(Settings, cli_mod.Settings())
    return Settings()


def _get_build_default_orchestrator() -> Any:
    cli_mod = sys.modules.get("hecate_runner.cli")
    if cli_mod and hasattr(cli_mod, "build_default_orchestrator"):
        return cli_mod.build_default_orchestrator
    from hecate_runner.orchestrator import build_default_orchestrator

    return build_default_orchestrator


def _get_configure_logging() -> Any:
    cli_mod = sys.modules.get("hecate_runner.cli")
    if cli_mod and hasattr(cli_mod, "_configure_logging"):
        return cli_mod._configure_logging
    from hecate_runner.cli import _configure_logging

    return _configure_logging


def _print_result(result: RunResult) -> None:
    console.print()
    console.print(f"[bold]Outcome:[/bold] {result.outcome}")
    if result.detail:
        console.print(f"[bold]Detail:[/bold] {result.detail}")
    if result.hunt_id:
        console.print(f"[bold]Hunt ID:[/bold] {result.hunt_id}")
    if result.research_id:
        console.print(f"[bold]Research ID:[/bold] {result.research_id}")
    if result.draft_path:
        console.print(f"[bold]Draft path:[/bold] {result.draft_path}")


def daemon(
    interval: Annotated[
        int | None,
        typer.Option(
            "--interval",
            "-i",
            help="Polling interval in seconds when intake queue is empty (default from settings: 60s).",
        ),
    ] = None,
    max_cycles: Annotated[
        int | None,
        typer.Option(
            "--max-cycles",
            "-m",
            help="Maximum number of cycles to run before exiting (default: infinite).",
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show what would happen without calling hecate."),
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "--ignore-quota",
            help="Bypass daily draft, research quota, and spacing limits.",
        ),
    ] = False,
    sweeps: Annotated[
        bool,
        typer.Option(
            "--sweeps/--no-sweeps",
            help="Enable periodic auto-hunt sweep execution in the daemon loop (default: True).",
        ),
    ] = True,
) -> None:
    """Run orchestrator perpetually as a resident daemon with an event-driven worker loop."""
    settings = _get_settings()
    configure_logging = _get_configure_logging()
    configure_logging(settings)
    build_default_orch = _get_build_default_orchestrator()

    effective_interval = interval if interval is not None else settings.daemon_interval_sec
    stop_event = threading.Event()
    last_sweep_check: float = 0.0
    sweep_interval_sec = float(settings.auto_hunt_sweep_interval_sec)
    last_replay_check: float = 0.0
    replay_interval_sec = float(settings.purple_team_continuous_replay_interval_sec)

    def _sig_handler(signum: int, frame: Any) -> None:
        signame = signal.Signals(signum).name
        console.print(
            f"\n[bold yellow]Daemon received {signame}. Initiating graceful shutdown...[/bold yellow]"
        )
        stop_event.set()

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    console.print(
        Panel(
            f"[bold green]Starting Hecate-Runner Autonomous Daemon[/bold green]\n\n"
            f"• Workspace: [cyan]{settings.hecate_workspace}[/cyan]\n"
            f"• CTI Provider: [cyan]{settings.cti_provider}[/cyan]\n"
            f"• Idle Poll Interval: [cyan]{effective_interval}s[/cyan]\n"
            f"• Auto Hunt Sweeps: [cyan]{'enabled (' + str(settings.auto_hunt_sweep_interval_sec) + 's interval)' if (sweeps and settings.auto_hunt_execution_enabled) else 'disabled'}[/cyan]\n"
            f"• Continuous Purple Team: [cyan]{'enabled (' + str(settings.purple_team_continuous_replay_interval_sec) + 's interval)' if settings.purple_team_continuous_replay_interval_sec > 0 else 'disabled'}[/cyan]\n"
            f"• Max Cycles: [cyan]{max_cycles or 'unlimited'}[/cyan]\n"
            f"• Research Reuse: [cyan]{'enabled (<=' + str(settings.research_reuse_max_age_days) + 'd)' if settings.research_reuse_enabled else 'disabled'}[/cyan]\n"
            f"• Dry Run: [cyan]{dry_run}[/cyan]\n"
            f"• Force Quotas: [cyan]{force}[/cyan]\n\n"
            "[dim]Press Ctrl+C to terminate cleanly.[/dim]",
            title="⚡ Hecate Daemon",
            box=box.ROUNDED,
        )
    )

    from hecate_runner.integration_checks import start_health_refresh

    cycles_completed = 0
    try:
        while not stop_event.is_set():
            start_health_refresh(settings)
            if force:
                orch = build_default_orch(settings, ignore_quota=True)
            else:
                orch = build_default_orch(settings)

            log.info("Daemon executing cycle #%d...", cycles_completed + 1)
            try:
                result = orch.run_once(dry_run=dry_run)
            finally:
                provider = getattr(orch, "cti", None)
                if provider is not None:
                    provider.close()
            _print_result(result)
            cycles_completed += 1

            # Run periodic autonomous hunt sweep check
            if sweeps and settings.auto_hunt_execution_enabled and not dry_run:
                now_ts = time.time()
                if (now_ts - last_sweep_check) >= sweep_interval_sec:
                    log.info("Daemon executing scheduled hunt sweep check...")
                    try:
                        from hecate_runner.execution.scheduler import HuntExecutionScheduler

                        sched = HuntExecutionScheduler(settings=settings)
                        sweep_res = sched.run_scheduled_sweeps()
                        if sweep_res:
                            console.print(
                                f"[bold cyan]🎯 Daemon processed {len(sweep_res)} hunt sweeps.[/bold cyan]"
                            )
                    except Exception as sweep_err:
                        log.error("Daemon hunt sweep error: %s", sweep_err, exc_info=True)
                    finally:
                        last_sweep_check = now_ts

            # Run periodic continuous Purple Team replay verification
            if replay_interval_sec > 0 and not dry_run:
                now_ts = time.time()
                if (now_ts - last_replay_check) >= replay_interval_sec:
                    log.info(
                        "Daemon executing continuous Purple Team replay verification across active hunts..."
                    )
                    try:
                        from hecate_runner.purple_team import run_continuous_replay_sweep

                        sweep_outcomes = run_continuous_replay_sweep(settings)
                        if sweep_outcomes:
                            missed = sum(
                                1
                                for o in sweep_outcomes
                                if o.get("passed_rules", 0) < o.get("total_rules", 0)
                            )
                            console.print(
                                f"[bold magenta]🛡️ Daemon completed Purple Team continuous replay across "
                                f"{len(sweep_outcomes)} hunts ({missed} with tuning suggestions generated).[/bold magenta]"
                            )
                    except Exception as pt_err:
                        log.error(
                            "Daemon Purple Team continuous replay error: %s", pt_err, exc_info=True
                        )
                    finally:
                        last_replay_check = now_ts

            if max_cycles is not None and cycles_completed >= max_cycles:
                console.print(
                    f"[bold green]Reached max cycles ({max_cycles}). Exiting daemon.[/bold green]"
                )
                break

            if stop_event.is_set():
                break

            # If an item was successfully drafted, check if there is immediate pending work before sleeping
            if result.outcome in ("draft_created", "drafted"):
                log.info(
                    "Cycle completed with draft %s. Pausing 5s before next item...", result.hunt_id
                )
                stop_event.wait(5.0)
            elif result.outcome in ("empty", "queue_empty", "no_cti"):
                log.info("CTI intake queue is idle. Sleeping for %ds...", effective_interval)
                stop_event.wait(float(effective_interval))
            elif result.outcome in ("quota_reached", "quota_exceeded"):
                log.warning(
                    "Daily quota reached (%s). Waiting for next window (%ds)...",
                    result.detail or "",
                    effective_interval,
                )
                stop_event.wait(float(effective_interval))
            elif result.outcome == "spacing_cooldown":
                # Do not thrash every 60s when cooldown has hours remaining.
                # Sleep until cooldown expires, polling at least every 15m (900s)
                # so newly arrived fast indicator sweeps are not starved,
                # and no less than effective_interval.
                rem_sec: float | None = getattr(result, "cooldown_remaining_sec", None)
                if rem_sec is None and result.detail and "/" in result.detail:
                    try:
                        elapsed_str, total_str = result.detail.replace("h", "").split("/")
                        rem = (float(total_str) - float(elapsed_str)) * 3600.0
                        if rem > 0:
                            rem_sec = rem
                    except Exception:
                        pass

                if rem_sec is not None and rem_sec > 0:
                    wait_sec = int(max(float(effective_interval), min(rem_sec, 900.0)))
                else:
                    wait_sec = effective_interval

                log.info(
                    "Spacing cooldown active (%s). Checking again in %ds...",
                    result.detail or "",
                    wait_sec,
                )
                stop_event.wait(float(wait_sec))
            else:
                log.info(
                    "Cycle completed with status '%s'. Sleeping for %ds...",
                    result.outcome,
                    effective_interval,
                )
                stop_event.wait(float(effective_interval))

    except Exception as exc:
        log.error("Fatal daemon error: %s", exc, exc_info=True)
        console.print(f"[bold red]Fatal daemon exception:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[bold green]Hecate daemon shut down gracefully after {cycles_completed} cycles.[/bold green]"
    )
    raise typer.Exit(code=0)


daemon_cmd = daemon
