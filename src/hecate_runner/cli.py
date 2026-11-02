"""Typer-based CLI entry point.

Commands:
    hecate-runner run           Execute one orchestrator cycle
    hecate-runner demo          Run an end-to-end zero-config demonstration cycle
    hecate-runner status        Print state, quota, config summary
    hecate-runner metrics       Summarize stage latency and LLM usage
    hecate-runner config        Dump effective config (redacts secrets)
    hecate-runner doctor        Sanity-check the deployment
    hecate-runner slack-bot     Start Slack Socket Mode interactive bot or offline simulation harness
    hecate-runner otx-poll      Route one high-signal OTX pulse into the CTI queue
    hecate-runner rss-poll      Route one high-signal RSS/Atom entry into the CTI queue
    hecate-runner misp-poll     Route one high-signal MISP event into the CTI queue
    hecate-runner propose       Stage a bounded query for a hunt, pending approval
    hecate-runner pending       List queries awaiting approval
    hecate-runner approve       Execute a previously proposed, guardrail-passed query
    hecate-runner reject        Discard a proposed query without executing it
    hecate-runner watch         Follow what a running cycle is deciding, step by step
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from hecate_agent.core.grounding import TechniqueFact, render_grounding_section
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from hecate_runner import __version__
from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.commands.bas import (
    bas_check_cmd,
    bas_detonate_cmd,
    bas_install_procedures_cmd,
    bas_reset_cmd,
    bas_verify_cmd,
)
from hecate_runner.commands.doctor import (
    _effective_model,
    _module_available,  # noqa: F401
    _stix_data_available,  # noqa: F401
    _tavily_key_available,  # noqa: F401
    doctor,
)
from hecate_runner.commands.publication import publish_review
from hecate_runner.commands.release import release_app
from hecate_runner.commands.slack import (
    daily_digest,
    ops_digest,
    setup_slack_channels,
    slack_bot_cmd,
    slack_channels,
    slack_test,
)
from hecate_runner.commands.sources import (
    misp_app,
    sources_app,
)
from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.dead_letter import (
    clear_dead_letters,
    dead_letter_dir,
    get_dead_letter,
    list_dead_letters,
    restore_dead_letter,
)
from hecate_runner.github_publisher import enqueue_hunt, outbox_status, sync_outbox
from hecate_runner.hecate_client import HecateClient
from hecate_runner.hunt_audit import (
    HuntFacts,
    audit_hunt_text,
    parse_hunt_file,
    replace_grounding_section,
)
from hecate_runner.log_rotation import rotate_log_if_needed
from hecate_runner.metrics import MetricsStore
from hecate_runner.misp_poller import run_misp_poll
from hecate_runner.orchestrator import (
    RunResult,
    build_default_orchestrator,
    build_orchestrator_for_item,
)
from hecate_runner.otx_poller import run_otx_poll
from hecate_runner.parked_store import get_parked, list_parked, parked_dir, restore
from hecate_runner.promotion_policy import evaluate_promotion, load_policy
from hecate_runner.query_execution import ProposedQuery, get_provider, validate_guardrails
from hecate_runner.query_store import PendingQueryStore
from hecate_runner.rss_poller import run_rss_poll
from hecate_runner.state import OrchestratorState
from hecate_runner.trail import LOGGER_NAME as TRAIL_LOGGER

log = logging.getLogger("hecate_runner.cli")

app = typer.Typer(
    name="hecate-runner",
    help="Autonomous hunt draft orchestrator for Hecate.",
    no_args_is_help=True,
    add_completion=False,
)
app.command("publish-review")(publish_review)
app.add_typer(release_app, name="release")
#: Technique IDs anywhere in a draft, so --check-attack validates the ones the
#: hunt actually records rather than only those its CTI named.
_DRAFT_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

console = Console()


def _stdout_already_targets(path: Path) -> bool:
    """True if sys.stdout is already writing to the same file as `path`.

    Under systemd, StandardOutput=append:<path> makes stdout point at the
    log file before our process even starts -- adding a separate
    logging.FileHandler(path) on top of a StreamHandler(sys.stdout) then
    doubles every line, since both end up writing to the same file. This
    check is redirection-mechanism-agnostic (systemd, shell `>>`, anything)
    rather than sniffing for systemd specifically, so it degrades safely:
    interactive runs (stdout is a terminal/pipe, not this file) are
    unaffected and still get both handlers as before.
    """
    try:
        stdout_stat = os.fstat(sys.stdout.fileno())
        target_stat = path.stat()
    except OSError:
        return False
    return (stdout_stat.st_dev, stdout_stat.st_ino) == (target_stat.st_dev, target_stat.st_ino)


def _configure_logging(settings: Settings, *, to_stdout: bool = True) -> None:
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    # Rotate before any handler opens the file. The orchestrator is a oneshot
    # unit, so "at startup" is the only moment both writers -- this process and
    # systemd's append: redirection -- are between writes.
    rotate_log_if_needed(
        settings.log_file,
        max_bytes=settings.log_max_bytes,
        backup_count=settings.log_backup_count,
    )
    # Under systemd, StandardOutput=append: already writes stdout into the log
    # file, so log through stdout alone. Opening the file here as well is not
    # just redundant: when the file is missing, systemd creates it root-owned
    # before dropping to User=, and this process then cannot open it. Every
    # cycle for three hours on 26 Sep failed with PermissionError that way,
    # after a state reset had deleted the log.
    handlers: list[logging.Handler]
    if to_stdout and _stdout_already_targets(settings.log_file):
        handlers = [logging.StreamHandler(sys.stdout)]
    else:
        handlers = [logging.FileHandler(settings.log_file)]
        if to_stdout:
            handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
    # One line per HTTP request (every MISP/OTX/RSS poll) was half of each
    # cycle's log; the trail's intake line already says what was fetched.
    if settings.log_level != "DEBUG":
        logging.getLogger("httpx").setLevel(logging.WARNING)


# --- Commands --------------------------------------------------------------


@app.command()
def run(
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
) -> None:
    """Execute one orchestrator cycle."""
    settings = Settings()
    _configure_logging(settings)

    if force:
        orch = build_default_orchestrator(settings, ignore_quota=True)
    else:
        orch = build_default_orchestrator(settings)
    result = orch.run_once(dry_run=dry_run)
    _print_result(result)
    raise typer.Exit(code=0 if result.ok else 1)


@app.command()
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
) -> None:
    """Run orchestrator perpetually as a resident daemon with an event-driven worker loop."""
    import signal
    import threading

    settings = Settings()
    _configure_logging(settings)

    effective_interval = interval if interval is not None else settings.daemon_interval_sec
    stop_event = threading.Event()

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
                orch = build_default_orchestrator(settings, ignore_quota=True)
            else:
                orch = build_default_orchestrator(settings)

            log.info("Daemon executing cycle #%d...", cycles_completed + 1)
            try:
                result = orch.run_once(dry_run=dry_run)
            finally:
                provider = getattr(orch, "cti", None)
                if provider is not None:
                    provider.close()
            _print_result(result)
            cycles_completed += 1

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


@app.command()
def demo(
    keep: Annotated[
        bool,
        typer.Option("--keep", help="Preserve the temporary demonstration workspace on disk."),
    ] = False,
) -> None:
    """Run an end-to-end demonstration cycle with bundled fixtures and mock providers.

    Requires no API keys, no LLM, and no network access. Creates a temporary workspace,
    processes a sample CTI item through research, hypothesis generation, ATT&CK mapping,
    grounding audit, and Sigma drafting, and displays the resulting draft hunt.
    """
    from hecate_runner.demo import run_demo

    exit_code, _ = run_demo(keep=keep, console=console)
    raise typer.Exit(code=exit_code)


@app.command()
def draft(
    text: Annotated[
        str | None,
        typer.Argument(
            help="The intelligence to draft from. Omit to read --file or standard input."
        ),
    ] = None,
    file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            "-f",
            help="Read the intelligence from this file.",
            exists=True,
            dir_okay=False,
        ),
    ] = None,
    url: Annotated[
        str,
        typer.Option(
            "--url",
            help="The report this intelligence summarises; it is fetched for source evidence.",
        ),
    ] = "",
    title: Annotated[
        str, typer.Option("--title", help="A title for the item; used as the research topic.")
    ] = "",
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show what would happen without calling hecate."),
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force", "--ignore-quota", help="Bypass daily draft and research quota limits."
        ),
    ] = False,
) -> None:
    """Draft a hunt from intelligence you supply, through the same cycle a feed item takes.

    The feeds and their cursors are not touched and triage is skipped, since
    you chose the item. Everything after intake is the scheduled cycle: source
    evidence, research, the hypothesis, technique and platform checks, the
    claim and grounding audits, and Sigma drafting. The draft counts against
    the daily draft and research quotas unless --force is given.
    """
    if text is not None and file is not None:
        console.print("[red]Give the intelligence as an argument or with --file, not both.[/red]")
        raise typer.Exit(code=2)
    if file is not None:
        content = file.read_text(encoding="utf-8")
    elif text is not None:
        content = text
    elif not sys.stdin.isatty():
        content = sys.stdin.read()
    else:
        console.print(
            "[red]No intelligence given: pass it as an argument, with --file, or on standard input.[/red]"
        )
        raise typer.Exit(code=2)
    content = content.strip()
    if not content:
        console.print("[red]The intelligence is empty.[/red]")
        raise typer.Exit(code=2)

    settings = Settings()
    _configure_logging(settings)
    item = CTIItem(
        content=content,
        source="manual",
        received_at=datetime.now(UTC),
        identifier=str(file) if file is not None else "manual",
        title=title.strip(),
        source_url=url.strip(),
    )
    result = build_orchestrator_for_item(settings, item, ignore_quota=force).run_once(
        dry_run=dry_run
    )
    _print_result(result)
    raise typer.Exit(code=0 if result.ok else 1)


@app.command(name="otx-poll")
def otx_poll() -> None:
    """Route the next high-signal OTX pulse into the CTI queue, if any."""
    settings = Settings()
    _configure_logging(settings)

    result = run_otx_poll(settings)

    console.print()
    console.print(f"[bold]Routed:[/bold] {result.routed}")
    if result.routed_pulse_ids:
        console.print(f"[bold]Pulse ID:[/bold] {', '.join(result.routed_pulse_ids)}")
    if result.skipped_queue_occupied:
        console.print("[yellow]CTI queue slot occupied - skipped this poll.[/yellow]")
    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")

    raise typer.Exit(code=0 if result.ok else 1)


@app.command(name="rss-poll")
def rss_poll() -> None:
    """Route the next high-signal RSS/Atom entry into the CTI queue, if any."""
    settings = Settings()
    _configure_logging(settings)

    result = run_rss_poll(settings)

    console.print()
    console.print(f"[bold]Routed:[/bold] {result.routed}")
    if result.routed_entry_ids:
        console.print(f"[bold]Entry:[/bold] {', '.join(result.routed_entry_ids)}")
    if result.skipped_queue_occupied:
        console.print("[yellow]CTI queue slot occupied - skipped this poll.[/yellow]")
    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")

    raise typer.Exit(code=0 if result.ok else 1)


@app.command(name="misp-poll")
def misp_poll() -> None:
    """Route the next high-signal MISP event into the CTI queue, if any."""
    settings = Settings()
    _configure_logging(settings)

    result = run_misp_poll(settings)

    console.print()
    console.print(f"[bold]Routed:[/bold] {result.routed}")
    if result.routed_event_uuids:
        console.print(f"[bold]Event:[/bold] {', '.join(result.routed_event_uuids)}")
    if result.skipped_queue_occupied:
        console.print("[yellow]CTI queue slot occupied - skipped this poll.[/yellow]")
    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")

    raise typer.Exit(code=0 if result.ok else 1)


@app.command()
def propose(
    hunt_id: Annotated[str, typer.Argument(help="Hunt this query is for, e.g. H-0016")],
    query: Annotated[str, typer.Option("--query", help="The query text (e.g. SPL)")],
    data_source: Annotated[str, typer.Option("--data-source", help="e.g. splunk")],
    time_range_days: Annotated[
        int, typer.Option("--time-range-days", help="Bounded lookback window")
    ],
    limit: Annotated[int, typer.Option("--limit", help="Max results")],
    justification: Annotated[
        str, typer.Option("--justification", help="Why this query, why these bounds")
    ] = "",
) -> None:
    """Stage a bounded query for a hunt. Rejected outright if it violates guardrails.

    This does not execute anything — it only stages a proposal for
    `hecate-runner approve` to run later. Nothing here writes queries for you;
    you (or, in the future, a separately-evaluated agent) provide the query
    text.
    """
    settings = Settings()
    proposed = ProposedQuery(
        hunt_id=hunt_id,
        data_source=data_source,
        query_text=query,
        time_range_days=time_range_days,
        limit=limit,
        justification=justification,
    )

    violations = validate_guardrails(
        proposed,
        max_time_range_days=settings.max_query_time_range_days,
        max_limit=settings.max_query_limit,
    )
    if violations:
        console.print(f"[red]Query rejected — {len(violations)} guardrail violation(s):[/red]")
        for v in violations:
            console.print(f"  [red]✗[/red] {v}")
        raise typer.Exit(code=1)

    store = PendingQueryStore(settings.pending_queries_dir)
    path = store.save(proposed)
    console.print(f"[green]✓[/green] Proposed query staged for {hunt_id} at {path}")
    console.print(
        f"  Data source: {data_source}  |  Time range: {time_range_days}d  |  Limit: {limit}"
    )
    console.print(
        f"\nRun [bold]hecate-runner approve {hunt_id}[/bold] to execute, or [bold]hecate-runner reject {hunt_id}[/bold] to discard."
    )


@app.command()
def audit(
    hunt_ids: Annotated[
        list[str] | None,
        typer.Argument(help="Hunt IDs to audit (e.g. H-0616). Omit to audit every hunt on disk."),
    ] = None,
    update: Annotated[
        bool,
        typer.Option(
            "--update", help="Rewrite each hunt's Grounding section with the fresh result."
        ),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict", help="Exit non-zero if any hunt carries a claim that traces to no source."
        ),
    ] = False,
    check_attack: Annotated[
        bool,
        typer.Option(
            "--check-attack",
            help=(
                "Validate technique IDs against the live ATT&CK matrix. Off by "
                "default because it costs one hecate subprocess per technique."
            ),
        ),
    ] = False,
) -> None:
    """Re-grade hunts already on disk against the evidence behind them.

    The audit normally runs while a hunt is drafted, so every hunt written
    before a given version of it was graded by an older one -- or, for drafts
    predating the audit, not at all. This re-runs it after the fact.
    """
    settings = Settings()
    _configure_logging(settings, to_stdout=False)

    paths = _hunt_paths(settings, hunt_ids)
    if not paths:
        console.print("[yellow]No hunt files matched.[/yellow]")
        raise typer.Exit(code=1 if hunt_ids else 0)

    hecate = HecateClient(
        workspace=settings.hecate_workspace,
        hecate_bin=settings.hecate_bin_resolved,
        env_overrides=settings.env_for_hecate(),
    )

    table = Table(title="Grounding audit", show_header=True, header_style="bold cyan")
    for column in ("Hunt", "CTI", "Asserted", "Research-only", "Inferred", "Unsupported"):
        table.add_column(column)

    total_unsupported = 0
    findings: list[tuple[str, list[str]]] = []

    for path in paths:
        text = path.read_text(encoding="utf-8")
        facts = parse_hunt_file(text)
        technique_facts = _attack_facts(hecate, settings, facts, text) if check_attack else None
        _, report = audit_hunt_text(text, technique_facts=technique_facts)
        counts = report.counts
        total_unsupported += counts["unsupported"]
        if report.unsupported:
            findings.append((facts.hunt_id or path.stem, [c.value for c in report.unsupported]))

        table.add_row(
            facts.hunt_id or path.stem,
            # A hunt whose CTI could not be recovered is called out rather than
            # scored: every claim would grade unsupported for want of evidence,
            # which reads as a fabrication finding and is not one.
            "[green]ok[/green]" if facts.has_cti else "[yellow]not found[/yellow]",
            str(counts["asserted"]),
            str(counts["corroborated"]),
            str(counts["derived"]),
            f"[red]{counts['unsupported']}[/red]" if counts["unsupported"] else "0",
        )

        if update:
            refreshed = replace_grounding_section(text, render_grounding_section(report))
            if refreshed != text:
                atomic_write_text(path, refreshed)

    console.print(table)
    for hunt_id, values in findings:
        console.print(f"[red]{hunt_id}[/red]: {', '.join(values)}")
    if update:
        console.print(f"\n[dim]Grounding sections rewritten for {len(paths)} hunt(s).[/dim]")

    if strict and total_unsupported:
        raise typer.Exit(code=1)


@app.command("promotion-check")
def promotion_check(
    hunt_id: Annotated[str, typer.Argument(help="Planning hunt ID to evaluate (e.g. H-0822).")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the deterministic policy decision as JSON.")
    ] = False,
) -> None:
    """Evaluate the versioned GitHub promotion policy without changing files."""
    settings = Settings()
    try:
        decision = evaluate_promotion(
            settings.hecate_workspace, hunt_id, policy_path=settings.github_publishing_policy_path
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Promotion blocked:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if json_output:
        # Plain echo, not Rich: console.print wraps at terminal width and parses
        # [brackets] as markup, which corrupts the JSON the promotion workflow parses.
        typer.echo(json.dumps(decision.to_dict(), sort_keys=True))
        return
    if decision.eligible:
        console.print(f"[green]Auto-merge eligible:[/green] {hunt_id}")
    elif decision.review_required:
        console.print(f"[yellow]Human review required:[/yellow] {hunt_id}")
    else:
        console.print(f"[cyan]Publication allowed; auto-merge disabled by policy:[/cyan] {hunt_id}")
    for reason in decision.reasons:
        console.print(f"  - {reason}")


@app.command("promotion-policy-validate")
def promotion_policy_validate() -> None:
    """Validate the workspace's versioned promotion policy."""
    settings = Settings()
    try:
        load_policy(settings.hecate_workspace, settings.github_publishing_policy_path)
    except (OSError, ValueError) as exc:
        console.print(f"[red]Invalid promotion policy:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    console.print("[green]Promotion policy is valid.[/green]")


@app.command("publish")
def publish(
    hunt_id: Annotated[
        str, typer.Argument(help="Planning hunt ID to submit as a GitHub pull request.")
    ],
) -> None:
    """Snapshot one hunt into the durable GitHub publication outbox."""
    settings = Settings()
    if not settings.github_publishing_enabled:
        console.print(
            "[red]GitHub publishing is disabled.[/red] Set HECATE_RUNNER_GITHUB_PUBLISHING_ENABLED=true."
        )
        raise typer.Exit(code=2)
    try:
        status = enqueue_hunt(settings, hunt_id)
        if status == "awaiting_review":
            console.print(
                f"{hunt_id} is staged privately; run publish-review {hunt_id} before any upload."
            )
            return
        results = sync_outbox(settings)
    except Exception as exc:
        console.print(f"[red]Could not publish {hunt_id}:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    current = next((result for result in results if result.hunt_id == hunt_id), None)
    if current:
        console.print(f"[green]PR #{current.pr_number}[/green] {current.pr_url} ({current.status})")
    else:
        record = next((row for row in outbox_status(settings) if row["hunt_id"] == hunt_id), None)
        if record and record["pr_url"]:
            console.print(f"{hunt_id}: {record['status']} — {record['pr_url']}")
        else:
            console.print(
                f"Queued {hunt_id} (outbox status: {status}); it will retry on the next run."
            )


@app.command("publish-sync")
def publish_sync(
    show_status: Annotated[
        bool, typer.Option("--status", help="List recent outbox records after syncing.")
    ] = False,
) -> None:
    """Retry due GitHub publication jobs without processing CTI."""
    settings = Settings()
    if not settings.github_publishing_enabled:
        console.print("GitHub publishing is disabled.")
        raise typer.Exit(code=2)
    try:
        results = sync_outbox(settings)
    except Exception as exc:
        console.print(f"[red]Could not sync publication outbox:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if results:
        for result in results:
            console.print(
                f"[green]{result.hunt_id}[/green] {result.status}: {result.pr_url or result.branch}"
            )
    else:
        console.print("No due publication jobs.")
    if show_status:
        table = Table(title="GitHub publication outbox", show_header=True, header_style="bold cyan")
        for column in ("Hunt", "Status", "Attempts", "PR", "Error"):
            table.add_column(column)
        for row in outbox_status(settings):
            table.add_row(
                str(row["hunt_id"]),
                str(row["status"]),
                str(row["attempts"]),
                str(row["pr_url"] or ""),
                str(row["last_error"] or ""),
            )
        console.print(table)


@app.command("deploy-queries")
def deploy_queries_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID (e.g. H-0868) to deploy queries for.")],
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
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose", "-v", help="Show full contract payload schemas and HTTP endpoints."
        ),
    ] = False,
) -> None:
    """Deploy or simulate deployment of hunt queries to target SIEM and EDR platforms."""
    settings = Settings()
    query_dir = settings.hecate_workspace / "queries" / hunt_id
    if not query_dir.exists():
        console.print(f"[red]Query directory not found:[/red] {query_dir}")
        raise typer.Exit(code=1)

    from hecate_runner.slack_bot import deploy_queries_for_hunt

    table = Table(
        title=f"SIEM & EDR Query Deployment for {hunt_id}",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("File")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Remote ID")
    table.add_column("Detail")

    deployments = deploy_queries_for_hunt(
        settings.hecate_workspace,
        hunt_id,
        dry_run=dry_run,
        target=target,
    )
    deployed_count = 0
    for res in deployments:
        status_color = "green" if res.get("ok") else "red"
        table.add_row(
            str(res.get("file", "")),
            str(res.get("target", "")),
            f"[{status_color}]{res.get('status')}[/{status_color}]",
            str(res.get("remote_id") or ""),
            str(res.get("detail", "")),
        )
        if res.get("ok"):
            deployed_count += 1

    console.print(table)
    mode_str = "simulated (dry-run)" if dry_run else "live"
    console.print(f"[bold]{deployed_count}[/bold] query(s) processed in {mode_str} mode.")

    if verbose:
        for res in deployments:
            summary = res.get("request_summary")
            if summary:
                console.print(
                    f"\n[bold cyan]── Contract Payload: {res.get('target')} ({res.get('file')}) ──[/bold cyan]"
                )
                console.print_json(data=summary)


# --- BAS Commands ----------------------------------------------------------
app.command("bas-check")(bas_check_cmd)
app.command("bas-install-procedures")(bas_install_procedures_cmd)
app.command("bas-reset")(bas_reset_cmd)
app.command("bas-detonate")(bas_detonate_cmd)
app.command("bas-verify")(bas_verify_cmd)


def _hunt_paths(settings: Settings, hunt_ids: list[str] | None) -> list[Path]:
    """Resolve hunt IDs to files, or every hunt when none are named."""
    root = settings.hunts_root
    if not hunt_ids:
        return sorted(root.rglob("H-*.md"))
    resolved: list[Path] = []
    for hunt_id in hunt_ids:
        matches = sorted(root.rglob(f"{hunt_id}.md"))
        if not matches:
            console.print(f"[yellow]No file found for {hunt_id}.[/yellow]")
            continue
        resolved.extend(matches)
    return resolved


def _attack_facts(
    hecate: HecateClient, settings: Settings, facts: HuntFacts, text: str
) -> dict[str, TechniqueFact]:
    """Look every technique in the draft up against the live matrix."""
    collected: dict[str, TechniqueFact] = {}
    for technique_id in sorted(set(_DRAFT_TECHNIQUE_RE.findall(text))):
        meta = hecate.lookup_technique(technique_id, timeout_sec=settings.llm_timeout_sec)
        collected[technique_id.upper()] = TechniqueFact(
            valid=meta.found,
            superseded_by=meta.technique_id if meta.superseded_from else "",
            names=tuple(n for n in (meta.name, meta.parent_name) if n),
        )
    return collected


@app.command()
def pending() -> None:
    """List queries awaiting approval."""
    settings = Settings()
    store = PendingQueryStore(settings.pending_queries_dir)
    queries = store.list_all()

    if not queries:
        console.print("[dim]No queries pending approval.[/dim]")
        return

    table = Table(title="Pending queries", show_header=True, header_style="bold cyan")
    table.add_column("Hunt")
    table.add_column("Data source")
    table.add_column("Range")
    table.add_column("Limit")
    table.add_column("Proposed at")
    table.add_column("Query", overflow="fold")
    for q in queries:
        table.add_row(
            q.hunt_id,
            q.data_source,
            f"{q.time_range_days}d",
            str(q.limit),
            q.proposed_at,
            q.query_text,
        )
    console.print(table)


@app.command()
def approve(
    hunt_id: Annotated[str, typer.Argument(help="Hunt whose pending query should be executed")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt")] = False,
) -> None:
    """Execute a previously proposed, guardrail-passed query.

    Re-validates guardrails before executing — defense in depth in case the
    staged file was hand-edited or the configured ceilings changed since
    `propose` ran. This is the one command in hecate-runner that can touch a real
    system when HECATE_RUNNER_QUERY_PROVIDER is set to a real backend; it's the
    deliberate human checkpoint the rest of the pipeline is built around.
    """
    settings = Settings()
    _configure_logging(settings, to_stdout=False)
    store = PendingQueryStore(settings.pending_queries_dir)
    proposed = store.load(hunt_id)

    if proposed is None:
        console.print(
            f"[red]No pending query for {hunt_id}.[/red] Run `hecate-runner pending` to see what's staged."
        )
        raise typer.Exit(code=1)

    violations = validate_guardrails(
        proposed,
        max_time_range_days=settings.max_query_time_range_days,
        max_limit=settings.max_query_limit,
    )
    if violations:
        console.print(
            f"[red]Refusing to execute — {len(violations)} guardrail violation(s) on re-check:[/red]"
        )
        for v in violations:
            console.print(f"  [red]✗[/red] {v}")
        console.print(
            "[dim]Left staged — fix and re-propose, or `hecate-runner reject` to discard.[/dim]"
        )
        raise typer.Exit(code=1)

    console.print(f"[bold]Hunt:[/bold] {proposed.hunt_id}")
    console.print(
        f"[bold]Data source:[/bold] {proposed.data_source} (provider: {settings.query_provider})"
    )
    console.print(f"[bold]Query:[/bold] {proposed.query_text}")
    console.print(
        f"[bold]Time range:[/bold] {proposed.time_range_days}d  [bold]Limit:[/bold] {proposed.limit}"
    )
    if proposed.justification:
        console.print(f"[bold]Justification:[/bold] {proposed.justification}")

    if not yes and not typer.confirm("\nExecute this query?"):
        console.print("[yellow]Cancelled — query remains staged.[/yellow]")
        raise typer.Exit(code=1)

    provider = get_provider(
        settings.query_provider,
        hecate_bin=settings.hecate_bin_resolved,
        workspace=settings.hecate_workspace,
    )
    result = provider.execute(proposed)

    console.print()
    console.print(f"[bold]Outcome:[/bold] {result.outcome}")
    console.print(f"[bold]Provider:[/bold] {result.provider}")
    console.print(f"[bold]Row count:[/bold] {result.row_count}")
    if result.detail:
        console.print(f"[bold]Detail:[/bold] {result.detail[:1000]}")

    if result.ok:
        store.remove(hunt_id)
    else:
        console.print(
            "[dim]Left staged since execution failed — retry with `hecate-runner approve` once fixed.[/dim]"
        )

    raise typer.Exit(code=0 if result.ok else 1)


@app.command()
def reject(
    hunt_id: Annotated[str, typer.Argument(help="Hunt whose pending query should be discarded")],
    reason: Annotated[str | None, typer.Option("--reason", help="Why, for the log")] = None,
) -> None:
    """Discard a proposed query without executing it."""
    settings = Settings()
    store = PendingQueryStore(settings.pending_queries_dir)
    proposed = store.load(hunt_id)

    if proposed is None:
        console.print(f"[red]No pending query for {hunt_id}.[/red]")
        raise typer.Exit(code=1)

    store.remove(hunt_id)
    console.print(
        f"[green]✓[/green] Rejected pending query for {hunt_id}"
        + (f" ({reason})" if reason else "")
    )


_TRAIL_MARKER = f"{TRAIL_LOGGER}: "
_LOG_LINE = re.compile(r"^\d{4}-\d\d-\d\d (\d\d:\d\d:\d\d),\d+ \[(\w+)\] ([\w.]+): (.*)$")


def _watch_line(line: str, show_all: bool) -> str | None:
    """The form of one log line `watch` prints, or None to hide it.

    Trail lines are the point: one per decision. Warnings and errors from any
    logger are shown too, because a stage that fails says so there first, and
    so is Hecate's own INFO output (what it offered the model), which is sparse.
    """
    match = _LOG_LINE.match(line.rstrip("\n"))
    if not match:
        # Continuation lines (tracebacks) belong to the line above them.
        return line.rstrip("\n") if show_all else None
    clock, level, logger_name, message = match.groups()
    if logger_name == TRAIL_LOGGER:
        return f"{clock} {message}"
    if level in {"WARNING", "ERROR", "CRITICAL"}:
        return f"{clock} {level:<7} {logger_name}: {message}"
    if logger_name.startswith("hecate_agent"):
        return f"{clock}   hecate: {message}"
    return f"{clock} {level:<7} {logger_name}: {message}" if show_all else None


@app.command()
def watch(
    lines: Annotated[
        int, typer.Option("--lines", "-n", help="Show this many earlier lines first.")
    ] = 30,
    show_all: Annotated[
        bool, typer.Option("--all", help="Every log line, not just the decision trail.")
    ] = False,
    follow: Annotated[
        bool, typer.Option("--follow/--no-follow", help="Keep printing new lines as they land.")
    ] = True,
) -> None:
    """Follow what the orchestrator is doing, one line per decision.

    Reads the orchestrator log, so it shows cycles started by the systemd timer
    as well as ones run by hand. Ctrl-C to stop.
    """
    import time

    log_file = Settings().log_file
    if not log_file.exists() and not follow:
        console.print(f"[yellow]No log yet at {log_file}[/yellow]")
        raise typer.Exit(code=1)
    while not log_file.exists():
        time.sleep(1)

    handle = log_file.open(encoding="utf-8", errors="replace")
    earlier = [shown for raw in handle if (shown := _watch_line(raw, show_all)) is not None]
    for shown in earlier[-lines:] if lines > 0 else []:
        print(shown)
    if not follow:
        return

    inode = os.fstat(handle.fileno()).st_ino
    try:
        while True:
            raw = handle.readline()
            if raw:
                shown = _watch_line(raw, show_all)
                if shown is not None:
                    print(shown, flush=True)
                continue
            time.sleep(0.5)
            # The log rotates at the start of a cycle; reopen the new file.
            try:
                if os.stat(log_file).st_ino != inode:
                    handle.close()
                    handle = log_file.open(encoding="utf-8", errors="replace")
                    inode = os.fstat(handle.fileno()).st_ino
            except FileNotFoundError:
                continue
    except KeyboardInterrupt:
        pass
    finally:
        handle.close()


@app.command()
def status(
    json_output: Annotated[bool, typer.Option("--json", help="Emit status as JSON.")] = False,
) -> None:
    """Show quota, last run, and total drafts."""
    settings = Settings()
    state = OrchestratorState.load(settings.state_file)
    from hecate_runner.dead_letter import list_dead_letters
    from hecate_runner.parked_store import list_parked

    parked_count = len(list_parked(settings.cti_queue_dir_resolved))
    dead_letter_count = len(list_dead_letters(settings.cti_queue_dir_resolved))

    from hecate_agent.core.llm_provider import CircuitState, get_circuit_breaker

    llm_p = settings.hecate_llm_provider or "default"
    cb = get_circuit_breaker(llm_p)
    if cb.state == CircuitState.OPEN:
        cb_display = f"[bold red]OPEN[/bold red] ({cb.cooldown_remaining:.1f}s cooldown remaining, {cb.failure_count} failures)"
    elif cb.state == CircuitState.HALF_OPEN:
        cb_display = "[bold yellow]HALF_OPEN[/bold yellow] (probing recovery)"
    else:
        cb_display = "[green]CLOSED[/green] (healthy)"

    if json_output:
        data = {
            "version": __version__,
            "hecate_workspace": str(settings.hecate_workspace),
            "cti_provider": settings.cti_provider,
            "cti_queue_dir": str(settings.cti_queue_dir_resolved),
            "model": _effective_model(settings),
            "llm_circuit_breaker": cb.status_dict(),
            "drafts_today": state.drafts_today,
            "max_drafts_per_day": settings.max_drafts_per_day,
            "research_runs_today": state.research_runs_today,
            "max_research_runs_per_day": settings.max_research_runs_per_day,
            "total_drafts_ever": state.total_drafts_ever,
            "last_run": state.last_run_iso,
            "consecutive_failures": state.consecutive_failures,
            "parked_drafts": parked_count,
            "dead_letter_drafts": dead_letter_count,
        }
        typer.echo(json.dumps(data, indent=2))
        return

    table = Table(title="hecate-runner status", show_header=False)
    table.add_column("key", style="cyan")
    table.add_column("value")

    table.add_row("Version", __version__)
    table.add_row("Hecate workspace", str(settings.hecate_workspace))
    table.add_row("CTI provider", settings.cti_provider)
    table.add_row("CTI queue dir", str(settings.cti_queue_dir_resolved))
    table.add_row("Model", _effective_model(settings))
    table.add_row("LLM Circuit Breaker", cb_display)
    table.add_row("Drafts today", f"{state.drafts_today} / {settings.max_drafts_per_day}")
    table.add_row(
        "Research runs today",
        f"{state.research_runs_today} / {settings.max_research_runs_per_day}",
    )
    table.add_row("Total drafts ever", str(state.total_drafts_ever))
    table.add_row("Last run", state.last_run_iso or "(never)")
    table.add_row("Consecutive failures", str(state.consecutive_failures))
    table.add_row("Parked drafts", str(parked_count))
    table.add_row("Dead-letter drafts", str(dead_letter_count))
    console.print(table)


@app.command()
def metrics(
    days: Annotated[
        int,
        typer.Option("--days", min=1, max=3650, help="Lookback window in days (default: 30)"),
    ] = 30,
    source: Annotated[
        str | None,
        typer.Option("--source", help="Filter to one CTI provider, e.g. rss or misp"),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit aggregated metrics as JSON.")
    ] = False,
) -> None:
    """Summarize stage latency and estimated LLM cost by CTI source."""
    settings = Settings()
    rows = MetricsStore(settings.metrics_file).aggregate(days=days, source=source)

    if json_output:
        typer.echo(json.dumps(rows or [], indent=2))
        return

    if not rows:
        console.print("No stage metrics found for that period.")
        return

    table = Table(title=f"Stage metrics, last {days} day(s)")
    table.add_column("Source", style="cyan")
    table.add_column("Stage")
    table.add_column("Cycles", justify="right")
    table.add_column("Avg wall", justify="right")
    table.add_column("LLM calls", justify="right")
    table.add_column("Input tokens", justify="right")
    table.add_column("Output tokens", justify="right")
    table.add_column("Total est.", justify="right")
    table.add_column("Non-ok", justify="right")

    for row in rows:
        cost = row["estimated_cost_usd"]
        avg_seconds = row["avg_duration_ms"] / 1000
        avg_wall = f"{avg_seconds:.1f}s" if avg_seconds < 60 else f"{avg_seconds / 60:.1f}m"
        table.add_row(
            row["source"],
            row["stage"],
            str(row["cycles"]),
            avg_wall,
            "n/a" if row["llm_calls"] is None else str(row["llm_calls"]),
            "n/a" if row["input_tokens"] is None else str(row["input_tokens"]),
            "n/a" if row["output_tokens"] is None else str(row["output_tokens"]),
            "n/a" if cost is None else f"${cost:.6f}",
            str(row["errors"]),
        )
    console.print(table)
    console.print(
        "Estimated cost uses Core's model pricing table; it may differ from provider invoices."
    )


parked_app = typer.Typer(help="Inspect and restore CTI held back by intake triage.")
app.add_typer(parked_app, name="parked")


@parked_app.command("list")
def parked_list() -> None:
    """List CTI held back by triage, newest first."""
    settings = Settings()
    items = list_parked(settings.cti_queue_dir_resolved)
    if not items:
        console.print("Nothing parked.")
        return

    table = Table(title="Parked CTI")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Parked")
    table.add_column("Source")
    table.add_column("Title")
    table.add_column("Why it was held back")
    for item in items:
        table.add_row(
            item.park_id,
            item.parked_at[:16].replace("T", " "),
            item.source,
            (item.title or "(untitled)")[:44],
            item.reason[:52],
        )
    console.print(table)
    console.print(
        f"\n{len(items)} item(s) in {parked_dir(settings.cti_queue_dir_resolved)}. "
        "Restore one with [bold]hecate-runner parked restore <id>[/bold]."
    )


@parked_app.command("show")
def parked_show(
    park_id: Annotated[str, typer.Argument(help="Parked item id, or an unambiguous prefix.")],
) -> None:
    """Print a parked item in full."""
    settings = Settings()
    item = get_parked(settings.cti_queue_dir_resolved, park_id)
    if item is None:
        console.print(f"[red]No parked item matching {park_id!r}.[/red]")
        raise typer.Exit(1)
    console.print(
        f"[bold]{item.park_id}[/bold]  ({item.source}, parked {item.parked_at[:16].replace('T', ' ')})"
    )
    console.print(f"[bold]Held back because:[/bold] {item.reason}")
    if item.source_url:
        console.print(f"[bold]Link:[/bold] {item.source_url}")
    console.print("")
    console.print(item.content)


@parked_app.command("restore")
def parked_restore(
    park_id: Annotated[str, typer.Argument(help="Parked item id, or an unambiguous prefix.")],
) -> None:
    """Put a parked item back on the file queue so a cycle picks it up."""
    settings = Settings()
    item = get_parked(settings.cti_queue_dir_resolved, park_id)
    if item is None:
        console.print(f"[red]No parked item matching {park_id!r}.[/red]")
        raise typer.Exit(1)

    next_file = settings.cti_next_file
    if next_file.exists() and next_file.read_text(encoding="utf-8", errors="replace").strip():
        console.print(
            f"[red]{next_file} already holds CTI.[/red] The file queue takes one item at a "
            "time; restoring now would overwrite it. Let the next cycle consume it first."
        )
        raise typer.Exit(1)

    restore(settings.cti_queue_dir_resolved, item)
    console.print(f"Restored [cyan]{item.park_id}[/cyan] to {next_file}.")

    # The restored item only gets picked up if the file provider is actually
    # in the rotation, which it is not in a default multi-provider setup.
    configured = (
        settings.cti_multi_provider_names
        if settings.cti_provider == "multi"
        else [settings.cti_provider]
    )
    if "file" not in configured:
        console.print(
            "\n[yellow]Note:[/yellow] the file queue is not in your CTI rotation "
            f"(currently: {', '.join(configured)}), so nothing will read it. Add "
            "[bold]file[/bold] to HECATE_RUNNER_CTI_MULTI_PROVIDERS to have the next "
            "cycle pick this up."
        )


dlq_app = typer.Typer(
    help="Inspect and restore poison-pill CTI quarantined in the dead-letter queue."
)
app.add_typer(dlq_app, name="dead-letter")


@dlq_app.command("list")
def dlq_list() -> None:
    """List CTI quarantined in the dead-letter queue."""
    settings = Settings()
    items = list_dead_letters(settings.cti_queue_dir_resolved)
    if not items:
        console.print("No dead-letter items quarantined.")
        return

    table = Table(title="Dead-Letter Queue (Quarantined Poison Pills)")
    table.add_column("ID", style="red", no_wrap=True)
    table.add_column("Quarantined")
    table.add_column("Source")
    table.add_column("Attempts")
    table.add_column("Last Error")
    for item in items:
        table.add_row(
            item.dead_letter_id,
            item.quarantined_at[:16].replace("T", " "),
            item.source,
            str(item.attempts),
            item.last_error[:50],
        )
    console.print(table)
    console.print(
        f"\n{len(items)} item(s) in {dead_letter_dir(settings.cti_queue_dir_resolved)}. "
        "Restore one with [bold]hecate-runner dead-letter restore <id>[/bold]."
    )


@dlq_app.command("show")
def dlq_show(
    dead_letter_id: Annotated[
        str, typer.Argument(help="Dead-letter item id, or an unambiguous prefix.")
    ],
) -> None:
    """Print a quarantined dead-letter item in full."""
    settings = Settings()
    item = get_dead_letter(settings.cti_queue_dir_resolved, dead_letter_id)
    if item is None:
        console.print(f"[red]No dead-letter item matching {dead_letter_id!r}.[/red]")
        raise typer.Exit(1)
    console.print(
        f"[bold red]{item.dead_letter_id}[/bold red]  ({item.source}, quarantined {item.quarantined_at[:16].replace('T', ' ')})"
    )
    console.print(f"[bold]Failed attempts:[/bold] {item.attempts}")
    console.print(f"[bold red]Last error:[/bold red] {item.last_error}")
    if item.source_url:
        console.print(f"[bold]Link:[/bold] {item.source_url}")
    console.print("")
    console.print(item.content)


@dlq_app.command("restore")
def dlq_restore(
    dead_letter_id: Annotated[
        str, typer.Argument(help="Dead-letter item id, or an unambiguous prefix.")
    ],
) -> None:
    """Restore a quarantined item back to next.txt so a cycle picks it up."""
    settings = Settings()
    next_file = settings.cti_next_file
    if next_file.exists() and next_file.read_text(encoding="utf-8", errors="replace").strip():
        console.print(
            f"[red]{next_file} already holds CTI.[/red] Let the next cycle consume it first."
        )
        raise typer.Exit(1)

    restored = restore_dead_letter(settings.cti_queue_dir_resolved, dead_letter_id)
    if not restored:
        console.print(f"[red]No dead-letter item matching {dead_letter_id!r}.[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Restored {dead_letter_id} to {restored}.[/green]")


@dlq_app.command("clear")
def dlq_clear() -> None:
    """Clear all quarantined dead-letter items."""
    settings = Settings()
    count = clear_dead_letters(settings.cti_queue_dir_resolved)
    console.print(f"Cleared {count} dead-letter item(s).")


@app.command()
def reset(
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt.")] = False,
    keep_cursors: Annotated[
        bool,
        typer.Option(
            "--keep-cursors",
            help="Leave CTI cursors alone, so feeds continue where they are instead of re-reading.",
        ),
    ] = False,
    no_archive: Annotated[
        bool, typer.Option("--no-archive", help="Delete without writing an archive first.")
    ] = False,
    archive_dir: Annotated[
        Path | None,
        typer.Option(
            help="Where to write the archive (default: the workspace's parent directory)."
        ),
    ] = None,
) -> None:
    """Reset the workspace to a blank state for a fresh evaluation.

    Archives, then removes: hunts, research, Sigma rules, LangGraph checkpoints,
    quota and run state, CTI cursors, parked and processed CTI, pending query
    proposals and logs. ID counters restart one past the highest ID in git
    history, so no ID is ever reused. Configuration and knowledge are kept.
    """
    from hecate_runner import reset as reset_mod

    settings = Settings()
    running = reset_mod.running_hecate_processes()
    if running:
        console.print("[red]Refusing to reset while hecate is running:[/red]")
        for line in running:
            console.print(f"  {line}")
        raise typer.Exit(1)

    plan = reset_mod.build_plan(settings, keep_cursors=keep_cursors)
    table = Table(title=f"Reset {plan.workspace}", show_header=True)
    table.add_column("What")
    table.add_column("Items", justify="right")
    for group, paths in plan.groups.items():
        table.add_row(group, "kept" if group == "CTI cursors" and keep_cursors else str(len(paths)))
    console.print(table)
    console.print(
        f"Next IDs after reset: [bold]H-{plan.hunt_counter + 1:04d}[/bold], "
        f"[bold]R-{plan.research_counter + 1:04d}[/bold]"
        + ("" if plan.git_repo else " (workspace is not a git repo: numbering restarts)")
    )
    if not keep_cursors:
        console.print(
            "[yellow]Cursors reset:[/yellow] feeds are re-read from their start on the next cycle."
        )
    if not yes and not typer.confirm("Proceed?", default=False):
        console.print("Nothing changed.")
        raise typer.Exit(0)

    # Re-checked: a timer-driven cycle may have started while the prompt was open.
    if reset_mod.running_hecate_processes():
        console.print("[red]A hecate process started meanwhile; nothing changed.[/red]")
        raise typer.Exit(1)
    if plan.paths and not no_archive:
        target = reset_mod.archive(plan, archive_dir or plan.workspace.parent)
        console.print(f"Archived {len(plan.paths)} item(s) to [cyan]{target}[/cyan]")
    reset_mod.execute(plan, settings)
    console.print(
        "[green]Workspace reset.[/green] Run [bold]hecate-runner status[/bold] to confirm."
    )


@app.command()
def config(
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit effective settings as plain JSON.")
    ] = False,
) -> None:
    """Dump effective settings as JSON (safe for pasting into an issue)."""
    settings = Settings()
    dumped = settings.redacted_dict()
    # Add derived paths for clarity
    dumped["_derived"] = {
        "hecate_bin_resolved": str(settings.hecate_bin_resolved),
        "cti_queue_dir_resolved": str(settings.cti_queue_dir_resolved),
        "hunts_root": str(settings.hunts_root),
        "log_file": str(settings.log_file),
        "state_file": str(settings.state_file),
    }
    if json_output:
        typer.echo(json.dumps(dumped, indent=2))
    else:
        console.print_json(json.dumps(dumped))


@app.command(name="dedup")
def dedup(
    path: Annotated[
        Path | None,
        typer.Argument(help="Optional path to query directory or rule file to scan."),
    ] = None,
    check: Annotated[
        Path | None,
        typer.Option("--check", "-c", help="Check candidate Sigma rule against corpus."),
    ] = None,
    threshold: Annotated[
        float,
        typer.Option("--threshold", "-t", help="Overlap similarity threshold (default: 0.5)."),
    ] = 0.5,
    include_overlapping: Annotated[
        bool,
        typer.Option("--include-overlapping", help="Show partial overlaps in results."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit results as plain JSON."),
    ] = False,
) -> None:
    """Analyze Sigma detection rules for duplicates, subsumptions, and redundancies."""
    from hecate_agent.core.sigma_subsumption import (
        SigmaDeduplicator,
        SigmaRuleAST,
        SubsumptionRelation,
    )

    settings = Settings()
    deduplicator = SigmaDeduplicator(overlap_threshold=threshold)

    # Determine paths to search
    search_dirs: list[Path] = []
    if path:
        if path.exists():
            search_dirs.append(path)
        else:
            console.print(f"[yellow]Warning: Specified path '{path}' does not exist.[/yellow]")
    else:
        workspace_queries = settings.hecate_workspace / "queries"
        if workspace_queries.exists() and workspace_queries.is_dir():
            search_dirs.append(workspace_queries)
        public_queries = Path("/home/chemch/betas/Hecate-Public/queries")
        if public_queries.exists() and public_queries.is_dir():
            search_dirs.append(public_queries)

    corpus_rules: list[SigmaRuleAST] = []
    seen: set[str] = set()
    for d in search_dirs:
        if d.is_file():
            try:
                corpus_rules.append(SigmaRuleAST.from_yaml_file(d))
            except Exception as e:
                console.print(f"[red]Error loading {d}: {e}[/red]")
        elif d.is_dir():
            for r in deduplicator.load_rules_from_directory(d):
                if r.file_path and r.file_path not in seen:
                    seen.add(r.file_path)
                    corpus_rules.append(r)

    # Branch 1: Checking candidate rule
    if check:
        if not check.exists():
            console.print(f"[red]Candidate file '{check}' does not exist.[/red]")
            raise typer.Exit(code=1)
        try:
            cand = SigmaRuleAST.from_yaml_file(check)
        except Exception as e:
            console.print(f"[red]Error parsing candidate rule {check}: {e}[/red]")
            raise typer.Exit(code=1) from e

        internal_issues = deduplicator.audit_internal_redundancy(cand)
        matches = deduplicator.check_candidate(cand, corpus_rules)

        if json_output:
            typer.echo(
                json.dumps(
                    {
                        "candidate": {"id": cand.id, "title": cand.title, "file": str(check)},
                        "internal_issues": internal_issues,
                        "matches": [m.to_dict() for m in matches],
                    },
                    indent=2,
                )
            )
            return

        console.print(
            Panel(
                f"[bold]Candidate Rule:[/bold] {cand.title}\n"
                f"[dim]ID:[/dim] {cand.id or 'None'} | [dim]Category:[/dim] {cand.category}\n"
                f"[dim]File:[/dim] {check}",
                title="🔍 [bold cyan]Sigma Rule Subsumption Check[/bold cyan]",
                border_style="cyan",
            )
        )
        if internal_issues:
            console.print("\n[bold yellow]⚠️ Internal Redundancies in Candidate Rule:[/bold yellow]")
            for iss in internal_issues:
                console.print(f"  • [yellow]{iss}[/yellow]")

        if not matches:
            console.print(
                "\n[bold green]✅ No duplicates or subsumptions found.[/bold green] Rule provides novel coverage."
            )
            return

        table = Table(title=f"Corpus Match Diagnostics ({len(matches)} matches)")
        table.add_column("Relation", style="bold")
        table.add_column("Existing Rule")
        table.add_column("Score", justify="right")
        table.add_column("Explanation")
        for m in matches:
            style = "green"
            if m.relation == SubsumptionRelation.EQUIVALENT:
                style = "bold red"
            elif m.relation in (SubsumptionRelation.SUBSUMES, SubsumptionRelation.SUBSUMED_BY):
                style = "bold yellow"
            elif m.relation == SubsumptionRelation.OVERLAPPING:
                style = "cyan"
            table.add_row(
                f"[{style}]{m.relation.value}[/{style}]",
                m.rule_b_title,
                f"{m.overlap_score:.0%}",
                m.explanation,
            )
        console.print(table)
        return

    # Branch 2: Corpus Analysis
    if not corpus_rules:
        console.print("[yellow]No Sigma rules found in workspace or public queries.[/yellow]")
        return

    report = deduplicator.analyze_corpus(corpus_rules, include_overlaps=include_overlapping)
    if json_output:
        typer.echo(report.to_json(indent=2))
        return

    console.print(
        Panel(
            f"[bold]Total Rules Scanned:[/bold] {report.total_rules}\n"
            f"[bold red]Duplicates (Equivalent):[/bold red] {len(report.duplicates)}\n"
            f"[bold yellow]Subsumptions (Broader/Narrower):[/bold yellow] {len(report.subsumptions)}\n"
            f"[bold cyan]Overlaps:[/bold cyan] {len(report.overlaps)}\n"
            f"[bold magenta]Internal Redundancies:[/bold magenta] {sum(len(v) for v in report.internal_redundancies.values())}",
            title="📊 [bold green]Sigma Deduplication & Subsumption Summary[/bold green]",
            border_style="green" if not report.has_issues else "yellow",
        )
    )

    if report.subsumptions:
        sub_tbl = Table(
            title=f"Subsumption Hierarchies ({len(report.subsumptions)})", border_style="yellow"
        )
        sub_tbl.add_column("Relation", style="bold yellow")
        sub_tbl.add_column("Broader Rule")
        sub_tbl.add_column("Narrower / Redundant Rule")
        sub_tbl.add_column("Explanation")
        for s in report.subsumptions:
            sub_tbl.add_row(s.relation.value, s.rule_a_title, s.rule_b_title, s.explanation)
        console.print(sub_tbl)

    if not report.has_issues and not (include_overlapping and report.overlaps):
        console.print(
            "\n[bold green]✅ Clean corpus: No duplicates, redundant subsumptions, or internal dead code detected.[/bold green]"
        )


@app.command(name="export-layer")
def export_layer_cmd(
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output JSON file path (default: stdout)."),
    ] = None,
    name: Annotated[
        str,
        typer.Option("--name", help="Layer title in ATT&CK Navigator."),
    ] = "Hecate Detection Coverage",
    score_by: Annotated[
        str,
        typer.Option("--score-by", help="Scoring metric: 'hunts', 'queries', or 'binary'."),
    ] = "hunts",
    tactic: Annotated[
        str | None,
        typer.Option("--tactic", help="Filter by specific ATT&CK tactic."),
    ] = None,
    platform: Annotated[
        str | None,
        typer.Option("--platform", help="Filter by platform (e.g. Windows, Linux)."),
    ] = None,
    include_uncovered: Annotated[
        bool,
        typer.Option("--include-uncovered", help="Include all techniques with score 0."),
    ] = False,
    hunts_dir: Annotated[
        Path | None,
        typer.Option("--hunts-dir", help="Custom hunts directory."),
    ] = None,
    queries_dir: Annotated[
        Path | None,
        typer.Option("--queries-dir", help="Custom queries directory."),
    ] = None,
) -> None:
    """Export MITRE ATT&CK Navigator JSON layer from hunts and queries."""
    from hecate_agent.core.attack_navigator import NavigatorExporter

    settings = Settings()
    h_dir = hunts_dir or settings.hunts_root
    q_dir = queries_dir or (settings.hecate_workspace / "queries")

    exporter = NavigatorExporter(hunts_dir=h_dir, queries_dir=q_dir)
    layer_dict = exporter.build_layer(
        name=name,
        score_by=score_by,
        tactic_filter=tactic,
        platform_filter=platform,
        include_uncovered=include_uncovered,
    )

    if output:
        out = exporter.export_to_file(output, layer_dict=layer_dict)
        console.print(f"[green]✓ Exported ATT&CK Navigator layer to:[/green] {out}")
        console.print(f"[dim]Techniques included: {len(layer_dict.get('techniques', []))}[/dim]")
    else:
        typer.echo(json.dumps(layer_dict, indent=2))


app.command(name="layer")(export_layer_cmd)


# --- Slack Commands & Digests ----------------------------------------------
app.command(name="slack-channels")(slack_channels)
app.command(name="slack-test")(slack_test)
app.command(name="ops-digest")(ops_digest)
app.command(name="setup-slack-channels")(setup_slack_channels)
app.command(name="daily-digest")(daily_digest)
app.command(name="slack-bot")(slack_bot_cmd)


# --- Doctor Diagnostics ----------------------------------------------------
app.command(name="doctor")(doctor)


# --- Sources and MISP Sub-apps ---------------------------------------------
app.add_typer(sources_app, name="sources")
app.add_typer(misp_app, name="misp")


if __name__ == "__main__":
    app()
