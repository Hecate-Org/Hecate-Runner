"""BAS (Breach and Attack Simulation) CLI commands."""

from __future__ import annotations

import sys
import time
from contextlib import nullcontext
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.config import Settings

console = Console()


def _get_settings() -> Settings:
    cli_mod = sys.modules.get("hecate_runner.cli")
    if cli_mod and hasattr(cli_mod, "Settings"):
        settings_factory = cli_mod.Settings
        instance = settings_factory()
        if isinstance(instance, Settings):
            return instance
    return Settings()


def bas_check_cmd() -> None:
    """Check approved lab procedures against real process events; save local BAS metrics."""
    from hecate_runner.bas.approved import APPROVED_PROCEDURES
    from hecate_runner.bas.runtime import run_approved_validation

    settings = _get_settings()
    procedures = [
        APPROVED_PROCEDURES[t] for t in settings.bas_auto_techniques if t in APPROVED_PROCEDURES
    ]
    if not procedures:
        console.print(
            "[red]Configure HECATE_BAS_AUTO_TECHNIQUES with reviewed procedures first.[/red]"
        )
        raise typer.Exit(code=1)
    failed = False
    for procedure in procedures:
        import shlex

        import yaml

        rule = yaml.safe_dump(
            {
                "title": "BAS Lab Process Sensor Control",
                "status": "test",
                "logsource": {"product": "linux", "category": "process_creation"},
                "tags": ["attack." + procedure.technique_id.lower()],
                "detection": {
                    "selection": {
                        "Image|endswith": "/" + procedure.argv[0],
                        "CommandLine": shlex.join(procedure.argv),
                    },
                    "condition": "selection",
                },
            }
        )
        result = run_approved_validation(settings, "LAB-CHECK", procedure, rule)
        console.print(f"{procedure.technique_id} ({procedure.command}): {result['status']}")
        if result.get("reason"):
            console.print(result["reason"])
        failed |= result["status"] != "verified_true_positive"
    console.print(
        "Scope: independent local process sensor + Sigma evaluation; no SIEM alert claimed."
    )
    if failed:
        raise typer.Exit(code=1)


def bas_install_procedures_cmd() -> None:
    """Install missing catalog-managed abilities; refuse to overwrite altered content."""
    from hecate_runner.bas import CalderaConnector, get_bas_provider
    from hecate_runner.bas.approved import (
        APPROVED_PROCEDURES,
        ability_definition,
        validate_approved_ability,
    )

    settings = _get_settings()
    provider = get_bas_provider("caldera", settings)
    assert isinstance(provider, CalderaConnector)
    with provider._get_client() as client:
        existing = client.get("/api/abilities")
        existing.raise_for_status()
        catalog = {a["ability_id"]: a for a in existing.json()}
        # Validate all existing procedures before making any writes.
        for procedure in APPROVED_PROCEDURES.values():
            if procedure.ability_id in catalog:
                validate_approved_ability(catalog[procedure.ability_id], procedure)
            elif not procedure.managed:
                raise typer.BadParameter(
                    f"Required stock ability missing: {procedure.technique_id}"
                )
        for procedure in APPROVED_PROCEDURES.values():
            if procedure.ability_id not in catalog:
                response = client.put(
                    "/api/rest", json={"index": "abilities", **ability_definition(procedure)}
                )
                response.raise_for_status()
                console.print(f"Installed fixed procedure {procedure.technique_id}")
        final = client.get("/api/abilities")
        final.raise_for_status()
        installed = {a["ability_id"]: a for a in final.json()}
        for procedure in APPROVED_PROCEDURES.values():
            validate_approved_ability(installed[procedure.ability_id], procedure)
    console.print(f"Verified {len(APPROVED_PROCEDURES)} pinned lab procedures.")


def bas_reset_cmd(
    note: Annotated[
        str,
        typer.Option("--note", "-n", help="Operator note explaining the reason for reset."),
    ] = "Audited reset via CLI",
) -> None:
    """Audit lab cleanup and clear quarantine only if the lab is clean."""
    from hecate_runner.bas.lifecycle import reset_lab

    settings = _get_settings()
    try:
        summary = reset_lab(
            container_name=settings.bas_sensor_container,
            operator_note=note,
            workspace=settings.hecate_workspace,
        )
    except Exception as exc:
        console.print(f"[bold red]Reset failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print("[bold green]BAS Lab Reset & Audit Complete[/bold green]")
    if summary.get("prior_quarantine"):
        console.print(
            f"Cleared prior quarantine: [yellow]{summary['prior_quarantine'].get('reason')}[/yellow]"
        )
    if summary.get("lingering_processes_found"):
        console.print(
            f"[yellow]Lingering processes detected and audited:[/yellow] {summary['lingering_processes_found']}"
        )
    else:
        console.print("[green]No unauthorized lingering processes found.[/green]")
    if summary.get("lingering_files_found"):
        console.print(
            f"[yellow]Lingering tmpfs files purged:[/yellow] {summary.get('files_purged', summary['lingering_files_found'])}"
        )
    else:
        console.print("[green]No unauthorized lingering tmpfs files found.[/green]")


def bas_detonate_cmd(
    technique_id: Annotated[
        str,
        typer.Argument(help="MITRE ATT&CK Technique ID (e.g. T1059.001, T1562.008)."),
    ],
    hunt_id: Annotated[
        str,
        typer.Option("--hunt-id", help="Hunt ID to associate with detonation."),
    ] = "H-DETONATE",
    provider_name: Annotated[
        str,
        typer.Option("--provider", "-p", help="BAS Provider: caldera, stratus, or mock."),
    ] = "mock",
    environment: Annotated[
        str,
        typer.Option("--env", "-e", help="Detonation environment (lab or staging)."),
    ] = "lab",
    host: Annotated[
        str | None,
        typer.Option("--host", "-h", help="Target agent/host allowlisted for detonation."),
    ] = None,
    account_id: Annotated[
        str | None,
        typer.Option(
            "--account-id", "-a", help="Target cloud account ID allowlisted for detonation."
        ),
    ] = None,
    platform: Annotated[
        str,
        typer.Option(
            "--platform", help="Target platform (linux, windows, darwin, aws, azure, gcp, k8s)."
        ),
    ] = "linux",
    timeout: Annotated[
        int,
        typer.Option("--timeout", "-t", help="Timeout in seconds."),
    ] = 60,
    verify_siem: Annotated[
        bool,
        typer.Option(
            "--verify-siem/--no-verify-siem",
            help="Verify live SIEM alert firing and measure True Positive detection latency.",
        ),
    ] = True,
    siem_target: Annotated[
        str,
        typer.Option("--siem-target", help="Target SIEM platform for live verification (splunk, mock)."),
    ] = "splunk",
    siem_query: Annotated[
        str | None,
        typer.Option(
            "--siem-query",
            help="Explicit SPL query to verify in SIEM (overrides heuristic or query file lookup).",
        ),
    ] = None,
) -> None:
    """Execute on-demand adversary emulation via MITRE CALDERA, Stratus Red Team, or Mock."""
    from rich.syntax import Syntax

    from hecate_runner.bas import (
        DetonationRequest,
        DetonationTarget,
        get_bas_provider,
        normalize_platform,
    )

    settings = _get_settings()
    target_host = host or (
        settings.bas_allowed_hosts[0] if settings.bas_allowed_hosts else "lab-host"
    )
    target_account = account_id or (
        settings.bas_allowed_accounts[0] if settings.bas_allowed_accounts else None
    )
    norm_platform = normalize_platform(platform)

    try:
        target = DetonationTarget(
            environment=environment,
            platform=norm_platform,
            host=target_host if not account_id else None,
            cloud_account=target_account if account_id else None,
        )
        provider = get_bas_provider(provider_name, settings)
    except Exception as exc:
        console.print(f"[bold red]Configuration / Safety Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    req = DetonationRequest(
        hunt_id=hunt_id,
        technique_id=technique_id,
        platform=norm_platform,
        target=target,
        timeout_sec=timeout,
    )

    lease = None
    if target.environment == "lab":
        from hecate_runner.bas.lifecycle import LabLease

        root = settings.hecate_workspace / ".hecate" / "bas"
        lease = LabLease(
            lease_path=root / "lab.lease",
            quarantine_path=root / "lab.quarantine",
            lock_path=root / "execution.lock",
        )
        try:
            lease.check_quarantine()
        except Exception as exc:
            console.print(f"[bold red]Safety Error:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc

    console.print(
        f"[bold cyan]Detonating technique {technique_id}[/bold cyan] via "
        f"[bold]{provider_name.upper()}[/bold] on {target.environment} ({target.host or target.cloud_account or 'local'})..."
    )

    import time

    t0_detonate = time.perf_counter()
    try:
        with lease.acquire(hunt_id, timeout_sec=timeout) if lease else nullcontext():
            result = provider.detonate(req)
            if lease and not result.cleanup_success:
                lease.quarantine("Manual BAS cleanup was not confirmed.", hunt_id)
    except Exception as exc:
        console.print(f"[bold red]Detonation failed with exception:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    status_color = "green" if result.success else "red"
    console.print(
        f"Status: [{status_color}]{result.stage.value.upper()}[/{status_color}] ({result.duration_seconds:.2f}s)"
    )
    if result.ability_id:
        console.print(f"Adversary/Ability ID: [bold]{result.ability_id}[/bold]")
    if result.error_message:
        console.print(f"[bold red]Error Message:[/bold red] {result.error_message}")
    if result.stdout:
        console.print(Panel(Syntax(result.stdout, "text", theme="monokai"), title="stdout"))
    if result.stderr:
        console.print(Panel(Syntax(result.stderr, "text", theme="monokai"), title="stderr"))
    if result.telemetry_signatures:
        console.print(
            f"[dim]Generated {len(result.telemetry_signatures)} raw telemetry events.[/dim]"
        )

    # Closed-Loop Detection Validation: Query SIEM search jobs API
    if verify_siem and result.success:
        from hecate_runner.bas.siem_verifier import SiemAlertVerifier

        console.print(
            f"\n[bold cyan]Closed-Loop Detection Validation: Querying {siem_target.upper()} Search Jobs API...[/bold cyan]"
        )
        siem_verifier = SiemAlertVerifier(settings.hecate_workspace)
        siem_res = siem_verifier.verify_detonation_alert(
            detonation=result,
            hunt_id=hunt_id,
            candidate_query=siem_query,
            siem_target=siem_target,
            t0_detonate=t0_detonate,
        )

        siem_table = Table(
            title=f"Closed-Loop SIEM Alert Verification: {hunt_id}",
            show_header=True,
            header_style="bold cyan",
        )
        siem_table.add_column("Metric / Property", style="bold")
        siem_table.add_column("Value")

        status_style = (
            "bold green"
            if siem_res.rule_triggered
            else ("bold yellow" if siem_res.telemetry_arrived else "bold red")
        )
        siem_table.add_row(
            "SIEM Alert Status", f"[{status_style}]{siem_res.status.upper()}[/{status_style}]"
        )
        siem_table.add_row("SIEM Backend", siem_res.siem_backend.upper())
        if siem_res.search_job_id:
            siem_table.add_row("Search Job ID", siem_res.search_job_id)
        if siem_res.detection_latency_sec is not None:
            latency_ms = siem_res.detection_latency_sec * 1000.0
            siem_table.add_row(
                "True Positive Detection Latency",
                f"[bold bright_green]{siem_res.detection_latency_sec:.3f}s ({latency_ms:.0f} ms)[/bold bright_green]",
            )
        siem_table.add_row("Alert Fired / Matched Hits", f"{siem_res.matched_events_count} hit(s)")
        siem_table.add_row("SPL Query Evaluated", siem_res.query_used)
        if siem_res.notes:
            siem_table.add_row("Verification Notes", "; ".join(siem_res.notes))

        console.print(siem_table)
    if not result.success or not result.cleanup_success:
        raise typer.Exit(code=1)


def bas_verify_cmd(
    hunt_id: Annotated[
        str,
        typer.Argument(help="Hunt ID (e.g. H-0868) to verify detection fidelity for."),
    ],
    provider_name: Annotated[
        str,
        typer.Option(
            "--provider",
            "-p",
            help="BAS Provider: caldera, stratus, or mock (defaults to settings.bas_mode).",
        ),
    ] = "",
    environment: Annotated[
        str,
        typer.Option("--env", "-e", help="Detonation environment (lab or staging)."),
    ] = "lab",
    host: Annotated[
        str | None,
        typer.Option("--host", "-h", help="Target host (must be allowlisted)."),
    ] = None,
    account_id: Annotated[
        str | None,
        typer.Option("--account-id", "-a", help="Target cloud account ID (must be allowlisted)."),
    ] = None,
    technique: Annotated[
        str | None,
        typer.Option("--technique", "-t", help="Specific ATT&CK Technique ID to verify."),
    ] = None,
    use_siem: Annotated[
        bool,
        typer.Option(
            "--siem/--no-siem", help="Verify against live SIEM (e.g. Splunk) query provider."
        ),
    ] = True,
    write_back: Annotated[
        bool,
        typer.Option(
            "--write-back/--no-write-back",
            help="Write verification result into hunt markdown frontmatter and body.",
        ),
    ] = True,
) -> None:
    """Run closed-loop live adversary emulation & detection verification against a hunt draft."""
    import os
    import shlex

    import yaml

    from hecate_runner.bas import (
        DetonationRequest,
        DetonationTarget,
        get_bas_provider,
        normalize_platform,
    )
    from hecate_runner.bas.approved import APPROVED_PROCEDURES
    from hecate_runner.bas.verifier import DetectionVerifier

    settings = _get_settings()
    try:
        from dotenv import load_dotenv

        load_dotenv(override=False)
        load_dotenv(settings.hecate_workspace / ".env", override=False)
    except ImportError:
        pass

    resolved_provider = provider_name or getattr(settings, "bas_mode", "mock")

    # Locate hunt markdown
    root = settings.hunts_root
    matches = sorted(root.rglob(f"{hunt_id}.md"))
    if not matches:
        console.print(f"[bold red]No hunt file found for {hunt_id}[/bold red] in {root}")
        raise typer.Exit(code=1)

    hunt_file = matches[0]
    content = hunt_file.read_text(encoding="utf-8")

    # Parse frontmatter
    fm_parts = content.split("---", 2)
    if len(fm_parts) < 3:
        console.print("[bold red]Invalid hunt format: frontmatter missing or malformed.[/bold red]")
        raise typer.Exit(code=1)

    try:
        fm = yaml.safe_load(fm_parts[1]) or {}
    except Exception as exc:
        console.print(f"[bold red]Frontmatter parse error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    techniques = fm.get("techniques") or []
    if isinstance(techniques, str):
        techniques = [techniques]
    if not techniques and not technique:
        console.print(
            f"[bold yellow]Hunt {hunt_id} has no mapped ATT&CK techniques in frontmatter.[/bold yellow]"
        )
        raise typer.Exit(code=1)

    if technique:
        technique_id = technique.upper()
    else:
        # Prefer a technique from the hunt that has an approved lab procedure
        approved_match = next((t for t in techniques if t in APPROVED_PROCEDURES), None)
        technique_id = (
            approved_match if approved_match else (str(techniques[0]) if techniques else "T1033")
        )

    proc = APPROVED_PROCEDURES.get(technique_id)

    platforms = fm.get("platform") or []
    if isinstance(platforms, str):
        platforms = [platforms]
    platforms_lower = {str(p).strip().lower() for p in platforms if str(p).strip()}
    is_cloud = any(p in ("cloud", "aws", "gcp", "azure", "k8s", "iaas") for p in platforms_lower)
    target_platform = (
        "aws" if is_cloud else (next(iter(platforms_lower)) if platforms_lower else "linux")
    )
    norm_platform = normalize_platform(target_platform)

    target_host = host or (
        settings.bas_allowed_hosts[0] if settings.bas_allowed_hosts else "lab-host"
    )
    target_account = account_id or (
        settings.bas_allowed_accounts[0] if (settings.bas_allowed_accounts and is_cloud) else None
    )

    try:
        target = DetonationTarget(
            environment=environment,
            platform=norm_platform,
            host=target_host if not is_cloud else None,
            cloud_account=target_account if is_cloud else None,
        )
        provider = get_bas_provider(resolved_provider, settings)
    except Exception as exc:
        console.print(f"[bold red]Provider / Safety Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    # Find candidate Sigma rule file and SIEM query
    sigma_yaml = ""
    candidate_query = None

    # If an approved procedure is used, formulate rule and SPL query
    if proc:
        rule_def = {
            "title": f"BAS Detection Verification: {proc.command}",
            "status": "test",
            "logsource": {"product": "linux", "category": "process_creation"},
            "tags": ["attack." + proc.technique_id.lower()],
            "detection": {
                "selection": {
                    "Image|endswith": "/" + proc.argv[0],
                    "CommandLine": shlex.join(proc.argv),
                },
                "condition": "selection",
            },
        }
        sigma_yaml = yaml.safe_dump(rule_def)
        candidate_query = f'Image="*/{proc.argv[0]}" CommandLine="{shlex.join(proc.argv)}"'
    else:
        from hecate_runner.bas.siem_verifier import SiemAlertVerifier

        candidate_query, _, resolved_yaml = SiemAlertVerifier(
            settings.hecate_workspace
        ).resolve_candidate_rule(hunt_id, technique_id)
        if resolved_yaml:
            sigma_yaml = resolved_yaml
        else:
            query_dir = settings.hecate_workspace / "queries" / hunt_id
            sigma_files = sorted(query_dir.glob("*.yml")) + sorted(query_dir.glob("*.yaml"))
            if sigma_files:
                sigma_yaml = sigma_files[0].read_text(encoding="utf-8")

    siem_provider = None
    if use_siem:
        splunk_host = os.getenv("SPLUNK_HOST") or os.getenv("SPLUNK_URL")
        if splunk_host or settings.query_provider == "splunk":
            from hecate_runner.query_execution import SplunkQueryProvider

            siem_provider = SplunkQueryProvider(settings.hecate_bin, settings.hecate_workspace)

    det_req = DetonationRequest(
        hunt_id=hunt_id,
        technique_id=technique_id,
        ability_id=proc.ability_id if proc else None,
        platform=norm_platform,
        target=target,
        timeout_sec=120 if proc else 60,
    )

    console.print(
        f"[bold cyan]Running BAS verification for {hunt_id}[/bold cyan] against technique [bold]{technique_id}[/bold] "
        f"using [bold]{resolved_provider.upper()}[/bold] on {target.environment}..."
    )
    if candidate_query and siem_provider:
        console.print(
            f"[cyan]Candidate SIEM Query ({siem_provider.name}):[/cyan] {candidate_query}"
        )

    sensor = None
    if resolved_provider == "caldera" and target.environment == "lab" and norm_platform == "linux":
        from hecate_runner.bas.sensor import LabProcessSensor

        try:
            sensor = LabProcessSensor(settings.bas_sensor_container, settings.bas_linux_host)
            sensor.preflight()
        except Exception as sensor_exc:
            console.print(f"[yellow]Sensor preflight notice: {sensor_exc}[/yellow]")
            sensor = None

    t0_detonate = time.perf_counter()
    try:
        det_result = provider.detonate(det_req)
    except Exception as exc:
        console.print(f"[bold red]Detonation failed with exception:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    raw_events: list[dict[str, Any]] = []
    if sensor and det_result.success:
        if proc:
            if hasattr(sensor, "collect_fused"):
                raw_events = sensor.collect_fused(
                    det_result, proc.argv, expected_files=proc.expected_files
                )
            else:
                raw_events = sensor.collect(det_result, proc.argv)
        else:
            raw_events = det_result.telemetry_signatures
    else:
        raw_events = det_result.telemetry_signatures

    verifier = DetectionVerifier(
        query_provider=siem_provider, max_wait_sec=30, workspace=settings.hecate_workspace
    )
    res = verifier.verify_detonation(
        detonation=det_result,
        rule_yaml=sigma_yaml,
        candidate_query=candidate_query,
        backend=siem_provider.name if siem_provider else "mock",
        raw_events=raw_events,
        t0_detonate=t0_detonate,
    )

    siem_latency_sec = res.detection_latency_sec
    siem_job_sid = res.search_job_id

    # If SIEM verification requested and live Splunk configured, run search jobs validation
    if use_siem and (siem_provider or os.getenv("SPLUNK_HOST")):
        from hecate_runner.bas.siem_verifier import SiemAlertVerifier

        siem_verifier = SiemAlertVerifier(settings.hecate_workspace)
        siem_res = siem_verifier.verify_detonation_alert(
            detonation=det_result,
            hunt_id=hunt_id,
            candidate_query=candidate_query,
            siem_target=siem_provider.name if siem_provider else "splunk",
            t0_detonate=t0_detonate,
        )
        siem_latency_sec = siem_res.detection_latency_sec
        siem_job_sid = siem_res.search_job_id
        if siem_res.rule_triggered:
            from hecate_runner.bas.verifier import VerificationStatus

            res.rule_triggered = True
            res.status = VerificationStatus.VERIFIED_TRUE_POSITIVE
            res.matched_events_count = siem_res.matched_events_count
            res.detection_latency_sec = siem_res.detection_latency_sec
            res.search_job_id = siem_res.search_job_id
            res.backend = siem_res.siem_backend
            for n in siem_res.notes:
                if n not in res.notes:
                    res.notes.append(n)

    table = Table(
        title=f"BAS Verification Results: {hunt_id}",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Property")
    table.add_column("Value")

    table.add_row("Status", f"[bold]{res.status.value.upper()}[/bold]")
    table.add_row("BAS Provider", res.provider.upper())
    table.add_row("Technique", res.technique_id)
    table.add_row("Telemetry Arrived", f"{'Yes' if res.telemetry_arrived else 'No'}")
    table.add_row(
        "Rule Triggered",
        f"{'Yes' if res.rule_triggered else 'No'} ({res.matched_events_count} hits)",
    )
    if siem_provider or res.backend:
        table.add_row("SIEM Backend", res.backend.upper())
    if siem_job_sid:
        table.add_row("Search Job ID", siem_job_sid)
    if siem_latency_sec is not None:
        latency_ms = siem_latency_sec * 1000.0
        table.add_row(
            "True Positive Detection Latency",
            f"[bold bright_green]{siem_latency_sec:.3f}s ({latency_ms:.0f} ms)[/bold bright_green]",
        )
    if candidate_query:
        table.add_row("Query Tested", candidate_query)
    table.add_row("Time Window", f"{res.window_start_utc} to {res.window_end_utc}")
    table.add_row("Duration", f"{det_result.duration_seconds:.2f}s")
    if res.notes:
        table.add_row("Notes", "; ".join(res.notes))

    console.print(table)

    if write_back:
        fm["bas_verified"] = res.status.value == "verified_true_positive"
        fm["bas_provider"] = res.provider
        fm["bas_status"] = res.status.value
        fm["bas_backend"] = res.backend
        fm["bas_detection_triggered"] = res.rule_triggered
        if siem_latency_sec is not None:
            fm["bas_detection_latency_sec"] = round(siem_latency_sec, 3)
        if siem_job_sid:
            fm["bas_search_job_id"] = siem_job_sid
        fm["bas_siem_alert_fired"] = res.rule_triggered
        new_fm = yaml.safe_dump(fm, sort_keys=False)
        updated_content = f"---\n{new_fm}---\n" + fm_parts[2].lstrip()
        atomic_write_text(hunt_file, updated_content)
        console.print(
            f"[bold green]Updated hunt draft frontmatter in[/bold green] {hunt_file.name}"
        )
