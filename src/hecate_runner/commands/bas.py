"""BAS (Breach and Attack Simulation) CLI commands."""

from __future__ import annotations

import sys
from typing import Annotated

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
    """Audit the lab environment, terminate lingering child processes, and clear quarantine."""
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

    try:
        result = provider.detonate(req)
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
    write_back: Annotated[
        bool,
        typer.Option(
            "--write-back/--no-write-back",
            help="Write verification result into hunt markdown frontmatter and body.",
        ),
    ] = True,
) -> None:
    """Run closed-loop live adversary emulation & detection verification against a hunt draft."""
    import yaml

    from hecate_runner.bas import (
        DetonationRequest,
        DetonationTarget,
        get_bas_provider,
        normalize_platform,
    )
    from hecate_runner.bas.verifier import DetectionVerifier

    settings = _get_settings()
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
    if not techniques:
        console.print(
            f"[bold yellow]Hunt {hunt_id} has no mapped ATT&CK techniques in frontmatter.[/bold yellow]"
        )
        raise typer.Exit(code=1)

    technique_id = str(techniques[0])
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

    # Find candidate Sigma rule file
    query_dir = settings.hecate_workspace / "queries" / hunt_id
    sigma_files = sorted(query_dir.glob("*.yml")) + sorted(query_dir.glob("*.yaml"))
    sigma_yaml = ""
    if sigma_files:
        sigma_yaml = sigma_files[0].read_text(encoding="utf-8")

    det_req = DetonationRequest(
        hunt_id=hunt_id,
        technique_id=technique_id,
        platform=norm_platform,
        target=target,
        timeout_sec=60,
    )

    console.print(
        f"[bold cyan]Running BAS verification for {hunt_id}[/bold cyan] against technique [bold]{technique_id}[/bold] "
        f"using [bold]{resolved_provider.upper()}[/bold] on {target.environment}..."
    )

    try:
        det_result = provider.detonate(det_req)
    except Exception as exc:
        console.print(f"[bold red]Detonation failed with exception:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    verifier = DetectionVerifier()
    res = verifier.verify_detonation(
        detonation=det_result,
        rule_yaml=sigma_yaml,
    )

    table = Table(
        title=f"BAS Verification Results: {hunt_id}",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Property")
    table.add_column("Value")

    table.add_row("Status", f"[bold]{res.status.value.upper()}[/bold]")
    table.add_row("Provider", res.provider.upper())
    table.add_row("Technique", res.technique_id)
    table.add_row("Telemetry Arrived", f"{'Yes' if res.telemetry_arrived else 'No'}")
    table.add_row(
        "Rule Triggered",
        f"{'Yes' if res.rule_triggered else 'No'} ({res.matched_events_count} hits)",
    )
    table.add_row("Time Window", f"{res.window_start_utc} to {res.window_end_utc}")
    table.add_row("Duration", f"{det_result.duration_seconds:.2f}s")
    if res.notes:
        table.add_row("Notes", "; ".join(res.notes))

    console.print(table)

    if write_back:
        fm["bas_verified"] = res.status.value == "verified_true_positive"
        fm["bas_provider"] = res.provider
        fm["bas_status"] = res.status.value
        fm["bas_detection_triggered"] = res.rule_triggered
        new_fm = yaml.safe_dump(fm, sort_keys=False)
        updated_content = f"---\n{new_fm}---\n" + fm_parts[2].lstrip()
        atomic_write_text(hunt_file, updated_content)
        console.print(
            f"[bold green]Updated hunt draft frontmatter in[/bold green] {hunt_file.name}"
        )
