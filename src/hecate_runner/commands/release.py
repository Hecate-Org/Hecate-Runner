"""Local community catalog checks, isolated lab controls, and release builds."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from hecate_runner.community_release import build_release, verify_catalog
from hecate_runner.config import Settings

release_app = typer.Typer(help="Prepare an explicit community catalog; nothing is published.")
console = Console()


@release_app.command("build")
def release_build(
    catalog: Annotated[
        Path, typer.Option(help="Public repository containing catalog/catalog.yaml.")
    ],
    output: Annotated[Path, typer.Option(help="New private build directory.")],
    evidence: Annotated[
        Path | None, typer.Option(help="Optional sanitized lab report for this catalog.")
    ] = None,
) -> None:
    try:
        result = build_release(catalog, output, settings=Settings(), evidence=evidence)
        console.print_json(json.dumps(result))
        console.print("Built locally. Review the index and archive before authorizing publication.")
    except Exception as exc:
        console.print(f"[red]Release build refused:[/red] {exc}")
        raise typer.Exit(code=1) from exc


@release_app.command("verify")
def release_verify(
    catalog: Annotated[Path, typer.Option(help="Repository containing the reviewed catalog.")],
    output: Annotated[Path, typer.Option(help="Private JSON report path.")],
) -> None:
    """Run catalog sensor controls using only the installed read-only BAS allowlist."""
    try:
        result = verify_catalog(catalog, Settings(), output)
        console.print(f"Observed local Sigma matches for {len(result['cases'])} catalog controls.")
        console.print(f"Private report: {output}")
        console.print("SIEM ingestion and alert delivery remain untested.")
    except Exception as exc:
        console.print(f"[red]Catalog validation stopped:[/red] {exc}")
        raise typer.Exit(code=1) from exc
