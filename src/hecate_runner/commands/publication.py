"""Operator review of an exact snapshot before public GitHub publication."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console

from hecate_runner.config import Settings
from hecate_runner.github_publisher import _snapshot_bundle, enqueue_hunt
from hecate_runner.promotion_policy import load_policy
from hecate_runner.public_review import approve_public_review, prepare_public_review

console = Console()


def publish_review(
    hunt_id: Annotated[str, typer.Argument(help="Hunt to inspect for public release.")],
    approve: Annotated[bool, typer.Option(help="Approve the exact inspected snapshot.")] = False,
    digest: Annotated[str, typer.Option(help="Exact digest printed by the inspection.")] = "",
    reviewer: Annotated[str, typer.Option(help="Operator who reviewed the release.")] = "",
    rights: Annotated[str, typer.Option(help="Basis for redistributing the source content.")] = "",
    privacy_checked: Annotated[
        bool, typer.Option(help="Private and customer data checked.")
    ] = False,
    redistribution_checked: Annotated[
        bool, typer.Option(help="Source licenses and distribution restrictions checked.")
    ] = False,
) -> None:
    settings = Settings()
    try:
        policy = load_policy(settings.hecate_workspace, settings.github_publishing_policy_path)
        if policy["target_visibility"] != "public":
            raise ValueError("This review command is for public GitHub destinations")
        files, _ = _snapshot_bundle(settings, hunt_id)
        review = prepare_public_review(settings, files)
        console.print(f"Destination: {review['destination']}")
        console.print(f"Review digest: {review['digest']}")
        console.print(f"Private preview: {review['review_directory']}")
        console.print(f"Files: {len(review['files'])}")
        if approve:
            approve_public_review(
                settings,
                files,
                expected_digest=digest,
                reviewer=reviewer,
                rights_note=rights,
                privacy_checked=privacy_checked,
                redistribution_checked=redistribution_checked,
            )
            status = enqueue_hunt(settings, hunt_id)
            console.print(f"Approved exact public snapshot; outbox status: {status}")
            console.print("The separate GitHub content-quality review still applies.")
        else:
            console.print("Inspect the private files before approving. Nothing was uploaded.")
    except (OSError, ValueError, RuntimeError) as exc:
        console.print(f"[red]Public review refused:[/red] {exc}")
        raise typer.Exit(code=1) from exc
