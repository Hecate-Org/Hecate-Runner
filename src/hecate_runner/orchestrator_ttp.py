"""ATT&CK technique resolution, tactic mapping, and platform scoping for Orchestrator."""

from __future__ import annotations

from typing import Any

from hecate_agent.core.grounding import TechniqueFact

from hecate_runner.orchestrator_derivations import (
    _NON_SCOPING_PLATFORM_THRESHOLD,
    _PLATFORM_LABELS,
    platforms_evidenced_in,
    platforms_named_in,
)
from hecate_runner.trail import listing


def resolve_ttps(
    orch: Any,
    techniques: list[str],
    scope_text: str = "",
    facts: dict[str, TechniqueFact] | None = None,
    protected: list[str] | None = None,
    intel_text: str = "",
    asserted: list[str] | None = None,
    specimen: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Derive real tactics/platforms for a hypothesis's techniques."""
    tactics: list[str] = []
    platforms: list[str] = []
    for technique_id in techniques:
        meta = orch.hecate.lookup_technique(technique_id, timeout_sec=orch.settings.llm_timeout_sec)
        if facts is not None:
            facts[technique_id.upper()] = TechniqueFact(
                valid=meta.found,
                superseded_by=(meta.superseded_from and meta.technique_id) or "",
                names=tuple(n for n in (meta.name, meta.parent_name) if n),
                platforms=(
                    ()
                    if len(meta.platforms) >= _NON_SCOPING_PLATFORM_THRESHOLD
                    else tuple(_PLATFORM_LABELS.get(pf, pf) for pf in meta.platforms)
                ),
            )
            if meta.superseded_from and meta.technique_id:
                facts[meta.technique_id.upper()] = TechniqueFact(
                    valid=True,
                    superseded_by="",
                    names=tuple(n for n in (meta.name, meta.parent_name) if n),
                    platforms=(
                        ()
                        if len(meta.platforms) >= _NON_SCOPING_PLATFORM_THRESHOLD
                        else tuple(_PLATFORM_LABELS.get(pf, pf) for pf in meta.platforms)
                    ),
                )
        if (
            meta.superseded_from
            and asserted is not None
            and meta.superseded_from.upper() in {t.upper() for t in asserted}
            and meta.technique_id.upper() not in {t.upper() for t in asserted}
        ):
            asserted.append(meta.technique_id)
        for tactic in meta.tactics:
            if tactic not in tactics:
                tactics.append(tactic)
        if len(meta.platforms) >= _NON_SCOPING_PLATFORM_THRESHOLD:
            continue
        for platform in meta.platforms:
            platform = _PLATFORM_LABELS.get(platform, platform)
            if platform not in platforms:
                platforms.append(platform)

    claimed = platforms_named_in(scope_text)
    claimant = "the hypothesis"
    orch._platform_dropped = set()
    shielded = {t.upper() for t in (protected or [])}

    if "Containers" in claimed and "Linux" not in claimed:
        claimed.append("Linux")
        orch.trail.step("scope", "Containers scope automatically inherits Linux platform telemetry")

    if specimen and "Containers" in specimen and "Linux" not in specimen:
        specimen.append("Linux")

    orch.trail.step(
        "scope",
        "techniques run on %s; hypothesis names %s",
        listing(platforms, "no narrow platform"),
        listing(claimed),
    )
    if specimen:
        unsupported = [p for p in claimed if p not in specimen]
        if unsupported:
            orch.trail.step(
                "scope",
                "hypothesis names %s; the specimen's evidence shows only %s: not scoping to %s",
                listing(claimed),
                listing(specimen),
                listing(unsupported),
            )
        kept = [p for p in claimed if p in specimen]
        if not kept:
            claimant = "the specimen's evidence"
        claimed = kept or list(specimen)
    if not claimed and intel_text:
        claimed = platforms_evidenced_in(intel_text)
        claimant = "the intel"
        if claimed:
            orch.trail.step("scope", "intel names or implies %s", listing(claimed))
    if claimed:
        scoped = [p for p in platforms if p in claimed]
        final_platforms = scoped if scoped else claimed
        if "Containers" in claimed and "Containers" not in final_platforms:
            final_platforms.append("Containers")
        if "Containers" in final_platforms and "Linux" not in final_platforms:
            final_platforms.append("Linux")
        if not scoped:
            orch.trail.step(
                "scope",
                "no overlap: trusting %s (%s) over the techniques",
                claimant,
                listing(claimed),
            )
        elif scoped != platforms:
            orch.trail.step("scope", "narrowed to what %s names: %s", claimant, listing(scoped))

        by_cti = shielded if asserted is None else {t.upper() for t in asserted}
        evidenced = platforms_evidenced_in(intel_text)
        if facts is not None:
            for tech_id, fact in facts.items():
                if tech_id.split(".")[0] not in shielded and tech_id not in shielded:
                    continue
                missing = [p for p in fact.platforms if p not in final_platforms]
                if not fact.platforms or len(missing) != len(fact.platforms):
                    continue
                if specimen and not any(p in specimen for p in missing):
                    orch.trail.step(
                        "scope",
                        "not widening for %s: the specimen's evidence shows only %s",
                        tech_id,
                        listing(specimen),
                    )
                    continue
                if specimen:
                    missing = [p for p in missing if p in specimen]
                if tech_id not in by_cti and tech_id.split(".")[0] not in by_cti:
                    missing = [p for p in missing if p in evidenced]
                    if not missing:
                        orch.trail.step(
                            "scope",
                            "not widening for %s: matched in the wording, but the intel "
                            "names none of %s",
                            tech_id,
                            listing(fact.platforms),
                        )
                        continue
                final_platforms = [*final_platforms, *missing]
                orch.trail.step(
                    "scope",
                    "keeping %s (the intel names it): adding %s to the platforms",
                    tech_id,
                    listing(missing),
                )

        if facts is not None:
            for tech_id, fact in facts.items():
                if fact.platforms and not any(p in final_platforms for p in fact.platforms):
                    if tech_id in by_cti or tech_id.split(".")[0] in by_cti:
                        orch.trail.step(
                            "scope",
                            "keeping %s: the CTI asserts it, though it runs only on %s",
                            tech_id,
                            listing(fact.platforms),
                        )
                        continue
                    orch._platform_dropped.add(tech_id)
                    orch.trail.step(
                        "scope",
                        "%s only runs on %s: dropping it",
                        tech_id,
                        listing(fact.platforms),
                    )

        return tactics, final_platforms

    return tactics, platforms
