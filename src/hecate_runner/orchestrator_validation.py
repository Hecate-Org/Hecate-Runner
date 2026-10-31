"""Purple-team replay and BAS validation procedures for Orchestrator."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from hecate_runner.cti.base import CTIItem

log = logging.getLogger("hecate_runner.orchestrator")


def run_purple_team_validation(
    orch: Any,
    req: Any,
    rules: list[dict[str, Any]],
    out_dir: Path,
    item: CTIItem,
) -> None:
    """Replay drafted rules against events synthesised from the source's artifacts."""
    if not rules:
        return

    try:
        from hecate_agent.core.sigma_self_tuner import SigmaSelfTuner
    except ImportError as exc:
        log.warning("Purple-team replay unavailable: %s", exc)
        return

    from hecate_runner.purple_team import BENIGN_SAMPLE, replay_events, replay_rule

    started = orch.trail.elapsed
    tuner = SigmaSelfTuner(max_iterations=3)
    artifacts = orch._source_evidence.artifacts if orch._source_evidence is not None else []
    cti_text = orch._primary_evidence_text(item)

    techniques: list[str] = []
    for e in orch._technique_evidence or []:
        tid = str(e.get("technique_id") or "").strip().upper()
        if tid and tid not in techniques:
            techniques.append(tid)

    meta_techs = item.metadata.get("techniques") or item.metadata.get("mitre_attack") or []
    if isinstance(meta_techs, list):
        for t in meta_techs:
            clean = str(t).strip().upper()
            if clean and clean not in techniques:
                techniques.append(clean)

    for rule in rules:
        r_techs = rule.get("techniques") or []
        if isinstance(r_techs, str):
            r_techs = [r_techs]
        for rt in r_techs:
            clean = str(rt).strip().upper()
            if clean and clean not in techniques:
                techniques.append(clean)
        ryaml = str(rule.get("rule_yaml", ""))
        for tag_m in re.findall(r"attack\.(t\d{4}(?:\.\d{3})?)", ryaml, re.IGNORECASE):
            upper_m = tag_m.upper()
            if upper_m not in techniques:
                techniques.append(upper_m)

    enable_atomic = getattr(orch.settings, "purple_team_atomic_emulation", True)
    platforms = getattr(req, "platforms", None)
    events = replay_events(
        orch._indicator_records,
        artifacts,
        cti_text=cti_text,
        techniques=techniques,
        enable_atomic=enable_atomic,
        platforms=platforms,
        http_requests=item.metadata.get("http_requests"),
    )

    req.purple_team_atomic_techniques = techniques if enable_atomic else []
    atomic_test_details: list[dict[str, str]] = []
    if enable_atomic and techniques:
        try:
            from hecate_agent.api import get_atomic_tests

            for tid in techniques:
                for t in get_atomic_tests(tid, platforms=platforms):
                    atomic_test_details.append(
                        {
                            "technique_id": tid,
                            "test_id": t.get("test_id", ""),
                            "name": t.get("name", ""),
                            "command": t.get("command", ""),
                        }
                    )
        except Exception:
            pass
    req.purple_team_atomic_tests = atomic_test_details

    replayed = validated = tuned = baseline_matches = 0
    for rule in rules:
        rule_yaml = str(rule.get("rule_yaml", "")).strip()
        if not rule_yaml:
            continue
        outcome = replay_rule(
            rule_yaml,
            events.get(str(rule.get("logsource_category", "")), []),
            BENIGN_SAMPLE,
            tuner,
            emulated_techniques=techniques if enable_atomic else None,
            atomic_tests=[t["test_id"] for t in atomic_test_details] if enable_atomic else None,
        )
        rule["purple_team"] = outcome.to_dict()
        if outcome.status == "no_replay_events":
            continue
        replayed += 1
        validated += outcome.validated
        baseline_matches += outcome.status == "baseline_match"
        if outcome.tuned:
            tuned += 1
            rule["rule_yaml"] = outcome.final_rule
        path = Path(str(rule.get("path") or ""))
        if path.is_file() and (outcome.tuned or outcome.validated):
            text = outcome.final_rule.rstrip() + "\n"
            if outcome.validated:
                text += "x_hecate_purple_team_validated: true\n"
            if outcome.tuned:
                text += "x_hecate_tuned: true\n"
            path.write_text(text, encoding="utf-8")
            try:
                from hecate_agent.api import transpile_sigma_rule

                trans_queries = transpile_sigma_rule(text)
                for t_res in trans_queries.values():
                    if getattr(t_res, "success", False) and getattr(t_res, "query", None):
                        path.with_suffix(t_res.file_extension).write_text(
                            t_res.query.strip() + "\n", encoding="utf-8"
                        )
            except Exception:
                pass

    req.purple_team_rules_evaluated = replayed
    req.purple_team_rules_validated = validated
    req.purple_team_rules_tuned = tuned
    req.purple_team_telemetry_count = sum(len(v) for v in events.values())

    emulation_desc = (
        f" ({len(techniques)} technique(s) dynamically emulated via Atomic Red Team)"
        if (enable_atomic and techniques)
        else " source-artifact"
    )
    orch.trail.step(
        "purple_team",
        f"replayed %d of %d rule(s) against %d{emulation_desc} event(s) in %.0fs: "
        "%d validated, %d matched the benign sample, %d tuned, %d with nothing to replay",
        replayed,
        len(rules),
        req.purple_team_telemetry_count,
        orch.trail.elapsed - started,
        validated,
        baseline_matches,
        tuned,
        len(rules) - replayed,
    )

    try:
        from hecate_runner.notifications import notify_purple_team

        tech_list = getattr(req, "attack_techniques", []) or []
        tech_label = (
            ", ".join(techniques[:3])
            if techniques
            else (str(tech_list[0]) if tech_list else "Adversary TTPs")
        )
        summary_msg = (
            f"{validated} of {replayed} evaluated rules validated "
            f"({baseline_matches} baseline matches, {tuned} tuned) "
            f"against {req.purple_team_telemetry_count} telemetry events"
            f"{' (Atomic Red Team dynamic emulation enabled)' if enable_atomic and techniques else ''}."
        )
        notify_purple_team(
            orch.settings,
            hunt_id=req.hunt_id,
            technique=tech_label,
            success=validated > 0,
            telemetry_count=req.purple_team_telemetry_count,
            summary=summary_msg,
        )
    except Exception as exc:
        log.warning("Purple-team Slack notification failed (%s)", exc)


def run_bas_validation(
    orch: Any,
    req: Any,
    rules: list[dict[str, Any]],
    out_dir: Path,
    item: CTIItem,
) -> None:
    """Execute closed-loop live adversary emulation & breach simulation (BAS) validation."""
    from hecate_runner.bas import (
        DetonationRequest,
        DetonationTarget,
        get_bas_provider,
        normalize_platform,
    )
    from hecate_runner.bas.verifier import DetectionVerifier

    started = orch.trail.elapsed
    provider_name = getattr(orch.settings, "bas_mode", "mock")
    if provider_name != "mock":
        from hecate_runner.bas.approved import select_approved_rule
        from hecate_runner.bas.runtime import run_approved_validation, skipped_bas

        reason = ""
        selection = None
        if not orch.settings.bas_auto_execute_live:
            reason = "Unattended live BAS is disabled; manual validation remains available."
        elif provider_name != "caldera":
            reason = "Unattended BAS is supported only for reviewed Linux CALDERA procedures."
        elif not {p.strip().lower() for p in req.platforms} & {"linux"}:
            reason = "No approved lab platform for this hunt (Linux lab only)."
        else:
            selection = select_approved_rule(
                rules, req.hypothesis.techniques, orch.settings.bas_auto_techniques
            )
            if selection is None:
                reason = "No approved procedure exercises this hunt's Linux rule predicates."
        if reason:
            req.bas_verification = skipped_bas(orch.settings, req.hunt_id, reason)
        else:
            assert selection is not None
            procedure, rule_yaml = selection
            req.bas_verification = run_approved_validation(
                orch.settings, req.hunt_id, procedure, rule_yaml
            )
        result = req.bas_verification
        orch.trail.step(
            "bas",
            "%s for %s: %s; telemetry=%s, rule match=%s",
            result["status"],
            req.hunt_id,
            result.get("reason") or "local sensor Sigma verification",
            result.get("telemetry_arrived", False),
            result.get("rule_triggered", False),
        )
        return

    if not rules:
        return
    try:
        provider = get_bas_provider(provider_name, orch.settings)
    except Exception as exc:
        log.warning("BAS provider initialization failed (%s): %s", provider_name, exc)
        return

    if provider.name != "mock" and not orch.settings.bas_auto_execute_live:
        log.info("Skipping unattended live BAS; manual bas-detonate remains available.")
        return

    technique = ""
    if req.hypothesis.techniques:
        technique = req.hypothesis.techniques[0]
    elif rules:
        rule_techs = rules[0].get("techniques") or []
        if rule_techs:
            technique = rule_techs[0]

    if not technique:
        log.debug("No ATT&CK technique identified for BAS validation on %s", req.hunt_id)
        return

    platforms_lower = {p.strip().lower() for p in req.platforms if p.strip()}
    is_cloud = any(p in ("cloud", "aws", "gcp", "azure", "k8s", "iaas") for p in platforms_lower)
    target_platform = (
        "aws" if is_cloud else (next(iter(platforms_lower)) if platforms_lower else "linux")
    )
    norm_platform = normalize_platform(target_platform)

    allowed_hosts = getattr(orch.settings, "bas_allowed_hosts", [])
    allowed_accounts = getattr(orch.settings, "bas_allowed_accounts", [])

    if norm_platform == "windows":
        target_host = getattr(orch.settings, "bas_windows_host", "") or (
            next((h for h in allowed_hosts if "win" in h.lower()), None)
            or (allowed_hosts[0] if allowed_hosts else "lab-agent-01")
        )
    elif norm_platform == "linux":
        target_host = getattr(orch.settings, "bas_linux_host", "") or (
            next((h for h in allowed_hosts if "win" not in h.lower()), None)
            or (allowed_hosts[0] if allowed_hosts else "lab-agent-01")
        )
    else:
        target_host = allowed_hosts[0] if allowed_hosts else "lab-agent-01"

    target_account = allowed_accounts[0] if (allowed_accounts and is_cloud) else None

    target = DetonationTarget(
        environment="lab",
        platform=norm_platform,
        host=target_host if not is_cloud else None,
        cloud_account=target_account if is_cloud else None,
    )

    det_req = DetonationRequest(
        hunt_id=req.hunt_id,
        technique_id=technique,
        platform=norm_platform,
        target=target,
        timeout_sec=60,
    )

    rule_yaml = rules[0].get("rule_yaml", "")

    try:
        det_result = provider.detonate(det_req)
        verifier = DetectionVerifier()
        ver_result = verifier.verify_detonation(
            detonation=det_result,
            rule_yaml=rule_yaml,
        )
        ver_dict = ver_result.to_dict()
        ver_dict["duration_seconds"] = det_result.duration_seconds
        req.bas_verification = ver_dict

        orch.trail.step(
            "bas",
            "validated %s against %s (%s on %s) in %.0fs: status=%s, telemetry=%s, detection=%s (%d hits)",
            technique,
            provider_name.upper(),
            target.environment,
            target.host or target.cloud_account or "local",
            orch.trail.elapsed - started,
            ver_result.status.value,
            "yes" if ver_result.telemetry_arrived else "no",
            "yes" if ver_result.rule_triggered else "no",
            ver_result.matched_events_count,
        )
        log.info("BAS validation completed for %s: %s", req.hunt_id, ver_result.summary())
    except Exception as exc:
        log.warning("BAS validation failed for %s (%s)", req.hunt_id, exc)
        orch.trail.step("bas", "failed for %s: %s", technique, exc)
