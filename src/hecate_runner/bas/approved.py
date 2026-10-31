"""Reviewed, read-only procedures for unattended execution in the Linux lab.

Technique IDs alone are not an execution policy: CALDERA may map a technique
to downloads, payloads, or commands containing facts from intelligence. Pin the
ability and inspect its executable content before allowing it to run.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from dataclasses import dataclass
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from hecate_runner.bas.base import SafetyViolationError


@dataclass(frozen=True)
class ApprovedProcedure:
    technique_id: str
    ability_id: str
    command: str
    observed_argv: tuple[str, ...] = ()
    managed: bool = False
    cleanup_command: str = ""
    cleanup_observed_argv: tuple[str, ...] = ()
    expected_files: tuple[str, ...] = ()

    @property
    def argv(self) -> tuple[str, ...]:
        return self.observed_argv or tuple(shlex.split(self.command))


def _managed(
    technique: str,
    command: str,
    observed: tuple[str, ...] = (),
    cleanup_command: str = "",
    cleanup_observed: tuple[str, ...] = (),
    expected_files: tuple[str, ...] = (),
) -> ApprovedProcedure:
    key = f"{command}:{cleanup_command}" if cleanup_command else command
    identity = str(uuid5(NAMESPACE_URL, f"https://hecate.local/bas/{technique}/v1/{key}"))
    return ApprovedProcedure(
        technique,
        identity,
        command,
        observed,
        True,
        cleanup_command,
        cleanup_observed,
        expected_files,
    )


APPROVED_PROCEDURES = {
    "T1033": ApprovedProcedure("T1033", "bd527b63-9f9e-46e0-9816-b8434d2b8989", "whoami"),
    "T1057": ApprovedProcedure("T1057", "335cea7b-bec0-48c6-adfb-6066070f5f68", "ps"),
    "T1083": ApprovedProcedure("T1083", "52177cc1-b9ab-4411-ac21-2eadc4b5d3b8", "ls"),
    "T1082": _managed("T1082", "uname -a"),
    "T1016": _managed("T1016", "ip address show"),
    "T1087.001": _managed("T1087.001", "cut -d: -f1 /etc/passwd"),
    "T1069.001": ApprovedProcedure("T1069.001", "5c4dd985-89e3-4590-9b57-71fed66ff4e2", "groups"),
    "T1124": _managed("T1124", 'date -u +"%Y-%m-%dT%H:%M:%SZ"'),
    "T1059.004": _managed("T1059.004", "sh -c 'printf hecate-bas-shell-probe'"),
    "T1140": _managed("T1140", "printf 'aGVjYXRlLWJhcy1wcm9iZQ==' | base64 -d", ("base64", "-d")),
    "T1070.004": _managed(
        "T1070.004",
        "sh -c 'touch /tmp/hecate-t1070-canary.tmp && rm -f /tmp/hecate-t1070-canary.tmp'",
        ("rm", "-f", "/tmp/hecate-t1070-canary.tmp"),
        cleanup_command="rm -f /tmp/hecate-t1070-canary.tmp",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1070-canary.tmp"),
        expected_files=("/tmp/hecate-t1070-canary.tmp",),
    ),
    "T1027": _managed(
        "T1027",
        "sh -c 'printf aGVjYXRlLWJhcw== | base64 -d > /tmp/hecate-t1027.tmp'",
        ("base64", "-d"),
        cleanup_command="rm -f /tmp/hecate-t1027.tmp",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1027.tmp"),
        expected_files=("/tmp/hecate-t1027.tmp",),
    ),
    "T1005": _managed(
        "T1005",
        "sh -c 'uname -a > /tmp/hecate-t1005.tmp'",
        ("uname", "-a"),
        cleanup_command="rm -f /tmp/hecate-t1005.tmp",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1005.tmp"),
        expected_files=("/tmp/hecate-t1005.tmp",),
    ),
}


def catalog_digest() -> str:
    """Return a deterministic SHA-256 digest of the approved procedure catalog."""
    hasher = hashlib.sha256()
    for tech_id in sorted(APPROVED_PROCEDURES):
        proc = APPROVED_PROCEDURES[tech_id]
        payload = json.dumps(
            {
                "technique_id": proc.technique_id,
                "ability_id": proc.ability_id,
                "command": proc.command,
                "observed_argv": list(proc.observed_argv),
                "managed": proc.managed,
                "cleanup_command": proc.cleanup_command,
                "expected_files": list(proc.expected_files),
            },
            sort_keys=True,
        ).encode("utf-8")
        hasher.update(payload)
        hasher.update(b"\0")
    return hasher.hexdigest()


def ability_definition(procedure: ApprovedProcedure) -> dict[str, Any]:
    """Exact fixed content for a Hecate-managed ability; no CTI inputs."""
    if APPROVED_PROCEDURES.get(procedure.technique_id) != procedure or not procedure.managed:
        raise SafetyViolationError("Only catalog-managed abilities can be installed.")
    exec_config: dict[str, Any] = {"command": procedure.command, "timeout": 10}
    if procedure.cleanup_command:
        exec_config["cleanup"] = [procedure.cleanup_command]
    return {
        "id": procedure.ability_id,
        "name": f"Hecate isolated lab {procedure.technique_id}",
        "description": "Pinned non-destructive Linux lab procedure; local sensor verification.",
        "tactic": {
            "T1059.004": "execution",
            "T1140": "stealth",
            "T1070.004": "defense-evasion",
            "T1027": "defense-evasion",
            "T1005": "collection",
        }.get(procedure.technique_id, "discovery"),
        "technique": {"attack_id": procedure.technique_id, "name": procedure.technique_id},
        "platforms": {"linux": {"sh": exec_config}},
    }


def validate_approved_ability(ability: dict[str, Any], procedure: ApprovedProcedure) -> None:
    """Reject altered commands and any additional executable behavior."""
    if (
        ability.get("ability_id") != procedure.ability_id
        or ability.get("technique_id") != procedure.technique_id
        or ability.get("requirements")
        or ability.get("privilege")
    ):
        raise SafetyViolationError("Approved CALDERA ability identity or requirements changed.")
    executors = [e for e in ability.get("executors", []) if e.get("platform") == "linux"]
    if len(executors) != 1:
        raise SafetyViolationError("Approved ability requires exactly one Linux executor.")
    executor = executors[0]

    # Validate cleanup
    cleanup = executor.get("cleanup")
    if procedure.cleanup_command:
        expected = [procedure.cleanup_command]
        actual = [cleanup] if isinstance(cleanup, str) else list(cleanup or [])
        if actual != expected:
            raise SafetyViolationError("Approved CALDERA cleanup command altered or missing.")
    elif cleanup:
        raise SafetyViolationError("Unapproved cleanup command present on ability.")

    if (
        executor.get("name") != "sh"
        or executor.get("command") != procedure.command
        or any(
            executor.get(key)
            for key in (
                "payloads",
                "uploads",
                "variations",
                "code",
                "build_target",
                "parsers",
                "additional_info",
            )
        )
    ):
        raise SafetyViolationError("Approved CALDERA procedure content changed; execution refused.")


def select_approved_rule(
    rules: list[dict[str, Any]], techniques: list[str], allowed: list[str]
) -> tuple[ApprovedProcedure, str] | None:
    """Select a matching Linux process rule, without broadening to parent techniques."""
    import yaml

    for rule in rules:
        text = rule.get("rule_yaml", "")
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(parsed, dict):
            continue
        source = parsed.get("logsource") or {}
        if not isinstance(source, dict):
            continue
        if source.get("product") != "linux" or source.get("category") != "process_creation":
            continue
        tags = {str(t).lower() for t in parsed.get("tags") or []}
        rule_techniques = {str(t).upper() for t in rule.get("techniques") or []}
        rule_techniques.update(
            t.removeprefix("attack.").upper() for t in tags if t.startswith("attack.t")
        )
        for technique in techniques:
            if (
                technique in allowed
                and technique in rule_techniques
                and technique in APPROVED_PROCEDURES
            ):
                procedure = APPROVED_PROCEDURES[technique]
                # Eligibility only: a shared ATT&CK tag does not mean this
                # fixed procedure exercises the rule's actual predicates.
                # Validation still requires independently observed live events.
                from hecate_agent.core.sigma_evaluator import SigmaEvaluator

                candidates = [
                    {
                        "data_source": "process_creation",
                        "product": "linux",
                        "Image": f"{directory}/{procedure.argv[0]}",
                        "CommandLine": shlex.join(procedure.argv),
                    }
                    for directory in ("/bin", "/usr/bin", "/sbin", "/usr/sbin")
                ]
                try:
                    if SigmaEvaluator.evaluate_rule(text, candidates, []).true_positives > 0:
                        return procedure, text
                except Exception:
                    continue
    return None
