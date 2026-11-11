"""Reviewed, read-only procedures for unattended execution in the Linux lab.

Technique IDs alone are not an execution policy: CALDERA may map a technique
to downloads, payloads, or commands containing facts from intelligence. Pin the
ability and inspect its executable content before allowing it to run.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from hecate_runner.bas.base import DetonationResult, SafetyViolationError


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
    fidelity_scope: str = "behavioral"  # "behavioral" | "smoke_check"

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
    fidelity_scope: str = "behavioral",
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
        fidelity_scope,
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
    "T1053.003": _managed(
        "T1053.003",
        "sh -c 'printf \"* * * * * true # hecate-t1053\\n\" > /tmp/hecate-t1053.tmp && crontab /tmp/hecate-t1053.tmp'",
        ("crontab", "/tmp/hecate-t1053.tmp"),
        cleanup_command="sh -c 'crontab -r && rm -f /tmp/hecate-t1053.tmp'",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1053.tmp"),
        expected_files=("/tmp/hecate-t1053.tmp",),
        fidelity_scope="behavioral",
    ),
    "T1105": _managed(
        "T1105",
        "sh -c 'curl -f -sS -m 2 http://127.0.0.1:8888/ -o /tmp/hecate-t1105.tmp && test -s /tmp/hecate-t1105.tmp'",
        ("curl", "-f", "-sS", "-m", "2", "http://127.0.0.1:8888/", "-o", "/tmp/hecate-t1105.tmp"),
        cleanup_command="rm -f /tmp/hecate-t1105.tmp",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1105.tmp"),
        expected_files=("/tmp/hecate-t1105.tmp",),
        fidelity_scope="behavioral",
    ),
    "T1049": _managed("T1049", "ss -tan"),
    "T1007": _managed(
        "T1007",
        "systemctl list-units --type=service --state=running",
        ("systemctl", "list-units", "--type=service", "--state=running"),
    ),
    "T1518.001": _managed(
        "T1518.001",
        "systemctl status ufw",
        ("systemctl", "status", "ufw"),
    ),
    "T1018": _managed("T1018", "arp -a"),
    "T1222.002": _managed(
        "T1222.002",
        "sh -c 'touch /tmp/hecate-t1222.tmp && chmod 644 /tmp/hecate-t1222.tmp && rm -f /tmp/hecate-t1222.tmp'",
        ("chmod", "644", "/tmp/hecate-t1222.tmp"),
        cleanup_command="rm -f /tmp/hecate-t1222.tmp",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1222.tmp"),
        expected_files=("/tmp/hecate-t1222.tmp",),
    ),
    "T1036.005": _managed(
        "T1036.005",
        "sh -c 'touch /tmp/hecate-t1036-crond.tmp && rm -f /tmp/hecate-t1036-crond.tmp'",
        ("touch", "/tmp/hecate-t1036-crond.tmp"),
        cleanup_command="rm -f /tmp/hecate-t1036-crond.tmp",
        cleanup_observed=("rm", "-f", "/tmp/hecate-t1036-crond.tmp"),
        expected_files=("/tmp/hecate-t1036-crond.tmp",),
    ),
    "T1543.002": _managed(
        "T1543.002",
        "systemctl is-active cron",
        ("systemctl", "is-active", "cron"),
        fidelity_scope="smoke_check",
    ),
    "T1552.001": _managed(
        "T1552.001",
        "grep -s 'BEGIN PRIVATE KEY' /etc/ssl/certs/",
        ("grep", "-s", "BEGIN PRIVATE KEY", "/etc/ssl/certs/"),
    ),
    "T1003.008": _managed(
        "T1003.008",
        "head -n 1 /etc/passwd",
        ("head", "-n", "1", "/etc/passwd"),
    ),
    "T1046": _managed(
        "T1046",
        "nc -z -v -w 1 127.0.0.1 22",
        ("nc", "-z", "-v", "-w", "1", "127.0.0.1", "22"),
    ),
    "T1526": _managed(
        "T1526",
        "curl -s -m 1 http://127.0.0.1:80/latest/meta-data/",
        ("curl", "-s", "-m", "1", "http://127.0.0.1:80/latest/meta-data/"),
    ),
    "T1613": _managed(
        "T1613",
        "cat /proc/1/cgroup",
        ("cat", "/proc/1/cgroup"),
    ),
    "T1071.001": _managed(
        "T1071.001",
        "curl -sI https://localhost/",
        ("curl", "-sI", "https://localhost/"),
        fidelity_scope="smoke_check",
    ),
    "T1190": _managed(
        "T1190",
        "curl -s http://127.0.0.1:80/",
        ("curl", "-s", "http://127.0.0.1:80/"),
        fidelity_scope="smoke_check",
    ),
    "T1041": _managed(
        "T1041",
        "sh -c 'printf hecate-exfil-test | wc -c'",
        ("wc", "-c"),
        fidelity_scope="smoke_check",
    ),
}


# These exact, validated catalog commands do not create remote artifacts that
# need teardown. Keep this explicit: a new procedure is not exempt merely
# because somebody forgot to define its cleanup command.
ARTIFACT_FREE_TECHNIQUES = frozenset(
    {
        "T1033",
        "T1057",
        "T1083",
        "T1082",
        "T1016",
        "T1087.001",
        "T1069.001",
        "T1124",
        "T1059.004",
        "T1140",
        "T1049",
        "T1007",
        "T1518.001",
        "T1018",
        "T1543.002",
        "T1552.001",
        "T1003.008",
        "T1046",
        "T1526",
        "T1613",
        "T1071.001",
        "T1190",
        "T1041",
    }
)


def resolve_fidelity_scope(detonation: DetonationResult, requested: str | None = None) -> str:
    """A caller cannot upgrade a pinned smoke check to behavioral validation."""
    scopes = [
        requested,
        result_fidelity_scope(
            {
                "ability_id": detonation.ability_id,
                "fidelity_scope": detonation.raw_details.get("fidelity_scope"),
            }
        ),
    ]
    return next((str(scope) for scope in scopes if scope and scope != "behavioral"), "behavioral")


def result_fidelity_scope(result: Mapping[str, Any]) -> str:
    scope = str(result.get("fidelity_scope") or "behavioral")
    if scope == "behavioral":
        for procedure in APPROVED_PROCEDURES.values():
            if (
                procedure.ability_id == result.get("ability_id")
                and procedure.fidelity_scope != "behavioral"
            ):
                return procedure.fidelity_scope
    return scope


def confirms_technique(result: Mapping[str, Any]) -> bool:
    """Keep local smoke checks out of technique-validation and promotion credit."""
    return (
        result.get("status") == "verified_true_positive"
        and result_fidelity_scope(result) == "behavioral"
    )


def result_status(result: Mapping[str, Any]) -> str:
    status = str(result.get("status", "unknown"))
    if status == "verified_true_positive" and not confirms_technique(result):
        return "smoke_check_match"
    return status


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
                "artifact_free": tech_id in ARTIFACT_FREE_TECHNIQUES,
                "fidelity_scope": proc.fidelity_scope,
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
        exec_config["cleanup"] = procedure.cleanup_command
    return {
        "id": procedure.ability_id,
        "name": f"Hecate isolated lab {procedure.technique_id}",
        "description": "Pinned non-destructive Linux lab procedure; local sensor verification.",
        "tactic": {
            "T1190": "initial-access",
            "T1059.004": "execution",
            "T1053.003": "persistence",
            "T1543.002": "persistence",
            "T1222.002": "defense-evasion",
            "T1036.005": "defense-evasion",
            "T1140": "defense-evasion",
            "T1070.004": "defense-evasion",
            "T1027": "defense-evasion",
            "T1003.008": "credential-access",
            "T1552.001": "credential-access",
            "T1005": "collection",
            "T1071.001": "command-and-control",
            "T1105": "command-and-control",
            "T1041": "exfiltration",
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

    common_parents = (
        "/usr/sbin/php-fpm",
        "/usr/sbin/php-cgi",
        "/usr/sbin/apache2",
        "/usr/sbin/httpd",
        "/usr/sbin/nginx",
        "/usr/bin/python3",
        "/bin/bash",
        "/bin/sh",
        "/usr/sbin/cron",
        "/lib/systemd/systemd",
    )

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
        category = source.get("category", "")
        product = str(source.get("product") or "").lower()
        if (
            product and product not in ("linux", "container", "containers", "unix")
        ) or category not in (
            "process_creation",
            "file_event",
            "file_change",
            "network_connection",
        ):
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
                if procedure.fidelity_scope != "behavioral":
                    continue
                # Eligibility only: a shared ATT&CK tag does not mean this
                # fixed procedure exercises the rule's actual predicates.
                # Validation still requires independently observed live events.
                from hecate_agent.core.sigma_evaluator import SigmaEvaluator

                candidates = [
                    {
                        "data_source": "process_creation",
                        "category": "process_creation",
                        "product": "linux",
                        "Image": f"{directory}/{procedure.argv[0]}",
                        "CommandLine": shlex.join(procedure.argv),
                        "User": "root",
                    }
                    for directory in ("/bin", "/usr/bin", "/sbin", "/usr/sbin")
                ]
                for directory in ("/bin", "/usr/bin"):
                    for parent in common_parents:
                        candidates.append(
                            {
                                "data_source": "process_creation",
                                "category": "process_creation",
                                "product": "linux",
                                "Image": f"{directory}/{procedure.argv[0]}",
                                "CommandLine": shlex.join(procedure.argv),
                                "ParentImage": parent,
                                "User": (
                                    "www-data"
                                    if any(w in parent for w in ("php", "apache", "httpd", "nginx"))
                                    else "root"
                                ),
                            }
                        )
                for fpath in procedure.expected_files:
                    candidates.append(
                        {
                            "data_source": "file_event",
                            "category": "file_event",
                            "product": "linux",
                            "TargetFilename": fpath,
                            "Image": f"/usr/bin/{procedure.argv[0]}",
                            "CommandLine": shlex.join(procedure.argv),
                        }
                    )
                try:
                    if SigmaEvaluator.evaluate_rule(text, candidates, []).true_positives > 0:
                        return procedure, text
                except Exception:
                    continue
    return None
