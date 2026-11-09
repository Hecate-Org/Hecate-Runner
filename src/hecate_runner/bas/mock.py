"""Mock BAS Provider for testing, local development, and offline CI/CD."""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

from hecate_runner.bas.base import (
    BASProvider,
    DetonationRequest,
    DetonationResult,
    DetonationStage,
)

log = logging.getLogger(__name__)

# Sample deterministic techniques supported by the mock provider
MOCK_TECHNIQUE_CATALOG: dict[str, list[str]] = {
    "T1059.001": ["ability-powershell-download-cradle", "ability-powershell-base64-exec"],
    "T1059.003": ["ability-cmd-obfuscated-echo", "ability-cmd-whoami-recon"],
    "T1059.007": ["ability-wscript-socgholish-js-exec"],
    "T1003.001": ["ability-lsass-comsvcs-minidump"],
    "T1562.008": ["aws.defense-evasion.cloudtrail-stop"],
    "T1098.001": ["aws.persistence.create-admin-access-key"],
    "T1530": ["aws.exfiltration.s3-bucket-dump"],
    "T1610": ["k8s.privilege-escalation.privileged-pod"],
}


class MockBASProvider(BASProvider):
    """Deterministic in-memory BAS provider."""

    name: str = "mock"
    provider_type: str = "simulator"

    def __init__(
        self,
        allowed_hosts: list[str] | None = None,
        allowed_accounts: list[str] | None = None,
        simulate_failure: bool = False,
        simulate_cleanup_failure: bool = False,
        artificial_delay_sec: float = 0.0,
    ):
        super().__init__(allowed_hosts=allowed_hosts, allowed_accounts=allowed_accounts)
        self.simulate_failure = simulate_failure
        self.simulate_cleanup_failure = simulate_cleanup_failure
        self.artificial_delay_sec = artificial_delay_sec
        self.history: list[DetonationRequest] = []
        self.cleanup_calls: list[DetonationRequest] = []

    def lookup_technique(self, technique_id: str) -> list[str]:
        return MOCK_TECHNIQUE_CATALOG.get(technique_id, [f"mock-ability-{technique_id.lower()}"])

    def detonate(self, request: DetonationRequest) -> DetonationResult:
        # Enforce safety constraints
        self.check_safety(request.target)
        self.history.append(request)

        start_time = datetime.now(UTC)
        if self.artificial_delay_sec > 0:
            time.sleep(self.artificial_delay_sec)

        ability_id = request.ability_id or (
            self.lookup_technique(request.technique_id)[0]
            if self.lookup_technique(request.technique_id)
            else f"mock-{request.technique_id}"
        )

        end_time = datetime.now(UTC)
        duration = (end_time - start_time).total_seconds()

        if self.simulate_failure:
            return DetonationResult(
                success=False,
                hunt_id=request.hunt_id,
                technique_id=request.technique_id,
                ability_id=ability_id,
                provider=self.name,
                start_time_utc=start_time.isoformat(),
                end_time_utc=end_time.isoformat(),
                duration_seconds=duration,
                exit_code=1,
                stdout="",
                stderr="Simulated adversary detonation error: execution failed on agent.",
                stage=DetonationStage.FAILED,
                cleanup_success=not self.simulate_cleanup_failure,
                cleanup_error="Cleanup failed" if self.simulate_cleanup_failure else None,
                error_message="Detonation failed due to simulated error condition.",
            )

        # Successful mock detonation
        cleanup_success = not self.simulate_cleanup_failure
        cleanup_error = "Mock cleanup failure simulated" if self.simulate_cleanup_failure else None

        # Synthesize realistic telemetry metadata
        is_cloud = any(c in ability_id.lower() for c in ("aws", "gcp", "azure", "cloudtrail"))
        is_psh = "powershell" in ability_id or request.technique_id == "T1059.001"
        is_js = (
            "wscript" in ability_id
            or "cscript" in ability_id
            or "javascript" in ability_id
            or request.technique_id == "T1059.007"
        )
        is_minidump = (
            "comsvcs" in ability_id.lower()
            or "minidump" in ability_id.lower()
            or request.technique_id in ("T1003.001", "T1218.011")
        )
        is_windows = request.platform == "windows" or is_psh or is_js or is_minidump

        if is_cloud:
            category = "cloud"
            product = (
                "aws"
                if "aws" in ability_id.lower()
                else ("azure" if "azure" in ability_id.lower() else "gcp")
            )
            event_type = "CloudTrail"
            process_name = ""
            image = ""
            cmdline = ""
        elif is_js:
            category = "process_creation"
            product = "windows"
            event_type = "Sysmon Event ID 1"
            process_name = "wscript.exe"
            image = "C:\\Windows\\System32\\wscript.exe"
            cmdline = "wscript.exe C:\\Users\\victim\\Downloads\\update.js"
        elif is_minidump:
            category = "process_creation"
            product = "windows"
            event_type = "Sysmon Event ID 1"
            process_name = "rundll32.exe"
            image = "C:\\Windows\\System32\\rundll32.exe"
            cmdline = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full"
        elif is_psh:
            category = "process_creation"
            product = "windows"
            event_type = "Sysmon Event ID 1"
            process_name = "powershell.exe"
            image = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            cmdline = f"powershell.exe -ExecutionPolicy Bypass -Command mock_detonation --technique {request.technique_id}"
        elif is_windows:
            category = "process_creation"
            product = "windows"
            event_type = "Sysmon Event ID 1"
            process_name = "cmd.exe"
            image = "C:\\Windows\\System32\\cmd.exe"
            cmdline = f"cmd.exe /c echo mock_detonation --technique {request.technique_id}"
        else:
            category = "process_creation"
            product = "linux"
            event_type = "Sysmon Event ID 1"
            process_name = "bash"
            image = "/bin/bash"
            cmdline = f"/bin/bash -c mock_detonation --technique {request.technique_id}"

        # If specific detection rules were provided in request params, synthesize
        # predicate-aware telemetry tailored to the rule ASTs.
        rules_param = request.params.get("rules") or []
        rule_yaml_param = request.params.get("rule_yaml")
        if not rules_param and rule_yaml_param:
            rules_param = [{"rule_yaml": rule_yaml_param}]

        if rules_param:
            from hecate_runner.bas.synthesizer import synthesize_events_from_rule

            telemetry = []
            for r_item in rules_param:
                r_yaml = r_item.get("rule_yaml") if isinstance(r_item, dict) else str(r_item)
                if r_yaml:
                    tp_ev, _ = synthesize_events_from_rule(
                        r_yaml,
                        hunt_id=request.hunt_id,
                        technique_id=request.technique_id,
                    )
                    telemetry.append(tp_ev)
            if not telemetry:
                telemetry = [
                    {
                        "category": "process_creation",
                        "product": "linux",
                        "data_source": "process_creation",
                        "technique_id": request.technique_id,
                        "hunt_id": request.hunt_id,
                        "CommandLine": f"/bin/bash -c mock_detonation --technique {request.technique_id}",
                        "timestamp_utc": start_time.isoformat(),
                    }
                ]
        else:
            telemetry = [
                {
                    "category": category,
                    "product": product,
                    "data_source": category,
                    "technique_id": request.technique_id,
                    "hunt_id": request.hunt_id,
                    "event_type": event_type,
                    "process_name": process_name,
                    "Image": image,
                    "CommandLine": cmdline,
                    "command_line": cmdline
                    or f"mock_detonation --technique {request.technique_id}",
                    "timestamp_utc": start_time.isoformat(),
                }
            ]

        return DetonationResult(
            success=True,
            hunt_id=request.hunt_id,
            technique_id=request.technique_id,
            ability_id=ability_id,
            provider=self.name,
            start_time_utc=start_time.isoformat(),
            end_time_utc=end_time.isoformat(),
            duration_seconds=duration,
            exit_code=0,
            stdout=f"Mock detonation of {ability_id} executed successfully.",
            stderr="",
            stage=DetonationStage.COMPLETED,
            cleanup_success=cleanup_success,
            cleanup_error=cleanup_error,
            telemetry_signatures=telemetry,
            raw_details={"mock_execution": True, "request_params": request.params},
        )

    def cleanup(self, request: DetonationRequest) -> bool:
        self.cleanup_calls.append(request)
        return not self.simulate_cleanup_failure

    def health_check(self) -> dict[str, Any]:
        return {
            "status": "healthy",
            "provider": self.name,
            "catalog_techniques": len(MOCK_TECHNIQUE_CATALOG),
            "simulated_failure": self.simulate_failure,
        }
