"""Stratus Red Team Connector for Cloud Adversary Emulation.

Interacts with the DataDog Stratus Red Team CLI to execute cloud adversary simulations
against AWS, Azure, GCP, and Kubernetes staging environments, verifying that cloud
control plane telemetry (CloudTrail, GuardDuty, Activity Logs) is generated.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from hecate_runner.bas.base import (
    BASProvider,
    DetonationRequest,
    DetonationResult,
    DetonationStage,
    SafetyViolationError,
)
from hecate_runner.subprocess_utils import run_process_group

log = logging.getLogger(__name__)

# Standard mapping of MITRE ATT&CK techniques to Stratus Red Team attack IDs
STRATUS_TECHNIQUE_MAP: dict[str, list[str]] = {
    # AWS
    "T1562.008": ["aws.defense-evasion.cloudtrail-stop"],
    "T1562.001": [
        "aws.defense-evasion.cloudtrail-delete",
        "gcp.defense-evasion.disable-cloud-logging",
    ],
    "T1098.001": ["aws.persistence.create-admin-access-key"],
    "T1098": [
        "azure.persistence.add-service-principal-credentials",
        "gcp.persistence.create-service-account-key",
    ],
    "T1136.003": [
        "aws.persistence.create-iam-user",
        "gcp.persistence.create-service-account",
    ],
    "T1078.004": ["aws.privilege-escalation.iam-backdoor-role"],
    "T1530": [
        "aws.exfiltration.s3-bucket-dump",
        "gcp.exfiltration.export-bucket",
    ],
    "T1485": [
        "aws.impact.s3-delete-bucket",
        "gcp.impact.delete-bucket",
    ],
    "T1552.005": ["aws.credential-access.ec2-get-password-data"],
    "T1059.009": ["aws.execution.ec2-user-data"],
    # Azure
    "T1059": ["azure.execution.vm-run-command"],
    "T1562": ["azure.defense-evasion.delete-diagnostic-settings"],
    # Kubernetes
    "T1610": ["k8s.privilege-escalation.privileged-pod"],
    "T1059.004": ["k8s.execution.curl-metadata-service"],
    # GCP
    "T1562.007": ["gcp.defense-evasion.disable-cloud-logging"],
}


class StratusConnector(BASProvider):
    """Connector for Stratus Red Team cloud adversary emulation."""

    name: str = "stratus"
    provider_type: str = "cloud_bas"

    def __init__(
        self,
        binary_path: str = "stratus-red-team",
        timeout_sec: int = 300,
        allowed_hosts: list[str] | None = None,
        allowed_accounts: list[str] | None = None,
        runner_fn: Callable[[list[str], int], subprocess.CompletedProcess[str]] | None = None,
        identity_resolver_fn: Callable[[str], str | None] | None = None,
    ):
        super().__init__(allowed_hosts=allowed_hosts, allowed_accounts=allowed_accounts)
        self.binary_path = binary_path
        self.timeout_sec = timeout_sec
        self._runner_fn = runner_fn
        self._identity_resolver_fn = identity_resolver_fn

    def get_active_cloud_identity(
        self, platform: str, *, env: dict[str, str] | None = None
    ) -> str | None:
        """Confirm the execution account against the provider, not an ID label.

        Use the same environment as the Stratus subprocesses. Authentication
        failures and unavailable tooling fail closed before provisioning.
        """
        execution_env = dict(os.environ) if env is None else env

        def run(args: list[str]) -> str:
            proc = run_process_group(args, text=True, env=execution_env, timeout=10, check=False)
            if proc.returncode != 0:
                raise ValueError("Cloud identity lookup failed")
            return proc.stdout.strip()

        try:
            if platform == "aws":
                account = json.loads(
                    run(["aws", "sts", "get-caller-identity", "--output", "json"])
                ).get("Account")
                return account if isinstance(account, str) and account else None
            if platform == "azure":
                # Stratus supports Azure CLI credentials. Refuse alternative
                # credential chains that could differ from this CLI probe.
                if any(
                    execution_env.get(k)
                    for k in (
                        "AZURE_CLIENT_ID",
                        "AZURE_CLIENT_SECRET",
                        "AZURE_CLIENT_CERTIFICATE_PATH",
                        "AZURE_FEDERATED_TOKEN_FILE",
                        "IDENTITY_ENDPOINT",
                        "MSI_ENDPOINT",
                    )
                ):
                    return None
                subscription = execution_env.get("AZURE_SUBSCRIPTION_ID")
                if not subscription:
                    return None
                data = json.loads(
                    run(
                        [
                            "az",
                            "rest",
                            "--method",
                            "get",
                            "--url",
                            f"https://management.azure.com/subscriptions/{subscription}?api-version=2022-12-01",
                        ]
                    )
                )
                subscription_id = data.get("subscriptionId")
                return (
                    subscription_id
                    if isinstance(subscription_id, str) and subscription_id
                    else None
                )
            if platform == "gcp":
                # Use application-default credentials, as Stratus does, rather
                # than gcloud's potentially different interactive login.
                import httpx

                project = execution_env.get("GOOGLE_PROJECT")
                # The CLI's ADC token command does not honor arbitrary service
                # credential files in the same way as the Go SDK.
                if execution_env.get("GOOGLE_APPLICATION_CREDENTIALS"):
                    return None
                if not project:
                    return None
                token = run(["gcloud", "auth", "application-default", "print-access-token"])
                response = httpx.get(
                    f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10,
                )
                response.raise_for_status()
                project_id = response.json().get("projectId")
                return project_id if isinstance(project_id, str) and project_id else None
            if platform == "k8s":
                context = run(["kubectl", "config", "current-context"])
                # A kubeconfig label alone does not establish authentication.
                identity = json.loads(
                    run(["kubectl", "--context", context, "auth", "whoami", "-o", "json"])
                )
                user = identity.get("status", {}).get("userInfo", {})
                if (
                    user.get("username")
                    and user["username"] != "system:anonymous"
                    and "system:unauthenticated" not in user.get("groups", [])
                ):
                    return context
        except Exception:
            log.warning("Could not independently verify %s execution identity", platform)
        return None

    def _execution_context(self, request: DetonationRequest) -> tuple[str, dict[str, str]]:
        self.check_safety(request.target)
        platform = request.target.platform.lower().strip()
        if request.platform.lower().strip() != platform:
            raise SafetyViolationError("Request and target platforms disagree.")
        ability = request.ability_id
        if not ability:
            matches = [
                a
                for a in self.lookup_technique(request.technique_id)
                if a.startswith(f"{platform}.")
            ]
            ability = matches[0] if matches else None
        if not ability or not ability.startswith(f"{platform}."):
            raise SafetyViolationError(
                f"No matching {platform} Stratus ability for {request.technique_id}."
            )
        env = dict(os.environ)
        account = request.target.cloud_account
        if not account:
            raise SafetyViolationError(
                "Cloud execution requires an explicit target account or context."
            )
        # These select the target used by Stratus; none constitutes identity proof.
        if platform == "azure":
            env["AZURE_SUBSCRIPTION_ID"] = account
            env["ARM_SUBSCRIPTION_ID"] = account
        elif platform == "gcp":
            env["GOOGLE_PROJECT"] = account
            env["GOOGLE_CLOUD_PROJECT"] = account
        active = (
            self._identity_resolver_fn(platform)
            if self._identity_resolver_fn is not None
            else self.get_active_cloud_identity(platform, env=env)
        )
        if not active:
            raise SafetyViolationError(
                f"Cannot verify active credentials for {platform}; refusing cloud execution."
            )
        if active != account:
            raise SafetyViolationError(
                f"Active {platform} identity '{active}' does not match requested target account '{account}'."
            )
        return ability, env

    def _run_cmd(
        self, args: list[str], timeout: int, *, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Execute Stratus with the verified operation's environment."""
        if self._runner_fn is not None:
            return self._runner_fn(args, timeout)
        return run_process_group(
            [self.binary_path, *args],
            text=True,
            env=env,
            timeout=timeout,
            check=False,
        )

    def health_check(self) -> dict[str, Any]:
        """Verify binary availability and installed version."""
        binary_found = bool(
            self._runner_fn is not None
            or shutil.which(self.binary_path)
            or os.path.isfile(self.binary_path)
        )
        version_str = "unknown"
        if binary_found:
            try:
                proc = self._run_cmd(["version"], timeout=10)
                if proc.returncode == 0:
                    version_str = proc.stdout.strip()
            except Exception as exc:
                version_str = f"error: {exc}"

        return {
            "status": "healthy" if binary_found else "uninstalled",
            "binary_path": self.binary_path,
            "binary_found": binary_found,
            "version": version_str,
            "mapped_techniques": len(STRATUS_TECHNIQUE_MAP),
        }

    def lookup_technique(self, technique_id: str) -> list[str]:
        """Map a MITRE ATT&CK Technique ID to supported Stratus Red Team IDs."""
        return STRATUS_TECHNIQUE_MAP.get(technique_id.upper(), [])

    def detonate(self, request: DetonationRequest) -> DetonationResult:
        """Execute the 3-step Stratus lifecycle: Warmup -> Detonate -> Cleanup."""
        ability_id, execution_env = self._execution_context(request)

        start_time = datetime.now(UTC)
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        current_stage = DetonationStage.WARMING_UP
        cleanup_success = False
        cleanup_error: str | None = None
        exit_code = 0
        warmup_attempted = False

        try:
            # 3. Stage 1: Warmup (provision test infrastructure)
            warmup_attempted = True
            log.info("Stratus Red Team warmup: %s", ability_id)
            warmup_proc = self._run_cmd(
                ["warmup", ability_id], timeout=self.timeout_sec, env=execution_env
            )
            stdout_parts.append(f"--- WARMUP ---\n{warmup_proc.stdout}")
            if warmup_proc.returncode != 0:
                stderr_parts.append(f"Warmup failed: {warmup_proc.stderr}")
                exit_code = warmup_proc.returncode
                current_stage = DetonationStage.FAILED
            else:
                # 4. Stage 2: Detonate (trigger the cloud adversary behavior)
                current_stage = DetonationStage.DETONATING
                log.info("Stratus Red Team detonate: %s", ability_id)
                detonate_proc = self._run_cmd(
                    ["detonate", ability_id], timeout=self.timeout_sec, env=execution_env
                )
                stdout_parts.append(f"--- DETONATE ---\n{detonate_proc.stdout}")
                if detonate_proc.returncode != 0:
                    stderr_parts.append(f"Detonate failed: {detonate_proc.stderr}")
                    exit_code = detonate_proc.returncode
                    current_stage = DetonationStage.FAILED
                else:
                    current_stage = DetonationStage.COMPLETED

        except subprocess.TimeoutExpired as exc:
            stderr_parts.append(f"Stratus command timed out: {exc}")
            exit_code = 124
            current_stage = DetonationStage.FAILED
        except Exception as exc:
            stderr_parts.append(f"Stratus execution exception: {exc}")
            exit_code = 1
            current_stage = DetonationStage.FAILED
        finally:
            # 5. Stage 3: Mandatory Cleanup (destroy cloud infrastructure)
            if request.cleanup_on_finish and warmup_attempted:
                log.info("Stratus Red Team cleanup: %s", ability_id)
                try:
                    cleanup_proc = self._run_cmd(
                        ["cleanup", ability_id], timeout=self.timeout_sec, env=execution_env
                    )
                    stdout_parts.append(f"--- CLEANUP ---\n{cleanup_proc.stdout}")
                    if cleanup_proc.returncode != 0:
                        cleanup_success = False
                        cleanup_error = f"Cleanup failed with code {cleanup_proc.returncode}: {cleanup_proc.stderr}"
                        stderr_parts.append(cleanup_error)
                    else:
                        cleanup_success = True
                except Exception as clean_exc:
                    cleanup_success = False
                    cleanup_error = f"Cleanup threw exception: {clean_exc}"
                    stderr_parts.append(cleanup_error)
            elif not request.cleanup_on_finish:
                cleanup_error = "Cleanup skipped by request (cleanup_on_finish=False)."

        end_time = datetime.now(UTC)
        duration = (end_time - start_time).total_seconds()
        is_success = (
            (exit_code == 0) and cleanup_success and current_stage == DetonationStage.COMPLETED
        )

        # Generate telemetry hints based on technique
        telemetry = [
            {
                "data_source": "cloud_control_plane",
                "technique_id": request.technique_id,
                "ability_id": ability_id,
                "cloud_provider": ability_id.split(".")[0],
                "event_type": ability_id.split(".")[-1],
                "timestamp_utc": start_time.isoformat(),
            }
        ]

        return DetonationResult(
            success=is_success,
            hunt_id=request.hunt_id,
            technique_id=request.technique_id,
            ability_id=ability_id,
            provider=self.name,
            start_time_utc=start_time.isoformat(),
            end_time_utc=end_time.isoformat(),
            duration_seconds=duration,
            exit_code=exit_code,
            stdout="\n".join(stdout_parts),
            stderr="\n".join(stderr_parts),
            stage=current_stage,
            cleanup_success=cleanup_success,
            cleanup_error=cleanup_error,
            telemetry_signatures=telemetry,
            raw_details={"ability_id": ability_id, "cloud_platform": request.target.platform},
            error_message="\n".join(stderr_parts) if not is_success else None,
        )

    def cleanup(self, request: DetonationRequest) -> bool:
        """Explicit on-demand cleanup invocation."""
        ability_id, execution_env = self._execution_context(request)

        try:
            proc = self._run_cmd(
                ["cleanup", ability_id], timeout=self.timeout_sec, env=execution_env
            )
            return proc.returncode == 0
        except Exception as exc:
            log.error("Failed explicit Stratus cleanup for %s: %s", ability_id, exc)
            return False
