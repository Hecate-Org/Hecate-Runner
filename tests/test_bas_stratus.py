"""Tests for Stratus Red Team cloud adversary emulation connector."""

import subprocess

import pytest

from hecate_runner.bas.base import (
    DetonationRequest,
    DetonationStage,
    DetonationTarget,
    SafetyViolationError,
)
from hecate_runner.bas.stratus import StratusConnector


def test_stratus_technique_lookup():
    connector = StratusConnector()
    aws_detonators = connector.lookup_technique("T1562.008")
    assert aws_detonators == ["aws.defense-evasion.cloudtrail-stop"]

    azure_detonators = connector.lookup_technique("T1098")
    assert "azure.persistence.add-service-principal-credentials" in azure_detonators

    k8s_detonators = connector.lookup_technique("T1610")
    assert "k8s.privilege-escalation.privileged-pod" in k8s_detonators

    gcp_detonators = connector.lookup_technique("T1562.007")
    assert "gcp.defense-evasion.disable-cloud-logging" in gcp_detonators

    shared = connector.lookup_technique("T1562.001")
    assert "aws.defense-evasion.cloudtrail-delete" in shared
    assert "gcp.defense-evasion.disable-cloud-logging" in shared

    unknown = connector.lookup_technique("T0000")
    assert unknown == []


def test_stratus_health_check_with_runner():
    def mock_runner(args: list[str], timeout: int):
        if args == ["version"]:
            return subprocess.CompletedProcess(
                args=["stratus", "version"],
                returncode=0,
                stdout="stratus-red-team version 2.15.0\n",
                stderr="",
            )
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    connector = StratusConnector(
        runner_fn=mock_runner,
        allowed_accounts=["123456789012"],
        identity_resolver_fn=lambda p: "123456789012",
    )
    health = connector.health_check()
    assert "2.15.0" in health["version"]
    assert health["mapped_techniques"] > 0


def test_stratus_detonation_lifecycle_success():
    calls: list[list[str]] = []

    def mock_runner(args: list[str], timeout: int):
        calls.append(args)
        return subprocess.CompletedProcess(
            args=["stratus", *args],
            returncode=0,
            stdout=f"stratus {args[0]} executed successfully",
            stderr="",
        )

    connector = StratusConnector(
        runner_fn=mock_runner,
        allowed_accounts=["123456789012"],
        identity_resolver_fn=lambda p: "123456789012",
    )
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1562.008",
        platform="aws",
        target=DetonationTarget(
            environment="staging",
            platform="aws",
            cloud_account="123456789012",
        ),
    )

    result = connector.detonate(request)
    assert result.success is True
    assert result.exit_code == 0
    assert result.stage == DetonationStage.COMPLETED
    assert result.ability_id == "aws.defense-evasion.cloudtrail-stop"
    assert result.cleanup_success is True

    # Verify order of execution: warmup -> detonate -> cleanup
    assert len(calls) == 3
    assert calls[0] == ["warmup", "aws.defense-evasion.cloudtrail-stop"]
    assert calls[1] == ["detonate", "aws.defense-evasion.cloudtrail-stop"]
    assert calls[2] == ["cleanup", "aws.defense-evasion.cloudtrail-stop"]

    assert len(result.telemetry_signatures) == 1
    assert result.telemetry_signatures[0]["cloud_provider"] == "aws"


def test_stratus_detonation_warmup_failure_aborts_detonate():
    calls: list[list[str]] = []

    def mock_runner(args: list[str], timeout: int):
        calls.append(args)
        if args[0] == "warmup":
            return subprocess.CompletedProcess(
                args=["stratus", *args],
                returncode=1,
                stdout="",
                stderr="Terraform init error",
            )
        return subprocess.CompletedProcess(
            args=["stratus", *args], returncode=0, stdout="", stderr=""
        )

    connector = StratusConnector(
        runner_fn=mock_runner,
        allowed_accounts=["123456789012"],
        identity_resolver_fn=lambda p: "123456789012",
    )
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1562.008",
        platform="aws",
        target=DetonationTarget(
            environment="staging", platform="aws", cloud_account="123456789012"
        ),
    )

    result = connector.detonate(request)
    assert result.success is False
    assert result.exit_code == 1
    assert result.stage == DetonationStage.FAILED
    assert "Warmup failed" in result.stderr

    # Detonate was NOT called because warmup failed, but cleanup was executed to prevent orphaned resources
    assert len(calls) == 2
    assert calls[0][0] == "warmup"
    assert calls[1][0] == "cleanup"
    assert not any(c[0] == "detonate" for c in calls)
    assert result.cleanup_success is True


def test_stratus_identity_mismatch_raises_safety_violation():
    def mock_runner(args: list[str], timeout: int):
        return subprocess.CompletedProcess(
            args=["stratus", *args], returncode=0, stdout="", stderr=""
        )

    # Active ambient identity is 999999999999, but request targets 123456789012
    connector = StratusConnector(
        runner_fn=mock_runner,
        allowed_accounts=["123456789012"],
        identity_resolver_fn=lambda p: "999999999999",
    )
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1562.008",
        platform="aws",
        target=DetonationTarget(
            environment="staging", platform="aws", cloud_account="123456789012"
        ),
    )
    with pytest.raises(SafetyViolationError) as exc_info:
        connector.detonate(request)
    assert "does not match requested target account" in str(exc_info.value)


def test_stratus_detonation_detonate_failure_still_runs_cleanup():
    calls: list[list[str]] = []

    def mock_runner(args: list[str], timeout: int):
        calls.append(args)
        if args[0] == "detonate":
            return subprocess.CompletedProcess(
                args=["stratus", *args],
                returncode=2,
                stdout="",
                stderr="AWS API rate limit exceeded",
            )
        return subprocess.CompletedProcess(
            args=["stratus", *args], returncode=0, stdout="", stderr=""
        )

    connector = StratusConnector(
        runner_fn=mock_runner,
        allowed_accounts=["123456789012"],
        identity_resolver_fn=lambda p: "123456789012",
    )
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1562.008",
        platform="aws",
        target=DetonationTarget(
            environment="staging", platform="aws", cloud_account="123456789012"
        ),
    )

    result = connector.detonate(request)
    assert result.success is False
    assert result.exit_code == 2

    # Even though detonate failed, cleanup MUST have been invoked
    assert len(calls) == 3
    assert calls[0][0] == "warmup"
    assert calls[1][0] == "detonate"
    assert calls[2][0] == "cleanup"


def test_stratus_detonation_safety_violation():
    connector = StratusConnector(allowed_accounts=["123456789012"])
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1562.008",
        platform="aws",
        target=DetonationTarget(
            environment="staging",
            cloud_account="999999999999",  # Not on allowlist
        ),
    )
    with pytest.raises(SafetyViolationError):
        connector.detonate(request)


def test_stratus_explicit_cleanup():
    calls: list[list[str]] = []

    def mock_runner(args: list[str], timeout: int):
        calls.append(args)
        return subprocess.CompletedProcess(
            args=["stratus", *args], returncode=0, stdout="cleaned", stderr=""
        )

    connector = StratusConnector(
        runner_fn=mock_runner,
        allowed_accounts=["123456789012"],
        identity_resolver_fn=lambda p: "123456789012",
    )
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1562.008",
        platform="aws",
        target=DetonationTarget(
            environment="staging", platform="aws", cloud_account="123456789012"
        ),
    )
    assert connector.cleanup(request) is True
    assert calls == [["cleanup", "aws.defense-evasion.cloudtrail-stop"]]


def test_stratus_gcp_platform_aware_detonation():
    calls: list[list[str]] = []

    def mock_runner(args: list[str], timeout: int):
        calls.append(args)
        return subprocess.CompletedProcess(
            args=["stratus", *args],
            returncode=0,
            stdout="ok",
            stderr="",
        )

    connector = StratusConnector(
        runner_fn=mock_runner,
        allowed_accounts=["my-gcp-project"],
        identity_resolver_fn=lambda p: "my-gcp-project",
    )
    req = DetonationRequest(
        hunt_id="H-GCP",
        technique_id="T1562.001",
        platform="gcp",
        target=DetonationTarget(environment="lab", platform="gcp", cloud_account="my-gcp-project"),
    )
    res = connector.detonate(req)
    assert res.success is True
    assert res.ability_id == "gcp.defense-evasion.disable-cloud-logging"
    assert calls[0] == ["warmup", "gcp.defense-evasion.disable-cloud-logging"]


def cloud_request(platform="aws", account="123456789012", technique="T1562.008", ability=None):
    return DetonationRequest(
        hunt_id="H-TEST",
        technique_id=technique,
        platform=platform,
        ability_id=ability,
        target=DetonationTarget(environment="staging", platform=platform, cloud_account=account),
    )


@pytest.mark.parametrize("cleanup", [False, True])
@pytest.mark.parametrize("active", [None, "999999999999"])
def test_identity_cannot_be_bypassed_even_with_injected_runner(monkeypatch, cleanup, active):
    from unittest.mock import Mock

    monkeypatch.setenv("HECATE_SKIP_CLOUD_IDENTITY_CHECK", "1")
    monkeypatch.setenv("AWS_ACCOUNT_ID", "123456789012")
    runner = Mock()
    connector = StratusConnector(
        runner_fn=runner, allowed_accounts=["123456789012"], identity_resolver_fn=lambda p: active
    )
    with pytest.raises(SafetyViolationError):
        (connector.cleanup if cleanup else connector.detonate)(cloud_request())
    runner.assert_not_called()


def test_aws_account_label_cannot_spoof_authenticated_identity(monkeypatch):
    from unittest.mock import Mock

    monkeypatch.setenv("AWS_ACCOUNT_ID", "123456789012")
    process = Mock(
        return_value=subprocess.CompletedProcess([], 0, '{"Account":"999999999999"}', "")
    )
    monkeypatch.setattr("hecate_runner.bas.stratus.run_process_group", process)
    connector = StratusConnector(allowed_accounts=["123456789012"])
    with pytest.raises(SafetyViolationError, match="does not match"):
        connector.detonate(cloud_request())
    assert process.call_count == 1
    assert process.call_args.args[0][:3] == ["aws", "sts", "get-caller-identity"]


@pytest.mark.parametrize("ability", [None, "aws.defense-evasion.cloudtrail-stop"])
def test_cross_cloud_ability_rejected_before_execution(ability):
    from unittest.mock import Mock

    runner = Mock()
    connector = StratusConnector(
        runner_fn=runner, allowed_accounts=["project"], identity_resolver_fn=lambda p: "project"
    )
    with pytest.raises(SafetyViolationError, match="No matching"):
        connector.detonate(cloud_request("gcp", "project", ability=ability))
    runner.assert_not_called()


def test_cloud_platform_disagreement_rejected():
    connector = StratusConnector(
        allowed_accounts=["123456789012"], identity_resolver_fn=lambda p: "123456789012"
    )
    request = cloud_request()
    request.platform = "azure"
    with pytest.raises(SafetyViolationError, match="platforms disagree"):
        connector.detonate(request)


def test_operation_uses_same_environment_as_identity_probe(monkeypatch):
    calls = []

    def process(args, **kwargs):
        calls.append((args, kwargs["env"]))
        if args[0] == "aws":
            monkeypatch.setenv("AWS_PROFILE", "changed-after-check")
            return subprocess.CompletedProcess(args, 0, '{"Account":"123456789012"}', "")
        return subprocess.CompletedProcess(args, 0, "ok", "")

    monkeypatch.setenv("AWS_PROFILE", "approved-profile")
    monkeypatch.setattr("hecate_runner.bas.stratus.run_process_group", process)
    result = StratusConnector(allowed_accounts=["123456789012"]).detonate(cloud_request())
    assert result.success
    assert len(calls) == 4
    assert all(env is calls[0][1] for _, env in calls)
    assert all(env["AWS_PROFILE"] == "approved-profile" for _, env in calls)


@pytest.mark.parametrize(
    "platform,account,technique,identity_json",
    [
        ("azure", "subscription", "T1098", '{"subscriptionId":"subscription"}'),
        ("k8s", "test-context", "T1610", '{"status":{"userInfo":{"username":"lab-user"}}}'),
    ],
)
def test_other_clouds_require_authenticated_lookup(
    monkeypatch, platform, account, technique, identity_json
):
    calls = []
    for name in (
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_CLIENT_CERTIFICATE_PATH",
        "AZURE_FEDERATED_TOKEN_FILE",
        "IDENTITY_ENDPOINT",
        "MSI_ENDPOINT",
    ):
        monkeypatch.delenv(name, raising=False)

    def process(args, **kwargs):
        calls.append((args, kwargs.get("env")))
        if args[:3] == ["kubectl", "config", "current-context"]:
            return subprocess.CompletedProcess(args, 0, account, "")
        if args[0] in {"az", "kubectl"}:
            return subprocess.CompletedProcess(args, 0, identity_json, "")
        return subprocess.CompletedProcess(args, 0, "ok", "")

    monkeypatch.setattr("hecate_runner.bas.stratus.run_process_group", process)
    result = StratusConnector(allowed_accounts=[account]).detonate(
        cloud_request(platform, account, technique)
    )
    assert result.success
    assert all(env is calls[0][1] for _, env in calls)
    if platform == "azure":
        assert calls[0][0][:2] == ["az", "rest"]
        assert calls[-1][1]["AZURE_SUBSCRIPTION_ID"] == account
        assert calls[-1][1]["ARM_SUBSCRIPTION_ID"] == account
    else:
        assert calls[1][0] == ["kubectl", "--context", account, "auth", "whoami", "-o", "json"]


def test_gcp_uses_adc_and_pins_project_for_entire_lifecycle(monkeypatch):
    from unittest.mock import Mock

    calls = []
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("GOOGLE_PROJECT", "unrelated-project")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "another-project")

    def process(args, **kwargs):
        calls.append((args, kwargs["env"]))
        if args[0] == "gcloud":
            return subprocess.CompletedProcess(args, 0, "test-adc-token", "")
        return subprocess.CompletedProcess(args, 0, "ok", "")

    response = Mock()
    response.json.return_value = {"projectId": "approved-project"}
    http_get = Mock(return_value=response)
    monkeypatch.setattr("hecate_runner.bas.stratus.run_process_group", process)
    monkeypatch.setattr("httpx.get", http_get)
    result = StratusConnector(allowed_accounts=["approved-project"]).detonate(
        cloud_request("gcp", "approved-project", "T1562.001")
    )
    assert result.success
    assert calls[0][0] == ["gcloud", "auth", "application-default", "print-access-token"]
    assert http_get.call_args.args[0].endswith("/projects/approved-project")
    assert http_get.call_args.kwargs["headers"] == {"Authorization": "Bearer test-adc-token"}
    assert all(env is calls[0][1] for _, env in calls)
    assert all(
        env["GOOGLE_PROJECT"] == env["GOOGLE_CLOUD_PROJECT"] == "approved-project"
        for _, env in calls
    )


@pytest.mark.parametrize(
    "platform,label,technique",
    [
        ("azure", "AZURE_SUBSCRIPTION_ID", "T1098"),
        ("gcp", "GOOGLE_PROJECT", "T1562.001"),
    ],
)
def test_cloud_target_label_alone_does_not_establish_access(
    monkeypatch, platform, label, technique
):
    from unittest.mock import Mock

    monkeypatch.setenv(label, "approved")
    process = Mock(return_value=subprocess.CompletedProcess([], 1, "", "not authenticated"))
    monkeypatch.setattr("hecate_runner.bas.stratus.run_process_group", process)
    with pytest.raises(SafetyViolationError, match="Cannot verify"):
        StratusConnector(allowed_accounts=["approved"]).detonate(
            cloud_request(platform, "approved", technique)
        )
    assert not any(call.args[0][0] == "stratus-red-team" for call in process.call_args_list)


def test_kubernetes_anonymous_context_is_not_authenticated(monkeypatch):
    def process(args, **kwargs):
        if args[:3] == ["kubectl", "config", "current-context"]:
            return subprocess.CompletedProcess(args, 0, "approved", "")
        return subprocess.CompletedProcess(
            args,
            0,
            '{"status":{"userInfo":{"username":"system:anonymous","groups":["system:unauthenticated"]}}}',
            "",
        )

    monkeypatch.setattr("hecate_runner.bas.stratus.run_process_group", process)
    with pytest.raises(SafetyViolationError, match="Cannot verify"):
        StratusConnector(allowed_accounts=["approved"]).detonate(
            cloud_request("k8s", "approved", "T1610")
        )
