"""Predicate-aware telemetry synthesis and closed-loop Sigma validation.

Synthesizes realistic adversary True Positive telemetry events and benign baseline control
events directly from drafted Sigma rule predicates, enabling deterministic in-process
validation across process, file, network, web, cloud, and registry detections.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import yaml
from hecate_agent.core.sigma_evaluator import SigmaEvaluator, base_field, extract_modifiers

log = logging.getLogger(__name__)

_AWS_PRODUCTS = frozenset({"aws", "cloudtrail", "cloud"})
_GCP_PRODUCTS = frozenset({"gcp", "google_cloud", "google"})
_AZURE_PRODUCTS = frozenset({"azure", "azure_ad", "entra_id", "microsoft365"})
_K8S_PRODUCTS = frozenset({"kubernetes", "k8s"})
_CLOUD_AUDIT_SERVICES = frozenset(
    {"cloudtrail", "cloud_audit", "gcp", "azure", "activitylogs", "activity_log"}
)


def _infer_category(product: str, category: str | None, service: str) -> str:
    """Resolve Sigma category, including cloud products that omit category."""
    explicit = (category or "").strip().lower()
    if explicit:
        return explicit
    if product in _AWS_PRODUCTS or product in _GCP_PRODUCTS or product in _AZURE_PRODUCTS:
        return "cloud_audit"
    if product in _K8S_PRODUCTS:
        return "kubernetes_audit"
    if service in _CLOUD_AUDIT_SERVICES or service == "cloudtrail":
        return "cloud_audit"
    if service in {"sysmon", "security", "powershell"}:
        return "process_creation"
    return "process_creation"


def _is_aws_cloud(product: str, service: str) -> bool:
    return product in _AWS_PRODUCTS or service == "cloudtrail"


def _is_gcp_cloud(product: str, service: str) -> bool:
    return product in _GCP_PRODUCTS or service in {"gcp", "google_cloud"}


def _is_azure_cloud(product: str, service: str) -> bool:
    return product in _AZURE_PRODUCTS or service in {"azure", "activitylogs", "activity_log"}


def synthesize_events_from_rule(
    rule_yaml: str, hunt_id: str = "", technique_id: str = ""
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Synthesize a true-positive adversary event and negative control events for a Sigma rule."""
    parsed = yaml.safe_load(rule_yaml)
    if not isinstance(parsed, dict):
        return {}, []

    logsource = parsed.get("logsource") or {}
    product = str(logsource.get("product") or "linux").lower()
    service = str(logsource.get("service") or "").lower()
    raw_category = logsource.get("category")
    category = _infer_category(
        product,
        str(raw_category) if raw_category is not None else None,
        service,
    )
    detection = parsed.get("detection") or {}

    now_iso = datetime.now(UTC).isoformat()
    tp_event: dict[str, Any] = {
        "product": product,
        "category": category,
        "data_source": category,
        "technique_id": technique_id,
        "hunt_id": hunt_id,
        "timestamp_utc": now_iso,
        "TimeCreated": now_iso,
        "_hecate_synthetic": True,
    }
    if service:
        tp_event["service"] = service

    field_constraints: dict[str, list[tuple[list[str], Any]]] = {}

    for sel_key, sel_val in detection.items():
        if sel_key in ("condition", "timeframe") or str(sel_key).startswith("filter"):
            continue
        items_to_process = sel_val if isinstance(sel_val, list) else [sel_val]
        for item_dict in items_to_process:
            if not isinstance(item_dict, dict):
                continue
            for k, v in item_dict.items():
                f_base = base_field(k)
                mods = extract_modifiers(k)
                val = v[0] if isinstance(v, list) else v
                field_constraints.setdefault(f_base, []).append((mods, val))

    for f_base, constraints in field_constraints.items():
        prefix = ""
        suffix = ""
        body = ""
        for mods, val in constraints:
            if not isinstance(val, str):
                tp_event[f_base] = val
                break
            if "endswith" in mods:
                suffix = val
            elif "startswith" in mods:
                prefix = val
            elif "contains" in mods:
                if not body:
                    body = val
            else:
                body = val

        if f_base not in tp_event:
            all_mods = [m for c in constraints for m in c[0]]
            if "endswith" in all_mods and not prefix and not body:
                if suffix.startswith("."):
                    constructed = (
                        f"C:\\temp\\hecate_canary{suffix}"
                        if product == "windows"
                        else f"/tmp/hecate_canary{suffix}"
                    )
                elif suffix.startswith("/"):
                    # endswith '/curl' → /usr/bin/curl; endswith '/bin/sh' → /bin/sh
                    # (never /usr/bin + /bin/sh → /usr/bin/bin/sh).
                    parts = [p for p in suffix.split("/") if p]
                    constructed = f"/usr/bin/{parts[0]}" if len(parts) == 1 else suffix
                elif suffix.startswith("\\"):
                    parts = [p for p in suffix.replace("/", "\\").split("\\") if p]
                    if product == "windows" and len(parts) == 1:
                        constructed = f"C:\\Windows\\System32\\{parts[0]}"
                    elif product == "windows":
                        constructed = "C:\\Windows\\System32" + suffix
                    else:
                        constructed = "/" + "/".join(parts)
                else:
                    constructed = (
                        "C:\\Windows\\System32\\" if product == "windows" else "/usr/bin/"
                    ) + suffix
            elif "contains" in all_mods and not prefix and not suffix:
                f_lower = f_base.lower()
                if f_lower in ("commandline", "cmdline", "process_command_line"):
                    constructed = (
                        f"powershell.exe -ExecutionPolicy Bypass -Command {body}"
                        if product == "windows"
                        else f"/bin/sh -c 'test {body} --probe'"
                    )
                elif f_lower in ("cs-uri-stem", "uri", "url", "target_url"):
                    constructed = body if body.startswith("/") else f"/{body}"
                else:
                    constructed = body
            else:
                mid = (
                    "hecate_canary"
                    if (
                        suffix.startswith(".")
                        or not body
                        or body.endswith("/")
                        or body.endswith("\\")
                    )
                    else ""
                )
                constructed = prefix + body + mid + suffix
            tp_event[f_base] = constructed

    # Populate realistic system context if missing
    if category == "process_creation":
        tp_event.setdefault("ProcessId", 4096)
        tp_event.setdefault(
            "Image",
            "C:\\Windows\\System32\\powershell.exe" if product == "windows" else "/usr/bin/bash",
        )
        tp_event.setdefault(
            "CommandLine",
            "powershell.exe -NoProfile" if product == "windows" else "/bin/bash -c 'probe'",
        )
        tp_event.setdefault("User", "SYSTEM" if product == "windows" else "root")
    elif category in ("file_event", "file_change"):
        tp_event.setdefault(
            "TargetFilename",
            "C:\\temp\\hecate_drop.tmp" if product == "windows" else "/tmp/hecate_drop.tmp",
        )
        tp_event.setdefault(
            "Image",
            "C:\\Windows\\System32\\cmd.exe" if product == "windows" else "/usr/bin/touch",
        )
    elif category == "network_connection":
        tp_event.setdefault("DestinationIp", "198.51.100.24")
        tp_event.setdefault("DestinationPort", 443)
        tp_event.setdefault("SourceIp", "10.0.0.15")
        tp_event.setdefault("SourcePort", 51234)
        tp_event.setdefault("Protocol", "tcp")
    elif category in ("registry_set", "registry_event", "registry_add", "registry_delete"):
        tp_event.setdefault(
            "TargetObject",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\hecate_service\\ImagePath",
        )
        tp_event.setdefault("Details", "C:\\temp\\hecate_payload.exe")
        tp_event.setdefault("Image", "C:\\Windows\\System32\\reg.exe")
    elif category in ("pipe_created", "named_pipe"):
        tp_event.setdefault("PipeName", "\\hecate_canary_pipe")
        tp_event.setdefault("Image", "C:\\Windows\\System32\\cmd.exe")
    elif category == "driver_load":
        tp_event.setdefault("ImageLoaded", "C:\\Windows\\System32\\drivers\\hecate_canary.sys")
        tp_event.setdefault("Signed", "false")
        tp_event.setdefault("SignatureStatus", "unsigned")
    elif category == "dns_query":
        tp_event.setdefault("QueryName", "c2.example.com")
        tp_event.setdefault(
            "Image",
            "C:\\Windows\\System32\\powershell.exe" if product == "windows" else "/usr/bin/curl",
        )
    elif category == "webserver":
        tp_event.setdefault("cs-method", "POST")
        tp_event.setdefault("cs-uri-stem", "/api/v1/resource")
        tp_event.setdefault("sc-status", 200)
        tp_event.setdefault("c-ip", "192.0.2.10")
    elif category in ("cloud_audit", "identity_audit") or _is_gcp_cloud(product, service):
        if _is_gcp_cloud(product, service) or (
            category in ("cloud_audit", "identity_audit") and product in _GCP_PRODUCTS
        ):
            tp_event.setdefault("protoPayload.serviceName", "iam.googleapis.com")
            tp_event.setdefault(
                "protoPayload.methodName",
                "google.iam.admin.v1.CreateServiceAccountKey",
            )
            tp_event.setdefault(
                "protoPayload.authenticationInfo.principalEmail",
                "admin@example.com",
            )
        elif _is_azure_cloud(product, service):
            tp_event.setdefault("operationName", "Microsoft.Authorization/roleAssignments/write")
            tp_event.setdefault("resultType", "Success")
            tp_event.setdefault("caller", "admin@contoso.com")
            tp_event.setdefault("Level", "Informational")
        else:
            # AWS CloudTrail / generic cloud_audit default
            tp_event.setdefault("eventSource", "iam.amazonaws.com")
            tp_event.setdefault("eventName", "CreateUser")
            tp_event.setdefault("awsRegion", "us-east-1")
            tp_event.setdefault("sourceIPAddress", "198.51.100.55")
            tp_event.setdefault("userAgent", "aws-cli/2.15.0")
            tp_event.setdefault(
                "userIdentity",
                {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::123456789012:user/admin",
                    "userName": "admin",
                },
            )
    elif category == "kubernetes_audit" or product in _K8S_PRODUCTS:
        tp_event.setdefault("verb", "create")
        tp_event.setdefault("resource", "pods")
        tp_event.setdefault("namespace", "kube-system")

    # Negative baseline control events
    benign_1: dict[str, Any] = {
        "product": product,
        "category": category,
        "data_source": category,
        "timestamp_utc": now_iso,
        "_hecate_synthetic": True,
    }
    benign_2: dict[str, Any] = {
        "product": product,
        "category": category,
        "data_source": category,
        "timestamp_utc": now_iso,
        "_hecate_synthetic": True,
    }

    if category == "process_creation":
        benign_1.update(
            {
                "Image": "C:\\Windows\\System32\\svchost.exe"
                if product == "windows"
                else "/usr/lib/systemd/systemd-journald",
                "CommandLine": "svchost.exe -k netsvcs"
                if product == "windows"
                else "/usr/lib/systemd/systemd-journald",
                "ProcessId": 1024,
            }
        )
        benign_2.update(
            {
                "Image": "C:\\Windows\\explorer.exe" if product == "windows" else "/bin/ls",
                "CommandLine": "C:\\Windows\\explorer.exe"
                if product == "windows"
                else "ls -la /var/log",
                "ProcessId": 2048,
            }
        )
    elif category in ("file_event", "file_change"):
        benign_1.update(
            {
                "TargetFilename": "C:\\Windows\\System32\\config\\system"
                if product == "windows"
                else "/var/log/syslog",
                "Image": "C:\\Windows\\System32\\ntoskrnl.exe"
                if product == "windows"
                else "/usr/bin/rsyslogd",
            }
        )
        benign_2.update(
            {
                "TargetFilename": "C:\\Windows\\Temp\\empty.log"
                if product == "windows"
                else "/etc/hosts",
                "Image": "C:\\Windows\\System32\\notepad.exe"
                if product == "windows"
                else "/usr/bin/nano",
            }
        )
    elif category == "network_connection":
        benign_1.update({"DestinationIp": "127.0.0.1", "DestinationPort": 53, "Protocol": "udp"})
        benign_2.update({"DestinationIp": "10.0.0.1", "DestinationPort": 443, "Protocol": "tcp"})
    elif category in ("registry_set", "registry_event", "registry_add", "registry_delete"):
        benign_1.update(
            {
                "TargetObject": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Hostname",
                "Details": "localhost",
                "Image": "C:\\Windows\\System32\\svchost.exe",
            }
        )
        benign_2.update(
            {
                "TargetObject": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters\\NtpServer",
                "Details": "time.windows.com",
                "Image": "C:\\Windows\\System32\\svchost.exe",
            }
        )
    elif category in ("pipe_created", "named_pipe"):
        benign_1.update({"PipeName": "\\spoolss", "Image": "C:\\Windows\\System32\\spoolsv.exe"})
        benign_2.update({"PipeName": "\\lsass", "Image": "C:\\Windows\\System32\\lsass.exe"})
    elif category == "driver_load":
        benign_1.update(
            {
                "ImageLoaded": "C:\\Windows\\System32\\drivers\\ntfs.sys",
                "Signed": "true",
                "SignatureStatus": "Valid",
            }
        )
        benign_2.update(
            {
                "ImageLoaded": "C:\\Windows\\System32\\drivers\\tcpip.sys",
                "Signed": "true",
                "SignatureStatus": "Valid",
            }
        )
    elif category == "dns_query":
        benign_1.update(
            {
                "QueryName": "ntp.ubuntu.com",
                "Image": "C:\\Windows\\System32\\svchost.exe"
                if product == "windows"
                else "/usr/lib/systemd/systemd-timesyncd",
            }
        )
        benign_2.update(
            {
                "QueryName": "time.windows.com",
                "Image": "C:\\Windows\\System32\\svchost.exe",
            }
        )
    elif category in ("cloud_audit", "identity_audit") or _is_gcp_cloud(product, service):
        if _is_gcp_cloud(product, service) or product in _GCP_PRODUCTS:
            benign_1.update(
                {
                    "protoPayload.serviceName": "compute.googleapis.com",
                    "protoPayload.methodName": "v1.compute.instances.get",
                    "protoPayload.authenticationInfo.principalEmail": "viewer@example.com",
                }
            )
            benign_2.update(
                {
                    "protoPayload.serviceName": "storage.googleapis.com",
                    "protoPayload.methodName": "storage.buckets.list",
                    "protoPayload.authenticationInfo.principalEmail": "viewer@example.com",
                }
            )
        elif _is_azure_cloud(product, service):
            benign_1.update(
                {
                    "operationName": "Microsoft.Resources/subscriptions/resourceGroups/read",
                    "resultType": "Success",
                    "caller": "reader@contoso.com",
                }
            )
            benign_2.update(
                {
                    "operationName": "Microsoft.Storage/storageAccounts/listKeys/action",
                    "resultType": "Success",
                    "caller": "reader@contoso.com",
                }
            )
        else:
            benign_1.update(
                {
                    "eventSource": "ec2.amazonaws.com",
                    "eventName": "DescribeInstances",
                    "awsRegion": "us-east-1",
                    "sourceIPAddress": "10.0.1.20",
                    "userAgent": "aws-sdk-go/v1.44.0",
                }
            )
            benign_2.update(
                {
                    "eventSource": "s3.amazonaws.com",
                    "eventName": "ListBuckets",
                    "awsRegion": "us-east-1",
                    "sourceIPAddress": "10.0.1.20",
                    "userAgent": "console.amazonaws.com",
                }
            )
    elif category == "kubernetes_audit" or product in _K8S_PRODUCTS:
        benign_1.update(
            {
                "verb": "get",
                "resource": "pods",
                "namespace": "kube-system",
                "user": {"username": "system:node:worker-1"},
            }
        )
        benign_2.update(
            {
                "verb": "list",
                "resource": "services",
                "namespace": "default",
                "user": {"username": "system:serviceaccount:default:ingress-nginx"},
            }
        )
    elif category == "webserver":
        benign_1.update({"cs-method": "GET", "cs-uri-stem": "/robots.txt", "sc-status": 200})
        benign_2.update({"cs-method": "GET", "cs-uri-stem": "/favicon.ico", "sc-status": 200})
    else:
        benign_1["CommandLine"] = "benign_system_baseline_process"
        benign_2["CommandLine"] = "benign_routine_telemetry"

    return tp_event, [benign_1, benign_2]


def evaluate_rule_synthetically(
    rule_yaml: str, hunt_id: str = "", technique_id: str = ""
) -> dict[str, Any]:
    """Execute in-memory true-positive and control evaluation using SigmaEvaluator."""
    tp_event, benign_events = synthesize_events_from_rule(
        rule_yaml, hunt_id=hunt_id, technique_id=technique_id
    )
    report = SigmaEvaluator.evaluate_rule(rule_yaml, [tp_event], benign_events)
    return {
        "rule_triggered": report.true_positives > 0,
        "true_positives": report.true_positives,
        "false_positives": report.false_positives,
        "is_clean": report.is_clean,
        "tp_event": tp_event,
        "benign_events": benign_events,
    }
