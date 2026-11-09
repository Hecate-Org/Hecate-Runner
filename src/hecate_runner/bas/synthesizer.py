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


def synthesize_events_from_rule(
    rule_yaml: str, hunt_id: str = "", technique_id: str = ""
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Synthesize a true-positive adversary event and negative control events for a Sigma rule."""
    parsed = yaml.safe_load(rule_yaml)
    if not isinstance(parsed, dict):
        return {}, []

    logsource = parsed.get("logsource") or {}
    product = str(logsource.get("product", "linux")).lower()
    category = str(logsource.get("category", "process_creation")).lower()
    service = str(logsource.get("service", "")).lower()
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
                elif suffix.startswith("/") or suffix.startswith("\\"):
                    constructed = (
                        ("C:\\Windows\\System32" if product == "windows" else "/usr/bin")
                        + suffix
                    )
                else:
                    constructed = (
                        ("C:\\Windows\\System32\\" if product == "windows" else "/usr/bin/")
                        + suffix
                    )
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
            "C:\\Windows\\System32\\powershell.exe"
            if product == "windows"
            else "/usr/bin/bash",
        )
        tp_event.setdefault(
            "CommandLine",
            "powershell.exe -NoProfile"
            if product == "windows"
            else "/bin/bash -c 'probe'",
        )
        tp_event.setdefault("User", "SYSTEM" if product == "windows" else "root")
    elif category in ("file_event", "file_change"):
        tp_event.setdefault(
            "TargetFilename",
            "C:\\temp\\hecate_drop.tmp"
            if product == "windows"
            else "/tmp/hecate_drop.tmp",
        )
        tp_event.setdefault(
            "Image",
            "C:\\Windows\\System32\\cmd.exe"
            if product == "windows"
            else "/usr/bin/touch",
        )
    elif category == "network_connection":
        tp_event.setdefault("DestinationIp", "198.51.100.24")
        tp_event.setdefault("DestinationPort", 443)
        tp_event.setdefault("SourceIp", "10.0.0.15")
        tp_event.setdefault("SourcePort", 51234)
        tp_event.setdefault("Protocol", "tcp")
    elif category == "webserver":
        tp_event.setdefault("cs-method", "POST")
        tp_event.setdefault("cs-uri-stem", "/api/v1/resource")
        tp_event.setdefault("sc-status", 200)
        tp_event.setdefault("c-ip", "192.0.2.10")

    # Negative baseline control events
    benign_1: dict[str, Any] = {
        "product": product,
        "category": category,
        "data_source": category,
        "timestamp_utc": now_iso,
    }
    benign_2: dict[str, Any] = {
        "product": product,
        "category": category,
        "data_source": category,
        "timestamp_utc": now_iso,
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
                "Image": "C:\\Windows\\explorer.exe"
                if product == "windows"
                else "/bin/ls",
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
        benign_1.update(
            {"DestinationIp": "127.0.0.1", "DestinationPort": 53, "Protocol": "udp"}
        )
        benign_2.update(
            {"DestinationIp": "10.0.0.1", "DestinationPort": 443, "Protocol": "tcp"}
        )
    elif category == "webserver":
        benign_1.update(
            {"cs-method": "GET", "cs-uri-stem": "/robots.txt", "sc-status": 200}
        )
        benign_2.update(
            {"cs-method": "GET", "cs-uri-stem": "/favicon.ico", "sc-status": 200}
        )
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
