"""Telemetry ingestion and field normalization engine across SIEM and EDR formats.

Normalizes varied schemas (Splunk, Sentinel KQL, Elastic EQL, CrowdStrike CQL, OCSF)
into consistent, strongly-typed security entities.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger(__name__)

# Canonical field aliases across telemetry dialects
_FIELD_ALIASES: dict[str, set[str]] = {
    "host": {
        "host",
        "hostname",
        "ComputerName",
        "Computer",
        "host.name",
        "endpoint.hostname",
        "DeviceName",
    },
    "user": {
        "user",
        "username",
        "User",
        "AccountName",
        "SubjectUserName",
        "TargetUserName",
        "user.name",
        "actor.user.name",
        "Account",
    },
    "process": {
        "process",
        "process_name",
        "ProcessName",
        "image",
        "Image",
        "process.name",
        "process.executable",
        "file.name",
        "FileName",
        "FolderPath",
    },
    "parent": {
        "parent",
        "parent_process",
        "ParentProcessName",
        "parent_image",
        "ParentImage",
        "process.parent.name",
        "InitiatingProcessFileName",
        "InitiatingProcessFolderPath",
    },
    "command_line": {
        "command_line",
        "CommandLine",
        "process.command_line",
        "cmdline",
        "process.args",
        "ProcessCommandLine",
        "InitiatingProcessCommandLine",
    },
    "ip": {
        "ip",
        "dst_ip",
        "DestinationIp",
        "dest_ip",
        "remote_ip",
        "dst_endpoint.ip",
        "network.destination.ip",
        "RemoteIP",
        "DestinationIP",
        "IpAddress",
    },
    "file_path": {
        "file_path",
        "TargetFilename",
        "file.path",
        "TargetObject",
        "FilePath",
        "TargetFileName",
    },
    "hash": {
        "hash",
        "md5",
        "sha256",
        "Hashes",
        "file.hash.sha256",
        "MD5",
        "SHA256",
        "SHA1",
    },
}


@dataclass
class NormalizedEvent:
    """Strongly-typed, dialect-agnostic security event extracted from SIEM telemetry."""

    event_id: str
    hunt_id: str
    target_siem: str
    timestamp: str
    host: str = ""
    user: str = ""
    process_name: str = ""
    parent_process: str = ""
    command_line: str = ""
    ip: str = ""
    file_path: str = ""
    hash_val: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _extract_field(data: dict[str, Any], aliases: set[str]) -> str:
    """Case-insensitive recursive lookup for candidate field names in a dictionary."""
    # 1. Exact or case-insensitive top-level match
    lowered_data = {k.lower(): v for k, v in data.items() if v is not None}
    for alias in aliases:
        val = lowered_data.get(alias.lower())
        if val is not None:
            if not isinstance(val, (dict, list)) and str(val).strip():
                return str(val).strip()
            if isinstance(val, dict):
                for subkey in ("name", "hostname", "value", "id", "ip"):
                    if subkey in val and not isinstance(val[subkey], (dict, list)) and str(val[subkey]).strip():
                        return str(val[subkey]).strip()

    # 2. Dot-delimited nested object lookup (e.g. process.name or host.name)
    for alias in aliases:
        if "." in alias:
            parts = alias.split(".")
            curr: Any = data
            for part in parts:
                if isinstance(curr, dict):
                    curr = curr.get(part)
                else:
                    curr = None
                    break
            if curr is not None and not isinstance(curr, (dict, list)) and str(curr).strip():
                return str(curr).strip()

    return ""


def normalize_event(
    raw: dict[str, Any] | Any,
    target_siem: str,
    hunt_id: str,
) -> NormalizedEvent:
    """Normalize a raw SIEM row, JSON object, or event dict into a NormalizedEvent."""
    now_iso = datetime.now(UTC).isoformat()
    raw_dict: dict[str, Any] = {}

    if isinstance(raw, dict):
        raw_dict = raw
    elif isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            raw_dict = parsed if isinstance(parsed, dict) else {"raw_text": raw}
        except Exception:
            raw_dict = {"raw_text": raw}
    elif isinstance(raw, list):
        raw_dict = {f"col_{i}": val for i, val in enumerate(raw)}
    else:
        raw_dict = {"raw_value": str(raw)}

    event_id = str(raw_dict.get("event_id") or raw_dict.get("id") or f"evt-{uuid.uuid4().hex[:8]}")
    ts = str(
        raw_dict.get("timestamp")
        or raw_dict.get("@timestamp")
        or raw_dict.get("TimeGenerated")
        or raw_dict.get("_time")
        or now_iso
    )

    return NormalizedEvent(
        event_id=event_id,
        hunt_id=hunt_id.upper(),
        target_siem=target_siem.lower(),
        timestamp=ts,
        host=_extract_field(raw_dict, _FIELD_ALIASES["host"]),
        user=_extract_field(raw_dict, _FIELD_ALIASES["user"]),
        process_name=_extract_field(raw_dict, _FIELD_ALIASES["process"]),
        parent_process=_extract_field(raw_dict, _FIELD_ALIASES["parent"]),
        command_line=_extract_field(raw_dict, _FIELD_ALIASES["command_line"]),
        ip=_extract_field(raw_dict, _FIELD_ALIASES["ip"]),
        file_path=_extract_field(raw_dict, _FIELD_ALIASES["file_path"]),
        hash_val=_extract_field(raw_dict, _FIELD_ALIASES["hash"]),
        raw_data=raw_dict,
    )


def normalize_events(
    raw_list: list[Any],
    target_siem: str,
    hunt_id: str,
) -> list[NormalizedEvent]:
    """Normalize a sequence of raw log events."""
    return [normalize_event(r, target_siem, hunt_id) for r in raw_list]


def extract_entities_from_events(events: list[NormalizedEvent]) -> dict[str, list[str]]:
    """Extract and deduplicate unique security entities across a set of normalized events."""
    entities: dict[str, set[str]] = {
        "hosts": set(),
        "users": set(),
        "processes": set(),
        "parent_processes": set(),
        "ips": set(),
        "hashes": set(),
    }
    for e in events:
        if e.host:
            entities["hosts"].add(e.host)
        if e.user:
            entities["users"].add(e.user)
        if e.process_name:
            entities["processes"].add(e.process_name)
        if e.parent_process:
            entities["parent_processes"].add(e.parent_process)
        if e.ip:
            entities["ips"].add(e.ip)
        if e.hash_val:
            entities["hashes"].add(e.hash_val)

    return {k: sorted(v) for k, v in entities.items()}
