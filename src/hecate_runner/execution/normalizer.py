"""Telemetry ingestion and field normalization engine aligned with OCSF schema.

Normalizes varied telemetry dialects (Splunk, Sentinel KQL, Elastic EQL, CrowdStrike CQL)
into strongly-typed Open Cybersecurity Schema Framework (OCSF) entity models and supports
endpoint-to-network lineage fusion.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

log = logging.getLogger(__name__)


class OCSFClassUID(IntEnum):
    """Canonical Open Cybersecurity Schema Framework (OCSF) Class Identifiers."""

    BASE_EVENT = 0
    FILE_ACTIVITY = 1001
    PROCESS_ACTIVITY = 1007
    SECURITY_FINDING = 2001
    AUTHENTICATION = 3001
    NETWORK_ACTIVITY = 4001
    DNS_ACTIVITY = 4003


class OCSFCategoryUID(IntEnum):
    """Canonical OCSF Category Identifiers."""

    UNSPECIFIED = 0
    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IDENTITY_AND_ACCESS = 3
    NETWORK_ACTIVITY = 4


# Canonical field aliases across telemetry dialects and OCSF object paths
_FIELD_ALIASES: dict[str, set[str]] = {
    "host": {
        "host",
        "hostname",
        "ComputerName",
        "Computer",
        "host.name",
        "endpoint.hostname",
        "DeviceName",
        "device.hostname",
        "device.name",
        "agent.hostname",
        "winlog.computer_name",
        "src_host",
        "dst_host",
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
        "actor.user.uid",
        "Account",
        "UserName",
    },
    "process": {
        "process",
        "process_name",
        "ProcessName",
        "image",
        "Image",
        "process.name",
        "process.executable",
        "process.file.name",
        "file.name",
        "FileName",
        "FolderPath",
        "InitiatingProcessFileName",
        "target_process_name",
        "NewProcessName",
        "ImageFileName",
    },
    "parent": {
        "parent",
        "parent_process",
        "ParentProcessName",
        "parent_image",
        "ParentImage",
        "process.parent.name",
        "process.parent_process.name",
        "process.parent.executable",
        "InitiatingProcessParentFileName",
        "InitiatingProcessFolderPath",
        "ParentBaseFileName",
    },
    "command_line": {
        "command_line",
        "CommandLine",
        "process.command_line",
        "process.cmd_line",
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
        "destination_ip",
        "src_ip",
        "source_ip",
        "SourceIp",
    },
    "src_ip": {
        "src_ip",
        "src",
        "source_ip",
        "SourceIp",
        "src_endpoint.ip",
        "source.ip",
        "network.source.ip",
        "c-ip",
        "SourceAddress",
        "src_addr",
        "client_ip",
        "ClientIP",
    },
    "dst_ip": {
        "dst_ip",
        "dest_ip",
        "dest",
        "DestinationIp",
        "dst_endpoint.ip",
        "destination.ip",
        "network.destination.ip",
        "remote_ip",
        "RemoteIP",
        "DestinationAddress",
        "dst_addr",
        "destination_ip",
        "server_ip",
        "ServerIP",
    },
    "src_port": {
        "src_port",
        "source_port",
        "SourcePort",
        "src_endpoint.port",
        "source.port",
        "network.source.port",
        "s_port",
    },
    "dst_port": {
        "dst_port",
        "dest_port",
        "DestinationPort",
        "dst_endpoint.port",
        "destination.port",
        "network.destination.port",
        "d_port",
    },
    "pid": {
        "pid",
        "process_id",
        "ProcessId",
        "process.pid",
        "NewProcessId",
        "TargetProcessId",
    },
    "parent_pid": {
        "parent_pid",
        "parent_process_id",
        "ParentProcessId",
        "process.parent.pid",
        "process.parent_process.pid",
    },
    "file_path": {
        "file_path",
        "TargetFilename",
        "file.path",
        "TargetObject",
        "FilePath",
        "TargetFileName",
        "file.name",
    },
    "hash": {
        "hash",
        "md5",
        "sha256",
        "Hashes",
        "file.hash.sha256",
        "file.hash.md5",
        "file.hash.sha1",
        "file.hashes.md5",
        "file.hashes.sha1",
        "MD5",
        "SHA256",
        "SHA1",
        "file.hashes.sha256",
    },
    "domain": {
        "domain",
        "queryname",
        "query",
        "domain_name",
        "destinationhostname",
        "cs-host",
        "query_name",
        "dns.query.name",
        "dns.question.name",
        "QueryName",
        "dst_endpoint.domain",
        "rdata",
        "answer",
        "dns_query",
    },
}


def classify_ocsf_event(data: dict[str, Any], query_file: str = "") -> tuple[int, str, int, str]:
    """Classify raw telemetry or dialect dict into standard OCSF class and category."""
    domain_val = _extract_field(data, _FIELD_ALIASES["domain"])
    event_code = str(data.get("EventCode") or data.get("EventID") or "")
    sourcetype = str(data.get("sourcetype") or "").lower()
    q_lower = query_file.lower()
    proc_name = _extract_field(data, _FIELD_ALIASES["process"])
    cmd_line = _extract_field(data, _FIELD_ALIASES["command_line"])
    file_path = _extract_field(data, _FIELD_ALIASES["file_path"])
    dst_ip = _extract_field(data, _FIELD_ALIASES["dst_ip"])
    is_network_st = any(
        k in sourcetype
        for k in ("network", "traffic", "zeek", "suricata", "pan:traffic", "netflow")
    )

    # Explicit DNS signals only. A DestinationHostname on process/network rows
    # must not override EventCode 1/3/4688 classification.
    if event_code == "22" or "dns" in sourcetype or "stream:dns" in sourcetype or "dns" in q_lower:
        return (
            int(OCSFClassUID.DNS_ACTIVITY),
            "DNS Activity",
            int(OCSFCategoryUID.NETWORK_ACTIVITY),
            "Network Activity",
        )

    if event_code in ("4624", "4625") or "auth" in sourcetype or "login" in q_lower:
        return (
            int(OCSFClassUID.AUTHENTICATION),
            "Authentication",
            int(OCSFCategoryUID.IDENTITY_AND_ACCESS),
            "Identity & Access Management",
        )

    # Process creation before domain-only DNS so Sysmon 1/4688 + DestinationHostname
    # stays Process Activity.
    if event_code in ("1", "4688") or (
        (cmd_line or proc_name or "process" in sourcetype or "audit" in sourcetype)
        and event_code not in ("3", "11", "2")
        and not is_network_st
    ):
        return (
            int(OCSFClassUID.PROCESS_ACTIVITY),
            "Process Activity",
            int(OCSFCategoryUID.SYSTEM_ACTIVITY),
            "System Activity",
        )

    if event_code in ("11", "2") or (file_path and not proc_name) or "file" in sourcetype:
        return (
            int(OCSFClassUID.FILE_ACTIVITY),
            "File Activity",
            int(OCSFCategoryUID.SYSTEM_ACTIVITY),
            "System Activity",
        )

    if (
        event_code == "3"
        or is_network_st
        or "network" in q_lower
        or "egress" in q_lower
        or (dst_ip and not cmd_line)
    ):
        return (
            int(OCSFClassUID.NETWORK_ACTIVITY),
            "Network Activity",
            int(OCSFCategoryUID.NETWORK_ACTIVITY),
            "Network Activity",
        )

    # Domain/query-only rows with no stronger process/network signal.
    if domain_val:
        return (
            int(OCSFClassUID.DNS_ACTIVITY),
            "DNS Activity",
            int(OCSFCategoryUID.NETWORK_ACTIVITY),
            "Network Activity",
        )

    if proc_name or cmd_line:
        return (
            int(OCSFClassUID.PROCESS_ACTIVITY),
            "Process Activity",
            int(OCSFCategoryUID.SYSTEM_ACTIVITY),
            "System Activity",
        )

    return (
        int(OCSFClassUID.BASE_EVENT),
        "Base Event",
        int(OCSFCategoryUID.UNSPECIFIED),
        "Unspecified",
    )


@dataclass
class NormalizedEvent:
    """Strongly-typed, dialect-agnostic security event aligned with OCSF v1.1.0."""

    event_id: str
    hunt_id: str
    target_siem: str
    timestamp: str

    # Flat dialect-agnostic accessors (100% backward compatible)
    host: str = ""
    user: str = ""
    process_name: str = ""
    parent_process: str = ""
    command_line: str = ""
    ip: str = ""
    file_path: str = ""
    hash_val: str = ""
    stage: str = ""
    stage_label: str = ""
    query_file: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)

    # OCSF Top-Level Schema Properties
    class_uid: int = int(OCSFClassUID.BASE_EVENT)
    class_name: str = "Base Event"
    category_uid: int = int(OCSFCategoryUID.UNSPECIFIED)
    category_name: str = "Unspecified"
    activity_id: int = 0
    activity_name: str = ""

    # Extended Entity Attributes
    domain: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    pid: str = ""
    parent_pid: str = ""

    # Endpoint-to-Network Fusion Tracking
    fused_lineage: bool = False
    fusion_source: str = ""
    fusion_detail: str = ""

    def needs_lineage_fusion(self) -> bool:
        """True if this event represents network/DNS telemetry lacking endpoint process context."""
        if self.fused_lineage:
            # Already fused once — avoid re-entry loops on partial lineage.
            return False
        has_c2_indicator = bool(self.dst_ip or self.domain or self.ip)
        has_endpoint = bool(self.host or self.src_ip)
        lacks_process_lineage = not (self.process_name and self.command_line)
        is_network_or_dns = self.class_uid in (
            int(OCSFClassUID.NETWORK_ACTIVITY),
            int(OCSFClassUID.DNS_ACTIVITY),
            int(OCSFClassUID.BASE_EVENT),
        )
        return has_c2_indicator and has_endpoint and lacks_process_lineage and is_network_or_dns

    def fuse_process_lineage(
        self,
        process_name: str,
        parent_process: str = "",
        command_line: str = "",
        user: str = "",
        pid: str = "",
        parent_pid: str = "",
        fusion_source: str = "endpoint_network_fusion",
        fusion_detail: str = "",
    ) -> None:
        """Fuse recovered endpoint process execution context into this network/DNS event.

        Parent-only tips are stored without setting ``fused_lineage``, so a later
        pass can still recover process name / command line.
        """
        if process_name:
            self.process_name = process_name
        if parent_process:
            self.parent_process = parent_process
        if command_line:
            self.command_line = command_line
        if user and not self.user:
            self.user = user
        if pid:
            self.pid = pid
        if parent_pid:
            self.parent_pid = parent_pid
        # Require process name or command line before claiming fusion complete.
        if not (self.process_name or self.command_line):
            return
        self.fused_lineage = True
        self.fusion_source = fusion_source
        self.fusion_detail = (
            fusion_detail
            or f"Fused process '{self.process_name}' (parent: '{self.parent_process}')"
        )
        self.raw_data["_hecate_fusion"] = {
            "fused_process": self.process_name,
            "fused_parent": self.parent_process,
            "fused_command_line": self.command_line,
            "fused_user": self.user,
            "fused_pid": self.pid,
            "fusion_source": self.fusion_source,
            "fusion_detail": self.fusion_detail,
        }

    def to_ocsf_dict(self) -> dict[str, Any]:
        """Serialize event into standard OCSF v1.1.0 JSON-compatible dictionary."""
        epoch_millis = 0
        try:
            raw_ts = str(self.timestamp or "").strip()
            if re.fullmatch(r"\d+(\.\d+)?", raw_ts):
                epoch_millis = int(float(raw_ts) * 1000)
            else:
                dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                epoch_millis = int(dt.timestamp() * 1000)
        except Exception:
            epoch_millis = int(datetime.now(UTC).timestamp() * 1000)

        ocsf_obj: dict[str, Any] = {
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "Hecate",
                    "vendor_name": "Hecate-CTI",
                    "feature": {"name": "Hunting Engine"},
                },
                "event_id": self.event_id,
                "correlation_id": self.hunt_id,
            },
            "class_uid": self.class_uid,
            "class_name": self.class_name,
            "category_uid": self.category_uid,
            "category_name": self.category_name,
            "activity_id": self.activity_id,
            "activity_name": self.activity_name or self.class_name,
            "time": epoch_millis,
            "time_dt": self.timestamp,
            "severity_id": 3 if self.stage else 1,
            "device": {
                "hostname": self.host,
                "ip": self.src_ip or (_host_if_ip(self.host)),
            },
            "actor": {
                "user": {
                    "name": self.user,
                }
            },
            "src_endpoint": {
                "ip": self.src_ip or (_host_if_ip(self.host)),
                "port": self.src_port,
            },
            "dst_endpoint": {
                "ip": self.dst_ip or self.ip,
                "port": self.dst_port,
                "domain": self.domain,
                "hostname": self.domain,
            },
            "process": {
                "name": self.process_name,
                "cmd_line": self.command_line,
                "pid": _parse_whole_number(self.pid),
                "file": {
                    "name": self.process_name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
                    if self.process_name
                    else "",
                    "path": self.process_name
                    if ("/" in self.process_name or "\\" in self.process_name)
                    else "",
                },
                "parent_process": {
                    "name": self.parent_process,
                    "pid": _parse_whole_number(self.parent_pid),
                },
            },
        }
        if self.file_path or self.hash_val:
            ocsf_obj["file"] = {
                "path": self.file_path,
                "name": self.file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
                if self.file_path
                else "",
                "hashes": _hash_dict_for_ocsf(self.hash_val),
            }
        if self.domain:
            ocsf_obj["dns"] = {
                "query": {
                    "hostname": self.domain,
                    "type": "A",
                }
            }
        if self.fused_lineage:
            ocsf_obj["enrichments"] = [
                {
                    "name": "endpoint_network_fusion",
                    "value": self.fusion_detail,
                    "provider": "hecate.fusion",
                }
            ]
        ocsf_obj["unmapped"] = self.raw_data
        return ocsf_obj

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _host_if_ip(value: str) -> str:
    """Return ``value`` when it is an IPv4 or IPv6 literal; otherwise empty."""
    text = str(value or "").strip()
    if not text:
        return ""
    # Common URI / log bracketing: [2001:db8::1]
    if text.startswith("[") and text.endswith("]") and ":" in text:
        text = text[1:-1].strip()
    # Drop IPv6 zone identifiers (fe80::1%eth0) before parsing.
    if "%" in text and ":" in text:
        text = text.split("%", 1)[0]
    try:
        import ipaddress

        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _hash_dict_for_ocsf(hash_val: str) -> dict[str, str]:
    """Map a hash string to the appropriate OCSF ``file.hashes`` key by length."""
    text = str(hash_val or "").strip()
    if not text:
        return {}
    # Hex digest lengths: MD5=32, SHA1=40, SHA256=64
    if len(text) == 64 and re.fullmatch(r"[0-9a-fA-F]+", text):
        return {"sha256": text}
    if len(text) == 40 and re.fullmatch(r"[0-9a-fA-F]+", text):
        return {"sha1": text}
    if len(text) == 32 and re.fullmatch(r"[0-9a-fA-F]+", text):
        return {"md5": text}
    return {"hash": text}


def _dict_get_ci(mapping: dict[str, Any], key: str) -> Any:
    """Return ``mapping[key]`` with case-insensitive key fallback."""
    if key in mapping:
        return mapping[key]
    key_l = key.lower()
    for existing, value in mapping.items():
        if isinstance(existing, str) and existing.lower() == key_l:
            return value
    return None


def _dig_dotted_path(data: dict[str, Any], dotted: str) -> Any:
    """Walk a dotted path with case-insensitive key matching at each level."""
    curr: Any = data
    for part in dotted.split("."):
        if not isinstance(curr, dict):
            return None
        curr = _dict_get_ci(curr, part)
        if curr is None:
            return None
    return curr


def _first_scalar(value: Any) -> str:
    """Return the first non-empty scalar from a value, list, or trivial object wrapper."""
    if value is None or isinstance(value, bool):
        # Booleans must not become hostnames/users ("True" / "False").
        return ""
    if isinstance(value, list):
        for item in value:
            found = _first_scalar(item)
            if found:
                return found
        return ""
    if isinstance(value, dict):
        for subkey in ("name", "hostname", "value", "id", "ip"):
            found = _first_scalar(_dict_get_ci(value, subkey))
            if found:
                return found
        return ""
    text = str(value).strip()
    return text


def _extract_field(data: dict[str, Any], aliases: set[str]) -> str:
    """Case-insensitive recursive lookup for candidate field names in a dictionary."""
    # 1. Exact or case-insensitive top-level match
    lowered_data = {str(k).lower(): v for k, v in data.items() if v is not None}
    for alias in aliases:
        val = lowered_data.get(alias.lower())
        if val is not None:
            found = _first_scalar(val)
            if found:
                return found

    # 2. Dot-delimited nested object lookup (e.g. process.name or Device.Hostname)
    for alias in aliases:
        if "." not in alias:
            continue
        found = _first_scalar(_dig_dotted_path(data, alias))
        if found:
            return found

    return ""


def _parse_port(value: str) -> int | None:
    """Parse a port from digits or whole-number floats like ``443.0``."""
    parsed = _parse_whole_number(value)
    return parsed if parsed is not None and 0 <= parsed <= 65535 else None


def _parse_whole_number(value: Any) -> int | None:
    """Parse a non-negative int from digits or whole-number floats like ``42.0``."""
    if isinstance(value, bool):
        return None
    text = str(value or "").strip()
    if not text:
        return None
    if text.isdigit():
        return int(text)
    try:
        as_float = float(text)
    except ValueError:
        return None
    if not as_float.is_integer() or as_float < 0:
        return None
    return int(as_float)


def _normalize_id_str(value: str) -> str:
    """Canonicalize process IDs so ``42.0`` becomes ``42`` for OCSF export."""
    parsed = _parse_whole_number(value)
    if parsed is None:
        # Drop negative / non-numeric PIDs rather than persisting junk.
        text = str(value or "").strip()
        return text if text.isdigit() else ""
    return str(parsed)


def _normalize_hash(value: str) -> str:
    """Strip common ``MD5=`` / ``SHA256=`` prefixes from hash fields."""
    text = str(value or "").strip()
    if not text:
        return ""
    for prefix in ("MD5=", "SHA256=", "SHA1=", "IMPHASH="):
        if text.upper().startswith(prefix):
            return text.split("=", 1)[1].strip()
    if "=" in text and re.match(r"^(?i)(md5|sha1|sha256|imphash)\s*=", text):
        return text.split("=", 1)[1].strip()
    return text


def normalize_event(
    raw: dict[str, Any] | Any,
    target_siem: str,
    hunt_id: str,
) -> NormalizedEvent:
    """Normalize a raw SIEM row, JSON object, or event dict into an OCSF-aligned NormalizedEvent."""
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
    # Splunk-style epoch _time → ISO so OCSF export and correlation share one clock.
    if re.fullmatch(r"\d+(\.\d+)?", ts.strip()):
        with contextlib.suppress(OverflowError, OSError, ValueError):
            ts = datetime.fromtimestamp(float(ts), tz=UTC).isoformat()

    domain_val = _extract_field(raw_dict, _FIELD_ALIASES["domain"])
    src_ip_val = _extract_field(raw_dict, _FIELD_ALIASES["src_ip"])
    dst_ip_val = _extract_field(raw_dict, _FIELD_ALIASES["dst_ip"])
    ip_val = dst_ip_val or _extract_field(raw_dict, _FIELD_ALIASES["ip"]) or src_ip_val

    src_port = _parse_port(_extract_field(raw_dict, _FIELD_ALIASES["src_port"]))
    dst_port = _parse_port(_extract_field(raw_dict, _FIELD_ALIASES["dst_port"]))

    pid_val = _normalize_id_str(_extract_field(raw_dict, _FIELD_ALIASES["pid"]))
    parent_pid_val = _normalize_id_str(_extract_field(raw_dict, _FIELD_ALIASES["parent_pid"]))

    q_file = str(raw_dict.get("_hecate_query_file") or "")
    class_uid, class_name, cat_uid, cat_name = classify_ocsf_event(raw_dict, query_file=q_file)

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
        ip=ip_val,
        file_path=_extract_field(raw_dict, _FIELD_ALIASES["file_path"]),
        hash_val=_normalize_hash(_extract_field(raw_dict, _FIELD_ALIASES["hash"])),
        stage=str(raw_dict.get("_hecate_stage") or ""),
        stage_label=str(raw_dict.get("_hecate_stage_label") or ""),
        query_file=q_file,
        raw_data=raw_dict,
        class_uid=class_uid,
        class_name=class_name,
        category_uid=cat_uid,
        category_name=cat_name,
        domain=domain_val,
        src_ip=src_ip_val,
        dst_ip=dst_ip_val,
        src_port=src_port,
        dst_port=dst_port,
        pid=pid_val,
        parent_pid=parent_pid_val,
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
        "domains": set(),
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
        if e.dst_ip:
            entities["ips"].add(e.dst_ip)
        if e.src_ip:
            entities["ips"].add(e.src_ip)
        if e.hash_val:
            entities["hashes"].add(e.hash_val)
        if e.domain:
            entities["domains"].add(e.domain)
        domain_val = _extract_field(e.raw_data, _FIELD_ALIASES["domain"])
        if domain_val:
            entities["domains"].add(domain_val)

    return {k: sorted(v) for k, v in entities.items()}
