"""Independent execve observation inside the isolated Linux BAS container.

strace supervises the agent and records successful process executions. CALDERA
link records are deliberately not used as detection telemetry. This is local
sensor evidence evaluated with Sigma, not evidence of a SIEM alert.
"""

from __future__ import annotations

import ast
import json
import re
import shlex
import subprocess
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from hecate_runner.bas.base import DetonationResult, SafetyViolationError

TRACE_PATH = "/tmp/hecate-exec.trace"
APPROVED_AGENT_IMAGES = {
    "sha256:63dbe5e24c5b8b852ddf0680032488291363c23b5b4fa975445ea0f41a909fbd",
}
SENSOR_ENTRYPOINT = [
    "/usr/bin/strace",
    "-f",
    "-qq",
    "-ttt",
    "-s",
    "8192",
    "-e",
    "trace=execve,execveat",
    "-e",
    "signal=none",
    "-o",
    TRACE_PATH,
    "/usr/local/bin/sandcat",
]
APPROVED_SENSOR_ENTRYPOINTS = {
    tuple(SENSOR_ENTRYPOINT),
    (
        "/usr/bin/strace",
        "-f",
        "-qq",
        "-ttt",
        "-s",
        "8192",
        "-e",
        "trace=execve,execveat,open,openat,creat,unlink,unlinkat,rename,renameat,renameat2,connect",
        "-e",
        "signal=none",
        "-o",
        TRACE_PATH,
        "/usr/local/bin/sandcat",
    ),
}
_EXEC = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<time>\d+\.\d+)\s+execve\("
    r'(?P<path>"(?:\\.|[^"\\])*")\s*,\s*'
    r"(?P<args>\[.*?\])\s*,"
)
_RESUMED = re.compile(r"^\s*(\d+)\s+\d+\.\d+\s+<\.\.\. execve resumed>.*= 0$")

_OPEN_SYSCALL = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<time>\d+\.\d+)\s+(?:open|openat)\((?:AT_FDCWD,\s*)?"
    r'(?P<path>"(?:\\.|[^"\\])*")\s*,\s*'
    r"(?P<flags>[^,\)]+)"
)
_CREAT_SYSCALL = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<time>\d+\.\d+)\s+creat\("
    r'(?P<path>"(?:\\.|[^"\\])*")\s*,\s*'
    r"(?P<mode>[^,\)]+)"
)
_UNLINK_SYSCALL = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<time>\d+\.\d+)\s+(?:unlink|unlinkat)\((?:AT_FDCWD,\s*)?"
    r'(?P<path>"(?:\\.|[^"\\])*")'
)
_RENAME_SYSCALL = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<time>\d+\.\d+)\s+(?:rename|renameat|renameat2)\((?:AT_FDCWD,\s*)?"
    r'(?P<oldpath>"(?:\\.|[^"\\])*")\s*,\s*(?:AT_FDCWD,\s*)?'
    r'(?P<newpath>"(?:\\.|[^"\\])*")'
)
_CONNECT_SYSCALL = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<time>\d+\.\d+)\s+connect\(\d+,\s*"
    r"\{sa_family=AF_INET,\s*sin_port=htons\((?P<port>\d+)\),\s*"
    r'sin_addr=inet_addr\("(?P<ip>[^"\\]+)"\)\}'
)
_RESUMED_FILE = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<time>\d+\.\d+)\s+<\.\.\.\s+(?:open|openat|unlink|unlinkat|creat|rename|renameat|renameat2)\s+resumed>.*=\s*(?P<ret>-?\d+)"
)


def parse_exec_trace(
    text: str, *, start: float, end: float, host: str, command: str | tuple[str, ...]
) -> list[dict[str, Any]]:
    """Return successful, bounded executions of the exact approved command."""
    events: list[dict[str, Any]] = []
    pending: dict[str, dict[str, Any]] = {}
    expected = list(shlex.split(command) if isinstance(command, str) else command)
    if not expected:
        return []
    for line in text.splitlines():
        match = _EXEC.match(line)
        if match:
            try:
                timestamp = float(match["time"])
                image = ast.literal_eval(match["path"])
                argv = ast.literal_eval(match["args"])
            except (ValueError, SyntaxError):
                continue
            if (
                not start <= timestamp <= end
                or not isinstance(argv, list)
                or argv != expected
                or PurePosixPath(image).name != PurePosixPath(expected[0]).name
            ):
                continue
            event = {
                "data_source": "process_creation",
                "category": "process_creation",
                "product": "linux",
                "sensor": "lab_execve",
                "Computer": host,
                "Image": image,
                "CommandLine": shlex.join(argv),
                "ProcessId": int(match["pid"]),
                "UtcTime": datetime.fromtimestamp(timestamp, UTC).isoformat(),
            }
            if line.endswith("= 0"):
                events.append(event)
            elif "<unfinished ...>" in line:
                pending[match["pid"]] = event
        else:
            resumed = _RESUMED.match(line)
            if resumed and resumed[1] in pending:
                events.append(pending.pop(resumed[1]))
    return events


def parse_file_trace(
    text: str,
    *,
    start: float,
    end: float,
    host: str,
    expected_files: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Return successful file operations (open/creat/unlink/rename) in /tmp within the window."""
    events: list[dict[str, Any]] = []
    pending: dict[str, dict[str, Any]] = {}

    for line in text.splitlines():
        # Match open / openat
        m_open = _OPEN_SYSCALL.match(line)
        if m_open:
            try:
                timestamp = float(m_open["time"])
                path = ast.literal_eval(m_open["path"])
                flags = m_open["flags"]
            except (ValueError, SyntaxError):
                continue
            if not start <= timestamp <= end or not path.startswith("/tmp/"):
                continue
            if path == TRACE_PATH:
                continue
            if expected_files and path not in expected_files:
                continue

            action = (
                "create"
                if "O_CREAT" in flags
                else (
                    "modify"
                    if any(f in flags for f in ("O_WRONLY", "O_RDWR", "O_TRUNC"))
                    else "open"
                )
            )
            pid = int(m_open["pid"])
            ev = {
                "data_source": "file_event",
                "category": "file_event",
                "product": "linux",
                "sensor": "lab_file_syscall",
                "Computer": host,
                "TargetFilename": path,
                "event_type": action,
                "ProcessId": pid,
                "UtcTime": datetime.fromtimestamp(timestamp, UTC).isoformat(),
            }
            if "<unfinished ...>" in line:
                pending[m_open["pid"]] = ev
            elif "= " in line and not line.rstrip().endswith("-1"):
                try:
                    ret_val = int(line.rsplit("= ", 1)[-1].split()[0])
                    if ret_val >= 0:
                        events.append(ev)
                except (ValueError, IndexError):
                    pass
            continue

        # Match creat
        m_creat = _CREAT_SYSCALL.match(line)
        if m_creat:
            try:
                timestamp = float(m_creat["time"])
                path = ast.literal_eval(m_creat["path"])
            except (ValueError, SyntaxError):
                continue
            if not start <= timestamp <= end or not path.startswith("/tmp/") or path == TRACE_PATH:
                continue
            if expected_files and path not in expected_files:
                continue
            pid = int(m_creat["pid"])
            ev = {
                "data_source": "file_event",
                "category": "file_event",
                "product": "linux",
                "sensor": "lab_file_syscall",
                "Computer": host,
                "TargetFilename": path,
                "event_type": "create",
                "ProcessId": pid,
                "UtcTime": datetime.fromtimestamp(timestamp, UTC).isoformat(),
            }
            if "<unfinished ...>" in line:
                pending[m_creat["pid"]] = ev
            elif "= " in line:
                try:
                    ret_val = int(line.rsplit("= ", 1)[-1].split()[0])
                    if ret_val >= 0:
                        events.append(ev)
                except (ValueError, IndexError):
                    pass
            continue

        # Match unlink / unlinkat
        m_unlink = _UNLINK_SYSCALL.match(line)
        if m_unlink:
            try:
                timestamp = float(m_unlink["time"])
                path = ast.literal_eval(m_unlink["path"])
            except (ValueError, SyntaxError):
                continue
            if not start <= timestamp <= end or not path.startswith("/tmp/") or path == TRACE_PATH:
                continue
            if expected_files and path not in expected_files:
                continue
            pid = int(m_unlink["pid"])
            ev = {
                "data_source": "file_event",
                "category": "file_event",
                "product": "linux",
                "sensor": "lab_file_syscall",
                "Computer": host,
                "TargetFilename": path,
                "event_type": "delete",
                "ProcessId": pid,
                "UtcTime": datetime.fromtimestamp(timestamp, UTC).isoformat(),
            }
            if "<unfinished ...>" in line:
                pending[m_unlink["pid"]] = ev
            elif line.rstrip().endswith("= 0"):
                events.append(ev)
            continue

        # Match rename / renameat / renameat2
        m_rename = _RENAME_SYSCALL.match(line)
        if m_rename:
            try:
                timestamp = float(m_rename["time"])
                newpath = ast.literal_eval(m_rename["newpath"])
            except (ValueError, SyntaxError):
                continue
            if (
                not start <= timestamp <= end
                or not newpath.startswith("/tmp/")
                or newpath == TRACE_PATH
            ):
                continue
            pid = int(m_rename["pid"])
            ev = {
                "data_source": "file_event",
                "category": "file_event",
                "product": "linux",
                "sensor": "lab_file_syscall",
                "Computer": host,
                "TargetFilename": newpath,
                "event_type": "rename",
                "ProcessId": pid,
                "UtcTime": datetime.fromtimestamp(timestamp, UTC).isoformat(),
            }
            if "<unfinished ...>" in line:
                pending[m_rename["pid"]] = ev
            elif line.rstrip().endswith("= 0"):
                events.append(ev)
            continue

        # Check resumed syscall
        m_res = _RESUMED_FILE.match(line)
        if m_res and m_res["pid"] in pending:
            ev = pending.pop(m_res["pid"])
            try:
                ret = int(m_res["ret"])
                if ret >= 0:
                    events.append(ev)
            except ValueError:
                pass

    return events


def parse_net_trace(
    text: str,
    *,
    start: float,
    end: float,
    host: str,
) -> list[dict[str, Any]]:
    """Return outbound TCP connection attempts within the execution window."""
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = _CONNECT_SYSCALL.match(line)
        if match:
            try:
                timestamp = float(match["time"])
                port = int(match["port"])
                ip = match["ip"]
                pid = int(match["pid"])
            except (ValueError, SyntaxError):
                continue
            if not start <= timestamp <= end:
                continue
            if "= 0" in line or "EINPROGRESS" in line:
                events.append(
                    {
                        "data_source": "network_connection",
                        "category": "network_connection",
                        "product": "linux",
                        "sensor": "lab_net_syscall",
                        "Computer": host,
                        "DestinationIp": ip,
                        "DestinationPort": port,
                        "Protocol": "tcp",
                        "ProcessId": pid,
                        "UtcTime": datetime.fromtimestamp(timestamp, UTC).isoformat(),
                    }
                )
    return events


class LabFileDeltaSensor:
    """Observe and hash ephemeral files in /tmp created or deleted during an emulation."""

    def __init__(self, container: str, host: str):
        self.container = container
        self.host = host

    @staticmethod
    def _docker(*args: str) -> str:
        result = subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=10, check=True
        )
        return result.stdout

    def compute_file_sha256(self, container_path: str) -> str:
        """Compute the SHA-256 digest of an ephemeral file inside the container."""
        if not self.container:
            return ""
        try:
            output = self._docker("exec", self.container, "sha256sum", container_path)
            return output.split()[0]
        except Exception:
            return ""

    def collect_delta_events(
        self,
        *,
        created_files: list[str],
        deleted_files: list[str] | None = None,
        start_utc: str,
        end_utc: str,
        process_id: int | None = None,
        image: str | None = None,
        command_line: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return standardized file_event telemetry for observed file creations and deletions."""
        events: list[dict[str, Any]] = []
        for file_path in created_files:
            file_hash = self.compute_file_sha256(file_path)
            ev: dict[str, Any] = {
                "data_source": "file_event",
                "category": "file_event",
                "product": "linux",
                "sensor": "lab_file_delta",
                "Computer": self.host,
                "TargetFilename": file_path,
                "event_type": "create",
                "UtcTime": start_utc,
            }
            if file_hash:
                ev["Hashes"] = {"SHA256": file_hash}
                ev["sha256"] = file_hash
            if process_id is not None:
                ev["ProcessId"] = process_id
            if image:
                ev["Image"] = image
            if command_line:
                ev["CommandLine"] = command_line
            events.append(ev)

        for file_path in deleted_files or []:
            ev = {
                "data_source": "file_event",
                "category": "file_event",
                "product": "linux",
                "sensor": "lab_file_delta",
                "Computer": self.host,
                "TargetFilename": file_path,
                "event_type": "delete",
                "UtcTime": end_utc,
            }
            if process_id is not None:
                ev["ProcessId"] = process_id
            if image:
                ev["Image"] = image
            if command_line:
                ev["CommandLine"] = command_line
            events.append(ev)

        return events


class LabSensorFusion:
    """Fuse multi-sensor telemetry (process, file, network) into a correlated stream."""

    @staticmethod
    def correlate_lineage(
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Enrich file and network events with process lineage when ProcessId matches."""
        proc_by_pid: dict[int, dict[str, Any]] = {}
        for ev in events:
            if ev.get("category") == "process_creation" and "ProcessId" in ev:
                proc_by_pid[ev["ProcessId"]] = ev

        for ev in events:
            if ev.get("category") != "process_creation":
                pid = ev.get("ProcessId")
                if pid in proc_by_pid:
                    parent = proc_by_pid[pid]
                    if "Image" not in ev and "Image" in parent:
                        ev["Image"] = parent["Image"]
                    if "CommandLine" not in ev and "CommandLine" in parent:
                        ev["CommandLine"] = parent["CommandLine"]
        return events

    @staticmethod
    def fuse(
        events: list[dict[str, Any]],
        *,
        hunt_id: str = "",
        technique_id: str = "",
    ) -> list[dict[str, Any]]:
        """Deduplicate, correlate, and sort events chronologically."""
        seen: set[tuple[str, str, str, str]] = set()
        deduped: list[dict[str, Any]] = []

        for ev in events:
            cat = str(ev.get("category", ""))
            target = str(
                ev.get("TargetFilename") or ev.get("CommandLine") or ev.get("DestinationPort", "")
            )
            action = str(ev.get("event_type", ""))
            time_str = str(ev.get("UtcTime", ""))
            key = (cat, target, action, time_str)
            if key in seen:
                continue
            seen.add(key)

            if hunt_id:
                ev["hunt_id"] = hunt_id
            if technique_id:
                ev["technique_id"] = technique_id
            deduped.append(ev)

        LabSensorFusion.correlate_lineage(deduped)
        deduped.sort(key=lambda e: str(e.get("UtcTime", "")))
        return deduped


class LabProcessSensor:
    """Read a dedicated container's process trace after validating its isolation."""

    def __init__(
        self,
        container: str,
        host: str,
        approved_images: set[str] | None = None,
    ):
        self.container = container
        self.host = host
        self.container_id = ""
        self.agent_image = ""
        self.controller_image = ""
        self.approved_images = (
            approved_images if approved_images is not None else APPROVED_AGENT_IMAGES
        )

    @staticmethod
    def _docker(*args: str) -> str:
        result = subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=10, check=True
        )
        return result.stdout

    def preflight(self) -> None:
        """Fail closed before scheduling if the target or sensor differs."""
        container = json.loads(self._docker("inspect", self.container))[0]
        agent_image = container.get("Image", "")
        if agent_image not in self.approved_images:
            raise SafetyViolationError(
                f"BAS agent image identity is not approved (got {agent_image!r})."
            )
        self.agent_image = agent_image
        config = container["Config"]
        host = container["HostConfig"]
        networks = container["NetworkSettings"]["Networks"]
        tmp_options = set((host.get("Tmpfs") or {}).get("/tmp", "").split(","))
        limits = {item["Name"]: item for item in host.get("Ulimits") or []}
        limits_ok = (
            limits.get("core", {}).get("Hard") == 0
            and limits.get("core", {}).get("Soft") == 0
            and limits.get("nofile", {}).get("Hard", 0) in range(1, 257)
            and limits.get("nofile", {}).get("Soft", 0) in range(1, 257)
            and limits.get("fsize", {}).get("Hard", 0) in range(1, 16777217)
            and limits.get("fsize", {}).get("Soft", 0) in range(1, 16777217)
        )
        if (
            not container["State"]["Running"]
            or config.get("Hostname") != self.host
            or config.get("User") != "65534:65534"
            or tuple(config.get("Entrypoint") or []) not in APPROVED_SENSOR_ENTRYPOINTS
            or config.get("Cmd")
            != [
                "-server",
                "http://caldera:8888",
                "-group",
                "hecate-local-lab",
                "-paw",
                "hecate-local-sandbox",
            ]
            or not host.get("ReadonlyRootfs")
            or host.get("Privileged")
            or "ALL" not in (host.get("CapDrop") or [])
            or host.get("CapAdd")
            or "no-new-privileges=true" not in (host.get("SecurityOpt") or [])
            or any("unconfined" in s for s in host.get("SecurityOpt") or [])
            or container.get("Mounts")
            or host.get("PidMode") == "host"
            or host.get("IpcMode") == "host"
            or host.get("PortBindings")
            or set(networks) != {"hecate-bas-lab"}
            or host.get("PidsLimit", 0) not in range(1, 129)
            or host.get("Memory", 0) not in range(1, 268435457)
            or host.get("NanoCpus", 0) not in range(1, 500000001)
            or not {"rw", "nosuid", "nodev", "noexec"} <= tmp_options
            or not limits_ok
        ):
            raise SafetyViolationError("BAS lab isolation or process sensor preflight failed.")
        network = json.loads(self._docker("network", "inspect", "hecate-bas-lab"))[0]
        if not network.get("Internal"):
            raise SafetyViolationError("BAS lab network must be internal.")
        from hecate_runner.bas.controller import validate_controller

        caldera_data = json.loads(self._docker("inspect", "caldera"))[0]
        validate_controller(caldera_data)
        self.controller_image = caldera_data.get("Image", "")
        self.container_id = container["Id"]
        # Readiness: the tracer must have observed the agent's initial exec.
        trace = self._docker("exec", self.container_id, "head", "-c", "8192", TRACE_PATH)
        if 'execve("/usr/local/bin/sandcat"' not in trace or "= 0" not in trace:
            raise SafetyViolationError("BAS process sensor is not recording executions.")

    def collect(
        self, detonation: DetonationResult, command: str | tuple[str, ...]
    ) -> list[dict[str, Any]]:
        if not self.container_id:
            raise SafetyViolationError("BAS process sensor was not checked before execution.")
        # Bounded read; newest trace records remain at the end of the file.
        trace = self._docker("exec", self.container_id, "tail", "-c", "4194304", TRACE_PATH)
        start = datetime.fromisoformat(detonation.start_time_utc).timestamp()
        end = datetime.fromisoformat(detonation.end_time_utc).timestamp()
        return parse_exec_trace(trace, start=start, end=end, host=self.host, command=command)

    def collect_fused(
        self,
        detonation: DetonationResult,
        command: str | tuple[str, ...],
        *,
        expected_files: tuple[str, ...] = (),
        file_delta_events: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        if not self.container_id:
            raise SafetyViolationError("BAS process sensor was not checked before execution.")
        trace = self._docker("exec", self.container_id, "tail", "-c", "4194304", TRACE_PATH)
        start = datetime.fromisoformat(detonation.start_time_utc).timestamp()
        end = datetime.fromisoformat(detonation.end_time_utc).timestamp()

        exec_events = parse_exec_trace(trace, start=start, end=end, host=self.host, command=command)
        file_events = parse_file_trace(
            trace, start=start, end=end, host=self.host, expected_files=expected_files
        )
        net_events = parse_net_trace(trace, start=start, end=end, host=self.host)

        all_events: list[dict[str, Any]] = list(exec_events) + list(file_events) + list(net_events)
        if file_delta_events:
            all_events.extend(file_delta_events)

        return LabSensorFusion.fuse(
            all_events,
            hunt_id=detonation.hunt_id,
            technique_id=detonation.technique_id,
        )
