"""Global lab leasing, watchdog timeout enforcement, and quarantine lifecycle.

Multi-workspace and manual/automatic entry points must share a common lab
boundary. This module guarantees mutual exclusion across processes, detects
expired or abandoned operations via an active watchdog deadline, and enforces
an audited quarantine state whenever cleanup cannot be confirmed.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import subprocess
import threading
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.bas.base import SafetyViolationError

log = logging.getLogger(__name__)

DEFAULT_LEASE_PATH = Path("/tmp/hecate-bas-lab.lease")
DEFAULT_QUARANTINE_PATH = Path("/tmp/hecate-bas-lab.quarantine")
DEFAULT_LOCK_PATH = Path("/tmp/hecate-bas-lab.lock")


class LabLease:
    """Manage cross-process lab locking, watchdog expiry, and quarantine."""

    def __init__(
        self,
        lease_path: Path = DEFAULT_LEASE_PATH,
        quarantine_path: Path = DEFAULT_QUARANTINE_PATH,
        lock_path: Path = DEFAULT_LOCK_PATH,
    ) -> None:
        self.lease_path = lease_path
        self.quarantine_path = quarantine_path
        self.lock_path = lock_path

    def is_quarantined(self) -> bool:
        return self.quarantine_path.exists()

    def get_quarantine_info(self) -> dict[str, Any] | None:
        if not self.is_quarantined():
            return None
        try:
            payload = json.loads(self.quarantine_path.read_text(encoding="utf-8"))
            return (
                payload if isinstance(payload, dict) else {"reason": "Invalid quarantine payload"}
            )
        except Exception:
            return {"reason": "Corrupted or unreadable quarantine state."}

    def quarantine(
        self, reason: str, hunt_id: str = "", details: dict[str, Any] | None = None
    ) -> None:
        """Place the lab in quarantine, forbidding further execution until audited reset."""
        payload = {
            "quarantined_at": datetime.now(UTC).isoformat(),
            "reason": reason,
            "hunt_id": hunt_id,
            "pid": os.getpid(),
            "details": details or {},
        }
        atomic_write_text(self.quarantine_path, json.dumps(payload, indent=2), mode=0o644)

    def clear_quarantine(self, operator_note: str = "") -> dict[str, Any] | None:
        """Clear quarantine state during an audited reset."""
        info = self.get_quarantine_info()
        if self.quarantine_path.exists():
            self.quarantine_path.unlink()
        return info

    def check_quarantine(self) -> None:
        """Raise SafetyViolationError if the lab is currently quarantined."""
        info = self.get_quarantine_info()
        if info is not None:
            reason = info.get("reason", "Unspecified safety quarantine.")
            raise SafetyViolationError(
                f"BAS lab is quarantined: {reason} Run 'hecate-runner bas-reset' to audit and clear."
            )

    @contextmanager
    def locked(self) -> Generator[None, None, None]:
        """Serialize both execution and reset; reset may inspect quarantine."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+") as lock_file:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise SafetyViolationError(
                    "Another BAS operation holds the active lab lease."
                ) from exc
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    @contextmanager
    def acquire(
        self, hunt_id: str, timeout_sec: int = 180
    ) -> Generator[dict[str, Any], None, None]:
        """Quarantine on deadline or exceptional exit while retaining the execution lock.

        The provider must also bound/stop remote execution. A timer cannot safely
        kill a Python worker or prove remote cleanup, so timeout requires reset.
        """
        if timeout_sec <= 0:
            raise SafetyViolationError("BAS lease timeout must be positive.")
        with self.locked():
            self.check_quarantine()
            if self.lease_path.exists():
                self.quarantine(
                    "Previous lab lease expired or was abandoned without clean release.", hunt_id
                )
                raise SafetyViolationError(
                    "Previous lab lease expired or was abandoned; lab has been quarantined."
                )
            now = time.time()
            deadline = time.monotonic() + timeout_sec
            lease_data = {
                "lease_id": uuid.uuid4().hex,
                "hunt_id": hunt_id,
                "pid": os.getpid(),
                "acquired_at": datetime.now(UTC).isoformat(),
                "expires_at": now + timeout_sec,
                "timeout_sec": timeout_sec,
            }
            atomic_write_text(self.lease_path, json.dumps(lease_data, indent=2), mode=0o600)
            expired = threading.Event()

            def expire() -> None:
                expired.set()
                self.quarantine(
                    "BAS execution exceeded its lease deadline; cleanup requires audit.", hunt_id
                )

            watchdog = threading.Timer(timeout_sec, expire)
            watchdog.daemon = True
            watchdog.start()
            try:
                yield lease_data
                if expired.is_set() or time.monotonic() >= deadline:
                    if not expired.is_set():
                        expire()
                    raise SafetyViolationError("BAS execution exceeded its lease deadline.")
            except BaseException:
                if not self.is_quarantined():
                    self.quarantine(
                        "BAS operation exited without confirmed clean release.", hunt_id
                    )
                raise
            finally:
                watchdog.cancel()
                watchdog.join()
                if expired.is_set():
                    raise SafetyViolationError("BAS execution exceeded its lease deadline.")
                if not self.is_quarantined():
                    self.lease_path.unlink(missing_ok=True)


def audit_container_tmpfs(container_name: str = "hecate-bas-agent") -> list[str]:
    """Return non-baseline files/directories present in /tmp inside the container."""
    try:
        proc = subprocess.run(
            [
                "docker",
                "exec",
                container_name,
                "find",
                "/tmp",
                "-maxdepth",
                "2",
                "!",
                "-name",
                "hecate-exec.trace",
                "!",
                "-path",
                "/tmp",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0:
            return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        raise SafetyViolationError("Container tmpfs inspection failed.")
    except (OSError, subprocess.SubprocessError) as exc:
        raise SafetyViolationError("Container tmpfs inspection failed.") from exc


def clean_container_tmpfs(
    container_name: str = "hecate-bas-agent", files: list[str] | None = None
) -> list[str]:
    """Purge uncleaned non-baseline files in /tmp inside the container."""
    targets = files if files is not None else audit_container_tmpfs(container_name)
    purged: list[str] = []
    for path in targets:
        # Extra safety check: never touch hecate-exec.trace or root or outside /tmp
        if not path.startswith("/tmp/") or path == "/tmp/hecate-exec.trace" or ".." in path:
            continue
        try:
            res = subprocess.run(
                ["docker", "exec", container_name, "rm", "-rf", path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if res.returncode == 0:
                purged.append(path)
        except Exception as exc:
            log.warning("Failed to remove lingering file %s in %s: %s", path, container_name, exc)
    return purged


def reset_lab(
    container_name: str = "hecate-bas-agent",
    controller_name: str = "caldera",
    operator_note: str = "",
    workspace: Path | None = None,
    lease: LabLease | None = None,
) -> dict[str, Any]:
    """Clear quarantine only after serialized, successful process and tmpfs audits.

    Unexpected processes require operator recovery; never claim to have killed
    them, or clear quarantine while they may still be changing container state.
    """
    root = workspace / ".hecate" / "bas" if workspace else None
    lab_lease = lease or (
        LabLease(root / "lab.lease", root / "lab.quarantine", root / "execution.lock")
        if root
        else LabLease()
    )
    with lab_lease.locked():
        record: dict[str, Any] = {
            "reset_at": datetime.now(UTC).isoformat(),
            "operator_note": operator_note or "Audited reset via hecate-runner bas-reset.",
            "prior_quarantine": lab_lease.get_quarantine_info(),
            "lingering_processes_found": [],
            "lingering_files_found": [],
            "files_purged": [],
            "docker_available": False,
            "status": "failed",
        }
        try:
            proc = subprocess.run(
                ["docker", "top", container_name, "-eo", "args"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            if proc.returncode != 0:
                raise SafetyViolationError("Container process inspection failed.")
            lines = proc.stdout.strip().splitlines()
            if len(lines) < 2 or lines[0].strip() not in {"COMMAND", "CMD"}:
                raise SafetyViolationError(
                    "Container process inspection returned no usable process list."
                )
            record["docker_available"] = True
            allowed = {"/usr/bin/strace", "/usr/local/bin/sandcat"}
            lingering = [
                line.strip()
                for line in lines[1:]
                if not line.strip() or line.split()[0] not in allowed
            ]
            record["lingering_processes_found"] = lingering
            if lingering:
                raise SafetyViolationError(
                    "Unexpected processes remain; recover the lab before resetting quarantine."
                )
            files = audit_container_tmpfs(container_name)
            record["lingering_files_found"] = files
            record["files_purged"] = clean_container_tmpfs(container_name, files)
            if audit_container_tmpfs(container_name):
                raise SafetyViolationError("Container tmpfs cleanup could not be confirmed.")
            record["status"] = "clean"
            # Persist the audit before clearing safety state.
            if workspace:
                audit_file = workspace / ".hecate" / "bas" / "resets.jsonl"
                audit_file.parent.mkdir(parents=True, exist_ok=True)
                with audit_file.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
            lab_lease.lease_path.unlink(missing_ok=True)
            lab_lease.clear_quarantine(operator_note)
        except Exception as exc:
            lab_lease.quarantine("Lab reset failed: " + str(exc))
            raise SafetyViolationError(
                "Lab reset failed; quarantine retained: " + str(exc)
            ) from exc
        return record
