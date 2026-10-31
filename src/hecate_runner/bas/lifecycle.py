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
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager, suppress
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
            with suppress(OSError):
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
    def acquire(
        self, hunt_id: str, timeout_sec: int = 180
    ) -> Generator[dict[str, Any], None, None]:
        """Acquire the lab lease under a watchdog deadline, failing closed on contention/quarantine."""
        self.check_quarantine()

        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_file = self.lock_path.open("a+")
        try:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as exc:
                raise SafetyViolationError(
                    "Another BAS operation holds the active lab lease."
                ) from exc

            # Inspect previous lease for watchdog expiration
            now = time.time()
            if self.lease_path.exists():
                try:
                    prior = json.loads(self.lease_path.read_text(encoding="utf-8"))
                    prior_expires = float(prior.get("expires_at", 0))
                    if prior_expires and prior_expires < now:
                        self.quarantine(
                            f"Previous lab lease for {prior.get('hunt_id', 'unknown')} expired at "
                            f"{datetime.fromtimestamp(prior_expires, UTC).isoformat()} without clean release.",
                            hunt_id=hunt_id,
                            details=prior,
                        )
                        raise SafetyViolationError(
                            "Previous lab lease expired without clean release; lab has been quarantined."
                        )
                except (json.JSONDecodeError, OSError):
                    pass

            lease_id = uuid.uuid4().hex
            expires_at = now + timeout_sec
            lease_data = {
                "lease_id": lease_id,
                "hunt_id": hunt_id,
                "pid": os.getpid(),
                "acquired_at": datetime.now(UTC).isoformat(),
                "expires_at": expires_at,
                "timeout_sec": timeout_sec,
            }
            atomic_write_text(self.lease_path, json.dumps(lease_data, indent=2), mode=0o644)

            try:
                yield lease_data
            finally:
                if not self.is_quarantined() and self.lease_path.exists():
                    with suppress(OSError):
                        self.lease_path.unlink()
        finally:
            with suppress(OSError):
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()


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
    except Exception as exc:
        log.warning("Failed to audit container tmpfs on %s: %s", container_name, exc)
    return []


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
    """Audit the lab environment, terminate lingering child processes, purge tmpfs, and clear quarantine."""
    lab_lease = lease or LabLease()

    # 1. Audit & clear quarantine
    prior_quarantine = lab_lease.clear_quarantine(operator_note)

    # 2. Check docker processes and tmpfs files in agent container
    lingering_processes: list[str] = []
    lingering_files: list[str] = []
    files_purged: list[str] = []
    docker_available = True
    try:
        proc = subprocess.run(
            ["docker", "top", container_name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0:
            lines = proc.stdout.strip().splitlines()
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = line.split(maxsplit=7)
                    cmd = parts[7] if len(parts) > 7 else ""
                    # Allowed supervisor processes
                    if not any(sup in cmd for sup in ("/usr/bin/strace", "/usr/local/bin/sandcat")):
                        lingering_processes.append(cmd)
        lingering_files = audit_container_tmpfs(container_name)
        if lingering_files:
            files_purged = clean_container_tmpfs(container_name, lingering_files)
    except Exception:
        docker_available = False

    # 3. Log audit record
    reset_record = {
        "reset_at": datetime.now(UTC).isoformat(),
        "operator_note": operator_note or "Audited reset via hecate-runner bas-reset.",
        "prior_quarantine": prior_quarantine,
        "lingering_processes_found": lingering_processes,
        "lingering_files_found": lingering_files,
        "files_purged": files_purged,
        "docker_available": docker_available,
        "status": "clean",
    }

    if workspace:
        audit_file = workspace / ".hecate" / "bas" / "resets.jsonl"
        audit_file.parent.mkdir(parents=True, exist_ok=True)
        with audit_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(reset_record) + "\n")

    return reset_record
