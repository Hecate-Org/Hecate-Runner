"""Tests for BAS lab lifecycle, leasing, watchdog expiry, quarantine, and audited reset."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from hecate_runner.bas.base import SafetyViolationError
from hecate_runner.bas.lifecycle import LabLease, reset_lab


def test_lease_acquire_and_clean_release(tmp_path: Path) -> None:
    lease = LabLease(
        lease_path=tmp_path / "lab.lease",
        quarantine_path=tmp_path / "lab.quarantine",
        lock_path=tmp_path / "lab.lock",
    )
    with lease.acquire("H-0001", timeout_sec=60) as info:
        assert info["hunt_id"] == "H-0001"
        assert lease.lease_path.exists()
        assert not lease.is_quarantined()

    assert not lease.lease_path.exists()
    assert not lease.is_quarantined()


def test_lease_contention_is_rejected(tmp_path: Path) -> None:
    lease1 = LabLease(
        lease_path=tmp_path / "lab.lease",
        quarantine_path=tmp_path / "lab.quarantine",
        lock_path=tmp_path / "lab.lock",
    )
    lease2 = LabLease(
        lease_path=tmp_path / "lab.lease",
        quarantine_path=tmp_path / "lab.quarantine",
        lock_path=tmp_path / "lab.lock",
    )
    with (
        lease1.acquire("H-0001", timeout_sec=60),
        pytest.raises(SafetyViolationError, match="holds the active lab lease"),
        lease2.acquire("H-0002", timeout_sec=60),
    ):
        pass


def test_watchdog_quarantines_expired_lease(tmp_path: Path) -> None:
    lease = LabLease(
        lease_path=tmp_path / "lab.lease",
        quarantine_path=tmp_path / "lab.quarantine",
        lock_path=tmp_path / "lab.lock",
    )
    # Simulate an abandoned, expired lease
    abandoned_lease = {
        "lease_id": "deadbeef",
        "hunt_id": "H-ABANDONED",
        "pid": 99999,
        "acquired_at": "2026-10-31T00:00:00Z",
        "expires_at": time.time() - 100,
        "timeout_sec": 60,
    }
    lease.lease_path.write_text(json.dumps(abandoned_lease), encoding="utf-8")

    with (
        pytest.raises(SafetyViolationError, match="expired without clean release"),
        lease.acquire("H-0002", timeout_sec=60),
    ):
        pass

    assert lease.is_quarantined()
    info = lease.get_quarantine_info()
    assert info is not None
    assert "expired" in info["reason"]


def test_quarantined_lab_refuses_detonation_until_reset(tmp_path: Path) -> None:
    lease = LabLease(
        lease_path=tmp_path / "lab.lease",
        quarantine_path=tmp_path / "lab.quarantine",
        lock_path=tmp_path / "lab.lock",
    )
    lease.quarantine("Unconfirmed remote cleanup", hunt_id="H-0001")
    assert lease.is_quarantined()

    with (
        pytest.raises(SafetyViolationError, match="quarantined: Unconfirmed remote cleanup"),
        lease.acquire("H-0002", timeout_sec=60),
    ):
        pass

    # Clear quarantine via audited reset
    reset_record = reset_lab(
        container_name="test-agent",
        operator_note="Manual verification and cleanup",
        workspace=tmp_path,
        lease=lease,
    )
    assert not lease.is_quarantined()
    assert reset_record["prior_quarantine"]["reason"] == "Unconfirmed remote cleanup"

    audit_file = tmp_path / ".hecate" / "bas" / "resets.jsonl"
    assert audit_file.exists()
    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    logged = json.loads(lines[0])
    assert logged["operator_note"] == "Manual verification and cleanup"


def test_reset_lab_inspects_lingering_processes(tmp_path: Path) -> None:
    lease = LabLease(
        lease_path=tmp_path / "lab.lease",
        quarantine_path=tmp_path / "lab.quarantine",
        lock_path=tmp_path / "lab.lock",
    )
    fake_docker_top = """UID        PID  PPID  C STIME TTY          TIME CMD
65534     1001     1  0 02:00 ?        00:00:00 /usr/bin/strace -f -qq -ttt -o /tmp/hecate-exec.trace /usr/local/bin/sandcat
65534     1002  1001  0 02:00 ?        00:00:00 /usr/local/bin/sandcat
65534     1050  1002  0 02:05 ?        00:00:00 python3 -m http.server 8000
"""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = fake_docker_top

        summary = reset_lab(
            container_name="test-agent",
            operator_note="Routine reset",
            workspace=tmp_path,
            lease=lease,
        )

        assert summary["lingering_processes_found"] == ["python3 -m http.server 8000"]


def test_audit_and_clean_container_tmpfs() -> None:
    from unittest.mock import MagicMock

    from hecate_runner.bas.lifecycle import audit_container_tmpfs, clean_container_tmpfs

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "/tmp/hecate-t1027.tmp\n/tmp/subdir/canary.tmp\n"
        mock_run.return_value = mock_proc

        files = audit_container_tmpfs("test-agent")
        assert files == ["/tmp/hecate-t1027.tmp", "/tmp/subdir/canary.tmp"]
        assert mock_run.call_args[0][0] == [
            "docker",
            "exec",
            "test-agent",
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
        ]

    # Test clean_container_tmpfs safety guards
    commands_executed = []

    def mock_clean_run(cmd, *args, **kwargs):
        commands_executed.append(cmd)
        m = MagicMock()
        m.returncode = 0
        return m

    with patch("subprocess.run", side_effect=mock_clean_run):
        purged = clean_container_tmpfs(
            "test-agent",
            [
                "/tmp/hecate-t1027.tmp",
                "/tmp/hecate-exec.trace",  # Protected sensor trace
                "/etc/passwd",  # Outside /tmp
                "/tmp/../etc/shadow",  # Path traversal
            ],
        )
        assert purged == ["/tmp/hecate-t1027.tmp"]
        assert len(commands_executed) == 1
        assert commands_executed[0] == [
            "docker",
            "exec",
            "test-agent",
            "rm",
            "-rf",
            "/tmp/hecate-t1027.tmp",
        ]


def test_reset_lab_audits_and_purges_tmpfs_files(tmp_path: Path) -> None:
    from unittest.mock import MagicMock

    lease = LabLease(
        lease_path=tmp_path / "lab.lease",
        quarantine_path=tmp_path / "lab.quarantine",
        lock_path=tmp_path / "lab.lock",
    )

    def mock_docker_run(cmd, *args, **kwargs):
        res = MagicMock()
        res.returncode = 0
        if "top" in cmd:
            res.stdout = (
                "UID PID PPID C STIME TTY TIME CMD\n65534 1 0 0 ? 00:00:00 /usr/bin/strace\n"
            )
        elif "find" in cmd:
            res.stdout = "/tmp/hecate-stale.bin\n"
        elif "rm" in cmd:
            res.stdout = ""
        else:
            res.stdout = ""
        return res

    with patch("subprocess.run", side_effect=mock_docker_run):
        summary = reset_lab(
            container_name="test-agent",
            operator_note="Purge files reset",
            workspace=tmp_path,
            lease=lease,
        )

        assert summary["lingering_files_found"] == ["/tmp/hecate-stale.bin"]
        assert summary["files_purged"] == ["/tmp/hecate-stale.bin"]
        assert summary["status"] == "clean"
