"""Unit tests for run_process_group utility in hecate_runner."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from hecate_runner.subprocess_utils import run_process_group


def test_run_process_group_successful_execution() -> None:
    res = run_process_group(["echo", "hello_runner"])
    assert res.returncode == 0
    assert "hello_runner" in res.stdout


def test_run_process_group_captures_stderr() -> None:
    res = run_process_group(["sh", "-c", "echo runner_error >&2; exit 42"])
    assert res.returncode == 42
    assert "runner_error" in res.stderr


def test_run_process_group_check_raises_called_process_error() -> None:
    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        run_process_group(["sh", "-c", "exit 5"], check=True)
    assert exc_info.value.returncode == 5


def test_run_process_group_timeout_raises_timeout_expired() -> None:
    with pytest.raises(subprocess.TimeoutExpired) as exc_info:
        run_process_group(["sleep", "10"], timeout=0.1)
    assert exc_info.value.cmd == ["sleep", "10"]


def test_run_process_group_kills_orphaned_grandchildren_on_timeout() -> None:
    """Ensure background grandchild processes are killed with os.killpg when timeout expires."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
        pid_file = f.name

    try:
        shell_cmd = f"sleep 30 & echo $! > {pid_file} ; sleep 30"
        with pytest.raises(subprocess.TimeoutExpired):
            run_process_group(["sh", "-c", shell_cmd], timeout=0.2)

        time.sleep(0.1)
        content = Path(pid_file).read_text().strip()
        assert content, "PID file was not written"
        grandchild_pid = int(content)

        # Confirm the background process was killed and does not remain running as an orphan
        with pytest.raises(ProcessLookupError):
            os.kill(grandchild_pid, 0)
    finally:
        Path(pid_file).unlink(missing_ok=True)
