"""Regression checks for the October code review; no Docker or network execution."""

from __future__ import annotations

import json
import subprocess
import threading
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from hecate_runner.bas.base import SafetyViolationError
from hecate_runner.bas.lifecycle import LabLease, audit_container_tmpfs, reset_lab
from hecate_runner.bas.mock import MockBASProvider
from hecate_runner.cli import app
from hecate_runner.config import Settings
from hecate_runner.cti.file_queue import FileQueueProvider


def make_lease(root):
    return LabLease(root / "lab.lease", root / "lab.quarantine", root / "execution.lock")


@pytest.mark.parametrize("failure", ["nonzero", "timeout", "lingering", "dirty"])
def test_reset_failure_retains_quarantine(tmp_path, failure):
    lease = make_lease(tmp_path)
    lease.quarantine("unconfirmed cleanup")

    def docker(cmd, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(cmd, 10)
        if failure == "nonzero":
            return subprocess.CompletedProcess(cmd, 1, "", "unavailable")
        if "top" in cmd:
            output = "COMMAND\n/usr/bin/strace -f\n/usr/local/bin/sandcat\n"
            if failure == "lingering":
                output += "python3 worker.py\n"
            return subprocess.CompletedProcess(cmd, 0, output, "")
        return subprocess.CompletedProcess(cmd, 0, "/tmp/stale\n" if "find" in cmd else "", "")

    with (
        patch("hecate_runner.bas.lifecycle.subprocess.run", side_effect=docker),
        pytest.raises(SafetyViolationError, match="quarantine retained"),
    ):
        reset_lab(lease=lease)
    assert lease.is_quarantined()


def test_failed_tmpfs_inspection_is_not_empty(tmp_path):
    with (
        patch(
            "hecate_runner.bas.lifecycle.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1, "", "error"),
        ),
        pytest.raises(SafetyViolationError, match="inspection failed"),
    ):
        audit_container_tmpfs("fake")


def test_cli_reset_uses_execution_quarantine(tmp_path, monkeypatch):
    lease = make_lease(tmp_path / ".hecate/bas")
    lease.quarantine("previous failure")
    lease.lease_path.write_text("{}")
    settings = Settings(_env_file=None, hecate_workspace=tmp_path)
    monkeypatch.setattr("hecate_runner.cli.Settings", lambda: settings)

    def docker(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd,
            0,
            "COMMAND\n/usr/bin/strace -f\n/usr/local/bin/sandcat\n" if "top" in cmd else "",
            "",
        )

    with patch("hecate_runner.bas.lifecycle.subprocess.run", side_effect=docker):
        result = CliRunner().invoke(app, ["bas-reset"])
    assert result.exit_code == 0, result.output
    assert not lease.is_quarantined()
    assert not lease.lease_path.exists()
    assert (
        json.loads((tmp_path / ".hecate/bas/resets.jsonl").read_text())["prior_quarantine"][
            "reason"
        ]
        == "previous failure"
    )


def test_manual_detonation_and_reset_cannot_overlap_active_lease(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, hecate_workspace=tmp_path, bas_allowed_hosts=["lab-host"])
    lease = make_lease(tmp_path / ".hecate/bas")
    provider = MockBASProvider(allowed_hosts=["lab-host"])
    monkeypatch.setattr("hecate_runner.cli.Settings", lambda: settings)
    monkeypatch.setattr("hecate_runner.bas.get_bas_provider", lambda *a: provider)
    with lease.acquire("H-ACTIVE"):
        result = CliRunner().invoke(app, ["bas-detonate", "T1033", "--provider", "caldera"])
        assert result.exit_code == 1
        assert "holds the active lab lease" in " ".join(result.output.split())
        with pytest.raises(SafetyViolationError, match="holds the active lab lease"):
            reset_lab(workspace=tmp_path)
    assert provider.history == []


def test_expired_execution_is_quarantined_before_return(tmp_path):
    lease = make_lease(tmp_path)
    # Real timer, synchronized on quarantine rather than a timing-sensitive sleep.
    observed = threading.Event()
    original = lease.quarantine

    def record(*a, **kw):
        original(*a, **kw)
        observed.set()

    with (
        patch.object(lease, "quarantine", side_effect=record),
        pytest.raises(SafetyViolationError, match="deadline"),
        lease.acquire("H-TIMEOUT", timeout_sec=0.01),
    ):
        assert observed.wait(2)
        assert lease.is_quarantined()
    assert lease.lease_path.exists()


def test_exception_retains_abandoned_lease(tmp_path):
    lease = make_lease(tmp_path)
    with pytest.raises(RuntimeError), lease.acquire("H-ERROR"):
        raise RuntimeError("unexpected provider error")
    assert lease.is_quarantined() and lease.lease_path.exists()


def test_acknowledging_missing_spool_item_preserves_next_item(tmp_path):
    queue = FileQueueProvider(tmp_path)
    first = queue.spool("first", "first.txt")
    item = queue.next_item()
    first.unlink()
    queue.next_file.write_text("unrelated second item")
    queue.acknowledge(item)
    assert queue.next_file.read_text() == "unrelated second item"
    assert list(queue.processed_dir.iterdir()) == []
