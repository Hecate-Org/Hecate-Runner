"""Tests for CLI commands: `hecate-runner bas-detonate` and `hecate-runner bas-verify`."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from hecate_runner.cli import app
from hecate_runner.config import Settings

runner = CliRunner()


def test_cli_bas_detonate_mock_success() -> None:
    result = runner.invoke(app, ["bas-detonate", "T1059.001", "--provider", "mock", "--env", "lab"])
    assert result.exit_code == 0
    assert "Detonating technique T1059.001" in result.output
    assert "COMPLETED" in result.output
    assert "Mock detonation" in result.output


def test_cli_bas_detonate_safety_violation() -> None:
    result = runner.invoke(
        app, ["bas-detonate", "T1059.001", "--provider", "mock", "--env", "production"]
    )
    assert result.exit_code == 1
    assert "Detonation rejected: Environment is flagged as" in result.output
    assert "production" in result.output


def test_cli_bas_verify_nonexistent_hunt() -> None:
    result = runner.invoke(app, ["bas-verify", "H-9999", "--provider", "mock"])
    assert result.exit_code == 1
    assert "No hunt file found for H-9999" in result.output


def test_cli_bas_verify_success_with_writeback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Setup mock workspace structure
    workspace = tmp_path / "workspace"
    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    queries_dir = workspace / "queries" / "H-0042"
    queries_dir.mkdir(parents=True)

    hunt_file = hunts_dir / "H-0042.md"
    initial_frontmatter = {
        "hunt_id": "H-0042",
        "title": "Adversary execution via PowerShell download cradle",
        "status": "planning",
        "techniques": ["T1059.001"],
        "platform": ["windows"],
    }
    hunt_file.write_text(
        f"---\n{yaml.safe_dump(initial_frontmatter)}---\n\n# H-0042: Test Hunt Draft\n",
        encoding="utf-8",
    )

    sigma_file = queries_dir / "process_creation__powershell.yml"
    sigma_file.write_text(
        """title: PowerShell Download Cradle
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
""",
        encoding="utf-8",
    )

    # Point Settings to our temporary workspace
    mock_settings = Settings(
        hecate_workspace=workspace,
        hunts_root=workspace / "hunts",
        bas_allowed_hosts=["lab-host"],
    )
    monkeypatch.setattr("hecate_runner.cli.Settings", lambda: mock_settings)

    result = runner.invoke(app, ["bas-verify", "H-0042", "--provider", "mock", "--write-back"])
    assert result.exit_code == 0
    assert "BAS Verification Results: H-0042" in result.output
    assert "VERIFIED_TRUE_POSITIVE" in result.output
    assert "Updated hunt draft frontmatter in H-0042.md" in result.output

    # Check updated frontmatter
    updated_content = hunt_file.read_text(encoding="utf-8")
    parts = updated_content.split("---", 2)
    fm = yaml.safe_load(parts[1])
    assert fm["bas_verified"] is True
    assert fm["bas_provider"] == "mock"
    assert fm["bas_status"] == "verified_true_positive"
    assert fm["bas_detection_triggered"] is True


def test_cli_bas_reset_clears_quarantine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    def docker(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd,
            0,
            "COMMAND\n/usr/bin/strace -f\n/usr/local/bin/sandcat\n" if "top" in cmd else "",
            "",
        )

    monkeypatch.setattr("hecate_runner.bas.lifecycle.subprocess.run", docker)
    from hecate_runner.bas.lifecycle import LabLease

    lease = LabLease(
        lease_path=tmp_path / "lab.lease",
        quarantine_path=tmp_path / "lab.quarantine",
        lock_path=tmp_path / "lab.lock",
    )
    lease.quarantine("Unconfirmed remote cleanup", hunt_id="H-0001")
    assert lease.is_quarantined()

    monkeypatch.setattr("hecate_runner.bas.lifecycle.LabLease", lambda *args, **kwargs: lease)
    monkeypatch.setattr("hecate_runner.cli.Settings", lambda: Settings(hecate_workspace=tmp_path))

    result = runner.invoke(app, ["bas-reset", "--note", "CLI audit test"])
    assert result.exit_code == 0
    assert "BAS Lab Reset & Audit Complete" in result.output
    assert "Cleared prior quarantine" in result.output
    assert not lease.is_quarantined()


def test_cli_bas_detonate_caldera_refuses_unreviewed_in_lab(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "hecate_runner.cli.Settings",
        lambda: Settings(bas_enabled=True, bas_allowed_hosts=["lab-host"]),
    )
    result = runner.invoke(
        app,
        ["bas-detonate", "T1003", "--provider", "caldera", "--env", "lab", "--host", "lab-host"],
    )
    assert result.exit_code == 1
    assert "reviewed Linux procedure" in result.output


def test_cli_bas_detonate_caldera_refuses_quarantined_lab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hecate_runner.bas.lifecycle import LabLease

    lease = LabLease(
        lease_path=tmp_path / "lab.lease",
        quarantine_path=tmp_path / "lab.quarantine",
        lock_path=tmp_path / "lab.lock",
    )
    lease.quarantine("Test quarantine", hunt_id="H-0001")

    monkeypatch.setattr("hecate_runner.bas.lifecycle.LabLease", lambda *args, **kwargs: lease)
    monkeypatch.setattr(
        "hecate_runner.cli.Settings",
        lambda: Settings(
            bas_enabled=True, bas_allowed_hosts=["lab-host"], hecate_workspace=tmp_path
        ),
    )

    result = runner.invoke(
        app,
        ["bas-detonate", "T1033", "--provider", "caldera", "--env", "lab", "--host", "lab-host"],
    )
    assert result.exit_code == 1
    assert "quarantined" in result.output


def test_cli_bas_reset_reports_purged_tmpfs_files(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "hecate_runner.bas.lifecycle.reset_lab",
        lambda *args, **kwargs: {
            "status": "clean",
            "lingering_processes_found": [],
            "lingering_files_found": ["/tmp/hecate-canary.tmp"],
            "files_purged": ["/tmp/hecate-canary.tmp"],
            "prior_quarantine": None,
        },
    )
    result = runner.invoke(app, ["bas-reset"])
    assert result.exit_code == 0
    assert "Lingering tmpfs files purged:" in result.output
    assert "/tmp/hecate-canary.tmp" in result.output
