"""Tests for hecate-runner export-layer CLI command."""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from hecate_runner.cli import app

runner = CliRunner()


def test_runner_export_layer_help() -> None:
    result = runner.invoke(app, ["export-layer", "--help"])
    assert result.exit_code == 0
    clean = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", result.output)
    assert "Export MITRE ATT&CK Navigator JSON layer" in clean
    assert "--score-by" in clean


def test_runner_layer_alias_help() -> None:
    result = runner.invoke(app, ["layer", "--help"])
    assert result.exit_code == 0
    clean = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", result.output)
    assert "Export MITRE ATT&CK Navigator JSON layer" in clean


def test_runner_export_layer_stdout(tmp_path: Path) -> None:
    hunts_dir = tmp_path / "hunts"
    queries_dir = tmp_path / "queries"
    hunts_dir.mkdir(parents=True)
    queries_dir.mkdir(parents=True)

    (hunts_dir / "H-0001.md").write_text(
        """---
hunt_id: H-0001
title: Reconnaissance Hunt
status: completed
date: '2026-10-31'
tactics:
  - reconnaissance
techniques:
  - T1595
platform:
  - Linux
---
# Hunt H-0001
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["export-layer", "--hunts-dir", str(hunts_dir), "--queries-dir", str(queries_dir)],
    )
    assert result.exit_code == 0
    layer = json.loads(result.output)
    assert layer["name"] == "Hecate Detection Coverage"
    assert layer["domain"] == "enterprise-attack"
    assert any(t.get("techniqueID") == "T1595" for t in layer["techniques"])


def test_runner_export_layer_to_file(tmp_path: Path) -> None:
    hunts_dir = tmp_path / "hunts"
    queries_dir = tmp_path / "queries"
    hunts_dir.mkdir(parents=True)
    queries_dir.mkdir(parents=True)

    (hunts_dir / "H-0001.md").write_text(
        """---
hunt_id: H-0001
title: Discovery Hunt
status: completed
date: '2026-10-31'
tactics:
  - discovery
techniques:
  - T1082
platform:
  - Windows
---
# Hunt H-0001
""",
        encoding="utf-8",
    )

    out_file = tmp_path / "runner_layer.json"
    result = runner.invoke(
        app,
        [
            "layer",
            "-o",
            str(out_file),
            "--name",
            "Custom Runner Layer",
            "--hunts-dir",
            str(hunts_dir),
            "--queries-dir",
            str(queries_dir),
        ],
    )
    assert result.exit_code == 0
    assert out_file.exists()
    layer = json.loads(out_file.read_text(encoding="utf-8"))
    assert layer["name"] == "Custom Runner Layer"
    assert any(t.get("techniqueID") == "T1082" for t in layer["techniques"])
