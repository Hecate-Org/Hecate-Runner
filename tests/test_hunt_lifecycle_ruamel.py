"""Tests for comment-preserving hunt frontmatter roundtripping via ruamel.yaml."""

from __future__ import annotations

from pathlib import Path

from hecate_runner.lifecycle import (
    get_hunt_lifecycle,
    parse_hunt_frontmatter,
    set_hunt_lifecycle,
)


def test_parse_hunt_frontmatter_empty_and_no_frontmatter() -> None:
    assert parse_hunt_frontmatter("Just a body without frontmatter") == (
        {},
        "",
        "Just a body without frontmatter",
    )
    assert parse_hunt_frontmatter("---broken yaml frontmatter without closing") == (
        {},
        "",
        "---broken yaml frontmatter without closing",
    )


def test_set_hunt_lifecycle_preserves_yaml_comments(tmp_path: Path) -> None:
    hunts_dir = tmp_path / "hunts"
    hunts_dir.mkdir(parents=True, exist_ok=True)
    hunt_file = hunts_dir / "H-9999.md"

    initial_content = """---
# Important: Detection validated in Sentinel lab
id: H-9999
title: "Suspicious Kerberos TGS Request" # inline comment
status: planning
severity: high # threat level
# Technique mappings
techniques:
  - T1558.001 # Silver Ticket
---
## Overview
This is the hunt body markdown.
It contains instructions for analysts.
"""
    hunt_file.write_text(initial_content, encoding="utf-8")

    # 1. Transition planning -> active
    res1 = set_hunt_lifecycle(tmp_path, "H-9999", "active", actor="soc_lead")
    assert res1["ok"] is True
    assert res1["status"] == "active"

    content_active = hunt_file.read_text(encoding="utf-8")
    assert "# Important: Detection validated in Sentinel lab" in content_active
    assert "# inline comment" in content_active
    assert "# threat level" in content_active
    assert "# Technique mappings" in content_active
    assert "# Silver Ticket" in content_active
    assert "status: active" in content_active
    assert "## Overview" in content_active

    # 2. Transition active -> deprecated
    res2 = set_hunt_lifecycle(
        tmp_path,
        "H-9999",
        "deprecated",
        reason="Superceded by modern audit rule",
        actor="soc_lead",
    )
    assert res2["ok"] is True
    assert res2["status"] == "deprecated"

    content_deprecated = hunt_file.read_text(encoding="utf-8")
    assert "# Important: Detection validated in Sentinel lab" in content_deprecated
    assert "# Silver Ticket" in content_deprecated
    assert "status: deprecated" in content_deprecated
    assert "deprecation_reason: Superceded by modern audit rule" in content_deprecated
    assert "deprecated_by: soc_lead" in content_deprecated

    # Verify get_hunt_lifecycle reads it cleanly
    info = get_hunt_lifecycle(tmp_path, "H-9999")
    assert info["found"] is True
    assert info["status"] == "deprecated"
    assert info["is_deprecated"] is True
    assert info["deprecated_by"] == "soc_lead"
