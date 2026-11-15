"""Query and hunt artifacts cannot redirect I/O into private host paths."""

import os
from unittest.mock import Mock

import pytest

from hecate_runner import slack_bot
from hecate_runner import workspace_paths as wp
from hecate_runner.lifecycle import find_hunt_path


@pytest.mark.parametrize(
    "value", ["../private", "/tmp", "H-0001/../../private", "H-*", "H-0001.md", "H-0001\\secret"]
)
def test_invalid_hunt_ids_are_rejected(value, tmp_path):
    with pytest.raises(ValueError):
        wp.query_directory(tmp_path, value)
    with pytest.raises(ValueError):
        find_hunt_path(tmp_path, value)


@pytest.mark.parametrize(
    "operation",
    [
        slack_bot.deploy_queries_for_hunt,
        slack_bot.undeploy_queries_for_hunt,
        slack_bot.sync_queries_for_hunt,
    ],
)
def test_symlinked_query_files_never_reach_deployment(operation, tmp_path, monkeypatch):
    private = tmp_path / "private"
    private.mkdir()
    (private / "credentials").write_text("private fixture")
    workspace = tmp_path / "workspace"
    query = workspace / "queries/H-0001"
    query.mkdir(parents=True)
    try:
        (query / "query.spl").symlink_to(private / "credentials")
    except OSError:
        pytest.skip("Symlinks unavailable")
    deploy = Mock()
    monkeypatch.setattr("hecate_agent.api.deploy_transpiled_query", deploy)
    with pytest.raises(ValueError):
        operation(workspace, "H-0001")
    deploy.assert_not_called()


def test_symlinked_parent_directory_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "workspace"
    root.mkdir()
    try:
        (root / "queries").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ValueError):
        wp.query_directory(root, "H-0001")


@pytest.mark.skipif(os.name != "posix", reason="Descriptor-relative opens are POSIX-specific")
def test_parent_symlink_race_cannot_redirect_an_artifact_read(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    query = root / "queries/H-0001"
    query.mkdir(parents=True)
    (query / "query.spl").write_text("public fixture")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "query.spl").write_text("private fixture")
    original = os.open

    def raced_open(path, flags, *args, **kwargs):
        if path == "query.spl":
            query.rename(query.with_name("held"))
            query.symlink_to(outside, target_is_directory=True)
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(wp.os, "open", raced_open)
    assert wp.read_artifact(query / "query.spl", root) == "public fixture"


@pytest.mark.skipif(
    os.name != "posix", reason="Descriptor-relative replacements are POSIX-specific"
)
def test_parent_symlink_race_cannot_redirect_an_artifact_write(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    query = root / "queries/H-0001"
    query.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "query.spl").write_text("private fixture")
    original = os.replace

    def raced_replace(source, destination, **kwargs):
        query.rename(query.with_name("held"))
        query.symlink_to(outside, target_is_directory=True)
        return original(source, destination, **kwargs)

    monkeypatch.setattr(wp.os, "replace", raced_replace)
    wp.write_artifact(query / "query.spl", "reviewed fixture", root)
    assert (outside / "query.spl").read_text() == "private fixture"
    assert (query.with_name("held") / "query.spl").read_text() == "reviewed fixture"


def test_size_limit_and_valid_hunt_lookup(tmp_path, monkeypatch):
    hunt = tmp_path / "hunts/2026/Q4/H-0001.md"
    hunt.parent.mkdir(parents=True)
    hunt.write_text("reviewed hunt")
    assert find_hunt_path(tmp_path, "h-0001") == hunt
    monkeypatch.setattr(wp, "MAX_ARTIFACT_BYTES", 3)
    with pytest.raises(ValueError, match="byte limit"):
        wp.read_artifact(hunt, tmp_path)
    with pytest.raises(ValueError, match="byte limit"):
        wp.write_artifact(hunt, "large", tmp_path)
