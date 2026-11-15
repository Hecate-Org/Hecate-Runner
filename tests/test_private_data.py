"""Publication outboxes share data only inside the isolated private group."""

import os
import sqlite3
import stat
from pathlib import Path

import pytest

from hecate_runner import private_data
from hecate_runner.config import Settings
from hecate_runner.github_publisher import PromotionOutbox
from hecate_runner.misp_publisher import _connect


@pytest.fixture
def isolated(monkeypatch):
    monkeypatch.setenv("HECATE_SERVICE_ISOLATED", "1")
    monkeypatch.setattr(private_data, "_shared_gid", os.getgid)


def test_migrated_outboxes_work_when_the_worker_cannot_chmod_existing_data(
    tmp_path, monkeypatch, isolated
):
    github = tmp_path / ".hecate/publisher/promotion-outbox.sqlite3"
    misp = tmp_path / ".hecate/misp/outbox.sqlite3"
    for path in (github, misp):
        path.parent.mkdir(parents=True)
        path.parent.chmod(0o2770)
        sqlite3.connect(path).close()
        path.chmod(0o660)

    def forbidden_chmod(*args, **kwargs):
        raise PermissionError("A different service owns this already-protected object")

    monkeypatch.setattr(Path, "chmod", forbidden_chmod)
    assert PromotionOutbox(github).summary() == []
    with _connect(Settings(hecate_workspace=tmp_path)) as database:
        assert database.execute("SELECT count(*) FROM exports").fetchone()[0] == 0
    for path in (github, misp):
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o2770
        assert stat.S_IMODE(path.stat().st_mode) == 0o660


def test_new_isolated_data_uses_the_private_group_policy(tmp_path, isolated):
    path = tmp_path / "outbox/data.sqlite3"
    private_data.prepare_directory(path.parent)
    path.write_text("fixture")
    private_data.protect_file(path)
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o2770
    assert stat.S_IMODE(path.stat().st_mode) == 0o660


def test_wrong_group_is_refused_before_permissions_are_changed(tmp_path, monkeypatch, isolated):
    path = tmp_path / "data.sqlite3"
    path.write_text("fixture")
    path.chmod(0o660)
    monkeypatch.setattr(private_data, "_shared_gid", lambda: os.getgid() + 100000)
    with pytest.raises(PermissionError, match="hecate-data"):
        private_data.protect_file(path)


def test_world_access_is_not_accepted_when_the_worker_cannot_restrict_it(
    tmp_path, monkeypatch, isolated
):
    path = tmp_path / "data.sqlite3"
    path.write_text("fixture")
    path.chmod(0o664)
    monkeypatch.setattr(Path, "chmod", lambda *a, **k: (_ for _ in ()).throw(PermissionError()))
    with pytest.raises(PermissionError):
        private_data.protect_file(path)


def test_private_data_refuses_symlink_files(tmp_path, isolated):
    outside = tmp_path / "outside"
    outside.write_text("fixture")
    alias = tmp_path / "alias"
    alias.symlink_to(outside)
    with pytest.raises(PermissionError):
        private_data.protect_file(alias)


def test_manual_installations_keep_owner_only_permissions(tmp_path, monkeypatch):
    monkeypatch.delenv("HECATE_SERVICE_ISOLATED", raising=False)
    path = tmp_path / "outbox/data.sqlite3"
    private_data.prepare_directory(path.parent)
    path.write_text("fixture")
    private_data.protect_file(path)
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_operator_cli_preserves_a_provisioned_shared_tree(tmp_path, monkeypatch):
    monkeypatch.delenv("HECATE_SERVICE_ISOLATED", raising=False)
    monkeypatch.setattr(private_data, "_shared_gid", os.getgid)
    path = tmp_path / "outbox/data.sqlite3"
    path.parent.mkdir()
    path.parent.chmod(0o2770)
    path.write_text("fixture")
    path.chmod(0o660)
    private_data.prepare_directory(path.parent)
    private_data.protect_file(path)
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o2770
    assert stat.S_IMODE(path.stat().st_mode) == 0o660
