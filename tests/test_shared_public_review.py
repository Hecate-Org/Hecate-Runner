"""Shared queues do not let a service account grant public release approval."""

import os
import stat
from pathlib import Path

import pytest

from hecate_runner import private_data, public_review
from hecate_runner.config import Settings


@pytest.fixture
def shared_review(tmp_path, monkeypatch):
    monkeypatch.setenv("HECATE_SERVICE_ISOLATED", "1")
    monkeypatch.setattr(private_data, "_shared_gid", os.getgid)
    settings = Settings(hecate_workspace=tmp_path, github_publishing_repository="example/public")
    files = {"README.md": "Reviewed public fixture\n"}
    return settings, files


def approve(settings, files):
    return public_review.approve_public_review(
        settings,
        files,
        expected_digest=public_review.review_digest(settings.github_publishing_repository, files),
        reviewer="workspace owner",
        rights_note="Original material authorized for public redistribution",
        privacy_checked=True,
        redistribution_checked=True,
    )


def test_operator_approval_is_group_readable_and_accepted_by_a_different_worker(
    shared_review, monkeypatch
):
    settings, files = shared_review
    approve(settings, files)
    digest = public_review.review_digest(settings.github_publishing_repository, files)
    path = settings.hecate_workspace / ".hecate/publisher/public-reviews" / digest / "approved.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    monkeypatch.setattr(
        public_review.os, "getuid", lambda: settings.hecate_workspace.stat().st_uid + 1
    )
    public_review.require_public_review(settings, files)


def test_service_accounts_cannot_create_operator_approval(shared_review, monkeypatch):
    settings, files = shared_review
    monkeypatch.setattr(
        public_review.os, "getuid", lambda: settings.hecate_workspace.stat().st_uid + 1
    )
    with pytest.raises(public_review.PublicReviewRequiredError, match="workspace owner"):
        approve(settings, files)
    assert not list(settings.hecate_workspace.rglob("approved.json"))


def test_group_writable_approval_is_never_trusted(shared_review):
    settings, files = shared_review
    approve(settings, files)
    path = next(settings.hecate_workspace.rglob("approved.json"))
    path.chmod(0o660)
    with pytest.raises(public_review.PublicReviewRequiredError):
        public_review.require_public_review(settings, files)


def test_worker_owned_forged_approval_is_refused(shared_review, monkeypatch):
    settings, files = shared_review
    approve(settings, files)
    approval = next(settings.hecate_workspace.rglob("approved.json"))
    original = Path.stat

    def worker_ownership(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == approval:
            fields = list(info)
            fields[4] = info.st_uid + 1
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(Path, "stat", worker_ownership)
    with pytest.raises(public_review.PublicReviewRequiredError):
        public_review.require_public_review(settings, files)
