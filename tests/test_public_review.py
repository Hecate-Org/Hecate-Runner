from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

from hecate_runner.config import Settings
from hecate_runner.github_publisher import _snapshot_bundle, enqueue_hunt, outbox_for, sync_outbox
from hecate_runner.public_review import (
    PublicReviewRequiredError,
    approve_public_review,
    prepare_public_review,
    require_public_review,
)


def _public_settings(tmp_path):
    root = tmp_path / "workspace"
    (root / "hunts/2026/Q4").mkdir(parents=True)
    (root / "hunts/2026/Q4/H-9001.md").write_text(
        "---\nhunt_id: H-9001\nstatus: planning\ntechniques: [T1033]\nplatform: [Linux]\n"
        "data_sources: [process_creation]\n---\n# Public test\n"
    )
    risks = dict.fromkeys(
        [
            "missing_cti",
            "missing_research",
            "missing_sigma",
            "incomplete_metadata",
            "low_confidence_source",
            "unsupported_claims",
            "bas_failed",
        ],
        "review",
    )
    risks.update(tlp_amber="block", unknown_tlp="allow")
    (root / "promotion-policy.yaml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "target_visibility": "public",
                "publisher_login": "hecate-publisher[bot]",
                "auto_merge": {"enabled": True, "merge_method": "squash"},
                "risk": risks,
                "review": {"minimum_approvals": 1, "allowed_associations": ["OWNER"]},
            }
        )
    )
    return Settings(
        _env_file=None, hecate_workspace=root, github_publishing_repository="example/Public"
    )


def approve(settings, files):
    request = prepare_public_review(settings, files)
    return approve_public_review(
        settings,
        files,
        expected_digest=request["digest"],
        reviewer="test-operator",
        rights_note="Original synthetic test content with redistribution permission.",
        privacy_checked=True,
        redistribution_checked=True,
    )


def test_unreviewed_public_hunt_is_private_and_not_due(tmp_path):
    settings = _public_settings(tmp_path)
    assert enqueue_hunt(settings, "H-9001") == "awaiting_review"
    assert not outbox_for(settings).has_due()
    files, _ = _snapshot_bundle(settings, "H-9001")
    request = prepare_public_review(settings, files)
    preview = Path(request["review_directory"])
    assert (preview / "files/hunts/2026/Q4/H-9001.md").is_file()
    assert not (preview / "approved.json").exists()
    if os.name == "posix":
        assert preview.stat().st_mode & 0o077 == 0
    approve(settings, files)
    assert enqueue_hunt(settings, "H-9001") == "queued"
    assert outbox_for(settings).has_due()


def test_approval_is_invalidated_by_content_policy_and_destination_changes(tmp_path):
    settings = _public_settings(tmp_path)
    files, _ = _snapshot_bundle(settings, "H-9001")
    approve(settings, files)
    require_public_review(settings, files)
    for changed in ({**files, "new.txt": "new content"}, {**files, next(iter(files)): "changed"}):
        with pytest.raises(PublicReviewRequiredError):
            require_public_review(settings, changed)
    settings.github_publishing_repository = "example/other-public-repo"
    with pytest.raises(PublicReviewRequiredError):
        require_public_review(settings, files)


def test_approval_requires_exact_digest_and_release_attestations(tmp_path):
    settings = _public_settings(tmp_path)
    files, _ = _snapshot_bundle(settings, "H-9001")
    request = prepare_public_review(settings, files)
    for digest, privacy in (("stale", True), (request["digest"], False)):
        with pytest.raises(PublicReviewRequiredError):
            approve_public_review(
                settings,
                files,
                expected_digest=digest,
                reviewer="test-operator",
                rights_note="Original test fixture with known source rights.",
                privacy_checked=privacy,
                redistribution_checked=True,
            )


def test_old_queued_public_jobs_never_construct_a_network_client_without_approval(
    tmp_path, monkeypatch
):
    settings = _public_settings(tmp_path)
    settings.github_publishing_enabled = True
    files, digest = _snapshot_bundle(settings, "H-9001")
    outbox_for(settings).enqueue("H-9001", digest, files)
    monkeypatch.setattr(
        "hecate_runner.github_publisher.GitHubAppClient",
        lambda *a: (_ for _ in ()).throw(
            AssertionError("Unreviewed content reached network client")
        ),
    )
    assert sync_outbox(settings) == []
    assert outbox_for(settings).summary()[0]["status"] == "awaiting_review"


def test_untrusted_approval_file_is_refused(tmp_path):
    settings = _public_settings(tmp_path)
    files, _ = _snapshot_bundle(settings, "H-9001")
    record = approve(settings, files)
    request = prepare_public_review(settings, files)
    path = Path(request["review_directory"]) / "approved.json"
    path.write_text(json.dumps({**record, "privacy_checked": False}))
    with pytest.raises(PublicReviewRequiredError):
        require_public_review(settings, files)


def test_policy_change_queues_exact_new_approved_snapshot(tmp_path):
    settings = _public_settings(tmp_path)
    enqueue_hunt(settings, "H-9001")
    before, digest_before = _snapshot_bundle(settings, "H-9001")
    policy = settings.hecate_workspace / "promotion-policy.yaml"
    data = yaml.safe_load(policy.read_text())
    data["auto_merge"]["merge_method"] = "merge"
    policy.write_text(yaml.safe_dump(data))
    after, digest_after = _snapshot_bundle(settings, "H-9001")
    assert before != after and digest_before != digest_after
    approve(settings, after)
    assert enqueue_hunt(settings, "H-9001") == "queued"
    row = outbox_for(settings).claim_due()
    assert json.loads(row["payload"]) == after
    require_public_review(settings, json.loads(row["payload"]))
