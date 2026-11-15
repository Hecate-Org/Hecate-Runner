"""Private, destination-bound approval before content reaches a public branch.

These records authorize an exact file snapshot. They do not replace the
repository's separate content-quality review or assert that a detection works.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.config import Settings
from hecate_runner.private_data import prepare_directory, uses_shared_policy


class PublicReviewRequiredError(ValueError):
    """The exact public snapshot has not received an operator's release approval."""


def review_digest(destination: str, files: dict[str, str]) -> str:
    """Include the destination, paths, and every byte, including promotion policy."""
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", destination):
        raise ValueError("Public destination must be owner/repository")
    digest = hashlib.sha256(destination.encode() + b"\0")
    for name, content in sorted(files.items()):
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name or str(path) != name:
            raise ValueError("Unsafe public artifact path")
        digest.update(name.encode() + b"\0" + content.encode() + b"\0")
    return digest.hexdigest()


def _root(settings: Settings, digest: str) -> Path:
    root = settings.hecate_workspace / ".hecate" / "publisher" / "public-reviews" / digest
    for path in reversed((root, *root.parents)):
        if (
            path == settings.hecate_workspace or path.is_relative_to(settings.hecate_workspace)
        ) and path.is_symlink():
            raise ValueError("Public review storage must not contain symlinks")
    prepare_directory(root)
    return root


def prepare_public_review(settings: Settings, files: dict[str, str]) -> dict[str, Any]:
    destination = settings.github_publishing_repository
    digest = review_digest(destination, files)
    root = _root(settings, digest)
    shared = uses_shared_policy(root, directory=True)
    data_mode = 0o660 if shared else 0o600
    manifest = []
    for name, content in sorted(files.items()):
        target = root / "files" / name
        prepare_directory(target.parent)
        atomic_write_text(target, content, mode=data_mode)
        manifest.append({"path": name, "sha256": hashlib.sha256(content.encode()).hexdigest()})
    request = {
        "schema_version": 1,
        "destination": destination,
        "digest": digest,
        "files": manifest,
        "review_directory": str(root),
    }
    atomic_write_text(root / "request.json", json.dumps(request, indent=2), mode=data_mode)
    return request


def approve_public_review(
    settings: Settings,
    files: dict[str, str],
    *,
    expected_digest: str,
    reviewer: str,
    rights_note: str,
    privacy_checked: bool,
    redistribution_checked: bool,
) -> dict[str, Any]:
    shared = uses_shared_policy(settings.hecate_workspace, directory=True)
    if shared and os.getuid() != settings.hecate_workspace.stat().st_uid:
        raise PublicReviewRequiredError(
            "Public release approval must be recorded by the workspace owner"
        )
    request = prepare_public_review(settings, files)
    if expected_digest != request["digest"]:
        raise PublicReviewRequiredError("Snapshot changed; inspect and approve its new digest")
    if (
        not privacy_checked
        or not redistribution_checked
        or not reviewer.strip()
        or len(reviewer) > 120
        or any(ord(c) < 32 for c in reviewer)
        or len(rights_note.strip()) < 20
    ):
        raise PublicReviewRequiredError(
            "Record the reviewer, source rights, and both release checks"
        )
    approval = {
        "schema_version": 1,
        "destination": request["destination"],
        "digest": request["digest"],
        "reviewer": reviewer.strip(),
        "rights_note": rights_note.strip(),
        "privacy_checked": True,
        "redistribution_checked": True,
        "approved_at": datetime.now(UTC).isoformat(),
    }
    atomic_write_text(
        _root(settings, str(request["digest"])) / "approved.json",
        json.dumps(approval, indent=2),
        mode=0o640 if shared else 0o600,
    )
    return approval


def require_public_review(settings: Settings, files: dict[str, str]) -> None:
    digest = review_digest(settings.github_publishing_repository, files)
    path = _root(settings, digest) / "approved.json"
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise PublicReviewRequiredError("Public release approval is missing")
        mode = path.stat()
        if os.name == "posix":
            shared = uses_shared_policy(path.parent, directory=True)
            if shared:
                valid = (
                    mode.st_uid == settings.hecate_workspace.stat().st_uid
                    and mode.st_gid == path.parent.stat().st_gid
                    and stat.S_IMODE(mode.st_mode) == 0o640
                )
            else:
                valid = not stat.S_IMODE(mode.st_mode) & 0o077 and mode.st_uid == os.getuid()
            if not valid:
                raise PublicReviewRequiredError(
                    "Public release approval must have trusted ownership and private read-only access"
                )
        approval = json.loads(path.read_text(encoding="utf-8"))
        if (
            approval.get("schema_version") != 1
            or approval.get("destination") != settings.github_publishing_repository
            or approval.get("digest") != digest
            or approval.get("privacy_checked") is not True
            or approval.get("redistribution_checked") is not True
            or not approval.get("reviewer")
            or not approval.get("rights_note")
        ):
            raise PublicReviewRequiredError("Public release approval does not match this snapshot")
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        raise PublicReviewRequiredError(
            f"Public release review required for digest {digest}; run publish-review first"
        ) from exc
