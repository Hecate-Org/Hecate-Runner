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
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    return root


def prepare_public_review(settings: Settings, files: dict[str, str]) -> dict[str, Any]:
    destination = settings.github_publishing_repository
    digest = review_digest(destination, files)
    root = _root(settings, digest)
    manifest = []
    for name, content in sorted(files.items()):
        target = root / "files" / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write_text(target, content, mode=0o600)
        manifest.append({"path": name, "sha256": hashlib.sha256(content.encode()).hexdigest()})
    request = {
        "schema_version": 1,
        "destination": destination,
        "digest": digest,
        "files": manifest,
        "review_directory": str(root),
    }
    atomic_write_text(root / "request.json", json.dumps(request, indent=2), mode=0o600)
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
        mode=0o600,
    )
    return approval


def require_public_review(settings: Settings, files: dict[str, str]) -> None:
    digest = review_digest(settings.github_publishing_repository, files)
    path = _root(settings, digest) / "approved.json"
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise PublicReviewRequiredError("Public release approval is missing")
        mode = path.stat()
        if os.name == "posix" and (
            stat.S_IMODE(mode.st_mode) & 0o077 or mode.st_uid != os.getuid()
        ):
            raise PublicReviewRequiredError("Public release approval must be owner-only")
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
