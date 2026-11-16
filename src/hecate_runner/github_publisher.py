"""Publish completed hunts to a policy-approved repository through an isolated GitHub PR.

The publisher never operates on the workspace's Git checkout. It snapshots a
small, validated set of artifacts into a SQLite outbox, then uses the GitHub
Git database API to create a branch and pull request. Retries therefore cannot
stage unrelated operator state or repeat CTI intake.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, cast
from urllib.parse import quote

import httpx
import jwt

from hecate_runner.config import Settings
from hecate_runner.hunt_audit import parse_hunt_file
from hecate_runner.private_data import prepare_directory, protect_file
from hecate_runner.promotion_policy import _TLP_RE, evaluate_promotion, load_policy
from hecate_runner.public_review import (
    PublicReviewRequiredError,
    prepare_public_review,
    require_public_review,
    review_digest,
)
from hecate_runner.sqlite_utils import connect_sqlite

log = logging.getLogger(__name__)

_HUNT_ID_RE = re.compile(r"^H-\d{4,}$")
_RESEARCH_ID_RE = re.compile(r"^R-\d{4,}$")
_MAX_BUNDLE_FILES = 200
_MAX_FILE_BYTES = 2_000_000
_MAX_BUNDLE_BYTES = 8_000_000
_API = "https://api.github.com"
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
)


class PublisherError(RuntimeError):
    """A publication could not be safely completed."""


@dataclass(frozen=True)
class PublishResult:
    hunt_id: str
    digest: str
    status: str
    branch: str
    pr_number: int | None = None
    pr_url: str | None = None


def _relative_file(workspace: Path, candidate: Path, *, allowed_root: str) -> tuple[str, str]:
    """Read a regular UTF-8 file and prove it belongs to the expected subtree."""
    workspace_root = workspace.resolve()
    root = (workspace_root / allowed_root).resolve()
    if not root.is_relative_to(workspace_root):
        raise PublisherError(f"Refusing to publish from a linked {allowed_root}/ directory")
    try:
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(root) or candidate.is_symlink() or not resolved.is_file():
            raise PublisherError(f"Refusing to publish an artifact outside {allowed_root}/")
        relative = resolved.relative_to(workspace.resolve()).as_posix()
        data = resolved.read_bytes()
    except PublisherError:
        raise
    except OSError as exc:
        # Isolation/group mode often surfaces as EACCES — keep it a PublisherError
        # so operators get a clear outbox failure instead of a raw stack trace.
        raise PublisherError(
            f"Could not read artifact (permission or IO error): {candidate}"
        ) from exc
    if len(data) > _MAX_FILE_BYTES or b"\x00" in data:
        raise PublisherError(f"Artifact is too large or not text: {relative}")
    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PublisherError(f"Artifact is not UTF-8 text: {relative}") from exc
    return relative, content


# Correlator always prefixes with a horizontal rule, but older/manual copies may not.
_INCREMENTAL_UPDATE_RE = re.compile(
    r"(?:\n---)?\n+## Incremental Threat Intel Update\b.*?(?=\n---\n|\n## Incremental Threat Intel Update\b|\Z)",
    re.DOTALL,
)


def public_hunt_text_for_promotion(hunt_text: str) -> str:
    """Strip living-dossier IOC appendices so publish digests track behavioral content.

    Correlator appends campaign IOC tables and ``last_enriched_at`` to the private
    hunt; those must not churn public review or ship as the publish surface.
    """
    text = hunt_text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"(?m)^last_enriched_at:\s*.*\n", "", text)
    # Repeat until stable so adjacent blocks and rule separators are fully removed.
    prev = None
    while prev != text:
        prev = text
        text = _INCREMENTAL_UPDATE_RE.sub("\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.rstrip() + ("\n" if text.strip() else "")


def snapshot_hunt_artifacts(settings: Settings, hunt_id: str) -> tuple[dict[str, str], str]:
    """Snapshot one hunt's artifacts for downstream storage, excluding GitHub policy."""
    if not _HUNT_ID_RE.fullmatch(hunt_id):
        raise PublisherError("Hunt IDs must look like H-0001")

    workspace = settings.hecate_workspace.resolve()
    matches = sorted((workspace / "hunts").glob(f"**/{hunt_id}.md"))
    if len(matches) != 1:
        raise PublisherError(f"Expected exactly one hunt file for {hunt_id}; found {len(matches)}")

    files: dict[str, str] = {}
    hunt_path, hunt_text = _relative_file(workspace, matches[0], allowed_root="hunts")
    if not re.fullmatch(r"hunts/\d{4}/Q[1-4]/" + re.escape(hunt_id) + r"\.md", hunt_path):
        raise PublisherError(f"Unexpected hunt path: {hunt_path}")
    # Digest/publish surface excludes correlator IOC appendices.
    files[hunt_path] = public_hunt_text_for_promotion(hunt_text)

    facts = parse_hunt_file(hunt_text)
    if facts.hunt_id != hunt_id:
        raise PublisherError(f"Hunt frontmatter ID does not match {hunt_id}")
    if facts.research_id:
        if not _RESEARCH_ID_RE.fullmatch(facts.research_id):
            raise PublisherError("Hunt has an invalid linked research ID")
        research_path = workspace / "research" / f"{facts.research_id}.md"
        if research_path.exists():
            rel, content = _relative_file(workspace, research_path, allowed_root="research")
            files[rel] = content

    query_dir = workspace / "queries" / hunt_id
    if query_dir.exists():
        if query_dir.is_symlink() or not query_dir.resolve().is_relative_to(
            (workspace / "queries").resolve()
        ):
            raise PublisherError("Refusing to publish a query directory outside queries/")
        for path in sorted(query_dir.iterdir()):
            if path.suffix.lower() not in {
                ".yml",
                ".yaml",
                ".kql",
                ".cql",
                ".leql",
                ".s1ql",
                ".spl",
                ".eql",
            }:
                continue
            # Correlator IOC stubs (and their transpiles) are local enrichment
            # noise — never include them in public promotion digests.
            if "incremental" in path.name.lower():
                continue
            if path.is_dir():
                raise PublisherError("Nested query directories are not publishable")
            rel, content = _relative_file(workspace, path, allowed_root="queries")
            if PurePosixPath(rel).parts[:2] != ("queries", hunt_id):
                raise PublisherError(f"Unexpected Sigma rule path: {rel}")
            files[rel] = content

    if len(files) > _MAX_BUNDLE_FILES:
        raise PublisherError("Hunt bundle contains too many files")
    total_bytes = sum(len(content.encode("utf-8")) for content in files.values())
    if total_bytes > _MAX_BUNDLE_BYTES:
        raise PublisherError("Hunt bundle exceeds the publication size limit")

    digest_builder = hashlib.sha256()
    for relative_path, content in sorted(files.items()):
        digest_builder.update(relative_path.encode("utf-8"))
        digest_builder.update(b"\0")
        digest_builder.update(content.encode("utf-8"))
        digest_builder.update(b"\0")
    digest = digest_builder.hexdigest()
    return files, digest


def _validate_public_bundle(settings: Settings, files: dict[str, str]) -> None:
    """Reject restricted markings and credentials before any public GitHub write."""
    secrets = [
        value
        for name, value in settings.model_dump().items()
        if isinstance(value, str)
        and len(value) >= 12
        and any(part in name for part in ("api_key", "token", "secret", "password"))
    ]
    for path, content in files.items():
        if any(value.upper() not in {"CLEAR", "WHITE"} for value in _TLP_RE.findall(content)):
            raise PublisherError(f"Restricted TLP marking prevents public publication: {path}")
        if any(pattern.search(content) for pattern in _SECRET_PATTERNS) or any(
            value in content for value in secrets
        ):
            raise PublisherError(f"Credential material prevents public publication: {path}")


def _snapshot_bundle(settings: Settings, hunt_id: str) -> tuple[dict[str, str], str]:
    """Apply GitHub promotion policy to the shared artifact snapshot."""
    files, digest = snapshot_hunt_artifacts(settings, hunt_id)
    workspace = settings.hecate_workspace.resolve()
    policy = load_policy(workspace, settings.github_publishing_policy_path)
    if policy["publisher_login"].lower() != f"{settings.github_app_slug.lower()}[bot]":
        raise PublisherError("Configured GitHub App slug does not match promotion-policy.yaml")
    decision = evaluate_promotion(
        workspace, hunt_id, policy_path=settings.github_publishing_policy_path
    )
    if policy["target_visibility"] == "public":
        _validate_public_bundle(settings, files)
    manifest_path = f"promotion-manifests/{hunt_id}-{digest[:12]}.json"
    files[manifest_path] = (
        json.dumps(
            {
                "schema_version": 1,
                "hunt_id": hunt_id,
                "sha256": digest,
                "files": sorted(path for path in files),
                "publisher": "hecate-runner",
                "target_repository": settings.github_publishing_repository,
                "target_visibility": policy["target_visibility"],
                # Never enable auto-merge for a review-classified hunt. The PR
                # review workflow runs asynchronously; enabling auto-merge
                # from the publisher can merge a risky bundle before that job
                # gets a chance to enforce the human approval requirement.
                "auto_merge": bool(policy["auto_merge"].get("enabled", False))
                and decision.eligible,
                "review_required": decision.review_required,
                "promotion_reasons": decision.reasons,
                "merge_method": policy["auto_merge"].get("merge_method", "squash"),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    # Queue/branch identity must cover the manifest and destination as approval does.
    return files, review_digest(settings.github_publishing_repository, files)


class PromotionOutbox:
    """Durable snapshots and retry state, isolated under the ignored .hecate dir."""

    def __init__(self, database: Path) -> None:
        self.database = database
        try:
            prepare_directory(database.parent)
            if database.exists() or database.is_symlink():
                protect_file(database)
            self._initialize()
            protect_file(database)
        except OSError as exc:
            raise PublisherError("Could not enforce GitHub outbox data permissions") from exc

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = connect_sqlite(self.database, timeout=30, wal=True, busy_timeout_ms=30000)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS promotions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hunt_id TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt REAL NOT NULL DEFAULT 0,
                    branch TEXT NOT NULL,
                    pr_number INTEGER,
                    pr_url TEXT,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(hunt_id, digest)
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS promotions_due ON promotions(status, next_attempt)"
            )
            # A crash after claiming work must not leave it stuck forever.
            stale = time.time() - 1800
            connection.execute(
                "UPDATE promotions SET status='queued', updated_at=? "
                "WHERE status='publishing' AND updated_at < ?",
                (datetime.now(UTC).isoformat(), datetime.fromtimestamp(stale, UTC).isoformat()),
            )

    def enqueue(
        self, hunt_id: str, digest: str, files: dict[str, str], *, reviewed: bool = True
    ) -> str:
        now = datetime.now(UTC).isoformat()
        branch = f"hecate/promotion/{hunt_id.lower()}-{digest[:12]}"
        payload = json.dumps(files, sort_keys=True, separators=(",", ":"))
        status = "queued" if reviewed else "awaiting_review"
        with self._connect() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO promotions
                   (hunt_id,digest,payload,status,branch,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    hunt_id,
                    digest,
                    payload,
                    status,
                    branch,
                    now,
                    now,
                ),
            )
            if reviewed:
                # Revive review/retry tips; never interrupt an in-flight publish.
                connection.execute(
                    "UPDATE promotions SET status='queued', updated_at=?, last_error=NULL "
                    "WHERE hunt_id=? AND digest=? AND status IN "
                    "('awaiting_review','superseded','retry')",
                    (now, hunt_id, digest),
                )
            else:
                # Content can oscillate back to a previously superseded digest.
                connection.execute(
                    "UPDATE promotions SET status='awaiting_review', updated_at=?, last_error=NULL "
                    "WHERE hunt_id=? AND digest=? AND status='superseded'",
                    (now, hunt_id, digest),
                )
            # Living dossiers: only the tip digest stays reviewable / queued.
            # Older awaiting_review rows for the same hunt are superseded in DB
            # (not merely hidden by latest_awaiting_review). Never touch
            # queued/retry/publishing/published peers.
            connection.execute(
                "UPDATE promotions SET status='superseded', updated_at=?, "
                "last_error=? WHERE hunt_id=? AND status='awaiting_review' AND digest!=?",
                (
                    now,
                    f"Superseded by digest {digest[:12]}",
                    hunt_id,
                    digest,
                ),
            )
            row = connection.execute(
                "SELECT status FROM promotions WHERE hunt_id=? AND digest=?", (hunt_id, digest)
            ).fetchone()
        return str(row["status"])

    def claim_due(self) -> sqlite3.Row | None:
        now_epoch = time.time()
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT * FROM promotions
                   WHERE status IN ('queued','retry') AND next_attempt <= ?
                   ORDER BY id LIMIT 1""",
                (now_epoch,),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            connection.execute(
                "UPDATE promotions SET status='publishing', attempts=attempts+1, updated_at=? WHERE id=?",
                (now, row["id"]),
            )
            connection.commit()
            return cast(sqlite3.Row, row)

    def finish(self, row_id: int, result: PublishResult) -> None:
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT hunt_id FROM promotions WHERE id=?", (row_id,)
            ).fetchone()
            if result.status in {"published", "merged"}:
                # Keep this tip's payload so diff_release_snapshots can compare
                # against last published. Prune older published/merged payloads
                # for the same hunt to bound outbox size.
                connection.execute(
                    """UPDATE promotions SET status=?, branch=?, pr_number=?, pr_url=?,
                       last_error=NULL, updated_at=? WHERE id=?""",
                    (
                        result.status,
                        result.branch,
                        result.pr_number,
                        result.pr_url,
                        now,
                        row_id,
                    ),
                )
                if row is not None:
                    connection.execute(
                        """UPDATE promotions SET payload='{}', updated_at=?
                           WHERE hunt_id=? AND status IN ('published','merged')
                             AND id!=? AND payload != '{}'""",
                        (now, row["hunt_id"], row_id),
                    )
            else:
                connection.execute(
                    """UPDATE promotions SET status=?, branch=?, pr_number=?, pr_url=?,
                       payload=CASE WHEN ? = 'closed' THEN '{}' ELSE payload END,
                       last_error=NULL, updated_at=? WHERE id=?""",
                    (
                        result.status,
                        result.branch,
                        result.pr_number,
                        result.pr_url,
                        result.status,
                        now,
                        row_id,
                    ),
                )

    def fail(self, row_id: int, attempts: int, error: str) -> None:
        delay = min(60 * (2 ** min(max(attempts - 1, 0), 8)), 21600)
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute(
                """UPDATE promotions SET status='retry', next_attempt=?, last_error=?,
                   updated_at=? WHERE id=?""",
                (now.timestamp() + delay, error[:1000], now.isoformat(), row_id),
            )

    def await_review(self, row_id: int) -> None:
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT hunt_id, digest FROM promotions WHERE id=?", (row_id,)
            ).fetchone()
            connection.execute(
                "UPDATE promotions SET status='awaiting_review', last_error=?, updated_at=? WHERE id=?",
                (
                    "Public privacy and redistribution review required",
                    now,
                    row_id,
                ),
            )
            if row is not None:
                connection.execute(
                    "UPDATE promotions SET status='superseded', updated_at=?, last_error=? "
                    "WHERE hunt_id=? AND status='awaiting_review' AND digest!=?",
                    (
                        now,
                        f"Superseded by digest {str(row['digest'])[:12]}",
                        row["hunt_id"],
                        row["digest"],
                    ),
                )

    def summary(self) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return connection.execute(
                """SELECT hunt_id,digest,status,attempts,branch,pr_number,pr_url,last_error
                   FROM promotions ORDER BY id DESC LIMIT 50"""
            ).fetchall()

    def compact_stale_awaiting_review(self) -> int:
        """DB-supersede non-tip ``awaiting_review`` rows (heals pre-hygiene outboxes)."""
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            # Cheap existence check — after the first heal this is a no-op hot path.
            stale = connection.execute(
                """SELECT 1 FROM promotions p
                   WHERE p.status = 'awaiting_review'
                     AND p.id NOT IN (
                       SELECT max_id FROM (
                         SELECT MAX(id) AS max_id FROM promotions
                         WHERE status = 'awaiting_review' GROUP BY hunt_id
                       )
                     )
                   LIMIT 1"""
            ).fetchone()
            if stale is None:
                return 0
            cur = connection.execute(
                """UPDATE promotions
                   SET status='superseded', updated_at=?,
                       last_error='Superseded by newer awaiting_review tip'
                   WHERE status = 'awaiting_review'
                     AND id NOT IN (
                       SELECT max_id FROM (
                         SELECT MAX(id) AS max_id FROM promotions
                         WHERE status = 'awaiting_review' GROUP BY hunt_id
                       )
                     )""",
                (now,),
            )
            return int(cur.rowcount or 0)

    def latest_awaiting_review(self) -> list[dict[str, Any]]:
        """One row per hunt: newest ``awaiting_review`` digest (older ones are noise)."""
        self.compact_stale_awaiting_review()
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT p.id, p.hunt_id, p.digest, p.updated_at, p.created_at, p.last_error,
                          (SELECT COUNT(*) FROM promotions o
                           WHERE o.hunt_id = p.hunt_id AND o.status = 'awaiting_review') AS awaiting_count
                   FROM promotions p
                   INNER JOIN (
                     SELECT hunt_id, MAX(id) AS max_id FROM promotions
                     WHERE status = 'awaiting_review' GROUP BY hunt_id
                   ) latest ON p.id = latest.max_id
                   ORDER BY p.hunt_id"""
            ).fetchall()
        return [dict(row) for row in rows]

    def last_published_snapshot(self, hunt_id: str) -> dict[str, Any] | None:
        """Most recent published/merged promotion for a hunt (payload may be cleared)."""
        with self._connect() as connection:
            row = connection.execute(
                """SELECT id, hunt_id, digest, payload, status, updated_at, pr_url, pr_number
                   FROM promotions
                   WHERE hunt_id = ? AND status IN ('published', 'merged')
                   ORDER BY id DESC LIMIT 1""",
                (hunt_id,),
            ).fetchone()
        return dict(row) if row else None

    def awaiting_snapshot(self, hunt_id: str, digest: str | None = None) -> dict[str, Any] | None:
        """Load an awaiting_review row (latest for hunt when digest omitted)."""
        with self._connect() as connection:
            if digest:
                row = connection.execute(
                    """SELECT id, hunt_id, digest, payload, status, updated_at
                       FROM promotions WHERE hunt_id = ? AND digest = ? AND status = 'awaiting_review'""",
                    (hunt_id, digest),
                ).fetchone()
            else:
                row = connection.execute(
                    """SELECT id, hunt_id, digest, payload, status, updated_at
                       FROM promotions WHERE hunt_id = ? AND status = 'awaiting_review'
                       ORDER BY id DESC LIMIT 1""",
                    (hunt_id,),
                ).fetchone()
        return dict(row) if row else None

    def has_due(self) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM promotions WHERE status IN ('queued','retry') AND next_attempt <= ? LIMIT 1",
                (time.time(),),
            ).fetchone()
        return row is not None


class GitHubAppClient:
    """Short-lived installation token client with narrowly scoped App access."""

    def __init__(self, settings: Settings) -> None:
        missing = [
            name
            for name, value in (
                ("HECATE_RUNNER_GITHUB_APP_ID", settings.github_app_id),
                ("HECATE_RUNNER_GITHUB_INSTALLATION_ID", settings.github_installation_id),
                ("HECATE_RUNNER_GITHUB_APP_PRIVATE_KEY_PATH", settings.github_app_private_key_path),
            )
            if not value
        ]
        if missing:
            raise PublisherError(
                "GitHub publishing is missing configuration: " + ", ".join(missing)
            )
        self.settings = settings
        assert settings.github_app_id
        assert settings.github_installation_id
        assert settings.github_app_private_key_path
        key_path = settings.github_app_private_key_path.expanduser()
        try:
            key_stat = key_path.stat()
            if not stat.S_ISREG(key_stat.st_mode) or stat.S_IMODE(key_stat.st_mode) & 0o077:
                raise PublisherError("GitHub App private key must be a regular file with mode 0600")
            private_key = key_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PublisherError("Could not read the GitHub App private key file") from exc
        issued = int(time.time()) - 30
        app_jwt = jwt.encode(
            {"iat": issued, "exp": issued + 540, "iss": settings.github_app_id},
            private_key,
            algorithm="RS256",
        )
        self.client = httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Authorization": f"Bearer {app_jwt}",
                "User-Agent": "hecate-runner-publisher",
            },
        )
        token_response = self._request(
            "POST",
            f"/app/installations/{quote(settings.github_installation_id, safe='')}/access_tokens",
            json={"permissions": {"contents": "write", "pull_requests": "write"}},
        )
        token = token_response.get("token")
        if not isinstance(token, str) or not token:
            raise PublisherError("GitHub did not return an installation token")
        self.client.headers["Authorization"] = f"Bearer {token}"

    @property
    def repository_path(self) -> str:
        repository = self.settings.github_publishing_repository.strip("/")
        if repository.count("/") != 1 or any(
            part in {"", ".", ".."} for part in repository.split("/")
        ):
            raise PublisherError("Target repository must use owner/name form")
        if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in repository.split("/")):
            raise PublisherError("Target repository contains invalid characters")
        return f"/repos/{repository}"

    def close(self) -> None:
        self.client.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
    ) -> Any:
        for attempt in range(4):
            try:
                response = self.client.request(method, f"{_API}{path}", json=json)
                if response.status_code in {429, 502, 503, 504} and attempt < 3:
                    retry_after = response.headers.get("Retry-After")
                    try:
                        delay = min(float(retry_after), 30.0) if retry_after else 2**attempt
                    except ValueError:
                        delay = 2**attempt
                    time.sleep(delay)
                    continue
                if response.is_error:
                    raise PublisherError(
                        f"GitHub API request failed ({method} {path}: HTTP {response.status_code})"
                    )
                if response.status_code == 204 or not response.content:
                    return None
                return response.json()
            except httpx.HTTPError as exc:
                if attempt < 3:
                    time.sleep(2**attempt)
                    continue
                raise PublisherError(f"GitHub API request failed ({method} {path})") from exc
        raise PublisherError("GitHub API request exhausted retries")

    def publish(self, row: sqlite3.Row) -> PublishResult:
        repo_path = self.repository_path
        policy = load_policy(
            self.settings.hecate_workspace, self.settings.github_publishing_policy_path
        )
        visibility = str(policy["target_visibility"])

        hunt_id = str(row["hunt_id"])
        digest = str(row["digest"])
        branch = str(row["branch"])
        files: dict[str, str] = json.loads(str(row["payload"]))
        if not files or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in files.items()
        ):
            raise PublisherError("Outbox bundle is malformed")
        manifests = [
            json.loads(content)
            for path, content in files.items()
            if path.startswith("promotion-manifests/")
        ]
        if len(manifests) != 1:
            raise PublisherError("Outbox bundle must contain exactly one promotion manifest")
        manifest = manifests[0]
        if (
            manifest.get("target_repository", self.settings.github_publishing_repository)
            != self.settings.github_publishing_repository
        ):
            raise PublisherError("Outbox destination does not match the configured repository")
        if manifest.get("target_visibility", "private") != visibility:
            raise PublisherError("Outbox visibility does not match the destination policy")
        if visibility == "public":
            _validate_public_bundle(self.settings, files)
            require_public_review(self.settings, files)
        self._assert_target_repository(repo_path, visibility)

        existing = self._find_pull_request(repo_path, branch)
        if existing:
            if existing.get("merged_at"):
                return PublishResult(
                    hunt_id, digest, "merged", branch, existing["number"], existing["html_url"]
                )
            if existing.get("state") == "closed":
                return PublishResult(
                    hunt_id, digest, "closed", branch, existing["number"], existing["html_url"]
                )
            auto_merge, merge_method = self._manifest_settings(files)
            is_merged = self._set_auto_merge(repo_path, existing, auto_merge, merge_method)
            status = "merged" if is_merged else "published"
            return PublishResult(
                hunt_id, digest, status, branch, existing["number"], existing["html_url"]
            )

        encoded_branch = quote(branch, safe="/")
        try:
            branch_ref = self._request("GET", f"{repo_path}/git/ref/heads/{encoded_branch}")
        except PublisherError as exc:
            if "HTTP 404" not in str(exc):
                raise
            branch_ref = None

        if branch_ref is None:
            self._assert_target_repository(repo_path, visibility)
            base_ref = self._request(
                "GET",
                f"{repo_path}/git/ref/heads/{quote(self.settings.github_publishing_base_branch, safe='/')}",
            )
            parent_sha = base_ref["object"]["sha"]
            base_commit = self._request("GET", f"{repo_path}/git/commits/{parent_sha}")
            tree = [
                {"path": path, "mode": "100644", "type": "blob", "content": content}
                for path, content in sorted(files.items())
            ]
            new_tree = self._request(
                "POST",
                f"{repo_path}/git/trees",
                json={"base_tree": base_commit["tree"]["sha"], "tree": tree},
            )
            commit = self._request(
                "POST",
                f"{repo_path}/git/commits",
                json={
                    "message": f"Publish {hunt_id} planning bundle\n\nHecate-Promotion-Digest: {digest}",
                    "tree": new_tree["sha"],
                    "parents": [parent_sha],
                    "author": {
                        "name": "Hecate Publisher",
                        "email": (
                            f"{self.settings.github_app_id}+{self.settings.github_app_slug}"
                            "[bot]@users.noreply.github.com"
                        ),
                    },
                    "committer": {
                        "name": "Hecate Publisher",
                        "email": (
                            f"{self.settings.github_app_id}+{self.settings.github_app_slug}"
                            "[bot]@users.noreply.github.com"
                        ),
                    },
                },
            )
            try:
                self._request(
                    "POST",
                    f"{repo_path}/git/refs",
                    json={"ref": f"refs/heads/{branch}", "sha": commit["sha"]},
                )
            except PublisherError as exc:
                # A concurrent retry may have created the deterministic ref.
                if "HTTP 422" not in str(exc):
                    raise

        pull_request = self._find_pull_request(repo_path, branch)
        if pull_request is None:
            self._assert_target_repository(repo_path, visibility)
            owner = self.settings.github_publishing_repository.split("/", 1)[0]
            body = (
                f"Automated planning bundle for **{hunt_id}**.\n\n"
                f"Bundle SHA-256: `{digest}`\n\n"
                "The required `content-validation` and `promotion-policy` checks decide whether this "
                "can merge automatically. Hunt status remains `planning`; this PR does not execute "
                "queries or activate detections."
            )
            try:
                pull_request = self._request(
                    "POST",
                    f"{repo_path}/pulls",
                    json={
                        "title": f"[Hecate] {hunt_id}: planning hunt",
                        "head": f"{owner}:{branch}",
                        "base": self.settings.github_publishing_base_branch,
                        "body": body,
                        "draft": False,
                    },
                )
            except PublisherError as exc:
                if "HTTP 422" not in str(exc):
                    raise
                pull_request = self._find_pull_request(repo_path, branch)
                if pull_request is None:
                    raise

        auto_merge, merge_method = self._manifest_settings(files)
        is_merged = self._set_auto_merge(repo_path, pull_request, auto_merge, merge_method)
        status = "merged" if is_merged else "published"
        return PublishResult(
            hunt_id,
            digest,
            status,
            branch,
            pull_request["number"],
            pull_request["html_url"],
        )

    def _find_pull_request(self, repo_path: str, branch: str) -> dict[str, Any] | None:
        owner = self.settings.github_publishing_repository.split("/", 1)[0]
        pulls = self._request(
            "GET",
            f"{repo_path}/pulls?state=all&head={quote(owner + ':' + branch, safe='')}&per_page=100",
        )
        return pulls[0] if pulls else None

    def _assert_target_repository(self, repo_path: str, visibility: str) -> None:
        repository = self._request("GET", repo_path)
        if repository.get("private") is not (visibility == "private"):
            raise PublisherError(
                "Target repository visibility does not match the publication policy"
            )

    @staticmethod
    def _manifest_settings(files: dict[str, str]) -> tuple[bool, str]:
        manifests = [
            content for path, content in files.items() if path.startswith("promotion-manifests/")
        ]
        if len(manifests) != 1:
            raise PublisherError("Outbox bundle must contain exactly one promotion manifest")
        try:
            value = json.loads(manifests[0])
        except json.JSONDecodeError as exc:
            raise PublisherError("Promotion manifest is malformed") from exc
        merge_method = value.get("merge_method", "squash")
        if merge_method not in {"merge", "squash", "rebase"}:
            raise PublisherError("Promotion manifest has an unsupported merge method")
        return value.get("auto_merge") is True, str(merge_method)

    def _set_auto_merge(
        self, repo_path: str, pull_request: dict[str, Any], enabled: bool, merge_method: str
    ) -> bool:
        """Configure GitHub auto-merge without bypassing repository checks."""
        if not enabled:
            query = """mutation DisableAutoMerge($pullRequestId: ID!) {
              disablePullRequestAutoMerge(input: {pullRequestId: $pullRequestId}) {
                pullRequest { number }
              }
            }"""
            try:
                self._request(
                    "POST",
                    "/graphql",
                    json={"query": query, "variables": {"pullRequestId": pull_request["node_id"]}},
                )
            except PublisherError as exc:
                log.info(
                    "Could not disable auto-merge for PR #%s (%s)",
                    pull_request.get("number"),
                    exc,
                )
            return False

        # Attempt GraphQL enablePullRequestAutoMerge first
        query = """mutation EnableAutoMerge($pullRequestId: ID!, $mergeMethod: PullRequestMergeMethod!) {
          enablePullRequestAutoMerge(input: {pullRequestId: $pullRequestId, mergeMethod: $mergeMethod}) {
            pullRequest { number autoMergeRequest { mergeMethod } }
          }
        }"""
        variables = {
            "pullRequestId": pull_request["node_id"],
            "mergeMethod": merge_method.upper(),
        }
        try:
            response = self._request(
                "POST",
                "/graphql",
                json={"query": query, "variables": variables},
            )
            if not response.get("errors"):
                return False  # Successfully enabled auto-merge queue on GitHub
            log.info(
                "GitHub auto-merge unavailable for PR #%s: %s; leaving PR open for checks/review",
                pull_request.get("number"),
                response.get("errors"),
            )
        except PublisherError as exc:
            log.info(
                "GitHub auto-merge failed for PR #%s (%s); leaving PR open for checks/review",
                pull_request.get("number"),
                exc,
            )
        return False


def outbox_for(settings: Settings) -> PromotionOutbox:
    return PromotionOutbox(
        settings.github_publishing_outbox_path
        or settings.hecate_workspace / ".hecate" / "publisher" / "promotion-outbox.sqlite3"
    )


def enqueue_hunt(settings: Settings, hunt_id: str) -> str:
    # Hard policy blocks (for example TLP:RED) raise here. Review-classified
    # bundles are still published so a human can review them in GitHub.
    files, digest = _snapshot_bundle(settings, hunt_id)
    reviewed = True
    policy = load_policy(settings.hecate_workspace, settings.github_publishing_policy_path)
    if policy["target_visibility"] == "public":
        prepare_public_review(settings, files)
        try:
            require_public_review(settings, files)
        except PublicReviewRequiredError:
            reviewed = False
    return outbox_for(settings).enqueue(hunt_id, digest, files, reviewed=reviewed)


def diff_release_snapshots(
    settings: Settings, hunt_id: str, *, digest: str | None = None
) -> dict[str, Any]:
    """Compare the latest (or specified) awaiting_review bundle to the last published one."""
    outbox = outbox_for(settings)
    pending = outbox.awaiting_snapshot(hunt_id, digest)
    if pending is None:
        return {
            "ok": False,
            "hunt_id": hunt_id,
            "error": f"No awaiting_review snapshot for {hunt_id}",
        }
    try:
        pending_files = json.loads(pending.get("payload") or "{}")
    except json.JSONDecodeError:
        pending_files = {}
    if not isinstance(pending_files, dict):
        pending_files = {}

    published = outbox.last_published_snapshot(hunt_id)
    published_files: dict[str, str] = {}
    published_digest = ""
    if published:
        published_digest = str(published.get("digest") or "")
        try:
            loaded = json.loads(published.get("payload") or "{}")
            if isinstance(loaded, dict) and loaded:
                published_files = {str(k): str(v) for k, v in loaded.items()}
        except json.JSONDecodeError:
            published_files = {}

    pending_paths = set(pending_files)
    published_paths = set(published_files)
    added = sorted(pending_paths - published_paths)
    removed = sorted(published_paths - pending_paths)
    changed = sorted(
        p
        for p in (pending_paths & published_paths)
        if pending_files.get(p) != published_files.get(p)
    )
    return {
        "ok": True,
        "hunt_id": hunt_id,
        "pending_digest": pending.get("digest"),
        "published_digest": published_digest or None,
        "baseline": "last_published" if published_files else "empty",
        "added": added,
        "removed": removed,
        "changed": changed,
        "pending_file_count": len(pending_files),
        "published_file_count": len(published_files),
    }


def sync_outbox(settings: Settings, *, max_items: int = 20) -> list[PublishResult]:
    """Publish due outbox rows; failures remain queued with bounded backoff."""
    if not settings.github_publishing_enabled:
        return []
    outbox = outbox_for(settings)
    if not outbox.has_due():
        return []
    client: GitHubAppClient | None = None
    results: list[PublishResult] = []
    try:
        for _ in range(max_items):
            row = outbox.claim_due()
            if row is None:
                break
            try:
                policy = load_policy(
                    settings.hecate_workspace, settings.github_publishing_policy_path
                )
                if policy["target_visibility"] == "public":
                    files = json.loads(str(row["payload"]))
                    _validate_public_bundle(settings, files)
                    try:
                        require_public_review(settings, files)
                    except PublicReviewRequiredError:
                        prepare_public_review(settings, files)
                        outbox.await_review(int(row["id"]))
                        continue
                if client is None:
                    client = GitHubAppClient(settings)
                result = client.publish(row)
                outbox.finish(int(row["id"]), result)
                results.append(result)
            except Exception as exc:
                outbox.fail(int(row["id"]), int(row["attempts"]) + 1, str(exc))
                log.warning(
                    "Could not publish %s (attempt %d); it remains in the outbox for retry: %s",
                    row["hunt_id"],
                    int(row["attempts"]) + 1,
                    exc,
                )
    finally:
        if client is not None:
            client.close()
    return results


def outbox_status(settings: Settings) -> list[dict[str, Any]]:
    return [dict(row) for row in outbox_for(settings).summary()]
