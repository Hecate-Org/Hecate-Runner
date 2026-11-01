"""File-queue CTI provider.

Supports both single-slot legacy ``<cti_queue>/next.txt`` and a multi-file
spooler directory (``<cti_queue>/spool/`` or files directly in ``<cti_queue>/``).
Archives consumed files to ``<cti_queue>/processed/cti-<timestamp>[-filename]``
after successful acknowledgment.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import re
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import CTIItem, CTIProvider

log = logging.getLogger(__name__)


@contextlib.contextmanager
def _queue_lock(lock_path: Path) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def route_item_to_queue(queue_dir: Path, item: CTIItem) -> Path:
    """Safely route a CTIItem into the file queue without losing data to race conditions.

    If next.txt is empty or does not exist, routes directly to next.txt.
    If next.txt is already occupied (e.g. concurrent poller wrote first or an unconsumed
    item is pending), safely spools to spool/ so neither item is overwritten or dropped.
    Synchronized with an exclusive flock.
    """
    queue_dir.mkdir(parents=True, exist_ok=True)
    next_file = queue_dir / "next.txt"
    lock_path = queue_dir / ".route.lock"

    with _queue_lock(lock_path):
        is_occupied = False
        try:
            if next_file.is_file() and next_file.stat().st_size > 0:
                is_occupied = bool(next_file.read_text(encoding="utf-8", errors="replace").strip())
        except OSError:
            is_occupied = False

        if not is_occupied:
            atomic_write_text(next_file, item.content)
            return next_file

        spool_dir = queue_dir / "spool"
        spool_dir.mkdir(parents=True, exist_ok=True)
        safe_id = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", item.identifier or "item")
        dest_file = spool_dir / f"{item.source}-{safe_id}.txt"
        atomic_write_text(dest_file, item.content)
        log.info(
            "Queue slot next.txt occupied; safely spooled %s to %s", item.identifier, dest_file
        )
        return dest_file


class FileQueueProvider(CTIProvider):
    """Read CTI from a multi-file spooler or next.txt, archive after ack."""

    name = "file"
    _RESERVED_DIRS: ClassVar[set[str]] = {"processed", "parked", "archive", "spool"}

    def __init__(self, queue_dir: Path):
        self.queue_dir = queue_dir
        self.next_file = queue_dir / "next.txt"
        self.spool_dir = queue_dir / "spool"
        self.processed_dir = queue_dir / "processed"

    def pending_items(self) -> list[Path]:
        """Return all pending queue files in FIFO processing order."""
        if not self.queue_dir.exists():
            return []

        pending: list[Path] = []

        # 1. next.txt always has immediate backwards-compatible priority
        try:
            if self.next_file.is_file() and self.next_file.stat().st_size > 0:
                pending.append(self.next_file)
        except OSError:
            pass

        # 2. Files in spool directory
        spool_files: list[Path] = []
        if self.spool_dir.is_dir():
            try:
                for p in self.spool_dir.iterdir():
                    try:
                        if p.is_file() and not p.name.startswith("."):
                            spool_files.append(p)
                    except OSError:
                        pass
            except OSError:
                pass

        # 3. Direct files in queue_dir (excluding next.txt, hidden files, and reserved subdirs)
        queue_files: list[Path] = []
        try:
            for p in self.queue_dir.iterdir():
                try:
                    if (
                        p.is_file()
                        and not p.name.startswith(".")
                        and p != self.next_file
                        and p.name not in self._RESERVED_DIRS
                    ):
                        queue_files.append(p)
                except OSError:
                    pass
        except OSError:
            pass

        # Sort non-next files by modification time (FIFO), safely handling concurrent unlinks
        other_files = spool_files + queue_files

        def _safe_sort_key(p: Path) -> tuple[int, str]:
            try:
                return (p.stat().st_mtime_ns, p.name)
            except OSError:
                return (0, p.name)

        other_files.sort(key=_safe_sort_key)
        pending.extend(other_files)
        return pending

    def spool(self, content: str | dict[str, Any], filename: str | None = None) -> Path:
        """Enqueue an item into the multi-file spooler."""
        self.ensure_dirs()
        if filename:
            target = self.spool_dir / filename
        else:
            now = datetime.now(UTC)
            stamp = now.strftime("%Y%m%d%H%M%S%f")
            ext = ".json" if isinstance(content, dict) else ".txt"
            target = self.spool_dir / f"{stamp}{ext}"

        raw = json.dumps(content, indent=2) if isinstance(content, dict) else str(content)
        atomic_write_text(target, raw)

        log.info("Spooled new CTI item to %s", target)
        return target

    def next_item(self) -> CTIItem | None:
        pending = self.pending_items()
        if not pending:
            log.debug("No CTI pending in %s", self.queue_dir)
            return None

        for candidate in pending:
            try:
                raw_text = candidate.read_text(encoding="utf-8", errors="replace").strip()
            except OSError as err:
                log.warning("Could not read CTI file %s: %s", candidate, err)
                continue

            if not raw_text:
                log.debug("CTI file %s empty, skipping", candidate)
                continue

            item = self._parse_file_content(candidate, raw_text)
            if item:
                return item

        return None

    def _parse_file_content(self, file_path: Path, raw_text: str) -> CTIItem | None:
        title = ""
        source_url = ""
        metadata: dict[str, Any] = {"queue_file": str(file_path)}
        content = raw_text

        if file_path.suffix.lower() == ".json":
            try:
                data = json.loads(raw_text)
                if isinstance(data, dict):
                    content = str(data.get("content") or raw_text)
                    title = str(data.get("title") or "")
                    source_url = str(data.get("source_url") or "")
                    custom_meta = data.get("metadata")
                    if isinstance(custom_meta, dict):
                        metadata.update(custom_meta)
                        metadata["queue_file"] = str(file_path)
            except json.JSONDecodeError:
                log.warning(
                    "File %s has .json suffix but is invalid JSON; reading as raw text", file_path
                )

        if not content.strip():
            return None

        return CTIItem(
            content=content,
            source=self.name,
            received_at=datetime.now(UTC),
            identifier=file_path.name,
            title=title,
            source_url=source_url,
            metadata=metadata,
        )

    def acknowledge(self, item: CTIItem) -> None:
        target_file: Path | None = None
        queued_path = item.metadata.get("queue_file") if item.metadata else None
        if queued_path:
            candidate = Path(queued_path)
            if candidate.exists() and candidate.is_file():
                target_file = candidate

        if target_file is None and not queued_path and item.identifier:
            for candidate in (
                self.spool_dir / item.identifier,
                self.queue_dir / item.identifier,
            ):
                if candidate.exists() and candidate.is_file():
                    target_file = candidate
                    break

        if target_file is None or not target_file.exists():
            log.debug("No file found to acknowledge for item %s", item.identifier)
            return

        self.processed_dir.mkdir(parents=True, exist_ok=True)
        stamp = (item.received_at or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
        if target_file.name == "next.txt":
            archive = self.processed_dir / f"cti-{stamp}.txt"
        else:
            archive = self.processed_dir / f"cti-{stamp}-{target_file.name}"

        shutil.move(str(target_file), str(archive))
        log.info("Archived CTI %s to %s", target_file, archive)

    def ensure_dirs(self) -> None:
        self.queue_dir.mkdir(parents=True, exist_ok=True)
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)
