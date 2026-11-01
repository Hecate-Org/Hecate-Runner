"""File-queue CTI provider.

Supports both single-slot legacy ``<cti_queue>/next.txt`` and a multi-file
spooler directory (``<cti_queue>/spool/`` or files directly in ``<cti_queue>/``).
Archives consumed files to ``<cti_queue>/processed/cti-<timestamp>[-filename]``
after successful acknowledgment.
"""

from __future__ import annotations

import json
import logging
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from hecate_runner.cti.base import CTIItem, CTIProvider

log = logging.getLogger(__name__)


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
        if self.next_file.is_file() and self.next_file.stat().st_size > 0:
            pending.append(self.next_file)

        # 2. Files in spool directory
        spool_files: list[Path] = []
        if self.spool_dir.is_dir():
            for p in self.spool_dir.iterdir():
                if p.is_file() and not p.name.startswith("."):
                    spool_files.append(p)

        # 3. Direct files in queue_dir (excluding next.txt, hidden files, and reserved subdirs)
        queue_files: list[Path] = []
        for p in self.queue_dir.iterdir():
            if (
                p.is_file()
                and not p.name.startswith(".")
                and p != self.next_file
                and p.name not in self._RESERVED_DIRS
            ):
                queue_files.append(p)

        # Sort non-next files by modification time (FIFO), breaking ties with name
        other_files = spool_files + queue_files
        other_files.sort(key=lambda p: (p.stat().st_mtime_ns, p.name))

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

        if isinstance(content, dict):
            target.write_text(json.dumps(content, indent=2))
        else:
            target.write_text(content)

        log.info("Spooled new CTI item to %s", target)
        return target

    def next_item(self) -> CTIItem | None:
        pending = self.pending_items()
        if not pending:
            log.debug("No CTI pending in %s", self.queue_dir)
            return None

        for candidate in pending:
            try:
                raw_text = candidate.read_text().strip()
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
