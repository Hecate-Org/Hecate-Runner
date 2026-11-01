"""Dead-letter queue (DLQ) for quarantining poison-pill CTI items.

When a CTI item fails processing repeatedly (e.g. malformed syntax,
parser crashes, LLM fatal errors), it is quarantined here with full failure
diagnostics rather than causing infinite retry loops in the intake daemon.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti import CTIItem

log = logging.getLogger(__name__)

_DIR_NAME = "dead_letter"
_RETRIES_FILE = ".retries.json"


@dataclass
class DeadLetterItem:
    """A CTI item quarantined in the dead-letter queue with failure details."""

    dead_letter_id: str
    quarantined_at: str
    source: str
    title: str
    content: str
    attempts: int
    last_error: str
    source_url: str = ""
    identifier: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    path: Path | None = None


def dead_letter_dir(queue_dir: Path) -> Path:
    return queue_dir / _DIR_NAME


def _item_key(item: CTIItem) -> str:
    """Unique key for tracking failure attempts across polls."""
    if item.identifier:
        return item.identifier
    seed = item.source_url or item.title or item.content[:200]
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def get_retry_count(queue_dir: Path, item: CTIItem) -> int:
    """Return how many times this item has failed previously."""
    tracker_path = queue_dir / _RETRIES_FILE
    if not tracker_path.exists():
        return 0
    try:
        data = json.loads(tracker_path.read_text(encoding="utf-8"))
        key = _item_key(item)
        entry = data.get(key, {})
        return int(entry.get("attempts", 0))
    except Exception as exc:
        log.warning("Could not read retry tracker %s: %s", tracker_path, exc)
        return 0


def record_failure(queue_dir: Path, item: CTIItem, error: str) -> int:
    """Record a failure for the item and return the new attempt count."""
    tracker_path = queue_dir / _RETRIES_FILE
    queue_dir.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {}
    if tracker_path.exists():
        try:
            data = json.loads(tracker_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}

    key = _item_key(item)
    entry = data.get(key, {})
    attempts = int(entry.get("attempts", 0)) + 1
    data[key] = {
        "attempts": attempts,
        "last_error": error,
        "last_attempt": datetime.now(UTC).isoformat(),
        "identifier": item.identifier,
        "title": item.title,
    }
    try:
        atomic_write_text(tracker_path, json.dumps(data, indent=2) + "\n")
    except Exception as exc:
        log.warning("Could not update retry tracker %s: %s", tracker_path, exc)
    return attempts


def clear_retry(queue_dir: Path, item: CTIItem) -> None:
    """Clear any recorded failures for this item (called on success or quarantine)."""
    tracker_path = queue_dir / _RETRIES_FILE
    if not tracker_path.exists():
        return
    try:
        data = json.loads(tracker_path.read_text(encoding="utf-8"))
        key = _item_key(item)
        if key in data:
            del data[key]
            atomic_write_text(tracker_path, json.dumps(data, indent=2) + "\n")
    except Exception:
        pass


def quarantine(
    queue_dir: Path,
    item: CTIItem,
    error: str,
    attempts: int,
) -> Path:
    """Quarantine a poison-pill item to dead_letter/ and return the created file path."""
    when = datetime.now(UTC)
    seed = item.identifier or item.source_url or item.title or item.content[:200]
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]
    dead_letter_id = f"{when.strftime('%Y%m%dT%H%M%SZ')}-{digest}"

    target_dir = dead_letter_dir(queue_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "dead_letter_id": dead_letter_id,
        "quarantined_at": when.isoformat(),
        "source": item.source,
        "title": item.title,
        "source_url": item.source_url,
        "identifier": item.identifier,
        "attempts": attempts,
        "last_error": error,
        "content": item.content,
        "metadata": item.metadata,
    }
    path = target_dir / f"{dead_letter_id}.json"
    atomic_write_text(path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    clear_retry(queue_dir, item)
    log.warning(
        "Quarantined poison-pill CTI item %s to %s after %d failed attempts: %s",
        dead_letter_id,
        path,
        attempts,
        error,
    )
    return path


def _read_dead_letter(path: Path) -> DeadLetterItem | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("Could not read dead-letter item %s", path)
        return None
    return DeadLetterItem(
        dead_letter_id=str(raw.get("dead_letter_id") or path.stem),
        quarantined_at=str(raw.get("quarantined_at") or ""),
        source=str(raw.get("source") or ""),
        title=str(raw.get("title") or ""),
        content=str(raw.get("content") or ""),
        attempts=int(raw.get("attempts") or 0),
        last_error=str(raw.get("last_error") or ""),
        source_url=str(raw.get("source_url") or ""),
        identifier=str(raw.get("identifier") or ""),
        metadata=raw.get("metadata", {}),
        path=path,
    )


def list_dead_letters(queue_dir: Path) -> list[DeadLetterItem]:
    """Return all dead-letter items, newest first."""
    target = dead_letter_dir(queue_dir)
    if not target.is_dir():
        return []
    items: list[DeadLetterItem] = []
    for path in sorted(target.glob("*.json")):
        item = _read_dead_letter(path)
        if item is not None:
            items.append(item)
    return sorted(items, key=lambda i: i.quarantined_at, reverse=True)


def get_dead_letter(queue_dir: Path, dead_letter_id: str) -> DeadLetterItem | None:
    """Find a dead-letter item by exact ID or unambiguous substring."""
    if not dead_letter_id:
        return None
    exact = dead_letter_dir(queue_dir) / f"{dead_letter_id}.json"
    if exact.exists():
        return _read_dead_letter(exact)
    matches = [i for i in list_dead_letters(queue_dir) if dead_letter_id in i.dead_letter_id]
    return matches[0] if len(matches) == 1 else None


def restore_dead_letter(queue_dir: Path, dead_letter_id: str) -> Path | None:
    """Restore a quarantined item back into next.txt for re-processing."""
    item = get_dead_letter(queue_dir, dead_letter_id)
    if item is None:
        return None

    next_file = queue_dir / "next.txt"
    queue_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(next_file, item.content.rstrip("\n") + "\n")
    if item.path and item.path.exists():
        item.path.unlink()
    clear_retry(queue_dir, CTIItem(content=item.content, identifier=item.identifier))
    log.info("Restored dead-letter item %s to %s", item.dead_letter_id, next_file)
    return next_file


def clear_dead_letters(queue_dir: Path) -> int:
    """Remove all dead-letter files and return the count removed."""
    target = dead_letter_dir(queue_dir)
    if not target.is_dir():
        return 0
    count = 0
    for path in target.glob("*.json"):
        try:
            path.unlink()
            count += 1
        except OSError:
            pass
    return count
