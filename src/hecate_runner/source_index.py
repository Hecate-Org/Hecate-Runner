"""Runner-side source URL/CVE membership index for intake deduplication.

Used when Core's ``hunt_catalog.source_catalog`` is unavailable (version skew)
so intake still avoids O(hunts) full-body scans on every CTI item.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any


def _source_metadata(path: Path, text: str) -> dict[str, Any]:
    urls: set[str] = set()
    for line in text.splitlines():
        for match in re.finditer(r"\]\(", line):
            tail = line[match.end() :]
            urls.update(tail[: end.start()] for end in re.finditer(r"\)", tail))
    cves: set[str] = set()
    for match in re.finditer(r"CVE-\d{4}-\d+", text, re.IGNORECASE):
        value = match.group().upper()
        cves.update(value[:length] for length in range(13, min(len(value), 41) + 1))
    # Non-standard labels used by some feeds (kept for literal fallback parity).
    for match in re.finditer(r"\bCUSTOM-CVE-[A-Z0-9_-]+\b", text, re.IGNORECASE):
        cves.add(match.group().upper())
    return {"url": sorted(urls), "cve": sorted(cves)}


def _tokens(data: dict[str, Any]) -> Iterator[tuple[str, str]]:
    return ((kind, token) for kind in ("url", "cve") for token in data[kind])


def source_catalog(hunts_root: Path) -> Any:
    """Return an incremental CatalogIndex, preferring Core's implementation."""
    try:
        from hecate_agent.core.hunt_catalog import source_catalog as core_catalog

        return core_catalog(hunts_root)
    except ImportError:
        from hecate_agent.core.catalog_index import CatalogIndex

        index = CatalogIndex(hunts_root, "runner-source-membership-v1")
        index.refresh(hunts_root.rglob("H-*.md"), _source_metadata, tokens=_tokens)
        return index
