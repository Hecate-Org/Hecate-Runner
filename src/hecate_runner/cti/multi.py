"""Composite CTI provider that fans out across multiple configured sources.

Wraps N ``CTIProvider`` instances (e.g. rss + otx + misp) behind the same
single-provider interface the orchestrator already knows, so
``Orchestrator`` never has to know it's talking to more than one source.

Which provider gets first pick each cycle is round-robined and persisted to
disk: a consistently high-volume source (e.g. RSS across ten feeds) would
otherwise crowd out a slower one (e.g. MISP with few new events) purely by
always being checked first. A source is only skipped in a given cycle if it
genuinely has nothing new — the rotation just decides tie-break order, not
which sources are eligible.

A single sub-provider raising is isolated (logged, skipped) rather than
sinking the whole cycle, mirroring how ``RssProvider`` already isolates a
single broken feed from the others.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import CTIItem, CTIProvider

log = logging.getLogger(__name__)

#: Default cool-down after a sub-provider reports nothing new.
DEFAULT_EMPTY_TTL_SEC = 300.0


class MultiProviderError(RuntimeError):
    """Raised when the multi CTI provider is misconfigured."""


@dataclass
class MultiCursorState:
    """Persisted index of which sub-provider gets first pick next cycle."""

    next_index: int = 0

    @classmethod
    def load(cls, path: Path) -> MultiCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(next_index=int(data.get("next_index", 0)))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            log.warning("Multi CTI cursor file %s corrupt (%s); resetting", path, exc)
            return cls()

    def save(self, path: Path) -> None:
        atomic_write_text(path, json.dumps({"next_index": self.next_index}))


TIER_1_CRITICAL: frozenset[str] = frozenset({"cisa_kev", "vulncheck", "github_poc", "nuclei"})
TIER_2_THREAT_FEEDS: frozenset[str] = frozenset(
    {
        "lolbas",
        "loldrivers",
        "gtfobins",
        "cisa_advisories",
        "cisa_ics",
        "attack_deltas",
        "otx",
        "misp",
        "malwarebazaar",
        "abuse_ch",
        "msrc",
        "cloud_threat",
        "dfir_report",
        "anyrun",
        "vxunderground",
    }
)


class MultiProvider(CTIProvider):
    """Fans out ``next_item``/``acknowledge`` across multiple sub-providers."""

    name = "multi"

    def __init__(
        self,
        providers: list[CTIProvider],
        cursor_file: Path,
        priority_tiers: bool = False,
        *,
        empty_ttl_sec: float = DEFAULT_EMPTY_TTL_SEC,
    ):
        if not providers:
            raise MultiProviderError(
                "At least one sub-provider is required to use the multi CTI provider"
            )
        names = [p.name for p in providers]
        if len(set(names)) != len(names):
            raise MultiProviderError(
                f"Duplicate provider names passed to multi CTI provider: {names}"
            )
        self.providers = providers
        self.cursor_file = cursor_file
        self.priority_tiers = priority_tiers
        self.empty_ttl_sec = max(0.0, float(empty_ttl_sec))
        self._by_name = {p.name: p for p in providers}
        #: Monotonic deadline until which a provider may be skipped after empty.
        self._empty_until: dict[str, float] = {}

    # --- CTIProvider interface -----------------------------------------------

    def close(self) -> None:
        for provider in self.providers:
            provider.close()

    def _is_cooling_down(self, name: str, *, now: float) -> bool:
        until = self._empty_until.get(name)
        return until is not None and now < until

    def _mark_empty(self, name: str, *, now: float) -> None:
        if self.empty_ttl_sec <= 0:
            self._empty_until.pop(name, None)
            return
        self._empty_until[name] = now + self.empty_ttl_sec

    def _clear_empty(self, name: str) -> None:
        self._empty_until.pop(name, None)

    def next_item(self) -> CTIItem | None:
        cursor = MultiCursorState.load(self.cursor_file)
        now = time.monotonic()

        if self.priority_tiers:
            # Priority tiers ensure high-signal KEV & PoCs are evaluated before general feeds
            tier1 = [p for p in self.providers if p.name in TIER_1_CRITICAL]
            tier2 = [p for p in self.providers if p.name in TIER_2_THREAT_FEEDS]
            tier3 = [
                p
                for p in self.providers
                if p.name not in TIER_1_CRITICAL and p.name not in TIER_2_THREAT_FEEDS
            ]
            tiers = [t for t in (tier1, tier2, tier3) if t]
        else:
            tiers = [self.providers]

        for tier in tiers:
            t_count = len(tier)
            t_start = cursor.next_index % t_count
            # If every provider in the tier is cooling down, probe them all.
            force_probe = all(
                self._is_cooling_down(tier[(t_start + o) % t_count].name, now=now)
                for o in range(t_count)
            )
            for offset in range(t_count):
                idx = (t_start + offset) % t_count
                provider = tier[idx]
                if not force_probe and self._is_cooling_down(provider.name, now=now):
                    log.debug(
                        "Multi CTI: skipping %s (empty within TTL)",
                        provider.name,
                    )
                    continue
                try:
                    item = provider.next_item()
                except Exception as exc:  # one bad source shouldn't sink the cycle
                    log.warning(
                        "CTI sub-provider %r failed (%s); trying the next configured source",
                        provider.name,
                        exc,
                    )
                    continue
                if item is not None:
                    self._clear_empty(provider.name)
                    log.info(
                        "Multi CTI: picked %s (rotation advances once the item is acknowledged)",
                        provider.name,
                    )
                    return item
                self._mark_empty(provider.name, now=now)

        log.debug("No new entries across %d configured CTI sources", len(self.providers))
        return None

    def acknowledge(self, item: CTIItem) -> None:
        provider = self._by_name.get(item.source)
        if provider is None:
            log.warning(
                "Cannot acknowledge CTI item: unknown source %r (known: %s)",
                item.source,
                list(self._by_name),
            )
            return
        provider.acknowledge(item)
        self._advance_rotation_past(provider.name)

    def _advance_rotation_past(self, name: str) -> None:
        """Point the rotation at the source after `name`.

        Called only after the sub-provider acknowledged successfully: if that
        raises, the item stays queued and the rotation must stay put so the
        retry comes back to the same source.
        """
        try:
            idx = [p.name for p in self.providers].index(name)
        except ValueError:  # pragma: no cover - guarded by the caller
            return
        cursor = MultiCursorState.load(self.cursor_file)
        cursor.next_index = (idx + 1) % len(self.providers)
        cursor.save(self.cursor_file)
        log.debug(
            "Multi CTI: rotation now starts at %s",
            self.providers[cursor.next_index].name,
        )
