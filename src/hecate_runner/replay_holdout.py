"""Reserve immutable synthetic replay groups before a tuner sees any samples."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# Repeated executions with new clocks/PIDs must stay in the same group.
_VOLATILE = frozenset(
    {
        "_time",
        "timestamp",
        "timestamp_utc",
        "utctime",
        "timecreated",
        "@timestamp",
        "processid",
        "parentprocessid",
        "processguid",
        "parentprocessguid",
        "eventrecordid",
        "recordid",
        "hecate_bas_run_id",
        "hecate_hunt_id",
    }
)


def event_group(event: dict[str, Any]) -> str:
    def stable(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(k).lower(): stable(v)
                for k, v in value.items()
                if str(k).lower() not in _VOLATILE
            }
        if isinstance(value, list):
            return [stable(v) for v in value]
        return value

    payload = json.dumps(stable(event), sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class ReplaySplit:
    positive: list[dict[str, Any]]
    benign: list[dict[str, Any]]
    holdout_positive: list[dict[str, Any]] = field(default_factory=list)
    holdout_benign: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    digest: str = ""

    @property
    def available(self) -> bool:
        return bool(self.holdout_positive and self.holdout_benign)


def reserve_holdout(positive: list[dict[str, Any]], benign: list[dict[str, Any]]) -> ReplaySplit:
    """Deduplicate by behavior and reserve 25% (at least one group per class).

    The split is independent of the rule and its match results. All input data
    is copied, so a tuner cannot mutate the withheld samples through aliases.
    Small or contradictory datasets permit sanity checks but no tuning.
    """
    unavailable = ReplaySplit(copy.deepcopy(positive), copy.deepcopy(benign))
    try:
        positive_groups = {event_group(e): copy.deepcopy(e) for e in positive}
        benign_groups = {event_group(e): copy.deepcopy(e) for e in benign}
    except (TypeError, ValueError):
        unavailable.reason = "Replay samples are not finite JSON event objects."
        return unavailable
    if positive_groups.keys() & benign_groups.keys():
        unavailable.reason = "Positive and benign samples contain overlapping behavior groups."
        return unavailable
    if min(len(positive_groups), len(benign_groups)) < 2:
        unavailable.reason = (
            "At least two distinct positive and two distinct benign behavior groups are required."
        )
        return unavailable

    def partition(
        groups: dict[str, dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        keys = sorted(groups)
        withheld = max(1, (len(keys) + 3) // 4)
        return [groups[k] for k in keys[withheld:]], [groups[k] for k in keys[:withheld]]

    training_positive, test_positive = partition(positive_groups)
    training_benign, test_benign = partition(benign_groups)
    fingerprint = json.dumps(
        {"version": 1, "positive": sorted(positive_groups), "benign": sorted(benign_groups)},
        sort_keys=True,
    )
    return ReplaySplit(
        training_positive,
        training_benign,
        test_positive,
        test_benign,
        digest=hashlib.sha256(fingerprint.encode()).hexdigest(),
    )
