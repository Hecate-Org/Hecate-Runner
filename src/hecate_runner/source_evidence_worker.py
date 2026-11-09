"""Private worker for the source evidence stage's shared, hard deadline."""

from __future__ import annotations

import contextlib
import json
import os
import sys
from dataclasses import asdict
from typing import Any


def collect(url: str, indicators: dict[str, list[str]]) -> dict[str, Any]:
    from hecate_agent.core.source_evidence import (
        build_indicator_records,
        extract_source_evidence,
    )
    from hecate_agent.core.source_extraction import SourceExtractionSession
    from hecate_agent.core.workspace import load_workspace_env, workspace_root

    load_workspace_env()
    cache_enabled = os.getenv("HECATE_RUNNER_SOURCE_EVIDENCE_CACHE_ENABLED", "true").lower() in {
        "1",
        "true",
        "yes",
    }
    session = SourceExtractionSession(
        max_calls=int(os.getenv("HECATE_RUNNER_SOURCE_EVIDENCE_MAX_CALLS", "16")),
        max_tokens=int(os.getenv("HECATE_RUNNER_SOURCE_EVIDENCE_MAX_TOKENS", "256000")),
        cache_path=workspace_root() / ".hecate" / "source_evidence.db" if cache_enabled else None,
        cache_ttl_sec=int(os.getenv("HECATE_RUNNER_SOURCE_EVIDENCE_CACHE_TTL_SEC", "86400")),
    )
    evidence = extract_source_evidence(url, session=session)
    records = (
        build_indicator_records(indicators, evidence, session=session) if evidence.text else []
    )
    return {"evidence": asdict(evidence), "records": [asdict(record) for record in records]}


def main() -> None:
    request = json.load(sys.stdin)
    # Providers may print diagnostics. Keep stdout exclusively for the result.
    with contextlib.redirect_stdout(sys.stderr):
        result = collect(request["url"], request["indicators"])
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
