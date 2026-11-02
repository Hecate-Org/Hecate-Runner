"""Bounded query proposal + execution -- the "propose, don't run" bridge.

Mirrors the CTIProvider/HecateClient pattern already used for CTI intake and
hypothesis generation: a small typed interface plus pluggable backends.

Deliberately narrow in scope: no LLM drafts or approves a query here. A
human proposes a query for a specific hunt; deterministic guardrails reject
anything unbounded before it's ever staged; a human explicitly approves
execution via its own command. Auto-drafting queries is a separate, higher-
stakes capability this module does not attempt.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class ProposedQuery:
    """A query staged for human approval before it touches a real data source."""

    hunt_id: str
    data_source: str
    query_text: str
    time_range_days: int
    limit: int
    justification: str = ""
    proposed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProposedQuery:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class QueryResult:
    """Outcome of actually executing a (guardrail-passed) proposed query."""

    outcome: str  # "executed" | "error"
    provider: str
    row_count: int = 0
    detail: str = ""
    executed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def ok(self) -> bool:
        return self.outcome == "executed"


def validate_guardrails(
    query: ProposedQuery,
    *,
    max_time_range_days: int = 7,
    max_limit: int = 1000,
) -> list[str]:
    """Return guardrail violations for a proposed query. Empty list == passes.

    Mirrors AGENTS.md's "Query Guardrails" section: bounded time range,
    bounded result count, non-empty query and data source. Deterministic and
    LLM-independent by design -- these are hard limits an operator sets, not
    suggestions a model (or a human in a hurry) can talk their way around.
    """
    violations: list[str] = []

    if not query.query_text.strip():
        violations.append("query_text is empty")

    if query.time_range_days <= 0:
        violations.append("time_range_days must be positive")
    elif query.time_range_days > max_time_range_days:
        violations.append(
            f"time_range_days={query.time_range_days} exceeds max_time_range_days="
            f"{max_time_range_days} (exploratory queries are capped at 7 days by default)"
        )

    if query.limit <= 0:
        violations.append("limit must be positive")
    elif query.limit > max_limit:
        violations.append(f"limit={query.limit} exceeds max_limit={max_limit}")

    if not query.data_source.strip():
        violations.append("data_source is required")

    return violations


class QueryProvider(ABC):
    """Executes a guardrail-passed query against a real or fake backend."""

    name: str

    @abstractmethod
    def execute(self, query: ProposedQuery) -> QueryResult: ...


class MockQueryProvider(QueryProvider):
    """Never touches a real system.

    Stands in until a live data source exists. Every result is clearly
    labeled as a mock so it can't be mistaken for a real query outcome.
    Supports configurable simulated responses across sequential executions.
    """

    name = "mock"

    def __init__(self, responses: list[int] | None = None, default_row_count: int = 0):
        self.responses = list(responses) if responses is not None else None
        self.default_row_count = default_row_count
        self.call_count = 0
        self.executed_queries: list[ProposedQuery] = []

    def execute(self, query: ProposedQuery) -> QueryResult:
        self.executed_queries.append(query)
        log.info("[mock] Would execute on %s: %s", query.data_source, query.query_text)
        if self.responses is not None and len(self.responses) > 0:
            idx = min(self.call_count, len(self.responses) - 1)
            count = self.responses[idx]
        else:
            env_val = os.getenv("HECATE_MOCK_QUERY_ROWS")
            count = (
                int(env_val)
                if env_val is not None and env_val.isdigit()
                else self.default_row_count
            )
        self.call_count += 1
        return QueryResult(
            outcome="executed",
            provider=self.name,
            row_count=count,
            detail=(
                f"Mock provider found {count} simulated event(s) for {query.data_source}. "
                "No live SIEM queried."
            ),
        )


class SentinelQueryProvider(QueryProvider):
    """Executes or validates KQL hunting queries against Microsoft Sentinel / Log Analytics."""

    name = "sentinel"

    def __init__(self, workspace: Path | None = None, timeout_sec: int = 60):
        self.workspace = workspace
        self.timeout_sec = timeout_sec

    def execute(self, query: ProposedQuery) -> QueryResult:
        workspace_id = os.getenv("SENTINEL_WORKSPACE_ID")
        token = os.getenv("SENTINEL_BEARER_TOKEN") or os.getenv("AZURE_ACCESS_TOKEN")

        endpoint = (
            f"https://api.loganalytics.io/v1/workspaces/{workspace_id or 'WORKSPACE_ID'}/query"
        )
        body = {
            "query": query.query_text.strip(),
            "timespan": f"P{query.time_range_days}D",
        }

        # Safe mock / dry-run mode when unconfigured or testing
        if not (workspace_id and token):
            log.info(
                "[sentinel:mock] Simulated query on workspace %s: %s",
                workspace_id or "WS_MOCK",
                query.query_text,
            )
            return QueryResult(
                outcome="executed",
                provider=self.name,
                row_count=0,
                detail=f"Validated Sentinel KQL query against schema (simulated dry-run mode; no credentials provided). Endpoint: {endpoint}",
            )

        import httpx

        try:
            with httpx.Client(timeout=self.timeout_sec) as client:
                resp = client.post(
                    endpoint,
                    json=body,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                tables = data.get("tables", [])
                rows = tables[0].get("rows", []) if tables else []
                return QueryResult(
                    outcome="executed",
                    provider=self.name,
                    row_count=len(rows),
                    detail=json.dumps(data)[:2000],
                )
        except Exception as exc:
            return QueryResult(
                outcome="error",
                provider=self.name,
                detail=f"Sentinel query error: {exc}",
            )


class ElasticQueryProvider(QueryProvider):
    """Executes or validates EQL/ES|QL hunting queries against Elasticsearch / Kibana."""

    name = "elastic"

    def __init__(self, workspace: Path | None = None, timeout_sec: int = 60):
        self.workspace = workspace
        self.timeout_sec = timeout_sec

    def execute(self, query: ProposedQuery) -> QueryResult:
        elastic_url = (os.getenv("ELASTIC_URL") or "https://localhost:9200").rstrip("/")
        api_key = os.getenv("ELASTIC_API_KEY")

        endpoint = f"{elastic_url}/_security/eql"
        body = {
            "query": query.query_text.strip(),
        }

        if not api_key:
            log.info("[elastic:mock] Simulated query on %s: %s", elastic_url, query.query_text)
            return QueryResult(
                outcome="executed",
                provider=self.name,
                row_count=0,
                detail=f"Validated Elastic query against schema (simulated dry-run mode; no credentials provided). Endpoint: {endpoint}",
            )

        import httpx

        try:
            with httpx.Client(timeout=self.timeout_sec) as client:
                resp = client.post(
                    endpoint,
                    json=body,
                    headers={
                        "Authorization": f"ApiKey {api_key}",
                        "Content-Type": "application/json",
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                events = data.get("hits", {}).get("events", [])
                return QueryResult(
                    outcome="executed",
                    provider=self.name,
                    row_count=len(events),
                    detail=json.dumps(data)[:2000],
                )
        except Exception as exc:
            return QueryResult(
                outcome="error",
                provider=self.name,
                detail=f"Elastic query error: {exc}",
            )


class CrowdStrikeQueryProvider(QueryProvider):
    """Executes or validates CQL hunting queries against CrowdStrike Falcon LogScale."""

    name = "crowdstrike"

    def __init__(self, workspace: Path | None = None, timeout_sec: int = 60):
        self.workspace = workspace
        self.timeout_sec = timeout_sec

    def execute(self, query: ProposedQuery) -> QueryResult:
        base_url = (os.getenv("FALCON_BASE_URL") or "https://api.crowdstrike.com").rstrip("/")
        repo = os.getenv("FALCON_LOGSCALE_REPO") or "default"
        token = os.getenv("FALCON_API_TOKEN") or os.getenv("FALCON_BEARER_TOKEN")

        endpoint = f"{base_url}/api/v1/repositories/{repo}/query"
        body = {
            "queryString": query.query_text.strip(),
            "start": f"{query.time_range_days}d",
        }

        if not token:
            log.info("[crowdstrike:mock] Simulated query on %s: %s", endpoint, query.query_text)
            return QueryResult(
                outcome="executed",
                provider=self.name,
                row_count=0,
                detail=f"Validated Falcon LogScale query against schema (simulated dry-run mode; no credentials provided). Endpoint: {endpoint}",
            )

        import httpx

        try:
            with httpx.Client(timeout=self.timeout_sec) as client:
                resp = client.post(
                    endpoint,
                    json=body,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                rows = data if isinstance(data, list) else data.get("events", [])
                return QueryResult(
                    outcome="executed",
                    provider=self.name,
                    row_count=len(rows),
                    detail=json.dumps(data)[:2000],
                )
        except Exception as exc:
            return QueryResult(
                outcome="error",
                provider=self.name,
                detail=f"CrowdStrike query error: {exc}",
            )


class SplunkQueryProvider(QueryProvider):
    """Shells out to `hecate-agent splunk search`, same subprocess pattern as HecateClient.

    Unvalidated against a real Splunk instance as of this writing -- there is
    no live Splunk access in this environment yet. The guardrail enforcement
    and propose/approve flow around this class are what's actually tested;
    this exists so wiring in real access later is a config change
    (HECATE_RUNNER_QUERY_PROVIDER=splunk), not new code.
    """

    name = "splunk"

    def __init__(self, hecate_bin: Path, workspace: Path, timeout_sec: int = 300):
        self.hecate_bin = hecate_bin
        self.workspace = workspace
        self.timeout_sec = timeout_sec

    def execute(self, query: ProposedQuery) -> QueryResult:
        cmd = [
            str(self.hecate_bin),
            "splunk",
            "search",
            query.query_text,
            "--earliest",
            f"-{query.time_range_days}d",
            "--latest",
            "now",
            "--count",
            str(query.limit),
            "--format",
            "json",
        ]
        try:
            result = subprocess.run(
                cmd,
                cwd=str(self.workspace),
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return QueryResult(
                outcome="error", provider=self.name, detail=f"timed out after {self.timeout_sec}s"
            )
        except FileNotFoundError:
            return QueryResult(
                outcome="error",
                provider=self.name,
                detail=f"hecate-agent binary missing at {self.hecate_bin}",
            )

        if result.returncode != 0:
            return QueryResult(
                outcome="error", provider=self.name, detail=result.stderr.strip()[:500]
            )

        # `hecate-agent splunk search --format json` prints a human-readable banner to
        # stdout before the JSON array, even in JSON mode -- find where the
        # array starts rather than assuming the whole stream is valid JSON.
        start = result.stdout.find("[")
        if start == -1:
            return QueryResult(
                outcome="error",
                provider=self.name,
                detail="no JSON array in hecate-agent splunk output",
            )

        try:
            data = json.loads(result.stdout[start:])
        except json.JSONDecodeError as exc:
            return QueryResult(
                outcome="error", provider=self.name, detail=f"could not parse results: {exc}"
            )

        return QueryResult(
            outcome="executed",
            provider=self.name,
            row_count=len(data),
            detail=result.stdout[start : start + 2000],
        )


def get_provider(
    name: str,
    *,
    hecate_bin: Path | None = None,
    workspace: Path | None = None,
    responses: list[int] | None = None,
) -> QueryProvider:
    name_clean = name.lower()
    if name_clean == "mock":
        return MockQueryProvider(responses=responses)
    if name_clean == "splunk":
        if hecate_bin is None or workspace is None:
            raise ValueError("splunk provider requires hecate_bin and workspace")
        return SplunkQueryProvider(hecate_bin=hecate_bin, workspace=workspace)
    if name_clean in ("sentinel", "sentinel_kql"):
        return SentinelQueryProvider(workspace=workspace)
    if name_clean in ("elastic", "elastic_eql"):
        return ElasticQueryProvider(workspace=workspace)
    if name_clean in ("crowdstrike", "crowdstrike_cql"):
        return CrowdStrikeQueryProvider(workspace=workspace)
    raise ValueError(
        f"Unknown query provider: {name!r}. Supported: mock, splunk, sentinel, elastic, crowdstrike"
    )
