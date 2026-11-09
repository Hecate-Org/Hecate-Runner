"""Live adapter contracts exercised through HTTP transports without real SIEM access."""

import json
from datetime import datetime
from unittest.mock import Mock

import httpx
import pytest
from typer.testing import CliRunner

from hecate_runner import cli
from hecate_runner.config import Settings
from hecate_runner.query_execution import ProposedQuery, get_provider
from hecate_runner.query_store import PendingQueryStore

CONFIG = {
    "sentinel": {
        "SENTINEL_WORKSPACE_ID": "00000000-0000-0000-0000-000000000001",
        "SENTINEL_BEARER_TOKEN": "test-secret",
    },
    "elastic": {
        "ELASTIC_URL": "https://elastic.test",
        "ELASTIC_API_KEY": "test-secret",
        "ELASTIC_INDEX": "logs-endpoint-*",
    },
    "crowdstrike": {
        "FALCON_LOGSCALE_URL": "https://logscale.test",
        "FALCON_LOGSCALE_REPO": "endpoint",
        "FALCON_LOGSCALE_TOKEN": "test-secret",
    },
}
QUERIES = {
    "sentinel": "SecurityEvent | where EventID == 4688",
    "elastic": 'process where process.name == "cmd.exe"',
    "crowdstrike": "CommandLine=/whoami/i",
}
RESULTS = {
    "sentinel": {"tables": [{"name": "PrimaryResult", "rows": [["event"]]}]},
    "elastic": {"hits": {"events": [{"_source": {"process": "cmd.exe"}}]}},
    "crowdstrike": [{"CommandLine": "whoami"}],
}


def proposal(provider, **changes):
    values = dict(
        hunt_id="H-0001",
        data_source=provider,
        query_text=QUERIES[provider],
        time_range_days=3,
        limit=2,
    )
    values.update(changes)
    return ProposedQuery(**values)


@pytest.fixture
def transport(monkeypatch):
    requests = []
    responses = []
    real_client = httpx.Client

    def respond(request):
        requests.append(request)
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(
        "hecate_runner.query_execution.httpx.Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(respond), **kwargs),
    )
    return requests, responses


@pytest.mark.parametrize("provider", CONFIG)
def test_provider_bounds_and_real_empty_results(provider, transport):
    requests, responses = transport
    responses.append(httpx.Response(200, json=RESULTS[provider]))
    adapter = get_provider(provider, env_overrides=CONFIG[provider])
    result = adapter.execute(proposal(provider))
    assert result.ok and result.row_count == 1
    request = requests[0]
    body = json.loads(request.content)
    if provider == "sentinel":
        assert request.url.host == "api.loganalytics.azure.com"
        assert body["query"].endswith("| take 2")
        assert "let __hecate_bounded_query" in body["query"]
        start, end = (datetime.fromisoformat(t) for t in body["timespan"].split("/"))
        assert (end - start).days == 3
        assert request.headers["Prefer"] == "wait=60"
    elif provider == "elastic":
        assert request.url.path == "/logs-endpoint-*/_eql/search"
        assert request.url.params["allow_partial_search_results"] == "false"
        assert body["size"] == 2 and body["query"].endswith("| head 2")
        bounds = body["filter"]["range"]["@timestamp"]
        assert (
            datetime.fromisoformat(bounds["lt"]) - datetime.fromisoformat(bounds["gte"])
        ).days == 3
    else:
        assert request.url.host == "logscale.test"
        assert request.url.path == "/api/v1/repositories/endpoint/query"
        assert request.headers["Accept"] == "application/json"
        assert body["isLive"] is False
        assert body["queryString"].endswith("| head(limit=2)")
        assert body["end"] - body["start"] == 3 * 86400000
    assert "test-secret" not in result.detail


@pytest.mark.parametrize(
    "provider, data",
    [
        ("sentinel", {"tables": [{"name": "PrimaryResult", "rows": []}]}),
        ("elastic", {"hits": {"events": []}}),
        ("crowdstrike", []),
    ],
)
def test_valid_empty_response_is_success(provider, data, transport):
    transport[1].append(httpx.Response(200, json=data))
    result = get_provider(provider, env_overrides=CONFIG[provider]).execute(proposal(provider))
    assert result.ok and result.row_count == 0


@pytest.mark.parametrize("provider", CONFIG)
def test_missing_credentials_fail_before_network(provider, monkeypatch):
    client = Mock()
    monkeypatch.setattr("hecate_runner.query_execution.httpx.Client", client)
    result = get_provider(provider).execute(proposal(provider))
    assert not result.ok and "Missing" in result.detail
    client.assert_not_called()


@pytest.mark.parametrize("provider", CONFIG)
@pytest.mark.parametrize(
    "changes",
    [
        {"limit": 0},
        {"limit": 1001},
        {"time_range_days": 8},
        {"time_range_days": -1},
        {"limit": "2"},
        {"limit": True},
    ],
)
def test_direct_adapter_cannot_bypass_guardrails(provider, changes, transport):
    result = get_provider(provider, env_overrides=CONFIG[provider]).execute(
        proposal(provider, **changes)
    )
    assert not result.ok
    assert transport[0] == []


@pytest.mark.parametrize("provider", CONFIG)
def test_operator_configured_ceilings_reach_adapter(provider, transport):
    transport[1].append(httpx.Response(200, json=RESULTS[provider]))
    adapter = get_provider(
        provider, env_overrides=CONFIG[provider], max_time_range_days=30, max_limit=10000
    )
    assert adapter.execute(proposal(provider, time_range_days=10, limit=2000)).ok


@pytest.mark.parametrize("provider", CONFIG)
@pytest.mark.parametrize("status", [400, 401, 429, 500])
def test_http_errors_never_become_empty_success(provider, status, transport):
    transport[1].append(httpx.Response(status, text="test-secret"))
    result = get_provider(provider, env_overrides=CONFIG[provider]).execute(proposal(provider))
    assert not result.ok and str(status) in result.detail
    assert "test-secret" not in result.detail


@pytest.mark.parametrize("provider", CONFIG)
def test_timeout_is_an_error(provider, transport):
    transport[1].append(httpx.ReadTimeout("test-secret"))
    result = get_provider(provider, env_overrides=CONFIG[provider]).execute(proposal(provider))
    assert not result.ok and "timed out" in result.detail
    assert "test-secret" not in result.detail


@pytest.mark.parametrize(
    "provider, data",
    [
        ("sentinel", {"tables": [{"rows": [["ok"]]}], "error": {"code": "PartialError"}}),
        ("sentinel", {"tables": []}),
        ("sentinel", {"tables": [{"rows": []}, {"rows": []}]}),
        ("elastic", {"is_partial": True, "hits": {"events": []}}),
        ("elastic", {"timed_out": True, "hits": {"events": []}}),
        ("elastic", {"shard_failures": [{"reason": "test"}], "hits": {"events": []}}),
        ("elastic", {}),
        ("crowdstrike", {"events": [], "done": False}),
        ("crowdstrike", {"error": "bad query"}),
    ],
)
def test_partial_or_invalid_success_bodies_are_errors(provider, data, transport):
    transport[1].append(httpx.Response(200, json=data))
    result = get_provider(provider, env_overrides=CONFIG[provider]).execute(proposal(provider))
    assert not result.ok


def test_elastic_counts_sequence_matches_and_cancels_pending_queries(transport):
    requests, responses = transport
    adapter = get_provider("elastic", env_overrides=CONFIG["elastic"])
    responses.append(httpx.Response(200, json={"hits": {"sequences": [{"events": [{}, {}]}]}}))
    result = adapter.execute(proposal("elastic"))
    assert result.ok and result.row_count == 1
    assert json.loads(result.detail)["result_kind"] == "sequences"
    responses.extend(
        [
            httpx.Response(200, json={"id": "pending-id", "is_running": True}),
            httpx.Response(200, json={"succeeded": True}),
        ]
    )
    assert not adapter.execute(proposal("elastic")).ok
    assert requests[-1].method == "DELETE"
    assert requests[-1].url.path == "/_eql/search/pending-id"


@pytest.mark.parametrize(
    "provider, data",
    [
        ("sentinel", {"tables": [{"rows": [[1], [2], [3]]}]}),
        ("elastic", {"hits": {"events": [{}, {}, {}]}}),
        ("crowdstrike", [{}, {}, {}]),
    ],
)
def test_unexpected_over_limit_results_are_errors(provider, data, transport):
    transport[1].append(httpx.Response(200, json=data))
    assert not get_provider(provider, env_overrides=CONFIG[provider]).execute(proposal(provider)).ok


@pytest.mark.parametrize(
    "text",
    [
        "SecurityEvent } ; SecurityEvent {",
        "SecurityEvent /* unclosed",
        'SecurityEvent | where X == "unclosed',
    ],
)
def test_kql_cannot_escape_or_swallow_limit(text, transport):
    result = get_provider("sentinel", env_overrides=CONFIG["sentinel"]).execute(
        proposal("sentinel", query_text=text)
    )
    assert not result.ok
    assert transport[0] == []


def test_kql_let_statements_and_comment_literals_keep_final_limit(transport):
    text = 'let name = @"C:\\temp";\nSecurityEvent | where ProcessName == name // trailing comment'
    transport[1].append(httpx.Response(200, json=RESULTS["sentinel"]))
    assert (
        get_provider("sentinel", env_overrides=CONFIG["sentinel"])
        .execute(proposal("sentinel", query_text=text))
        .ok
    )
    sent = json.loads(transport[0][0].content)["query"]
    assert text in sent and sent.endswith("| take 2")


def test_alias_environment_precedence_and_workspace_isolation(tmp_path, monkeypatch, transport):
    (tmp_path / ".env").write_text(
        "FALCON_LOGSCALE_URL=https://logs.test\nFALCON_LOGSCALE_REPO=events\nFALCON_LOGSCALE_TOKEN=old-secret\n"
    )
    monkeypatch.setenv("FALCON_API_TOKEN", "new-secret")
    transport[1].append(httpx.Response(200, json=[]))
    assert get_provider("crowdstrike", workspace=tmp_path).execute(proposal("crowdstrike")).ok
    assert transport[0][0].headers["Authorization"] == "Bearer new-secret"
    monkeypatch.setenv("FALCON_LOGSCALE_TOKEN", "")
    assert not get_provider("crowdstrike", workspace=tmp_path).execute(proposal("crowdstrike")).ok
    assert len(transport[0]) == 1


@pytest.mark.parametrize("provider", CONFIG)
def test_settings_and_cli_pass_live_configuration_and_retain_failed_proposals(
    provider, settings, monkeypatch, transport
):
    config = Settings(
        hecate_workspace=settings.hecate_workspace,
        query_provider=provider,
        **CONFIG[provider],
        _env_file=None,
    )
    assert "test-secret" not in str(config.redacted_dict())
    monkeypatch.setattr(cli, "Settings", lambda: config)
    store = PendingQueryStore(config.pending_queries_dir)
    store.save(proposal(provider))
    transport[1].append(httpx.Response(401))
    result = CliRunner().invoke(cli.app, ["approve", "H-0001", "--yes"])
    assert result.exit_code == 1
    assert store.load("H-0001") is not None
    transport[1].append(httpx.Response(200, json=RESULTS[provider]))
    result = CliRunner().invoke(cli.app, ["approve", "H-0001", "--yes"])
    assert result.exit_code == 0, result.output
    assert store.load("H-0001") is None


def test_doctor_identifies_live_provider_and_missing_configuration(settings, monkeypatch):
    config = settings.model_copy(update={"query_provider": "elastic"})
    monkeypatch.setattr(cli, "Settings", lambda: config)
    result = CliRunner().invoke(cli.app, ["doctor", "--json"])
    data = json.loads(result.output)
    check = next(c for c in data["checks"] if "live query provider 'elastic'" in c["name"])
    assert check["status"] != "ok"
    assert "ELASTIC_URL" in check["remediation"]


def test_local_dotenv_credentials_reach_adapter(tmp_path, monkeypatch, transport):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "HECATE_RUNNER_QUERY_PROVIDER=elastic\nELASTIC_URL=https://es.test\n"
        "ELASTIC_INDEX=logs-*\nELASTIC_API_KEY=local-test-secret\n"
    )
    config = Settings(hecate_workspace=tmp_path / "workspace")
    assert config.query_provider == "elastic"
    adapter = get_provider(
        config.query_provider,
        workspace=config.hecate_workspace,
        env_overrides=config.query_provider_env(),
    )
    transport[1].append(httpx.Response(200, json=RESULTS["elastic"]))
    assert adapter.execute(proposal("elastic")).ok
    assert transport[0][0].headers["Authorization"] == "ApiKey local-test-secret"
    assert "local-test-secret" not in str(config.redacted_dict())


def test_large_preview_remains_valid_bounded_json(transport):
    transport[1].append(httpx.Response(200, json=[{"message": "x" * 10000}]))
    result = get_provider("crowdstrike", env_overrides=CONFIG["crowdstrike"]).execute(
        proposal("crowdstrike")
    )
    assert result.ok
    assert len(result.detail) <= 2000
    assert json.loads(result.detail)["preview_truncated"] is True


@pytest.mark.parametrize(
    "provider, changed",
    [
        ("sentinel", {"SENTINEL_WORKSPACE_ID": "not-a-guid"}),
        ("elastic", {"ELASTIC_INDEX": "../other"}),
        ("elastic", {"ELASTIC_URL": "https://user:test-secret@es.test"}),
        ("elastic", {"ELASTIC_URL": "https://es.test?token=test-secret"}),
        ("crowdstrike", {"FALCON_LOGSCALE_REPO": "../other"}),
    ],
)
def test_invalid_target_configuration_never_sends_credentials(provider, changed, transport):
    adapter = get_provider(provider, env_overrides={**CONFIG[provider], **changed})
    result = adapter.execute(proposal(provider))
    assert not result.ok
    assert "test-secret" not in result.detail
    assert not transport[0]
