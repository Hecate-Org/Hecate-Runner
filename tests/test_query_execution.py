"""Tests for the propose/execute guardrail logic and providers."""

from __future__ import annotations

from pathlib import Path

import pytest

from hecate_runner.query_execution import (
    CrowdStrikeQueryProvider,
    ElasticQueryProvider,
    MockQueryProvider,
    ProposedQuery,
    SentinelQueryProvider,
    SplunkQueryProvider,
    get_provider,
    validate_guardrails,
)


def _query(**overrides: object) -> ProposedQuery:
    defaults = dict(
        hunt_id="H-0001",
        data_source="splunk",
        query_text="index=main | head 10",
        time_range_days=7,
        limit=100,
    )
    defaults.update(overrides)
    return ProposedQuery(**defaults)  # type: ignore[arg-type]


class TestValidateGuardrails:
    def test_valid_query_has_no_violations(self) -> None:
        assert validate_guardrails(_query()) == []

    def test_empty_query_text_rejected(self) -> None:
        violations = validate_guardrails(_query(query_text="   "))
        assert any("query_text" in v for v in violations)

    def test_time_range_over_max_rejected(self) -> None:
        violations = validate_guardrails(_query(time_range_days=30), max_time_range_days=7)
        assert any("time_range_days" in v for v in violations)

    def test_time_range_at_max_is_allowed(self) -> None:
        assert validate_guardrails(_query(time_range_days=7), max_time_range_days=7) == []

    def test_zero_or_negative_time_range_rejected(self) -> None:
        violations = validate_guardrails(_query(time_range_days=0))
        assert any("time_range_days" in v for v in violations)

    def test_limit_over_max_rejected(self) -> None:
        violations = validate_guardrails(_query(limit=50000), max_limit=1000)
        assert any("limit" in v for v in violations)

    def test_limit_at_max_is_allowed(self) -> None:
        assert validate_guardrails(_query(limit=1000), max_limit=1000) == []

    def test_zero_or_negative_limit_rejected(self) -> None:
        violations = validate_guardrails(_query(limit=0))
        assert any("limit" in v for v in violations)

    def test_missing_data_source_rejected(self) -> None:
        violations = validate_guardrails(_query(data_source=""))
        assert any("data_source" in v for v in violations)

    def test_multiple_violations_all_reported(self) -> None:
        violations = validate_guardrails(_query(time_range_days=999, limit=999999, query_text=""))
        assert len(violations) == 3


class TestProposedQuerySerialization:
    def test_round_trips_through_dict(self) -> None:
        original = _query(justification="testing round trip")
        restored = ProposedQuery.from_dict(original.to_dict())
        assert restored == original

    def test_from_dict_ignores_unknown_keys(self) -> None:
        data = _query().to_dict()
        data["unexpected_future_field"] = "ignored"
        # Must not raise.
        ProposedQuery.from_dict(data)


class TestMockQueryProvider:
    def test_always_succeeds_without_touching_anything(self) -> None:
        provider = MockQueryProvider()
        result = provider.execute(_query())
        assert result.ok
        assert result.provider == "mock"
        assert result.row_count == 0
        assert "Mock provider" in result.detail

    def test_configurable_responses_sequence(self) -> None:
        provider = MockQueryProvider(responses=[0, 5, 2])
        r1 = provider.execute(_query())
        r2 = provider.execute(_query())
        r3 = provider.execute(_query())
        r4 = provider.execute(_query())  # Stays at last response
        assert r1.row_count == 0
        assert r2.row_count == 5
        assert r3.row_count == 2
        assert r4.row_count == 2
        assert len(provider.executed_queries) == 4

    def test_reads_env_mock_query_rows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HECATE_MOCK_QUERY_ROWS", "42")
        provider = MockQueryProvider()
        result = provider.execute(_query())
        assert result.row_count == 42


class TestGetProvider:
    def test_mock_provider_needs_no_args(self) -> None:
        provider = get_provider("mock")
        assert isinstance(provider, MockQueryProvider)

    def test_sentinel_provider_constructs(self) -> None:
        provider = get_provider("sentinel")
        assert isinstance(provider, SentinelQueryProvider)
        provider_kql = get_provider("sentinel_kql")
        assert isinstance(provider_kql, SentinelQueryProvider)

    def test_elastic_provider_constructs(self) -> None:
        provider = get_provider("elastic")
        assert isinstance(provider, ElasticQueryProvider)
        provider_eql = get_provider("elastic_eql")
        assert isinstance(provider_eql, ElasticQueryProvider)

    def test_crowdstrike_provider_constructs(self) -> None:
        provider = get_provider("crowdstrike")
        assert isinstance(provider, CrowdStrikeQueryProvider)
        provider_cql = get_provider("crowdstrike_cql")
        assert isinstance(provider_cql, CrowdStrikeQueryProvider)

    def test_splunk_provider_requires_hecate_bin_and_workspace(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="requires hecate_bin"):
            get_provider("splunk")

    def test_splunk_provider_constructs_with_args(self, tmp_path: Path) -> None:
        provider = get_provider("splunk", hecate_bin=tmp_path / "hecate", workspace=tmp_path)
        assert isinstance(provider, SplunkQueryProvider)

    def test_unknown_provider_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown query provider"):
            get_provider("bigquery")


class TestSentinelQueryProvider:
    def test_dry_run_without_credentials(self) -> None:
        provider = SentinelQueryProvider()
        res = provider.execute(_query())
        assert res.ok is True
        assert res.provider == "sentinel"
        assert res.row_count == 0
        assert "Validated Sentinel KQL query" in res.detail

    def test_mocked_live_query(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import unittest.mock as mock

        monkeypatch.setenv("SENTINEL_WORKSPACE_ID", "test-ws")
        monkeypatch.setenv("SENTINEL_BEARER_TOKEN", "test-token")

        fake_resp = mock.MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {
            "tables": [{"rows": [["event1", "cmd.exe"], ["event2", "powershell.exe"]]}]
        }

        with mock.patch("httpx.Client.post", return_value=fake_resp) as mock_post:
            provider = SentinelQueryProvider()
            res = provider.execute(_query(query_text="DeviceProcessEvents | take 10"))
            assert res.ok is True
            assert res.row_count == 2
            assert mock_post.called


class TestElasticQueryProvider:
    def test_dry_run_without_credentials(self) -> None:
        provider = ElasticQueryProvider()
        res = provider.execute(_query())
        assert res.ok is True
        assert res.provider == "elastic"
        assert res.row_count == 0
        assert "Validated Elastic query" in res.detail

    def test_mocked_live_query(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import unittest.mock as mock

        monkeypatch.setenv("ELASTIC_URL", "https://es.local:9200")
        monkeypatch.setenv("ELASTIC_API_KEY", "es-key-123")

        fake_resp = mock.MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {"hits": {"events": [{"_source": {"process": "cmd.exe"}}]}}

        with mock.patch("httpx.Client.post", return_value=fake_resp) as mock_post:
            provider = ElasticQueryProvider()
            res = provider.execute(_query(query_text='any where process.name == "cmd.exe"'))
            assert res.ok is True
            assert res.row_count == 1
            assert mock_post.called


class TestCrowdStrikeQueryProvider:
    def test_dry_run_without_credentials(self) -> None:
        provider = CrowdStrikeQueryProvider()
        res = provider.execute(_query())
        assert res.ok is True
        assert res.provider == "crowdstrike"
        assert res.row_count == 0
        assert "Validated Falcon LogScale query" in res.detail

    def test_mocked_live_query(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import unittest.mock as mock

        monkeypatch.setenv("FALCON_API_TOKEN", "cs-token-xyz")

        fake_resp = mock.MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = [{"event": 1}, {"event": 2}, {"event": 3}]

        with mock.patch("httpx.Client.post", return_value=fake_resp) as mock_post:
            provider = CrowdStrikeQueryProvider()
            res = provider.execute(_query(query_text="CommandLine=/whoami/i"))
            assert res.ok is True
            assert res.row_count == 3
            assert mock_post.called


class TestSplunkQueryProvider:
    def _make_fake_hecate(self, tmp_path: Path, script: str) -> Path:
        fake = tmp_path / "fake_hecate.sh"
        fake.write_text(script)
        fake.chmod(0o755)
        return fake

    def test_parses_json_array_after_banner(self, tmp_path: Path) -> None:
        # Mirrors real `hecate-agent splunk search --format json` output: a
        # human-readable banner precedes the JSON array even in JSON mode.
        script = (
            "#!/bin/sh\n"
            "printf 'Executing query: index=main\\n'\n"
            "printf 'Time range: -7d to now\\n\\n'\n"
            'printf \'[{"user": "alice"}, {"user": "bob"}]\'\n'
        )
        fake = self._make_fake_hecate(tmp_path, script)
        provider = SplunkQueryProvider(hecate_bin=fake, workspace=tmp_path)

        result = provider.execute(_query())
        assert result.ok
        assert result.row_count == 2

    def test_nonzero_exit_is_an_error(self, tmp_path: Path) -> None:
        fake = self._make_fake_hecate(tmp_path, "#!/bin/sh\necho 'auth failed' >&2\nexit 1\n")
        provider = SplunkQueryProvider(hecate_bin=fake, workspace=tmp_path)

        result = provider.execute(_query())
        assert not result.ok
        assert "auth failed" in result.detail

    def test_no_json_array_in_output_is_an_error(self, tmp_path: Path) -> None:
        fake = self._make_fake_hecate(tmp_path, "#!/bin/sh\necho 'No results found'\n")
        provider = SplunkQueryProvider(hecate_bin=fake, workspace=tmp_path)

        result = provider.execute(_query())
        assert not result.ok

    def test_timeout_is_an_error(self, tmp_path: Path) -> None:
        fake = self._make_fake_hecate(tmp_path, "#!/bin/sh\nsleep 5\n")
        provider = SplunkQueryProvider(hecate_bin=fake, workspace=tmp_path, timeout_sec=1)

        result = provider.execute(_query())
        assert not result.ok
        assert "timed out" in result.detail

    def test_missing_binary_is_an_error(self, tmp_path: Path) -> None:
        provider = SplunkQueryProvider(hecate_bin=tmp_path / "does_not_exist", workspace=tmp_path)

        result = provider.execute(_query())
        assert not result.ok
