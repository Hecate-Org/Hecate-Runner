"""Tests for SIEM Telemetry Forwarder."""

from unittest import mock

from hecate_runner.bas.forwarder import forward_events_to_splunk


def test_forward_events_empty():
    count = forward_events_to_splunk([])
    assert count == 0


def test_forward_events_bearer_token(monkeypatch):
    monkeypatch.setenv("SPLUNK_HOST", "https://test-splunk:8089")
    monkeypatch.setenv("SPLUNK_TOKEN", "test-token-123")
    monkeypatch.setenv("SPLUNK_VERIFY_SSL", "false")

    sample_events = [
        {"CommandLine": "whoami", "Image": "/usr/bin/whoami"},
        {"CommandLine": "id", "Image": "/usr/bin/id"},
    ]

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200

    with mock.patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        count = forward_events_to_splunk(sample_events)
        assert count == 2
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert "https://test-splunk:8089/services/receivers/simple" in args[0]
        assert kwargs["headers"]["Authorization"] == "Bearer test-token-123"
        assert kwargs["params"] == {"index": "main", "sourcetype": "hecate:telemetry"}


def test_forward_events_basic_auth_fallback(monkeypatch):
    monkeypatch.setenv("SPLUNK_HOST", "https://test-splunk:8089")
    monkeypatch.setenv("SPLUNK_TOKEN", "expired-token")
    monkeypatch.setenv("SPLUNK_USERNAME", "admin")
    monkeypatch.setenv("SPLUNK_PASSWORD", "Secret123!")

    sample_events = [{"CommandLine": "whoami"}]

    resp_401 = mock.MagicMock()
    resp_401.status_code = 401

    resp_200 = mock.MagicMock()
    resp_200.status_code = 200

    with mock.patch("httpx.Client.post", side_effect=[resp_401, resp_200]) as mock_post:
        count = forward_events_to_splunk(sample_events)
        assert count == 1
        assert mock_post.call_count == 2
        # Second call uses basic auth
        second_kwargs = mock_post.call_args_list[1][1]
        assert second_kwargs["auth"] == ("admin", "Secret123!")


def test_tls_verification_defaults_on_and_allows_explicit_override(monkeypatch, tmp_path):
    monkeypatch.delenv("SPLUNK_VERIFY_SSL", raising=False)
    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)
    with mock.patch("httpx.Client") as client:
        # Default host is localhost → skip verify (self-signed lab certs).
        assert forward_events_to_splunk([{"event": "test"}], workspace=tmp_path) == 1
        assert client.call_args.kwargs["verify"] is False
        # Non-loopback host verifies TLS by default.
        forward_events_to_splunk(
            [{"event": "test"}],
            workspace=tmp_path,
            host="https://splunk.example:8089",
        )
        assert client.call_args.kwargs["verify"] is True
        forward_events_to_splunk([{"event": "test"}], workspace=tmp_path, verify_ssl=False)
        assert client.call_args.kwargs["verify"] is False


def test_credentials_are_isolated_between_workspaces(monkeypatch, tmp_path):
    import os

    from hecate_runner.bas.forwarder import splunk_settings

    for name in ("SPLUNK_HOST", "SPLUNK_TOKEN", "SPLUNK_PASSWORD", "SPLUNK_VERIFY_SSL"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / ".env").write_text("SPLUNK_TOKEN=ancestor-secret\n")
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / ".env").write_text("SPLUNK_HOST=https://first\nSPLUNK_TOKEN=first-secret\n")
    (second / ".env").write_text("SPLUNK_HOST=https://second\nSPLUNK_TOKEN=second-secret\n")
    monkeypatch.chdir(first)
    assert "SPLUNK_TOKEN" not in splunk_settings()
    assert splunk_settings(first)["SPLUNK_TOKEN"] == "first-secret"
    assert splunk_settings(second)["SPLUNK_TOKEN"] == "second-secret"
    assert "SPLUNK_TOKEN" not in os.environ
    monkeypatch.setenv("SPLUNK_TOKEN", "explicit-secret")
    assert splunk_settings(first)["SPLUNK_TOKEN"] == "explicit-secret"


def test_forwarder_uses_selected_workspace_credentials(monkeypatch, tmp_path):
    for name in ("SPLUNK_HOST", "SPLUNK_TOKEN", "SPLUNK_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / ".env").write_text("SPLUNK_HOST=https://selected\nSPLUNK_TOKEN=selected-token\n")
    with mock.patch("httpx.Client") as client:
        forward_events_to_splunk([{"event": "test"}], workspace=tmp_path)
        post = client.return_value.__enter__.return_value.post
        assert post.call_args.args[0].startswith("https://selected/")
        assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer selected-token"


def test_isolated_hec_wraps_events_and_never_uses_management_credentials(monkeypatch):
    import json

    import httpx

    monkeypatch.setenv("HECATE_STRICT_CREDENTIAL_ROLES", "1")
    monkeypatch.setenv("SPLUNK_HEC_URL", "https://localhost:8088")
    monkeypatch.setenv("SPLUNK_INGEST_TOKEN", "-".join(["hec", "fixture"]))
    monkeypatch.setenv("SPLUNK_PASSWORD", "-".join(["forbidden", "fallback"]))
    response = httpx.Response(
        200, json={"code": 0}, request=httpx.Request("POST", "https://localhost")
    )
    with mock.patch("httpx.Client.post", return_value=response) as post:
        assert forward_events_to_splunk([{"Image": "lab-process"}]) == 1
        assert post.call_count == 1
        assert post.call_args.args[0] == "https://localhost:8088/services/collector/event"
        assert post.call_args.kwargs["headers"]["Authorization"] == "Splunk " + "-".join(
            ["hec", "fixture"]
        )
        assert json.loads(post.call_args.kwargs["content"]) == {
            "index": "main",
            "sourcetype": "hecate:telemetry",
            "event": {"Image": "lab-process"},
        }
        assert not isinstance(post.call_args.kwargs["auth"], tuple)


def test_isolated_ingestion_refuses_missing_hec_configuration(monkeypatch):
    monkeypatch.setenv("HECATE_STRICT_CREDENTIAL_ROLES", "1")
    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)
    monkeypatch.setenv("SPLUNK_TOKEN", "-".join(["legacy", "fixture"]))
    with mock.patch("httpx.Client") as client:
        assert forward_events_to_splunk([{"Image": "lab-process"}]) == 0
        client.assert_not_called()


def test_hec_rejections_never_retry_with_broader_credentials(monkeypatch):
    import httpx

    monkeypatch.setenv("SPLUNK_HEC_URL", "https://localhost:8088")
    monkeypatch.setenv("SPLUNK_INGEST_TOKEN", "-".join(["hec", "fixture"]))
    monkeypatch.setenv("SPLUNK_PASSWORD", "-".join(["forbidden", "fallback"]))
    for status, code in [(403, 7), (200, 7), (401, 4)]:
        response = httpx.Response(
            status, json={"code": code}, request=httpx.Request("POST", "https://localhost")
        )
        with mock.patch("httpx.Client.post", return_value=response) as post:
            assert forward_events_to_splunk([{"Image": "lab-process"}]) == 0
            assert post.call_count == 1


def test_hec_rejects_credentials_or_unsafe_url_syntax(monkeypatch):
    monkeypatch.setenv("SPLUNK_INGEST_TOKEN", "-".join(["hec", "fixture"]))
    for url in [
        "http://localhost:8088",
        "https://localhost:8088/other",
        "https://localhost:8088?token=bad",
    ]:
        monkeypatch.setenv("SPLUNK_HEC_URL", url)
        with mock.patch("httpx.Client") as client:
            assert forward_events_to_splunk([{"Image": "lab-process"}]) == 0
            client.assert_not_called()
