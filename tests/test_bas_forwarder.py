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
