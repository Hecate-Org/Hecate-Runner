"""Alert proof must come from Splunk and identify this exact execution."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from hecate_runner.bas.alerts import find_fired_alert


@pytest.fixture
def alert_case():
    start = datetime.now(UTC) - timedelta(seconds=60)
    event = {
        "hecate_bas_run_id": "this-run",
        "hecate_hunt_id": "H-TEST",
        "timestamp_utc": start.isoformat(),
    }
    record = {
        "savedsearch_name": "exact-rule",
        "sid": "scheduler-real",
        "trigger_time": (start + timedelta(seconds=20)).timestamp(),
    }
    client = Mock()
    client._request.side_effect = lambda method, endpoint, params: (
        {"entry": [{"name": "exact-rule", "content": {"search": "search Image=whoami"}}]}
        if "/saved/searches/" in endpoint
        else {"entry": [{"content": record}]}
    )
    client.get_search_results.return_value = [event]
    args = dict(
        name="exact-rule",
        query="Image=whoami",
        owner="nobody",
        app="search",
        run_id="this-run",
        hunt_id="H-TEST",
        started=start,
        ended=start + timedelta(seconds=2),
        excluded_sid="adhoc",
    )
    return client, record, event, args


def test_fired_alert_requires_its_own_results_and_reports_server_latency(alert_case):
    client, _record, _event, args = alert_case
    proof = find_fired_alert(client, **args)
    assert proof.sid == "scheduler-real"
    assert proof.name == "exact-rule"
    assert proof.latency_sec == 20
    client.get_search_results.assert_called_once_with("scheduler-real", count=100)
    assert client._request.call_args.args[1].endswith("/alerts/fired_alerts/exact-rule")


@pytest.mark.parametrize(
    "field,value",
    [
        ("savedsearch_name", "other-rule"),
        ("sid", "adhoc"),
        ("sid", ""),
        ("trigger_time", 0),
        ("trigger_time", "garbage"),
        ("trigger_time", float("nan")),
        ("trigger_time", float("inf")),
        ("trigger_time", 999999999999),
    ],
)
def test_alert_like_records_are_not_sufficient(alert_case, field, value):
    client, _record, _event, args = alert_case
    _record[field] = value
    assert find_fired_alert(client, **args) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("hecate_bas_run_id", "previous-run"),
        ("hecate_bas_run_id", None),
        ("hecate_hunt_id", "H-OTHER"),
        ("timestamp_utc", "1970-01-01T00:00:00Z"),
        ("timestamp_utc", None),
        ("timestamp_utc", float("nan")),
    ],
)
def test_alert_must_include_this_runs_time_scoped_event(alert_case, field, value):
    client, _record, _event, args = alert_case
    _event[field] = value
    assert find_fired_alert(client, **args) is None


def test_changed_saved_search_cannot_verify_original_hunt_rule(alert_case):
    client, _record, _event, args = alert_case
    args["query"] = "Image=other"
    assert find_fired_alert(client, **args) is None
    client.get_search_results.assert_not_called()


def test_alert_api_permission_error_is_not_a_detection_miss(alert_case):
    client, _record, _event, args = alert_case
    client._request.side_effect = PermissionError("403 fired alerts not readable")
    with pytest.raises(PermissionError):
        find_fired_alert(client, **args)
