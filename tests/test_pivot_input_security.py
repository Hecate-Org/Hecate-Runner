"""Adversarial telemetry must not become automatic query syntax."""

import json
from unittest.mock import Mock

import pytest

from hecate_runner.execution import query_values as values
from hecate_runner.execution.pivot_engine import PivotExecutionEngine, synthesize_pivot_queries


@pytest.mark.parametrize("field", ["hosts", "processes", "parent_processes", "users", "ips"])
@pytest.mark.parametrize(
    "payload",
    [
        'victim" | outputlookup stolen',
        "bad\n| collect",
        "bad\x00",
        "*",
        "a; DROP TABLE events",
        "a\x60command",
    ],
)
def test_query_operators_in_any_entity_are_refused(field, payload):
    with pytest.raises(ValueError):
        synthesize_pivot_queries("splunk", {field: [payload]})


@pytest.mark.parametrize("dialect", ["splunk", "sentinel", "elastic", "crowdstrike", "chronicle"])
def test_quotes_are_literal_after_name_normalization(dialect):
    pivots = synthesize_pivot_queries(
        dialect, {"users": ["DOMAIN\\O'Neil\"quoted"], "processes": ['C:\\Tools\\a"b.exe']}
    )
    assert pivots
    assert values.quoted('a"b.exe', dialect) == json.dumps('a"b.exe')
    assert '\\"' in next(p["query"] for p in pivots if p["type"] == "child_process")


def test_sql_entities_cannot_close_a_literal_or_add_wildcards():
    pivots = synthesize_pivot_queries("snowflake", {"users": ["O'Neil_%"]})
    query = next(p["query"] for p in pivots if p["type"] == "user_auth")
    assert "'O''Neil_%'" in query
    assert "POSITION(" in query
    assert "ILIKE" not in query


@pytest.mark.parametrize("ip", ["1.2.3.4 OR 1=1", "127.0.0.1/8", "not-an-ip"])
def test_ip_pivots_require_an_actual_address(ip):
    with pytest.raises(ValueError):
        synthesize_pivot_queries("splunk", {"ips": [ip]})


def test_invalid_entity_never_reaches_a_live_provider(settings):
    gate = Mock()
    engine = PivotExecutionEngine(gate, Mock(), settings)
    assert engine.execute_pivots("finding", "H-0001", "splunk", {"users": ['bad" | collect']}) == []
    gate.execute_safely.assert_not_called()


def test_ipv6_is_normalized_and_valid_process_paths_remain_usable():
    result = synthesize_pivot_queries(
        "splunk", {"ips": ["2001:0db8::1"], "processes": ["C:\\Windows\\System32\\cmd.exe"]}
    )
    assert any('dest_ip="2001:db8::1"' in p["query"] for p in result)
    assert any('parent_process="*cmd.exe"' in p["query"] for p in result)


@pytest.mark.parametrize("value", ["/", "C:\\", "@example.test", "DOMAIN\\"])
def test_normalization_must_not_turn_entities_into_empty_wildcards(value):
    from hecate_runner.execution.query_values import basename, username

    normalize = username if "@" in value or value.startswith("DOMAIN") else basename
    with pytest.raises(ValueError):
        normalize(value)
