import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

from hecate_runner.drift_alerts import deliver_drift_alerts, notify_drift_report


def query(status="missing_remote", file="test.spl", **extra):
    return {"target": "splunk_spl", "file": file, "status": status, **extra}


def report(*queries):
    return {
        "hunts": {"H-0001": list(queries)},
        "drifted_by_hunt": {"H-0001": [q for q in queries if q["status"] == "drift_detected"]},
        "missing_by_hunt": {"H-0001": [q for q in queries if q["status"] == "missing_remote"]},
        "error_count": sum(q["status"] == "error" for q in queries),
        "missing_count": sum(q["status"] == "missing_remote" for q in queries),
        "drifted_count": sum(q["status"] == "drift_detected" for q in queries),
    }


def test_suppresses_unchanged_alert_across_restarts_and_reminds_daily(settings):
    send = Mock(return_value=(True, "ok"))
    notify_drift_report(settings, report(query()), send, now=100)
    notify_drift_report(
        settings.model_copy(), report(query(detail="new timestamp")), send, now=3700
    )
    assert send.call_count == 1
    notify_drift_report(settings, report(query()), send, now=86500)
    assert send.call_count == 2


def test_changes_alert_immediately_and_missing_and_changed_share_one_card(settings):
    send = Mock(return_value=(True, "ok"))
    notify_drift_report(settings, report(query()), send, now=100)
    changed = query("drift_detected", file="other.spl", drift_diff="local A / remote B")
    notify_drift_report(settings, report(query(), changed), send, now=101)
    assert len(send.call_args.args[2]) == 2
    notify_drift_report(settings, report(changed, query()), send, now=102)
    assert send.call_count == 2
    changed["drift_diff"] = "local A / remote C"
    notify_drift_report(settings, report(query(), changed), send, now=103)
    assert send.call_count == 3


def test_failed_delivery_retries_without_waiting_for_reminder(settings):
    send = Mock(side_effect=[(False, "rate_limited"), (True, "ok")])
    notify_drift_report(settings, report(query()), send, now=100)
    notify_drift_report(settings, report(query()), send, now=131)
    assert send.call_count == 2


def test_errors_do_not_rearm_but_verified_resolution_does(settings):
    send = Mock(return_value=(True, "ok"))
    notify_drift_report(settings, report(query()), send, now=100)
    notify_drift_report(settings, report(query("error")), send, now=101)
    notify_drift_report(settings, report(query()), send, now=102)
    assert send.call_count == 1
    notify_drift_report(settings, report(query("in_sync")), send, now=103)
    notify_drift_report(settings, report(query()), send, now=104)
    assert send.call_count == 2


def test_error_on_one_query_does_not_change_another_queries_alert(settings):
    send = Mock(return_value=(True, "ok"))
    notify_drift_report(settings, report(query(), query(file="second.spl")), send, now=100)
    notify_drift_report(settings, report(query(), query("error", file="second.spl")), send, now=101)
    assert send.call_count == 1


def test_reminders_can_be_disabled(settings):
    settings.siem_drift_alert_reminder_sec = 0
    send = Mock(return_value=(True, "ok"))
    notify_drift_report(settings, report(query()), send, now=100)
    notify_drift_report(settings, report(query()), send, now=1000000)
    assert send.call_count == 1


def test_concurrent_sweeps_send_once(settings):
    send = Mock(return_value=(True, "ok"))
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(notify_drift_report, settings, report(query()), send, now=100)
            for _ in range(2)
        ]
        for future in futures:
            future.result()
    assert send.call_count == 1


def test_removed_catalog_hunt_rearms_on_reappearance(settings):
    (settings.hecate_workspace / "queries").mkdir(exist_ok=True)
    send = Mock(return_value=(True, "ok"))
    notify_drift_report(settings, report(query()), send, now=100)
    notify_drift_report(settings, {"hunts": {}, "error_count": 0}, send, now=101)
    notify_drift_report(settings, report(query()), send, now=102)
    assert send.call_count == 2


def test_delivery_exception_is_retried(settings):
    send = Mock(side_effect=[TimeoutError("Slack unavailable"), (True, "ok")])
    notify_drift_report(settings, report(query()), send, now=100)
    notify_drift_report(settings, report(query()), send, now=131)
    assert send.call_count == 2


def test_daemon_does_not_wait_for_siem_audits_or_slack(settings, monkeypatch):
    from typer.testing import CliRunner

    from hecate_runner import cli
    from hecate_runner.orchestrator import RunResult

    settings.siem_drift_audit_interval_sec = 1
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    orch = Mock()
    orch.run_once.return_value = RunResult(outcome="no_cti")
    monkeypatch.setattr(cli, "build_default_orchestrator", lambda *a, **k: orch)
    monkeypatch.setattr("hecate_runner.integration_checks.start_health_refresh", lambda *a: None)
    audit = Mock(return_value=report(query()))
    send = Mock(return_value=(True, "ok"))
    monkeypatch.setattr("hecate_runner.siem_drift.audit_workspace_queries", audit)
    monkeypatch.setattr("hecate_runner.notifications.notify_siem_drift", send)
    result = CliRunner().invoke(cli.app, ["daemon", "--max-cycles", "2", "--interval", "1"])
    assert result.exit_code == 0, result.output
    audit.assert_not_called()
    send.assert_not_called()


def test_manual_report_sends_one_card_with_missing_and_changed_queries(settings, monkeypatch):
    from typer.testing import CliRunner

    from hecate_runner import cli

    monkeypatch.setattr(cli, "Settings", lambda: settings)
    audit = Mock(
        return_value={
            **report(query(), query("drift_detected", file="changed.spl")),
            "drifted_count": 1,
            "missing_count": 1,
        }
    )
    monkeypatch.setattr("hecate_runner.siem_drift.audit_workspace_queries", audit)
    send = Mock(return_value=(True, "ok"))
    monkeypatch.setattr("hecate_runner.notifications.notify_siem_drift", send)
    result = CliRunner().invoke(cli.app, ["audit-siem", "--dry-run", "--alert-slack"])
    assert result.exit_code == 0, result.output
    assert send.call_count == 1
    assert len(send.call_args.args[2]) == 2


def test_delivery_occurs_after_commit_and_retry_survives_restart(settings):
    notify_drift_report(settings, report(query()), now=100)
    database = settings.hecate_workspace / ".hecate/siem/drift_alerts.db"

    def send(*args):
        # A separate writer must be able to proceed while Slack is contacted.
        with sqlite3.connect(database, timeout=0) as conn:
            conn.execute("BEGIN IMMEDIATE")
            assert conn.execute("SELECT count(*) FROM outbox").fetchone()[0] == 1
        return True, "ok"

    assert deliver_drift_alerts(settings.model_copy(), send, now=101) == 1
    assert deliver_drift_alerts(settings, Mock(), now=102) == 0


def test_crashed_claim_is_retried_only_after_expiry(settings):
    notify_drift_report(settings, report(query()), now=100)
    database = settings.hecate_workspace / ".hecate/siem/drift_alerts.db"
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE outbox SET claim_token='crashed',lease_until=200")
    send = Mock(return_value=(True, "ok"))
    assert deliver_drift_alerts(settings, send, now=199) == 0
    assert deliver_drift_alerts(settings, send, now=201) == 1
    assert send.call_count == 1


def test_slow_delivery_cannot_duplicate_after_lease_expiry(settings):
    started, release = threading.Event(), threading.Event()
    notify_drift_report(settings, report(query()), now=100)

    def slow_send(*args):
        started.set()
        assert release.wait(5)
        return True, "ok"

    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(deliver_drift_alerts, settings, slow_send, now=100)
        try:
            assert started.wait(5)
            duplicate = Mock(return_value=(True, "ok"))
            assert deliver_drift_alerts(settings, duplicate, now=1000) == 0
            duplicate.assert_not_called()
        finally:
            release.set()
        assert first.result(timeout=5) == 1


def test_condition_change_during_send_is_not_acknowledged_as_delivered(settings):
    notify_drift_report(settings, report(query()), now=100)
    changed = query("drift_detected", drift_diff="A to B")

    def change_during_send(*args):
        notify_drift_report(settings, report(changed), now=101)
        return True, "ok"

    assert deliver_drift_alerts(settings, change_during_send, now=100) == 0
    send = Mock(return_value=(True, "ok"))
    assert deliver_drift_alerts(settings, send, now=102) == 1
    assert send.call_args.args[2] == [changed]
    assert deliver_drift_alerts(settings, send, now=103) == 0


def test_resolution_during_send_does_not_suppress_recurrence(settings):
    notify_drift_report(settings, report(query()), now=100)

    def resolve_and_recur(*args):
        notify_drift_report(settings, report(query("in_sync")), now=101)
        notify_drift_report(settings, report(query()), now=102)
        return True, "ok"

    deliver_drift_alerts(settings, resolve_and_recur, now=100)
    send = Mock(return_value=(True, "ok"))
    assert deliver_drift_alerts(settings, send, now=103) == 1


def test_resolved_query_is_removed_from_pending_card_even_when_another_errors(settings):
    notify_drift_report(settings, report(query(), query(file="other.spl")), now=100)
    notify_drift_report(
        settings, report(query("in_sync"), query("error", file="other.spl")), now=101
    )
    send = Mock(return_value=(True, "ok"))
    deliver_drift_alerts(settings, send, now=102)
    assert [q["file"] for q in send.call_args.args[2]] == ["other.spl"]


def test_existing_delivered_state_migrates_without_realerting(settings):
    notify_drift_report(settings, report(query()), Mock(return_value=(True, "ok")), now=100)
    database = settings.hecate_workspace / ".hecate/siem/drift_alerts.db"
    with sqlite3.connect(database) as conn:
        old = conn.execute("SELECT hunt,observed,delivered,last_sent FROM alerts").fetchone()
        conn.execute("DROP TABLE alerts")
        conn.execute(
            "CREATE TABLE alerts(hunt TEXT PRIMARY KEY,observed TEXT,delivered TEXT,last_sent REAL)"
        )
        conn.execute("INSERT INTO alerts VALUES(?,?,?,?)", old)
    send = Mock(return_value=(True, "ok"))
    notify_drift_report(settings, report(query()), send, now=101)
    send.assert_not_called()
