"""Maintenance must make progress independently without overlapping jobs."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from hecate_runner import cli, maintenance
from hecate_runner.maintenance import MaintenanceScheduler, run_job


@pytest.fixture
def scheduler(settings, monkeypatch):
    settings.github_publishing_enabled = True
    settings.misp_publishing_enabled = True
    settings.maintenance_interval_sec = 10
    settings.maintenance_job_timeout_sec = 3
    clock = SimpleNamespace(value=100.0)
    monkeypatch.setattr(
        maintenance,
        "time",
        SimpleNamespace(time=lambda: clock.value, monotonic=lambda: clock.value),
    )
    processes = []

    def spawn(*args, **kwargs):
        process = Mock(pid=999999)
        process.poll.return_value = None
        processes.append((process, args, kwargs))
        return process

    monkeypatch.setattr(maintenance.subprocess, "Popen", spawn)
    monkeypatch.setattr(maintenance.os, "killpg", Mock())
    instance = MaintenanceScheduler(settings)
    yield instance, processes, clock
    instance.close()


def test_jobs_have_independent_schedules_and_persistent_due_times(scheduler):
    instance, processes, _ = scheduler
    instance.tick()
    assert set(instance.active) == {"github", "misp", "siem", "alerts"}
    assert len(processes) == 4
    processes[0][0].poll.return_value = 0
    instance.tick()
    assert "github" not in instance.active
    assert "siem" in instance.active
    assert json.loads((instance.root / "github.json").read_text())["next_run"] == 110
    instance.tick()
    assert len(processes) == 4
    # A second scheduler cannot overlap the other jobs, or ignore GitHub's due time.
    replacement = MaintenanceScheduler(instance.settings)
    replacement.tick()
    assert replacement.active == {}


def test_timeout_kills_worker_backs_off_and_releases_lock(scheduler):
    instance, processes, clock = scheduler
    instance.tick()
    clock.value += 4
    instance.tick(launch=False)
    assert not instance.active
    assert maintenance.os.killpg.call_count == 4
    assert all(process.wait.called for process, *_ in processes)
    state = json.loads((instance.root / "github.json").read_text())
    assert state["status"] == "timed_out" and state["next_run"] > clock.value
    replacement = MaintenanceScheduler(instance.settings)
    replacement.tick()
    assert not replacement.active
    clock.value = state["next_run"]
    replacement.tick()
    assert "github" in replacement.active
    replacement.close()


def test_different_jobs_do_not_wait_for_a_slow_publisher(scheduler):
    instance, _, _ = scheduler
    instance.tick()
    github_pid = instance.active["github"].process
    for job, active in instance.active.items():
        if job != "github":
            active.process.poll.return_value = 0
    instance.tick(launch=False)
    assert list(instance.active) == ["github"]
    assert github_pid.poll() is None


def test_spawn_failure_is_backed_off_and_does_not_starve_other_jobs(scheduler, monkeypatch):
    instance, _, clock = scheduler
    spawn = maintenance.subprocess.Popen

    def fail_github(args, **kwargs):
        if args[-1] == "github":
            raise OSError("temporary process limit")
        return spawn(args, **kwargs)

    monkeypatch.setattr(maintenance.subprocess, "Popen", fail_github)
    instance.tick()
    assert set(instance.active) == {"misp", "siem", "alerts"}
    assert json.loads((instance.root / "github.json").read_text())["next_run"] > clock.value


def test_worker_config_matches_effective_settings(scheduler):
    instance, processes, _ = scheduler
    instance.tick()
    for _, _, kwargs in processes:
        assert kwargs["env"]["HECATE_WORKSPACE"] == str(instance.settings.hecate_workspace)
        assert kwargs["env"]["HECATE_RUNNER_MAINTENANCE_INTERVAL_SEC"] == "10"
        assert kwargs["pass_fds"] and kwargs["start_new_session"]
        assert "PIPE" not in str(kwargs.get("stdout"))


def test_worker_config_preserves_alternate_credential_aliases(settings):
    settings.query_sentinel_token = "test-token-from-local-override"
    env = maintenance._worker_env(settings)
    assert env["SENTINEL_BEARER_TOKEN"] == "test-token-from-local-override"


def test_publisher_batches_are_bounded(settings, monkeypatch):
    github, misp = Mock(), Mock()
    monkeypatch.setattr("hecate_runner.github_publisher.sync_outbox", github)
    monkeypatch.setattr("hecate_runner.misp_publisher.sync_misp_outbox", misp)
    run_job(settings, "github")
    run_job(settings, "misp")
    github.assert_called_once_with(settings, max_items=1)
    misp.assert_called_once_with(settings, max_items=1)


def test_siem_job_queues_alerts_without_contacting_slack(settings, monkeypatch):
    audit = Mock(return_value={"hunts": {}, "error_count": 0})
    notify, slack = Mock(), Mock()
    monkeypatch.setattr("hecate_runner.siem_drift.audit_workspace_queries", audit)
    monkeypatch.setattr("hecate_runner.drift_alerts.notify_drift_report", notify)
    monkeypatch.setattr("hecate_runner.notifications.notify_siem_drift", slack)
    run_job(settings, "siem")
    notify.assert_called_once_with(settings, audit.return_value)
    slack.assert_not_called()


def test_maintenance_dry_run_never_spawns_workers(settings, monkeypatch):
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    spawn = Mock()
    monkeypatch.setattr(maintenance.subprocess, "Popen", spawn)
    result = CliRunner().invoke(cli.app, ["maintenance", "--once", "--dry-run"])
    assert result.exit_code == 0, result.output
    spawn.assert_not_called()


@pytest.mark.parametrize("returncode", [0, 1])
def test_maintenance_once_reaps_finished_work_and_reports_failure(
    settings, monkeypatch, returncode
):
    settings.siem_drift_audit_interval_sec = 0
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    process = Mock(pid=999999)
    process.poll.return_value = returncode
    spawn = Mock(return_value=process)
    monkeypatch.setattr(maintenance.subprocess, "Popen", spawn)
    kill = Mock()
    monkeypatch.setattr(maintenance.os, "killpg", kill)
    result = CliRunner().invoke(cli.app, ["maintenance", "--once"])
    assert result.exit_code == returncode, result.output
    assert spawn.call_count == 1
    kill.assert_not_called()
    state = json.loads((settings.hecate_workspace / ".hecate/maintenance/alerts.json").read_text())
    assert state["status"] == ("complete" if returncode == 0 else "failed")


@pytest.mark.skipif(sys.platform != "linux", reason="Process cleanup check uses /proc")
def test_real_worker_timeout_stops_descendants(settings, monkeypatch, tmp_path):
    settings.siem_drift_audit_interval_sec = 0
    settings.maintenance_job_timeout_sec = 2
    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir()
    (bootstrap / "sitecustomize.py").write_text("""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from hecate_runner import maintenance

def block(settings, job):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    Path(os.environ["TEST_MARKER"]).write_text(json.dumps([os.getpid(), child.pid]))
    time.sleep(60)

maintenance.run_job = block
""")
    marker = tmp_path / "pids.json"
    monkeypatch.setenv(
        "PYTHONPATH", os.pathsep.join(filter(None, [str(bootstrap), os.environ.get("PYTHONPATH")]))
    )
    monkeypatch.setenv("TEST_MARKER", str(marker))
    instance = MaintenanceScheduler(settings)
    try:
        instance.tick()
        # The worker inherits the lock: losing the scheduler's descriptor must
        # not allow a replacement to overlap it while it is still executing.
        instance.active["alerts"].lock.close()
        replacement = MaintenanceScheduler(settings)
        replacement.tick()
        assert replacement.active == {}
        deadline = time.monotonic() + 5
        while instance.active and time.monotonic() < deadline:
            time.sleep(0.02)
            instance.tick(launch=False)
        assert not instance.active
        for pid in json.loads(marker.read_text()):
            status = Path(f"/proc/{pid}/stat")
            if status.exists():
                assert status.read_text().split(")", 1)[1].split()[0] == "Z"
        assert json.loads((instance.root / "alerts.json").read_text())["status"] == "timed_out"
    finally:
        instance.close()
