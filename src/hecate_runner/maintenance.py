"""Independent, bounded workers for publication, SIEM audits and alert delivery."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import IO, Any

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.config import Settings
from hecate_runner.log_rotation import rotate_log_if_needed
from hecate_runner.work_locks import acquire_work_lock

log = logging.getLogger(__name__)
JOBS = ("github", "misp", "siem", "alerts")


def run_job(settings: Settings, job: str) -> None:
    """One bounded batch. Publisher outboxes retain their per-item retry backoff."""
    if job == "github":
        from hecate_runner.github_publisher import sync_outbox

        sync_outbox(settings, max_items=1)
    elif job == "misp":
        from hecate_runner.misp_publisher import sync_misp_outbox

        sync_misp_outbox(settings, max_items=1)
    elif job == "siem":
        from hecate_runner.drift_alerts import notify_drift_report
        from hecate_runner.siem_drift import audit_workspace_queries, reconcile_all_drifted_queries

        report = audit_workspace_queries(
            settings.hecate_workspace, dry_run=False, trigger="maintenance"
        )
        notify_drift_report(settings, report)  # Durable queue only; Slack has its own worker.
        if settings.siem_drift_auto_reconcile and (
            report.get("drifted_count") or report.get("missing_count")
        ):
            reconcile_all_drifted_queries(
                settings.hecate_workspace, dry_run=False, actor="maintenance"
            )
    elif job == "alerts":
        from hecate_runner.drift_alerts import deliver_drift_alerts
        from hecate_runner.notifications import notify_siem_drift

        deliver_drift_alerts(settings, notify_siem_drift, max_items=20)
    else:
        raise ValueError(f"Unknown maintenance job: {job}")


def _worker_env(settings: Settings) -> dict[str, str]:
    # Pass the effective configuration through the environment, never command
    # arguments or a credentials file. Preserve non-Runner provider variables.
    env = dict(os.environ)
    values = settings.model_dump(mode="json")
    for name, model_field in Settings.model_fields.items():
        validation_alias = model_field.validation_alias
        aliases = (
            [model_field.alias]
            if model_field.alias
            else [validation_alias]
            if isinstance(validation_alias, str)
            else [
                item for item in getattr(validation_alias, "choices", []) if isinstance(item, str)
            ]
        )
        if not aliases:
            continue
        value = values[name]
        if value is None:
            for alias in aliases:
                env.pop(alias, None)
        else:
            env[aliases[0]] = (
                json.dumps(value) if isinstance(value, (dict, list, bool)) else str(value)
            )
    env.update(settings.env_for_hecate())
    env["HECATE_WORKSPACE"] = str(settings.hecate_workspace)
    return env


@dataclass
class _ActiveJob:
    process: subprocess.Popen[Any]
    lock: IO[str]
    started: float
    failures: int


class MaintenanceScheduler:
    """At most one process per job/workspace; slow targets cannot block others.

    State survives restarts. A lock is inherited by the worker, so a scheduler
    crash does not permit a replacement to overlap an already-running job.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.root = settings.hecate_workspace / ".hecate/maintenance"
        self.active: dict[str, _ActiveJob] = {}
        self.env = _worker_env(settings)
        self.failed = False

    def intervals(self) -> dict[str, int]:
        return {
            "github": self.settings.maintenance_interval_sec
            if self.settings.github_publishing_enabled
            else 0,
            "misp": self.settings.maintenance_interval_sec
            if self.settings.misp_publishing_enabled
            else 0,
            "siem": self.settings.siem_drift_audit_interval_sec,
            "alerts": self.settings.maintenance_interval_sec,
        }

    def _state(self, job: str) -> dict[str, Any]:
        try:
            state = json.loads((self.root / f"{job}.json").read_text())
            return state if isinstance(state, dict) else {}
        except (OSError, ValueError):
            return {}

    def _finish(self, job: str, *, status: str, returncode: int) -> None:
        active = self.active.pop(job)
        self.failed = self.failed or returncode != 0
        try:
            failures = active.failures + 1 if returncode else 0
            delay = (
                max(self.intervals()[job], min(3600, 30 * 2 ** min(failures - 1, 7)))
                if failures
                else self.intervals()[job]
            )
            atomic_write_text(
                self.root / f"{job}.json",
                json.dumps(
                    {
                        "status": status,
                        "returncode": returncode,
                        "failures": failures,
                        "finished_at": time.time(),
                        "next_run": time.time() + delay,
                        "duration_ms": round((time.monotonic() - active.started) * 1000),
                    }
                ),
            )
            log.info("Maintenance %s %s (status=%d)", job, status, returncode)
        finally:
            active.lock.close()

    @staticmethod
    def _kill(process: subprocess.Popen[Any]) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)

    def tick(self, *, launch: bool = True) -> None:
        for job, active in list(self.active.items()):
            code = active.process.poll()
            if code is not None:
                self._finish(job, status="complete" if code == 0 else "failed", returncode=code)
            elif time.monotonic() - active.started >= self.settings.maintenance_job_timeout_sec:
                self._kill(active.process)
                self._finish(job, status="timed_out", returncode=-signal.SIGKILL)
        if not launch:
            return
        for job, interval in self.intervals().items():
            if interval <= 0 or job in self.active:
                continue
            lock = acquire_work_lock(self.root / f"{job}.lock")
            if lock is None:
                continue
            try:
                state = self._state(job)
                if state.get("next_run", 0) > time.time():
                    lock.close()
                    continue
                self.settings.log_dir.mkdir(parents=True, exist_ok=True)
                rotate_log_if_needed(
                    self.settings.log_dir / "maintenance.log",
                    max_bytes=self.settings.log_max_bytes,
                    backup_count=self.settings.log_backup_count,
                )
                with (self.settings.log_dir / "maintenance.log").open("a") as output:
                    popen_kwargs: dict[str, Any] = {
                        "cwd": self.settings.hecate_workspace,
                        "env": self.env,
                        "stdout": output,
                        "stderr": subprocess.STDOUT,
                    }
                    if os.name == "posix":
                        popen_kwargs["start_new_session"] = True
                        popen_kwargs["pass_fds"] = (lock.fileno(),)
                    process = subprocess.Popen(
                        [sys.executable, "-m", "hecate_runner.maintenance_worker", job],
                        **popen_kwargs,
                    )
                self.active[job] = _ActiveJob(
                    process, lock, time.monotonic(), state.get("failures", 0)
                )
            except Exception:
                self.failed = True
                try:
                    atomic_write_text(
                        self.root / f"{job}.json",
                        json.dumps(
                            {
                                "status": "start_failed",
                                "next_run": time.time() + 30,
                                "failures": self._state(job).get("failures", 0) + 1,
                            }
                        ),
                    )
                    log.exception("Could not start maintenance job %s", job)
                finally:
                    lock.close()

    def close(self) -> None:
        for job, active in list(self.active.items()):
            code = active.process.poll()
            if code is None:
                self._kill(active.process)
                self._finish(job, status="interrupted", returncode=-signal.SIGKILL)
            else:
                self._finish(job, status="complete" if code == 0 else "failed", returncode=code)
