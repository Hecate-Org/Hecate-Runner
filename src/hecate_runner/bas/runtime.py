"""Scoped lab automation and private, durable BAS run evidence."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.bas.approved import APPROVED_PROCEDURES, ApprovedProcedure, catalog_digest
from hecate_runner.bas.base import DetonationRequest, DetonationTarget, SafetyViolationError
from hecate_runner.bas.lifecycle import LabLease, audit_container_tmpfs
from hecate_runner.bas.sensor import LabFileDeltaSensor, LabProcessSensor
from hecate_runner.bas.verifier import DetectionVerifier
from hecate_runner.config import Settings


def save_bas_record(settings: Settings, record: dict[str, Any]) -> dict[str, Any]:
    """Keep execution evidence outside Git and expose nonsecret runtime status."""
    record.setdefault("run_id", uuid.uuid4().hex)
    record.setdefault("verified_at", datetime.now(UTC).isoformat())
    root = settings.hecate_workspace / ".hecate" / "bas"
    atomic_write_text(
        root / "runs" / f"{record['run_id']}.json", json.dumps(record, indent=2), mode=0o600
    )
    atomic_write_text(
        root / "state.json",
        json.dumps(
            {
                "enabled": settings.bas_enabled,
                "auto_execute_live": settings.bas_auto_execute_live,
                "provider": settings.bas_mode,
                "telemetry": settings.bas_telemetry,
                "allowed_techniques": settings.bas_auto_techniques,
                "last_status": record.get("status"),
                "last_reason": record.get("reason", ""),
                "updated_at": record["verified_at"],
            },
            indent=2,
        ),
        mode=0o600,
    )
    return record


def skipped_bas(settings: Settings, hunt_id: str, reason: str) -> dict[str, Any]:
    return save_bas_record(
        settings,
        {
            "hunt_id": hunt_id,
            "provider": settings.bas_mode,
            "status": "skipped",
            "reason": reason,
            "notes": [reason],
            "telemetry_arrived": False,
            "rule_triggered": False,
        },
    )


def run_approved_validation(
    settings: Settings,
    hunt_id: str,
    procedure: ApprovedProcedure,
    rule_yaml: str,
    lease: LabLease | None = None,
) -> dict[str, Any]:
    """Execute one pinned read-only procedure and evaluate independently observed events."""
    from hecate_runner.bas import get_bas_provider

    root = settings.hecate_workspace / ".hecate" / "bas"
    root.mkdir(parents=True, exist_ok=True)
    record: dict[str, Any] = {
        "hunt_id": hunt_id,
        "provider": "caldera",
        "technique_id": procedure.technique_id,
        "ability_id": procedure.ability_id,
        "backend": settings.bas_telemetry,
        "verification_scope": "local_sensor_sigma",
        "purpose": "sensor_control" if hunt_id == "LAB-CHECK" else "hunt_validation",
        "telemetry_arrived": False,
        "rule_triggered": False,
        "catalog_digest": catalog_digest(),
    }
    lab_lease = lease or LabLease(
        lease_path=root / "lab.lease",
        quarantine_path=root / "lab.quarantine",
        lock_path=root / "execution.lock",
    )
    try:
        with lab_lease.acquire(hunt_id=hunt_id, timeout_sec=180) as lease_info:
            record["lease_id"] = lease_info["lease_id"]
            if (
                settings.bas_mode != "caldera"
                or settings.bas_telemetry not in {"lab_process", "lab_fusion"}
                or settings.bas_fallback_to_mock
                or not settings.bas_linux_host
                or settings.bas_linux_host not in settings.bas_allowed_hosts
                or procedure.technique_id not in settings.bas_auto_techniques
                or APPROVED_PROCEDURES.get(procedure.technique_id) != procedure
                or urlparse(settings.caldera_url).hostname not in {"localhost", "127.0.0.1", "::1"}
                or settings.caldera_agent_group != "hecate-local-lab"
            ):
                raise SafetyViolationError(
                    "Approved automation requires CALDERA, an allowlisted Linux lab, and its process sensor."
                )
            sensor = LabProcessSensor(settings.bas_sensor_container, settings.bas_linux_host)
            sensor.preflight()
            record["agent_image"] = getattr(sensor, "agent_image", "")
            record["controller_image"] = getattr(sensor, "controller_image", "")

            # Audit container tmpfs before detonation
            pre_files = audit_container_tmpfs(settings.bas_sensor_container)
            if pre_files:
                lab_lease.quarantine(
                    "Dirty lab: unexpected pre-existing files in container /tmp.",
                    hunt_id=hunt_id,
                    details={"files": pre_files},
                )
                raise SafetyViolationError(
                    f"Lab /tmp contains uncleaned files prior to execution: {pre_files}"
                )

            provider = get_bas_provider("caldera", settings)
            request = DetonationRequest(
                hunt_id=hunt_id,
                technique_id=procedure.technique_id,
                ability_id=procedure.ability_id,
                platform="linux",
                target=DetonationTarget(
                    environment="lab", platform="linux", host=settings.bas_linux_host
                ),
                # Allow two 60s agent beacons and scheduling slack.
                timeout_sec=180,
                params={"approved_only": True},
            )
            detonation = provider.detonate(request)
            if detonation.success:
                delta_sensor = LabFileDeltaSensor(
                    settings.bas_sensor_container, settings.bas_linux_host
                )
                file_delta_events: list[dict[str, Any]] = []
                if procedure.expected_files and detonation.cleanup_success:
                    file_delta_events = delta_sensor.collect_delta_events(
                        created_files=list(procedure.expected_files),
                        deleted_files=list(procedure.expected_files),
                        start_utc=detonation.start_time_utc,
                        end_utc=detonation.end_time_utc,
                        command_line=procedure.command,
                    )
                if hasattr(sensor, "collect_fused"):
                    events = sensor.collect_fused(
                        detonation,
                        procedure.argv,
                        expected_files=procedure.expected_files,
                        file_delta_events=file_delta_events,
                    )
                else:
                    events = sensor.collect(detonation, procedure.argv)
            else:
                events = []

            verification = DetectionVerifier().verify_detonation(
                detonation,
                rule_yaml=rule_yaml,
                raw_events=events,
                backend=settings.bas_telemetry,
            )
            record.update(verification.to_dict())
            record["duration_seconds"] = detonation.duration_seconds
            record["cleanup_success"] = detonation.cleanup_success
            record["sensor_events_count"] = len(events)
            record["telemetry_categories"] = sorted(
                {str(e.get("category")) for e in events if e.get("category")}
            )

            # Audit container tmpfs after execution and cleanup
            post_files = audit_container_tmpfs(settings.bas_sensor_container)
            if post_files:
                lab_lease.quarantine(
                    "Ephemeral state violation: uncleaned files in container /tmp after execution.",
                    hunt_id=hunt_id,
                    details={"files": post_files},
                )
                record.update(status="error", rule_triggered=False)
                record["notes"].append(f"Uncleaned files in /tmp: {post_files}")
            elif not detonation.cleanup_success:
                lab_lease.quarantine(
                    "Remote operation cleanup was not confirmed.",
                    hunt_id=hunt_id,
                    details={"technique_id": procedure.technique_id},
                )
                record.update(status="error", rule_triggered=False)
                record["notes"].append("Remote operation cleanup was not confirmed.")
    except Exception as exc:
        msg = str(exc)
        if "Another BAS operation holds" in msg or "Another BAS lab validation" in msg:
            return skipped_bas(settings, hunt_id, "Another BAS lab validation is running.")
        record.update(status="error", reason=msg, notes=[msg])
    return save_bas_record(settings, record)
