"""Separate SIEM search matches from correlated, authoritative alert firings."""

from __future__ import annotations

import contextlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.bas.approved import confirms_technique, resolve_fidelity_scope
from hecate_runner.bas.base import DetonationResult
from hecate_runner.bas.forwarder import forward_events_to_splunk, splunk_settings
from hecate_runner.siem_drift import record_detection_validation

log = logging.getLogger(__name__)


@dataclass
class SiemAlertVerificationResult:
    """Detailed outcome of closed-loop live SIEM alert verification and latency measurement."""

    hunt_id: str
    technique_id: str
    ability_id: str
    bas_provider: str
    siem_backend: str
    status: str  # "verified_true_positive", "detection_miss", "telemetry_missing", "error"
    rule_triggered: bool
    telemetry_arrived: bool
    detection_latency_sec: float | None
    detonation_time_utc: str
    alert_time_utc: str
    matched_events_count: int
    query_used: str
    search_job_id: str = ""
    siem_alert_fired: bool = False
    cleanup_success: bool = False
    query_match_latency_sec: float | None = None
    fidelity_scope: str = "behavioral"
    verification_scope: str = "siem_query"
    alert_search_id: str = ""
    alert_name: str = ""
    run_id: str = ""
    alert_evidence: dict[str, Any] = field(default_factory=dict)
    sample_events: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    verified_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SiemAlertVerifier:
    """Executes closed-loop detection validation against live SIEM search jobs API."""

    def __init__(
        self,
        workspace: Path,
        poll_interval_sec: float = 0.25,
        max_wait_sec: float = 20.0,
    ) -> None:
        self.workspace = workspace
        self.poll_interval_sec = poll_interval_sec
        self.max_wait_sec = max_wait_sec

    def resolve_candidate_rule(
        self,
        hunt_id: str,
        technique_id: str | None = None,
    ) -> tuple[str, str, str]:
        """Locate candidate SPL query, source filename, and companion Sigma rule YAML.

        Returns:
            Tuple of (query_string, source_file_name, sigma_yaml_content)
        """
        query_dir = self.workspace / "queries" / hunt_id
        if not query_dir.is_dir():
            return "", "", ""
        # Resolve an actual rule and its same-stem query. Never manufacture a
        # detection, or pair an unrelated YAML rule with a native query.
        rules = sorted([*query_dir.glob("*.yml"), *query_dir.glob("*.yaml")])
        for rule in rules:
            content = rule.read_text(encoding="utf-8")
            if technique_id:
                technique = technique_id.lower()
                names = (technique, technique.replace(".", "_"), technique.replace(".", ""))
                if (
                    not any(name in rule.stem.lower() for name in names)
                    and technique not in content.lower()
                    and (len(rules) != 1 or "attack.t" in content.lower())
                ):
                    continue
            companion = rule.with_suffix(".spl")
            query = companion.read_text(encoding="utf-8").strip() if companion.is_file() else ""
            return query, rule.name, content
        # Native-only rules can be searched, but cannot support a Sigma probe.
        for native in sorted(query_dir.glob("*.spl")):
            if technique_id and not any(
                name in native.stem.lower()
                for name in (
                    technique_id.lower(),
                    technique_id.lower().replace(".", "_"),
                    technique_id.lower().replace(".", ""),
                )
            ):
                continue
            return native.read_text(encoding="utf-8").strip(), native.name, ""
        return "", "", ""

    def resolve_candidate_query(
        self,
        hunt_id: str,
        technique_id: str | None = None,
    ) -> tuple[str, str]:
        """Locate the most relevant candidate SPL query for a hunt and technique.

        Returns:
            Tuple of (query_string, source_file_name)
        """
        query_str, filename, _ = self.resolve_candidate_rule(hunt_id, technique_id)
        return query_str, filename

    def _normalize_spl_query(self, raw_query: str) -> str:
        """Normalize transpiled SPL query so it executes against raw JSON index events."""
        clean = raw_query.strip()
        if clean.startswith("search "):
            clean = clean[7:].strip()

        # Normalize escaped backslashes for Splunk string literals
        clean = clean.replace("*\\\\", "*").replace("*\\", "*")

        if not clean.startswith("index=") and not clean.startswith("|"):
            return f"index=* | spath | search {clean}"
        return clean

    def verify_detonation_alert(
        self,
        detonation: DetonationResult,
        hunt_id: str,
        candidate_query: str | None = None,
        siem_target: str = "splunk",
        timeout_sec: float | None = None,
        forward_telemetry: bool = True,
        t0_detonate: float | None = None,
        raw_events: list[dict[str, Any]] | None = None,
        fidelity_scope: str | None = None,
    ) -> SiemAlertVerificationResult:
        """Measure True Positive Detection Latency and verify SIEM alert generation.

        Args:
            detonation: Output of adversary emulation detonation.
            hunt_id: Hunt ID under validation.
            candidate_query: Candidate detection query (or resolved automatically).
            siem_target: Target SIEM backend ('splunk' or 'mock').
            timeout_sec: Maximum wait time for live SIEM alert polling.
            forward_telemetry: Whether to ship BAS events into SIEM receiver.
            t0_detonate: Start timestamp for detection latency measurement (perf_counter).
        """
        fidelity_scope = resolve_fidelity_scope(detonation, fidelity_scope)
        max_wait = timeout_sec or self.max_wait_sec
        t0 = t0_detonate if t0_detonate is not None else time.perf_counter()
        det_time_utc = detonation.end_time_utc or datetime.now(UTC).isoformat()
        technique_id = detonation.technique_id or "UNKNOWN"
        ability_id = detonation.ability_id or ""
        notes: list[str] = []

        env = splunk_settings(self.workspace)

        # 1. Telemetry verification & forwarding
        telemetry_events = list(
            raw_events if raw_events is not None else detonation.telemetry_signatures or []
        )
        telemetry_arrived = len(telemetry_events) > 0
        # Resolve only the on-disk hunt detection. A custom native query is not
        # evaluated by the Sigma simulator unless it is the exact companion.
        disk_query, query_source, resolved_yaml = self.resolve_candidate_rule(hunt_id, technique_id)
        query_text = candidate_query or disk_query
        can_simulate = bool(resolved_yaml) and (
            not candidate_query or candidate_query == disk_query
        )
        notes.append(f"Candidate query from {query_source}: {query_text}")

        # 3. Handle Mock / Offline Mode
        splunk_host = env.get("SPLUNK_HOST") or env.get("SPLUNK_URL")
        splunk_token = env.get("SPLUNK_TOKEN") or env.get("SPLUNK_PASSWORD")
        is_mock = siem_target.lower() == "mock" or detonation.provider == "mock"

        if not is_mock and not (splunk_host and splunk_token):
            notes.append(
                f"SIEM target is '{siem_target}' but SPLUNK_HOST and SPLUNK_TOKEN are not configured; "
                "refusing silent mock fallback."
            )
            result = SiemAlertVerificationResult(
                hunt_id=hunt_id,
                technique_id=technique_id,
                ability_id=ability_id,
                bas_provider=detonation.provider,
                fidelity_scope=fidelity_scope,
                siem_backend=siem_target,
                status="unconfigured_credentials",
                rule_triggered=False,
                telemetry_arrived=telemetry_arrived,
                detection_latency_sec=None,
                detonation_time_utc=det_time_utc,
                alert_time_utc="",
                matched_events_count=0,
                query_used=query_text,
                notes=notes,
            )
            self._persist_result(result)
            return result

        if is_mock:
            matched_events: list[dict[str, Any]] = []

            # 1. If candidate Sigma YAML is available, evaluate via AST
            if can_simulate and telemetry_events:
                try:
                    from hecate_agent.core.sigma_evaluator import SigmaEvaluator

                    for ev in telemetry_events:
                        if SigmaEvaluator.evaluate_rule(resolved_yaml, [ev], []).true_positives > 0:
                            matched_events.append(ev)
                except Exception as eval_exc:
                    notes.append(f"Sigma AST evaluation warning in mock mode: {eval_exc}")

            matched = len(matched_events)
            rule_triggered = matched > 0 and detonation.success and telemetry_arrived
            status = (
                "simulation_match"
                if rule_triggered
                else ("detection_miss" if telemetry_arrived else "telemetry_missing")
            )
            if not can_simulate:
                status = "simulation_unsupported"
                notes.append(
                    "Native query semantics cannot be verified by the offline Sigma evaluator."
                )

            notes.append(
                f"Mock SIEM provider: Sigma probe against {len(telemetry_events)} telemetry event(s); "
                f"matched={matched} (AST logic probe, not live SIEM alert)."
            )

            result = SiemAlertVerificationResult(
                hunt_id=hunt_id,
                technique_id=technique_id,
                ability_id=ability_id,
                bas_provider=detonation.provider,
                fidelity_scope=fidelity_scope,
                siem_backend="mock",
                verification_scope="synthetic_sigma_logic",
                status=status,
                rule_triggered=rule_triggered,
                telemetry_arrived=telemetry_arrived,
                detection_latency_sec=None,
                detonation_time_utc=det_time_utc,
                alert_time_utc="",
                matched_events_count=matched,
                query_used=query_text,
                search_job_id="",
                sample_events=matched_events[:1] if matched_events else telemetry_events[:1],
                notes=notes,
            )
            self._persist_result(result)
            return result

        if not query_text or not detonation.success or not detonation.cleanup_success:
            result = SiemAlertVerificationResult(
                hunt_id=hunt_id,
                technique_id=technique_id,
                ability_id=ability_id,
                bas_provider=detonation.provider,
                fidelity_scope=fidelity_scope,
                siem_backend=siem_target,
                status=(
                    "detonation_failed"
                    if not detonation.success
                    else "error"
                    if not detonation.cleanup_success
                    else "detection_unavailable"
                ),
                rule_triggered=False,
                telemetry_arrived=False,
                detection_latency_sec=None,
                detonation_time_utc=det_time_utc,
                alert_time_utc="",
                matched_events_count=0,
                query_used=query_text,
                notes=notes,
            )
            self._persist_result(result)
            return result
        run_id = uuid4().hex
        telemetry_events = [
            {**e, "hecate_bas_run_id": run_id, "hecate_hunt_id": hunt_id}
            for e in telemetry_events
            if e.get("data_source") not in {"caldera_link", "cloud_control_plane"}
            and e.get("sensor") != "lab_file_delta"
        ]
        telemetry_arrived = bool(telemetry_events)
        correlation_available = False
        if telemetry_arrived and forward_telemetry:
            try:
                forwarded = forward_events_to_splunk(telemetry_events, workspace=self.workspace)
                correlation_available = forwarded > 0
                notes.append(f"Forwarded {forwarded} sensor event(s) to Splunk.")
            except Exception as exc:
                notes.append(f"SIEM telemetry forwarding error: {exc}")

        # 4. Live Splunk Search Jobs API Verification
        from hecate_agent.core.splunk_client import SplunkClient

        try:
            client = SplunkClient(
                host=splunk_host,
                token=env.get("SPLUNK_TOKEN"),
                username=env.get("SPLUNK_USERNAME"),
                password=env.get("SPLUNK_PASSWORD"),
                verify_ssl=env.get("SPLUNK_VERIFY_SSL", "true").strip().lower()
                not in ("false", "0", "no"),
            )
        except Exception as client_exc:
            notes.append(f"Splunk client initialization failed: {client_exc}")
            result = SiemAlertVerificationResult(
                hunt_id=hunt_id,
                technique_id=technique_id,
                ability_id=ability_id,
                bas_provider=detonation.provider,
                fidelity_scope=fidelity_scope,
                siem_backend="splunk",
                status="error",
                rule_triggered=False,
                telemetry_arrived=telemetry_arrived,
                detection_latency_sec=None,
                detonation_time_utc=det_time_utc,
                alert_time_utc="",
                matched_events_count=0,
                query_used=query_text,
                notes=notes,
            )
            self._persist_result(result)
            return result

        expected_names: list[str] = []
        if disk_query and resolved_yaml and query_text == disk_query:
            import yaml
            from hecate_agent.core.query_deployer import QueryDeployer

            rule = yaml.safe_load(resolved_yaml)
            if isinstance(rule, dict) and rule.get("title"):
                # Automatic generation uses the Sigma title; manual deployment
                # and reconciliation use the humanized filename. Both identify
                # this exact on-disk query through the deployer's query hash.
                file_title = Path(query_source).stem.replace("__", " - ").replace("_", " ").title()
                expected_names = list(
                    dict.fromkeys(
                        QueryDeployer.compute_remote_id(
                            QueryDeployer.TARGET_SPLUNK, hunt_id, title, disk_query
                        )
                        for title in (str(rule["title"]), file_title)
                    )
                )
        if not correlation_available or not expected_names:
            notes.append(
                "Alert firing cannot be correlated: a deployed hunt rule and forwarded run marker are required."
            )
        normalized_spl = self._normalize_spl_query(query_text)
        job_sid = ""
        matched_results: list[dict[str, Any]] = []
        latency_sec: float | None = None
        query_latency_sec: float | None = None
        proof = None
        started = None
        ended = None
        status = "detection_miss"
        alert_time_utc = ""

        # Scope time window tightly around detonation time
        earliest_time = "-2m"
        try:
            started = datetime.fromisoformat(detonation.start_time_utc.replace("Z", "+00:00"))
            if started.tzinfo is None:
                started = started.replace(tzinfo=UTC)
            started = started.astimezone(UTC)
            ended = datetime.fromisoformat(detonation.end_time_utc.replace("Z", "+00:00"))
            if ended.tzinfo is None:
                ended = ended.replace(tzinfo=UTC)
            earliest_time = (started - timedelta(seconds=30)).isoformat()
        except (ValueError, TypeError):
            notes.append("Invalid detonation wall-clock timestamp; using the last two minutes.")

        try:
            poll_start = time.perf_counter()
            while (time.perf_counter() - poll_start) < max_wait:
                if matched_results:
                    # Keep polling the independent alert record without repeatedly
                    # redispatching the already successful candidate search.
                    pass
                else:
                    job_sid = client.create_search_job(
                        query=normalized_spl,
                        earliest_time=earliest_time,
                        latest_time="now",
                    )
                    if not any(f"Dispatched Splunk search job ID: {job_sid}" in n for n in notes):
                        notes.append(f"Dispatched Splunk search job ID: {job_sid}")

                    # Poll this job for completion
                    job_poll_start = time.perf_counter()
                    while time.perf_counter() < min(job_poll_start + 10.0, poll_start + max_wait):
                        job_status = client.get_search_job_status(job_sid)
                        content = job_status.get("entry", [{}])[0].get("content", {})
                        is_done = content.get("isDone", False)

                        if is_done:
                            matched_results = client.get_search_results(job_sid, count=25)
                            if len(matched_results) > 0:
                                t_alert = time.perf_counter()
                                query_latency_sec = max(0.001, t_alert - t0)
                                status = "query_match"
                                notes.append(
                                    f"Candidate search matched {len(matched_results)} log event(s) in {query_latency_sec:.3f}s; "
                                    "this is not proof of alert firing."
                                )
                                break
                            # Job is done but 0 results found: break job poll to re-dispatch if time remains
                            break

                        time.sleep(self.poll_interval_sec)

                if correlation_available and expected_names and started and ended:
                    from hecate_runner.bas.alerts import find_fired_alert

                    for expected_name in expected_names:
                        try:
                            proof = find_fired_alert(
                                client,
                                name=expected_name,
                                query=disk_query,
                                owner=env.get("SPLUNK_USER") or "nobody",
                                app=env.get("SPLUNK_APP") or "search",
                                run_id=run_id,
                                hunt_id=hunt_id,
                                started=started,
                                ended=ended,
                                excluded_sid=job_sid,
                            )
                        except Exception as exc:
                            message = f"Alert verification unavailable for {expected_name}: {exc}"
                            if message not in notes:
                                notes.append(message)
                        if proof:
                            break
                    if proof:
                        status = "verified_true_positive"
                        latency_sec = proof.latency_sec
                        alert_time_utc = proof.triggered_at
                        notes.append(
                            f"Verified fired alert {proof.name} ({proof.sid}) with this run's correlated event."
                        )
                        break
                if matched_results and (not correlation_available or not expected_names):
                    break
                time.sleep(self.poll_interval_sec)

            if status not in {"verified_true_positive", "query_match"}:
                if not telemetry_arrived:
                    status = "telemetry_missing"
                    notes.append("No telemetry arrived during detonation window.")
                else:
                    notes.append(
                        f"Search job completed with 0 matches within {max_wait:.1f}s timeout."
                    )
            if not proof:
                notes.append(
                    "SIEM alert firing remains unverified; no correlated fired-alert record was observed."
                )

        except Exception as exc:
            status = "error"
            notes.append(f"Splunk search jobs API exception: {exc}")

        if fidelity_scope != "behavioral" and status in {"verified_true_positive", "query_match"}:
            status = "smoke_check_match"
            notes.append(
                "Smoke check evidence does not validate the attack technique, even if a SIEM alert fired."
            )

        result = SiemAlertVerificationResult(
            hunt_id=hunt_id,
            technique_id=technique_id,
            ability_id=ability_id,
            bas_provider=detonation.provider,
            fidelity_scope=fidelity_scope,
            siem_backend="splunk",
            status=status,
            rule_triggered=status in {"verified_true_positive", "query_match", "smoke_check_match"},
            siem_alert_fired=proof is not None,
            cleanup_success=detonation.cleanup_success,
            query_match_latency_sec=query_latency_sec,
            verification_scope="smoke_check"
            if fidelity_scope != "behavioral"
            else "siem_alert"
            if proof
            else "siem_query",
            alert_search_id=proof.sid if proof else "",
            alert_name=proof.name if proof else "",
            run_id=run_id,
            alert_evidence=proof.event if proof else {},
            telemetry_arrived=telemetry_arrived,
            detection_latency_sec=latency_sec,
            detonation_time_utc=det_time_utc,
            alert_time_utc=alert_time_utc,
            matched_events_count=max(len(matched_results), 1 if proof else 0),
            query_used=normalized_spl,
            search_job_id=job_sid,
            sample_events=matched_results[:3],
            notes=notes,
        )
        self._persist_result(result)
        return result

    def _persist_result(self, res: SiemAlertVerificationResult) -> None:
        """Persist verification provenance into SQLite drift history and durable BAS runs."""
        # 1. SQLite drift history
        try:
            record_detection_validation(
                workspace=self.workspace,
                hunt_id=res.hunt_id,
                technique_id=res.technique_id,
                ability_id=res.ability_id,
                bas_provider=res.bas_provider,
                siem_backend=res.siem_backend,
                status=res.status,
                rule_triggered=res.rule_triggered,
                telemetry_arrived=res.telemetry_arrived,
                detection_latency_sec=res.detection_latency_sec,
                matched_events_count=res.matched_events_count,
                query_used=res.query_used,
                search_job_id=res.search_job_id,
                detonation_time_utc=res.detonation_time_utc,
                notes="; ".join(res.notes),
                siem_alert_fired=res.siem_alert_fired,
                query_match_latency_sec=res.query_match_latency_sec,
                alert_search_id=res.alert_search_id,
                alert_name=res.alert_name,
                alert_time_utc=res.alert_time_utc,
            )
        except Exception as db_exc:
            log.warning("Could not persist detection validation into SQLite: %s", db_exc)

        # 2. Durable BAS run JSON for TUI monitor
        try:
            run_id = res.run_id or uuid4().hex
            run_data = res.to_dict()
            run_data["run_id"] = run_id
            run_data["duration_seconds"] = res.detection_latency_sec or 0.0

            root = self.workspace / ".hecate" / "bas"
            root.mkdir(parents=True, exist_ok=True)
            runs_dir = root / "runs"
            runs_dir.mkdir(parents=True, exist_ok=True)

            atomic_write_text(
                runs_dir / f"{run_id}.json",
                json.dumps(run_data, indent=2),
                mode=0o600,
            )

            # Update state.json
            state_file = root / "state.json"
            state_data: dict[str, Any] = {}
            if state_file.exists():
                with contextlib.suppress(Exception):
                    state_data = json.loads(state_file.read_text(encoding="utf-8"))

            if not state_data.get("last_alert_search_id"):
                for key in (
                    "last_detection_latency_sec",
                    "last_verified_hunt",
                    "last_verified_technique",
                ):
                    state_data.pop(key, None)
            if res.siem_alert_fired and confirms_technique(res.to_dict()):
                state_data.update(
                    {
                        "last_verified_hunt": res.hunt_id,
                        "last_verified_technique": res.technique_id,
                        "last_detection_latency_sec": res.detection_latency_sec,
                        "last_alert_search_id": res.alert_search_id,
                        "last_alert_name": res.alert_name,
                    }
                )
            state_data.update(
                {
                    "last_status": res.status,
                    "last_reason": "; ".join(res.notes[:2]),
                    "updated_at": res.verified_at,
                    "last_siem_backend": res.siem_backend,
                    "last_checked_hunt": res.hunt_id,
                    "last_checked_technique": res.technique_id,
                    "last_query_match_latency_sec": res.query_match_latency_sec,
                    "last_search_job_id": res.search_job_id,
                }
            )
            atomic_write_text(state_file, json.dumps(state_data, indent=2), mode=0o600)

        except Exception as file_exc:
            log.warning("Could not persist BAS run record: %s", file_exc)
