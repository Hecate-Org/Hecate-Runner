"""Operator UX: quota access diagnostics + latest-release pending digests."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

from hecate_agent.commands.monitor_samplers import RunnerStatusSampler, _diagnose_state_access
from hecate_runner.config import Settings
from hecate_runner.github_publisher import PromotionOutbox, diff_release_snapshots
from hecate_runner.slack_blocks import build_pending_hunts_card, format_release_diff_message
from hecate_runner.state import OrchestratorState, diagnose_state_file_access


def test_diagnose_state_file_access_reports_permission_denied(tmp_path: Path) -> None:
    state = tmp_path / ".orchestrator_state.json"
    state.write_text('{"date":"2099-01-01","drafts_today":1}', encoding="utf-8")
    state.chmod(0o000)
    try:
        msg = diagnose_state_file_access(state)
        assert msg is not None
        assert "permission denied" in msg.lower() or "Cannot read" in msg
        loaded, issue = OrchestratorState.load_or_explain(state)
        assert issue is not None
        assert loaded.drafts_today == 0
    finally:
        state.chmod(0o600)


def test_monitor_sampler_sets_quota_unavailable_reason(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    state = ws / ".orchestrator_state.json"
    state.write_text(
        json.dumps(
            {
                "date": "2099-01-01",
                "drafts_today": 2,
                "research_runs_today": 1,
                "total_drafts_ever": 9,
            }
        ),
        encoding="utf-8",
    )
    state.chmod(0o000)
    try:
        reason = _diagnose_state_access(state)
        assert reason is not None
        sampler = RunnerStatusSampler(ws)
        with mock.patch.object(sampler, "_sample_heavy", wraps=sampler._sample_heavy):
            # Force heavy path against this workspace env
            with mock.patch.dict(os.environ, {"HECATE_WORKSPACE": str(ws)}, clear=False):
                heavy = sampler._sample_heavy(tmp_path)
        assert heavy.quota_unavailable_reason is not None
        assert heavy.drafts_today is None
    finally:
        state.chmod(0o600)


def test_pending_card_shows_latest_release_digest_only() -> None:
    releases = [
        {
            "hunt_id": "H-0032",
            "digest": "abc123def456",
            "updated_at": "2026-11-15T12:00:00+00:00",
            "awaiting_count": 23,
        }
    ]
    card = build_pending_hunts_card([], releases=releases)
    blocks = card[0]["blocks"]
    text = json.dumps(blocks)
    assert "Release digests" in text
    assert "abc123def456"[:12] in text or "abc123def456" in text
    assert "22 older" in text or "Superseded" in text
    assert "hecate_release_diff" in text
    assert "Diff vs last published" in text


def test_outbox_latest_awaiting_and_diff(tmp_path: Path) -> None:
    db = tmp_path / "outbox.sqlite3"
    outbox = PromotionOutbox(db)
    files_v1 = {"hunts/2026/Q4/H-0001.md": "v1\n", "queries/H-0001/a.yml": "old\n"}
    files_v2 = {
        "hunts/2026/Q4/H-0001.md": "v2\n",
        "queries/H-0001/a.yml": "new\n",
        "queries/H-0001/b.yml": "extra\n",
    }
    outbox.enqueue("H-0001", "digest-old", files_v1, reviewed=False)
    # Mark older as published baseline
    with outbox._connect() as conn:
        conn.execute(
            "UPDATE promotions SET status='published', payload=? WHERE digest='digest-old'",
            (json.dumps(files_v1),),
        )
    outbox.enqueue("H-0001", "digest-mid", {"hunts/2026/Q4/H-0001.md": "mid\n"}, reviewed=False)
    outbox.enqueue("H-0001", "digest-new", files_v2, reviewed=False)

    latest = outbox.latest_awaiting_review()
    assert len(latest) == 1
    assert latest[0]["digest"] == "digest-new"
    # Older awaiting_review rows are DB-superseded, not merely hidden.
    assert latest[0]["awaiting_count"] == 1
    with outbox._connect() as conn:
        statuses = {
            row["digest"]: row["status"]
            for row in conn.execute(
                "SELECT digest, status FROM promotions WHERE hunt_id='H-0001'"
            )
        }
    assert statuses["digest-mid"] == "superseded"
    assert statuses["digest-new"] == "awaiting_review"

    settings = Settings(  # type: ignore[call-arg]
        _env_file=None,
        hecate_workspace=tmp_path,
        github_publishing_enabled=True,
        github_publishing_outbox_path=db,
    )
    diff = diff_release_snapshots(settings, "H-0001")
    assert diff["ok"] is True
    assert diff["pending_digest"] == "digest-new"
    assert "queries/H-0001/b.yml" in diff["added"]
    assert "queries/H-0001/a.yml" in diff["changed"]
    msg = format_release_diff_message(diff)
    assert "Added" in msg and "Changed" in msg
