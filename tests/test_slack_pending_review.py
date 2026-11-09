import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml
from slack_bolt import App, BoltRequest, BoltResponse

from hecate_runner.config import Settings
from hecate_runner.lifecycle import parse_hunt_frontmatter
from hecate_runner.slack_blocks import build_pending_hunts_card
from hecate_runner.slack_bot import SlackBotService, list_pending_hunts, park_hunt, review_hunt

_BODY = """
# {hunt_id}: Draft

```yaml
title: Embedded rule
status: experimental
detection:
  condition: selection
```
"""


def _write_hunt(workspace: Path, hunt_id: str, status: str = "planning") -> Path:
    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True, exist_ok=True)
    path = hunts_dir / f"{hunt_id}.md"
    path.write_text(
        f'---\nhunt_id: {hunt_id}\ntitle: "DRAFT - {hunt_id} test"\nstatus: {status}\n'
        f'date: 2026-11-03\ntechniques: ["T1190", "T1059.006"]\nspawned_from: R-0975\n---\n'
        + _BODY.format(hunt_id=hunt_id),
        encoding="utf-8",
    )
    return path


def _frontmatter(path: Path) -> dict:
    fm, _, _ = parse_hunt_frontmatter(path.read_text(encoding="utf-8"))
    return fm


def _service(workspace: Path) -> tuple[SlackBotService, App]:
    settings = Settings(
        hecate_workspace=workspace,
        slack_bot_token="xoxb-fake",
        slack_app_token="xapp-fake",
        slack_interactive_enabled=True,
    )
    app = App(token="xoxb-fake", signing_secret="fake", token_verification_enabled=False)
    return SlackBotService(settings=settings, app=app), app


def _listener(app: App, body: dict):
    req = BoltRequest(body=body, mode="socket_mode")
    resp = BoltResponse(status=200)
    matched = [lst for lst in app._listeners if lst.matches(req=req, resp=resp)]
    assert len(matched) == 1
    return matched[0]


def _action_listener(app: App, action_id: str):
    return _listener(
        app, {"type": "block_actions", "actions": [{"action_id": action_id, "value": "x"}]}
    )


def test_list_pending_hunts_reads_only_frontmatter_status(tmp_path: Path):
    _write_hunt(tmp_path, "H-0002")
    _write_hunt(tmp_path, "H-0001")
    _write_hunt(tmp_path, "H-0003", status="active")

    pending = list_pending_hunts(tmp_path)

    assert [h["hunt_id"] for h in pending] == ["H-0001", "H-0002"]
    assert pending[0]["techniques"] == ["T1190", "T1059.006"]
    assert pending[0]["research_id"] == "R-0975"


def test_review_hunt_approve_records_reviewer_and_keeps_body(tmp_path: Path):
    path = _write_hunt(tmp_path, "H-0001")

    res = review_hunt(tmp_path, "H-0001", approve=True, reviewer="slack:U1 (alice)")

    assert res["ok"] is True
    fm = _frontmatter(path)
    assert fm["status"] == "active"
    assert fm["review_decision"] == "approved"
    assert fm["reviewed_by"] == "slack:U1 (alice)"
    assert fm["techniques"] == ["T1190", "T1059.006"]
    assert "status: experimental" in path.read_text(encoding="utf-8")


def test_approving_a_rendered_draft_removes_its_draft_markers(tmp_path: Path, sample_hypothesis):
    """H-0021 was approved and published still titled and headed "DRAFT"."""
    from datetime import UTC, datetime

    from hecate_runner.hunt_writer import DraftHuntRequest, render_draft

    req = DraftHuntRequest(
        hunt_id="H-0001",
        threat_intel="intel",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 11, 9, tzinfo=UTC),
    )
    draft = render_draft(req)
    assert "DRAFT - Automated Hunt Draft" in draft and "Do not execute queries" in draft
    hunts_dir = tmp_path / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    path = hunts_dir / "H-0001.md"
    path.write_text(draft, encoding="utf-8")

    review_hunt(tmp_path, "H-0001", approve=True, reviewer="slack:U1 (alice)")

    text = path.read_text(encoding="utf-8")
    fm = _frontmatter(path)
    assert fm["title"] == "Adversaries dump LSASS memory via comsvcs.dll MiniDump."
    assert "draft" not in fm["tags"] and "requires-human-review" not in fm["tags"]
    assert "(draft)" not in fm["hunter"]
    assert "# H-0001: Adversaries dump LSASS memory via comsvcs.dll MiniDump.\n" in text
    assert "DRAFT" not in text
    assert "Do not execute queries" not in text
    assert "- **Status:** active" in text
    assert "**Reviewed:** 20" in text and "by slack:U1 (alice)" in text


def test_rejecting_a_draft_keeps_its_draft_markers(tmp_path: Path):
    path = _write_hunt(tmp_path, "H-0001")
    review_hunt(tmp_path, "H-0001", approve=False, reviewer="slack:U1", reason="no")
    assert _frontmatter(path)["title"] == "DRAFT - H-0001 test"


def test_review_hunt_reject_stores_reason_safely(tmp_path: Path):
    path = _write_hunt(tmp_path, "H-0001")
    reason = 'Duplicate of H-0007.\nSee "notes": no new telemetry'

    res = review_hunt(tmp_path, "H-0001", approve=False, reviewer="slack:U1", reason=reason)

    assert res["status"] == "suppressed"
    fm = _frontmatter(path)
    assert fm["status"] == "suppressed"
    assert fm["review_decision"] == "rejected"
    assert fm["review_reason"] == reason
    assert "status: experimental" in path.read_text(encoding="utf-8")


def test_review_hunt_refuses_already_reviewed_hunt(tmp_path: Path):
    path = _write_hunt(tmp_path, "H-0001")
    review_hunt(tmp_path, "H-0001", approve=True, reviewer="slack:U1")
    before = path.read_text(encoding="utf-8")

    res = review_hunt(tmp_path, "H-0001", approve=False, reviewer="slack:U2", reason="late")

    assert res["ok"] is False
    assert "not awaiting review" in res["error"]
    assert path.read_text(encoding="utf-8") == before


def test_review_hunt_missing_hunt(tmp_path: Path):
    res = review_hunt(tmp_path, "H-9999", approve=True, reviewer="slack:U1")
    assert res["ok"] is False


def test_park_hunt_leaves_embedded_rule_status_alone(tmp_path: Path):
    path = _write_hunt(tmp_path, "H-0001")

    park_hunt(tmp_path, "H-0001")

    assert _frontmatter(path)["status"] == "suppressed"
    assert "status: experimental" in path.read_text(encoding="utf-8")


def test_pending_card_buttons_and_block_limit():
    hunts = [{"hunt_id": f"H-{i:04d}", "title": "t", "techniques": []} for i in range(30)]

    blocks = build_pending_hunts_card(hunts, notice="note")[0]["blocks"]

    assert len(blocks) <= 50
    actions = [b for b in blocks if b["type"] == "actions"]
    assert len(actions) == 20
    assert [e["action_id"] for e in actions[0]["elements"]] == [
        "hecate_pending_approve",
        "hecate_pending_reject",
    ]
    assert "of 30" in blocks[-1]["elements"][0]["text"]


def test_pending_card_empty_queue():
    blocks = build_pending_hunts_card([])[0]["blocks"]
    assert "(0)" in blocks[0]["text"]["text"]
    assert not [b for b in blocks if b["type"] == "actions"]


def test_slash_command_pending_lists_hunts(tmp_path: Path):
    _write_hunt(tmp_path, "H-0001")
    _, app = _service(tmp_path)
    respond = MagicMock()

    _listener(app, {"command": "/hecate", "text": "pending"}).ack_function(
        ack=MagicMock(),
        body={"command": "/hecate", "text": "pending", "user_id": "U1", "channel_id": "C1"},
        respond=respond,
    )

    blocks = respond.call_args[1]["attachments"][0]["blocks"]
    assert "Hunts Awaiting Review (1)" in blocks[0]["text"]["text"]
    assert any(b.get("block_id") == "pending_review_H-0001" for b in blocks)


def _publishing_service(workspace: Path) -> tuple[SlackBotService, App]:
    service, app = _service(workspace)
    service.settings = service.settings.model_copy(
        update={
            "github_publishing_enabled": True,
            "github_publishing_repository": "Hecate-Org/Hecate-Public",
        }
    )
    return service, app


def _approve_listener(app: App):
    return _listener(
        app,
        {
            "type": "view_submission",
            "view": {"type": "modal", "callback_id": "hecate_approve_hunt_modal"},
        },
    )


def _approval(checks: list[str], rights: str) -> dict:
    return {
        "callback_id": "hecate_approve_hunt_modal",
        "private_metadata": json.dumps(
            {"hunt_id": "H-0001", "response_url": "https://hooks.slack.test/r"}
        ),
        "state": {
            "values": {
                "release_checks": {"checks": {"selected_options": [{"value": c} for c in checks]}},
                "release_rights": {"rights": {"value": rights}},
            }
        },
    }


_RIGHTS = "MIT-licensed public repository; author credited and linked."


def test_approve_button_opens_the_release_modal_without_approving(tmp_path: Path):
    path = _write_hunt(tmp_path, "H-0001")
    _, app = _publishing_service(tmp_path)
    client = MagicMock()

    _action_listener(app, "hecate_pending_approve").ack_function(
        ack=MagicMock(),
        body={
            "actions": [{"value": "H-0001"}],
            "trigger_id": "T1",
            "response_url": "https://hooks.slack.test/r",
        },
        client=client,
    )

    view = client.views_open.call_args[1]["view"]
    assert view["callback_id"] == "hecate_approve_hunt_modal"
    assert {b.get("block_id") for b in view["blocks"]} >= {"release_checks", "release_rights"}
    assert "Hecate-Org/Hecate-Public" in view["blocks"][0]["text"]["text"]
    assert _frontmatter(path)["status"] == "planning"


def test_approve_modal_has_no_release_checks_when_publishing_is_off(tmp_path: Path):
    _write_hunt(tmp_path, "H-0001")
    _, app = _service(tmp_path)
    client = MagicMock()

    _action_listener(app, "hecate_pending_approve").ack_function(
        ack=MagicMock(), body={"actions": [{"value": "H-0001"}], "trigger_id": "T1"}, client=client
    )

    view = client.views_open.call_args[1]["view"]
    assert [b.get("block_id") for b in view["blocks"] if b["type"] == "input"] == []
    assert "Publishing is off" in view["blocks"][0]["text"]["text"]


def test_approval_without_both_release_checks_keeps_the_modal_open(tmp_path: Path):
    path = _write_hunt(tmp_path, "H-0001")
    _, app = _publishing_service(tmp_path)
    ack = MagicMock()

    with patch("hecate_runner.slack_bot.publish_reviewed_hunt") as publish:
        _approve_listener(app).ack_function(
            ack=ack,
            body={"user": {"id": "U1"}},
            view=_approval(["privacy"], "too short"),
            client=MagicMock(),
        )

    errors = ack.call_args[1]["errors"]
    assert set(errors) == {"release_checks", "release_rights"}
    assert _frontmatter(path)["status"] == "planning"
    publish.assert_not_called()


def test_approval_publishes_and_points_to_the_pull_request(tmp_path: Path):
    path = _write_hunt(tmp_path, "H-0001")
    _, app = _publishing_service(tmp_path)
    ack = MagicMock()
    published = {"ok": True, "pr_url": "https://github.test/pull/7", "pr_number": 7}

    with (
        patch("hecate_runner.slack_bot.publish_reviewed_hunt", return_value=published) as publish,
        patch("slack_sdk.webhook.WebhookClient") as webhook,
    ):
        _approve_listener(app).ack_function(
            ack=ack,
            body={"user": {"id": "U1", "username": "alice"}},
            view=_approval(["privacy", "redistribution"], _RIGHTS),
            client=MagicMock(),
        )

    ack.assert_called_once_with()
    fm = _frontmatter(path)
    assert (fm["status"], fm["review_decision"]) == ("active", "approved")
    assert publish.call_args[1] == {"reviewer": "slack:U1 (alice)", "rights_note": _RIGHTS}
    notice = webhook.return_value.send.call_args[1]["attachments"][0]["blocks"][1]["text"]["text"]
    assert "`H-0001` approved by <@U1>" in notice
    assert "<https://github.test/pull/7|PR #7>" in notice


def test_a_failed_publication_is_reported_and_leaves_the_hunt_approved(tmp_path: Path):
    path = _write_hunt(tmp_path, "H-0001")
    _, app = _publishing_service(tmp_path)

    with (
        patch(
            "hecate_runner.slack_bot.publish_reviewed_hunt",
            return_value={"ok": False, "error": "GitHub App key is missing"},
        ),
        patch("slack_sdk.webhook.WebhookClient") as webhook,
    ):
        _approve_listener(app).ack_function(
            ack=MagicMock(),
            body={"user": {"id": "U1"}},
            view=_approval(["privacy", "redistribution"], _RIGHTS),
            client=MagicMock(),
        )

    assert _frontmatter(path)["status"] == "active"
    notice = webhook.return_value.send.call_args[1]["attachments"][0]["blocks"][1]["text"]["text"]
    assert "Not published: GitHub App key is missing" in notice
    assert "hecate-runner publish H-0001" in notice


def test_the_release_sign_off_matches_the_snapshot_the_publisher_queues(tmp_path: Path):
    from hecate_runner.github_publisher import PublishResult
    from hecate_runner.public_review import require_public_review
    from hecate_runner.slack_bot import publish_reviewed_hunt

    service, _ = _publishing_service(tmp_path)
    settings = service.settings
    files = {"hunts/2026/Q4/H-0001.md": "---\nhunt_id: H-0001\n---\n"}

    def enqueue(s: Settings, hunt_id: str) -> str:
        require_public_review(s, files)
        return "queued"

    pr = PublishResult("H-0001", "d" * 64, "published", "b", 7, "https://github.test/pull/7")
    with (
        patch("hecate_runner.github_publisher._snapshot_bundle", return_value=(files, "d" * 64)),
        patch("hecate_runner.github_publisher.enqueue_hunt", side_effect=enqueue),
        patch("hecate_runner.github_publisher.sync_outbox", return_value=[pr]),
    ):
        res = publish_reviewed_hunt(settings, "H-0001", reviewer="slack:U1", rights_note=_RIGHTS)

    assert res == {"ok": True, "pr_url": "https://github.test/pull/7", "pr_number": 7}


def test_reject_button_opens_reason_modal(tmp_path: Path):
    _write_hunt(tmp_path, "H-0001")
    _, app = _service(tmp_path)
    client = MagicMock()

    _action_listener(app, "hecate_pending_reject").ack_function(
        ack=MagicMock(),
        body={
            "actions": [{"value": "H-0001"}],
            "trigger_id": "T1",
            "response_url": "https://hooks.slack.test/r",
        },
        client=client,
    )

    kwargs = client.views_open.call_args[1]
    assert kwargs["trigger_id"] == "T1"
    assert kwargs["view"]["callback_id"] == "hecate_reject_hunt_modal"
    assert json.loads(kwargs["view"]["private_metadata"]) == {
        "hunt_id": "H-0001",
        "response_url": "https://hooks.slack.test/r",
    }


def _submission(reason: str | None) -> dict:
    return {
        "callback_id": "hecate_reject_hunt_modal",
        "private_metadata": json.dumps(
            {"hunt_id": "H-0001", "response_url": "https://hooks.slack.test/r"}
        ),
        "state": {"values": {"reject_reason": {"reason": {"value": reason}}}},
    }


def test_reject_submission_suppresses_and_refreshes_list(tmp_path: Path):
    path = _write_hunt(tmp_path, "H-0001")
    _, app = _service(tmp_path)
    listener = _listener(
        app,
        {
            "type": "view_submission",
            "view": {"type": "modal", "callback_id": "hecate_reject_hunt_modal"},
        },
    )
    ack = MagicMock()

    with patch("slack_sdk.webhook.WebhookClient") as webhook:
        listener.ack_function(
            ack=ack,
            body={"user": {"id": "U2", "username": "bob"}},
            view=_submission("  Too noisy  "),
        )

    ack.assert_called_once_with()
    fm = _frontmatter(path)
    assert fm["status"] == "suppressed"
    assert fm["review_reason"] == "Too noisy"
    webhook.assert_called_once_with("https://hooks.slack.test/r")
    sent = webhook.return_value.send.call_args[1]
    assert sent["replace_original"] is True
    assert "`H-0001` rejected by <@U2>" in sent["attachments"][0]["blocks"][1]["text"]["text"]


def test_reject_submission_errors_keep_modal_open(tmp_path: Path):
    path = _write_hunt(tmp_path, "H-0001")
    _, app = _service(tmp_path)
    listener = _listener(
        app,
        {
            "type": "view_submission",
            "view": {"type": "modal", "callback_id": "hecate_reject_hunt_modal"},
        },
    )

    ack = MagicMock()
    listener.ack_function(ack=ack, body={"user": {"id": "U2"}}, view=_submission("   "))
    assert ack.call_args[1]["response_action"] == "errors"
    assert _frontmatter(path)["status"] == "planning"

    review_hunt(tmp_path, "H-0001", approve=True, reviewer="slack:U1")
    ack = MagicMock()
    listener.ack_function(ack=ack, body={"user": {"id": "U2"}}, view=_submission("late"))
    assert "not awaiting review" in ack.call_args[1]["errors"]["reject_reason"]
    assert yaml.safe_load(path.read_text(encoding="utf-8").split("---")[1])["status"] == "active"


_BLOCKING_RULE = """
title: Unauthenticated flow deploy
description: an unauthenticated client deploys a flow
logsource:
  category: webserver
  product: linux
detection:
  selection:
    cs-method: POST
    cs-uri-stem|contains: /flows
  condition: selection
"""


def test_approval_stops_on_a_blocking_publish_finding_until_overridden(tmp_path: Path):
    path = _write_hunt(tmp_path, "H-0001")
    (tmp_path / "queries" / "H-0001").mkdir(parents=True)
    (tmp_path / "queries" / "H-0001" / "deploy.yml").write_text(_BLOCKING_RULE, encoding="utf-8")

    refused = review_hunt(tmp_path, "H-0001", approve=True, reviewer="slack:U1")
    assert refused["ok"] is False and refused["needs_override"] is True
    assert _frontmatter(path)["status"] == "planning"

    approved = review_hunt(
        tmp_path,
        "H-0001",
        approve=True,
        reviewer="slack:U1",
        override="The web log has no auth field; reviewed the source procedure.",
    )
    assert approved["ok"] is True
    fm = _frontmatter(path)
    assert fm["status"] == "active"
    assert fm["publish_check"] == "block"
    assert fm["publish_override_by"] == "slack:U1"
    assert "auth field" in fm["publish_override"]


def test_pending_card_and_approve_modal_show_blocking_findings():
    from hecate_runner.slack_blocks import build_approve_hunt_modal, build_pending_hunts_card

    card = build_pending_hunts_card(
        [{"hunt_id": "H-0001", "title": "Deploy", "publish_check": "block", "publish_blocking": 2}]
    )[0]["blocks"]
    text = " ".join(
        block.get("text", {}).get("text", "")
        for block in card
        if isinstance(block.get("text"), dict)
    )
    assert "2 blocking" in text

    modal = build_approve_hunt_modal(
        "H-0001",
        "{}",
        destination=None,
        findings=[{"check": "auth_claim", "target": "deploy.yml", "message": "no auth field"}],
    )
    joined = json.dumps(modal)
    assert "publish_override" in joined
    assert "no auth field" in joined
    assert "release_checks" not in joined


def test_pending_card_and_approve_modal_show_lab_hits():
    from hecate_runner.slack_blocks import build_approve_hunt_modal, build_pending_hunts_card

    card = build_pending_hunts_card(
        [
            {
                "hunt_id": "H-0002",
                "title": "LSASS",
                "lab_probe": "miss",
                "lab_probe_provider": "sentinel",
                "lab_probe_window_days": 1,
                "lab_probe_hits": 0,
            }
        ]
    )[0]["blocks"]
    text = " ".join(
        block.get("text", {}).get("text", "")
        for block in card
        if isinstance(block.get("text"), dict)
    )
    assert "Lab hits" in text
    assert "miss" in text
    assert "sentinel" in text

    modal = build_approve_hunt_modal(
        "H-0002",
        "{}",
        destination=None,
        lab_probe={
            "status": "hit",
            "provider": "elastic",
            "window_days": 1,
            "total_hits": 4,
        },
    )
    joined = json.dumps(modal)
    assert "4 hit" in joined
    assert "elastic" in joined
