from __future__ import annotations

from typer.testing import CliRunner

from hecate_runner import cli
from hecate_runner.metrics import MetricsStore


def test_ops_digest_can_render_real_metric_store_without_posting(settings, monkeypatch):
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    monkeypatch.setattr(
        "hecate_runner.commands.slack.notify_ops_metrics",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("Offline digest posted to Slack")),
    )
    assert MetricsStore(settings.metrics_file).summary()["completed_cycles"] == 0
    result = CliRunner().invoke(cli.app, ["ops-digest", "--no-post"])
    assert result.exit_code == 0, result.output
    assert "Total Pipeline Cycles" in result.output
