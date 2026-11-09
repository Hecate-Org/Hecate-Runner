from pathlib import Path
from unittest.mock import Mock

from typer.testing import CliRunner

from hecate_runner import cli
from hecate_runner.bas.siem_verifier import SiemAlertVerifier
from hecate_runner.config import Settings


def test_defaults_use_current_workspace_not_legacy_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    old = home / "betas/Hecate-Workspace"
    old.mkdir(parents=True)
    (old / ".env").write_text("HECATE_RUNNER_MIN_HOURS_BETWEEN_DRAFTS=91\n")
    fresh = tmp_path / "arbitrary-renamed-clone"
    fresh.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.delenv("HECATE_WORKSPACE", raising=False)
    monkeypatch.chdir(fresh)
    config = Settings()
    assert config.hecate_workspace == fresh
    assert config.min_hours_between_drafts == 6


def test_explicit_workspace_selects_its_own_dotenv(tmp_path, monkeypatch):
    selected = tmp_path / "customer-workspace"
    selected.mkdir()
    (selected / ".env").write_text("HECATE_RUNNER_MIN_HOURS_BETWEEN_DRAFTS=8\n")
    monkeypatch.chdir(tmp_path)
    config = Settings(hecate_workspace=selected)
    assert config.hecate_workspace == selected
    assert config.min_hours_between_drafts == 8


def test_runner_dedup_loads_only_selected_workspace(settings, monkeypatch):
    from hecate_agent.core.sigma_subsumption import SigmaDeduplicator

    root = settings.hecate_workspace / "queries"
    root.mkdir(exist_ok=True)
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    load = Mock(return_value=[])
    monkeypatch.setattr(SigmaDeduplicator, "load_rules_from_directory", load)
    result = CliRunner().invoke(cli.app, ["dedup", "--json"])
    assert result.exit_code == 0, result.output
    load.assert_called_once_with(root)


def test_bas_does_not_borrow_a_siblings_rules(tmp_path):
    selected = tmp_path / "selected"
    selected.mkdir()
    foreign = tmp_path / "Hecate-Public/queries/H-0001"
    foreign.mkdir(parents=True)
    (foreign / "test.spl").write_text("index=foreign")
    verifier = SiemAlertVerifier(workspace=selected)
    query, source, _ = verifier.resolve_candidate_rule("H-0001")
    assert "index=foreign" not in query
    assert str(foreign) not in source


def test_env_updates_target_selected_workspace_even_before_env_exists(
    settings, tmp_path, monkeypatch
):
    from hecate_runner.commands import sources

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / ".env").write_text("TEST=foreign\n")
    monkeypatch.chdir(elsewhere)
    monkeypatch.setattr(sources, "_get_settings", lambda: settings)
    assert sources._find_canonical_env_file() == settings.hecate_workspace / ".env"
