"""Dedicated service configuration must reject privilege and credential mixing."""

import importlib.util
from pathlib import Path

import pytest

from hecate_runner.config import Settings

SPEC = importlib.util.spec_from_file_location(
    "service_installer",
    Path(__file__).resolve().parents[1] / "scripts/install-isolated-services.py",
)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def write_env(path, values):
    path.write_text("\n".join(f"{key}={value}" for key, value in values.items()) + "\n")
    path.chmod(0o600)


@pytest.mark.parametrize(
    "key",
    [
        "SPLUNK_TOKEN",
        "SPLUNK_WRITE_TOKEN",
        "GITHUB_TOKEN",
        "PYTHONPATH",
        "LD_PRELOAD",
        "HECATE_WORKSPACE",
        "HECATE_BAS_BROKER_SOCKET",
    ],
)
def test_reader_environment_cannot_override_isolation_or_import_writer_credentials(tmp_path, key):
    path = tmp_path / "reader.env"
    write_env(path, {key: "-".join(["test", "fixture"])})
    with pytest.raises(ValueError):
        installer.read_environment(path, "reader")


def test_credential_files_must_not_be_group_or_world_readable(tmp_path):
    path = tmp_path / "reader.env"
    write_env(path, {"SPLUNK_READ_TOKEN": "-".join(["reader", "fixture"])})
    path.chmod(0o644)
    with pytest.raises(ValueError):
        installer.read_environment(path, "reader")


def test_distinct_splunk_credentials_are_required(tmp_path):
    for role in installer.ROLES:
        write_env(tmp_path / f"{role}.env", {"SPLUNK_HOST": "https://localhost:8089"})
    with pytest.raises(ValueError, match="distinct"):
        installer.validate_environments(tmp_path)
    write_env(
        tmp_path / "reader.env",
        {"SPLUNK_HOST": "https://localhost:8089", "SPLUNK_READ_TOKEN": "r" * 25},
    )
    write_env(
        tmp_path / "writer.env",
        {"SPLUNK_HOST": "https://localhost:8089", "SPLUNK_WRITE_TOKEN": "w" * 25},
    )
    assert installer.validate_environments(tmp_path)["reader"]["SPLUNK_READ_TOKEN"] == "r" * 25


def test_isolated_settings_ignore_a_workspace_dotenv(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("HECATE_RUNNER_MIN_HOURS_BETWEEN_DRAFTS=91\n")
    monkeypatch.setenv("HECATE_SERVICE_ISOLATED", "1")
    assert Settings(hecate_workspace=tmp_path).min_hours_between_drafts != 91


@pytest.mark.parametrize("path", ["/tmp/with space", "/tmp/%n", "/tmp/$HOME", "/tmp/line\nbreak"])
def test_paths_cannot_inject_systemd_specifiers_or_commands(path):
    with pytest.raises(ValueError):
        installer.systemd_path(Path(path))


def test_runtime_relocation_does_not_retain_operator_home_paths(tmp_path, monkeypatch):
    stage = tmp_path / "stage"
    binary = stage / "venv/bin/command"
    binary.parent.mkdir(parents=True)
    binary.write_text(f"#!{stage}/venv/bin/python\n")
    cfg = stage / "venv/pyvenv.cfg"
    cfg.write_text(f"home = {stage}/python/bin\n")
    monkeypatch.setattr(installer.os, "chown", lambda *args, **kwargs: None)
    release = tmp_path / "installed"
    installer.prepare_runtime(stage, release)
    assert str(stage) not in (release / "venv/bin/command").read_text()
    assert str(release) in (release / "venv/pyvenv.cfg").read_text()


def test_runtime_cannot_link_back_to_private_operator_files(tmp_path, monkeypatch):
    stage = tmp_path / "stage"
    stage.mkdir()
    outside = tmp_path / "private"
    outside.write_text("private fixture")
    try:
        (stage / "bad-link").symlink_to(outside)
    except OSError:
        pytest.skip("Symlinks unavailable")
    monkeypatch.setattr(installer.os, "chown", lambda *args, **kwargs: None)
    with pytest.raises(ValueError, match="symlink"):
        installer.prepare_runtime(stage, tmp_path / "installed")


def test_service_units_use_dedicated_accounts_and_protect_host_code():
    root = Path(__file__).resolve().parents[1] / "systemd"
    for name, role in zip(installer.UNITS, (*installer.ROLES, "bas"), strict=True):
        text = (root / f"{name}.service").read_text()
        assert f"User=hecate-{role}" in text
        assert "User=chemch" not in text
        assert "NoNewPrivileges=true" in text
        assert "ProtectSystem=strict" in text
        assert "ProtectHome=true" in text
        assert "CapabilityBoundingSet=\n" in text
        if role != "bas":
            assert "HECATE_SERVICE_ISOLATED=1" in text
            assert "HECATE_STRICT_CREDENTIAL_ROLES=1" in text
            assert "ReadWritePaths=/home" not in text
