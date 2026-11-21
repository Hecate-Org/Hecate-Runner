"""Runtime replacement keeps a recoverable selection and requires root."""

import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "runtime_updater", Path(__file__).resolve().parents[1] / "scripts/update-service-runtime.py"
)
updater = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updater)


def test_runtime_selection_is_atomic_and_can_restore_the_previous_release(tmp_path):
    previous = tmp_path / "old"
    candidate = tmp_path / "new"
    previous.mkdir()
    candidate.mkdir()
    current = tmp_path / "runtime"
    current.symlink_to(previous)
    updater.select_runtime(current, candidate)
    assert current.resolve() == candidate
    updater.select_runtime(current, previous)
    assert current.resolve() == previous
    assert not list(tmp_path.glob(".runtime-update-*"))


def test_failed_swap_preserves_the_running_selection(tmp_path, monkeypatch):
    previous = tmp_path / "old"
    previous.mkdir()
    current = tmp_path / "runtime"
    current.symlink_to(previous)

    def fail_replace(*args):
        raise OSError("fixture swap failure")

    monkeypatch.setattr(updater.os, "replace", fail_replace)
    with pytest.raises(OSError):
        updater.select_runtime(current, tmp_path / "new")
    assert current.resolve() == previous
    assert not list(tmp_path.glob(".runtime-update-*"))


def test_unprivileged_updates_stop_before_host_mutations(tmp_path, monkeypatch):
    monkeypatch.setattr(updater.os, "geteuid", lambda: 1000)
    with pytest.raises(PermissionError, match="sudo"):
        updater.update(tmp_path)


def test_canaries_use_actual_shared_reference_setting_without_credentials(tmp_path, monkeypatch):
    import subprocess

    calls = []

    def command(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="123\n")

    original = Path.read_bytes

    def environ(path):
        if path == Path("/proc/123/environ"):
            return (
                b"HOME=/private/reader\0HECATE_WORKSPACE=/workspace\0"
                b"HECATE_STIX_CACHE=/reference/attack\0OPENAI_API_KEY=must-not-copy\0"
            )
        return original(path)

    monkeypatch.setattr(updater.installer, "command", command)
    monkeypatch.setattr(Path, "read_bytes", environ)
    updater.check_service_canaries("hecate-runner-daemon", "reader", tmp_path)
    args, options = calls[-1]
    assert args[:4] == ("/usr/bin/nsenter", "--target", "123", "--mount")
    assert "hecate-reader" in args
    assert options["env"]["HECATE_STIX_CACHE"] == "/reference/attack"
    assert "OPENAI_API_KEY" not in options["env"]
    assert "must-not-copy" not in repr(calls)


def test_canaries_reject_missing_live_service_before_entering_namespace(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.setattr(
        updater.installer,
        "command",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="0\n"),
    )
    with pytest.raises(ValueError, match="No live process"):
        updater.check_service_canaries("hecate-runner-daemon", "reader", tmp_path)
