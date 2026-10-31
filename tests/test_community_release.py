from __future__ import annotations

import json
import zipfile

import pytest
import yaml

from hecate_runner.community_release import CatalogError, build_release, verify_catalog
from hecate_runner.config import Settings
from hecate_runner.github_publisher import PublisherError


@pytest.fixture
def catalog_root(tmp_path):
    root = tmp_path / "catalog-repo"
    (root / "catalog").mkdir(parents=True)
    (root / "detections/linux").mkdir(parents=True)
    (root / "validation").mkdir()
    case = {
        "id": "6f22dded-facc-44ab-a5e9-08690f7b0a6a",
        "slug": "user-identity",
        "rule": "detections/linux/user-identity.yml",
        "tests": "validation/user-identity.json",
        "technique": "T1033",
        "license": "MIT",
        "rights": "original_hecate_content",
        "source": "https://github.com/Hecate-Org/Hecate-Runner",
        "telemetry": ["Linux process creation events with Image"],
    }
    (root / "catalog/catalog.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "version": "0.1.0",
                "classification": "TLP:CLEAR",
                "license": "MIT",
                "cases": [case],
            }
        )
    )
    (root / case["rule"]).write_text(
        yaml.safe_dump(
            {
                "title": "Linux identity hunting",
                "id": case["id"],
                "status": "experimental",
                "tags": ["attack.t1033"],
                "logsource": {"product": "linux", "category": "process_creation"},
                "detection": {"selection": {"Image|endswith": "/whoami"}, "condition": "selection"},
                "falsepositives": ["Normal administration"],
                "level": "low",
            }
        )
    )
    (root / case["tests"]).write_text(
        json.dumps(
            {
                "schema_version": 1,
                "synthetic": True,
                "positive": [{"Image": "/usr/bin/whoami", "CommandLine": "whoami"}],
                "negative": [{"Image": "/usr/bin/printf", "CommandLine": "printf marker"}],
            }
        )
    )
    (root / "LICENSE").write_text("MIT License\nOriginal test content.\n")
    (root / "LICENSES.md").write_text("Only the original catalog files are licensed.\n")
    return root


def settings_for(root):
    return Settings(_env_file=None, hecate_workspace=root)


def test_reproducible_bundle_excludes_unlisted_private_content(catalog_root, tmp_path):
    (catalog_root / "sessions").mkdir()
    (catalog_root / "sessions/private.json").write_text('"private-secret-not-for-release"')
    first = build_release(catalog_root, tmp_path / "build-a", settings=settings_for(catalog_root))
    second = build_release(catalog_root, tmp_path / "build-b", settings=settings_for(catalog_root))
    assert first["sha256"] == second["sha256"]
    with zipfile.ZipFile(first["archive"]) as archive:
        assert not any(
            name.startswith(("sessions/", "research/", "hunts/", ".hecate/"))
            for name in archive.namelist()
        )
        assert not any(b"private-secret" in archive.read(name) for name in archive.namelist())
        index = json.loads(archive.read("index.json"))
        case = index["cases"][0]
        assert case["lab_validation"]["scope"] == "not_tested"
        assert case["fixture_validation"]["production_false_positive_rate"] == "not_measured"
        assert all(
            q.get("platform_execution") == "not_tested"
            for q in case["native_queries"].values()
            if q["status"] != "unsupported"
        )


@pytest.mark.parametrize("change", ["path", "rights", "duplicate", "fixture", "symlink"])
def test_catalog_rejects_unsafe_sources_and_failed_fixtures(catalog_root, tmp_path, change):
    path = catalog_root / "catalog/catalog.yaml"
    data = yaml.safe_load(path.read_text())
    if change == "path":
        data["cases"][0]["rule"] = "../private.yml"
    if change == "rights":
        data["cases"][0]["rights"] = "unknown"
    if change == "duplicate":
        data["cases"].append(data["cases"][0].copy())
    if change == "fixture":
        fixture = catalog_root / data["cases"][0]["tests"]
        content = json.loads(fixture.read_text())
        content["positive"][0]["Image"] = "/usr/bin/false"
        fixture.write_text(json.dumps(content))
    if change == "symlink":
        rule = catalog_root / data["cases"][0]["rule"]
        original = rule.read_text()
        rule.unlink()
        external = tmp_path / "external.yml"
        external.write_text(original)
        try:
            rule.symlink_to(external)
        except OSError:
            pytest.skip("Symlinks unavailable")
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(CatalogError):
        build_release(catalog_root, tmp_path / "refused", settings=settings_for(catalog_root))
    assert not (tmp_path / "refused").exists()


def test_duplicate_yaml_keys_and_secrets_are_rejected(catalog_root, tmp_path):
    path = catalog_root / "catalog/catalog.yaml"
    original = path.read_text()
    path.write_text(original + "license: unknown\n")
    with pytest.raises(CatalogError, match="unique"):
        build_release(catalog_root, tmp_path / "duplicate", settings=settings_for(catalog_root))
    path.write_text(original)
    (catalog_root / "LICENSES.md").write_text("ghp_" + "a" * 40)
    with pytest.raises(PublisherError, match="Credential"):
        build_release(catalog_root, tmp_path / "secret", settings=settings_for(catalog_root))
    assert not (tmp_path / "secret").exists()


def test_live_verification_records_controls_without_exporting_raw_events(
    catalog_root, tmp_path, monkeypatch
):
    calls = []

    def run(settings, hunt_id, procedure, rule):
        calls.append((hunt_id, procedure.command))
        return {
            "status": "verified_true_positive",
            "cleanup_success": True,
            "telemetry_arrived": True,
            "rule_triggered": True,
            "sensor_events_count": 1,
            "run_id": "a" * 32,
            "verified_at": "2026-10-31T00:00:00+00:00",
            "agent_image": "sha256:" + "a" * 64,
            "controller_image": "sha256:" + "b" * 64,
            "sample_matched_events": [{"Computer": "private-host", "User": "private-user"}],
        }

    monkeypatch.setattr("hecate_runner.bas.runtime.run_approved_validation", run)
    evidence = tmp_path / "evidence.json"
    verify_catalog(catalog_root, settings_for(catalog_root), evidence)
    assert calls == [("LAB-CHECK", "whoami")]
    assert "private-host" not in evidence.read_text()
    result = build_release(
        catalog_root, tmp_path / "observed", settings=settings_for(catalog_root), evidence=evidence
    )
    index = json.loads((tmp_path / "observed/index.json").read_text())
    assert index["cases"][0]["lab_validation"]["scope"] == "local_sensor_sigma"
    assert result["source_digest"] != index["catalog_digest"]
    data = json.loads(evidence.read_text())
    case = next(iter(data["cases"].values()))
    case["alert_delivery"] = "verified"
    evidence.write_text(json.dumps(data))
    with pytest.raises(CatalogError, match="scope"):
        build_release(
            catalog_root,
            tmp_path / "overclaim",
            settings=settings_for(catalog_root),
            evidence=evidence,
        )


def test_failed_live_control_stops_and_cannot_be_packaged(catalog_root, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "hecate_runner.bas.runtime.run_approved_validation", lambda *a: {"status": "error"}
    )
    evidence = tmp_path / "failed.json"
    with pytest.raises(CatalogError, match="no further"):
        verify_catalog(catalog_root, settings_for(catalog_root), evidence)
    with pytest.raises(CatalogError):
        build_release(
            catalog_root, tmp_path / "bad", settings=settings_for(catalog_root), evidence=evidence
        )
