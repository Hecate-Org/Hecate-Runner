"""Build reviewed, reproducible detection packs without exporting a workspace.

Only an explicit original-content catalog is accepted. Builds are local and
private; publication is a separate operator action on an exact source digest.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import inspect
import json
import re
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID

import yaml
from hecate_agent.core.sigma_evaluator import SigmaEvaluator
from hecate_agent.core.sigma_transpiler import SigmaTranspiler
from sigma.collection import SigmaCollection

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.bas.approved import APPROVED_PROCEDURES
from hecate_runner.config import Settings
from hecate_runner.github_publisher import _validate_public_bundle


class CatalogError(ValueError):
    """A catalog cannot truthfully or safely become a community release."""


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueLoader, node: yaml.MappingNode) -> dict[str, Any]:
    pairs = loader.construct_pairs(node)
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise CatalogError("YAML keys must be unique strings")
        result[key] = value
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _read(root: Path, name: str) -> str:
    relative = PurePosixPath(name)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or "\\" in name
        or str(relative) != name
        or not relative.parts
    ):
        raise CatalogError("Catalog contains an unsafe path")
    path = root / name
    for candidate in (path, *path.parents):
        if candidate == root:
            break
        if candidate.is_symlink():
            raise CatalogError("Catalog files and directories must not be symlinks")
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise CatalogError(f"Missing regular catalog file: {name}")
    raw = path.read_bytes()
    if len(raw) > 1_000_000 or b"\0" in raw:
        raise CatalogError(f"Catalog file is too large or not text: {name}")
    return raw.decode("utf-8")


def _digest(files: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for name, value in sorted(files.items()):
        digest.update(name.encode() + b"\0" + value.encode() + b"\0")
    return digest.hexdigest()


def load_catalog(root: Path) -> tuple[dict[str, Any], dict[str, str]]:
    """Read only listed rules/fixtures; never sweep hunts, sessions, or research."""
    files = {name: _read(root, name) for name in ("catalog/catalog.yaml", "LICENSE", "LICENSES.md")}
    catalog = yaml.load(files["catalog/catalog.yaml"], Loader=_UniqueLoader)
    if (
        not isinstance(catalog, dict)
        or catalog.get("schema_version") != 1
        or not re.fullmatch(r"\d+\.\d+\.\d+", str(catalog.get("version", "")))
        or catalog.get("classification") != "TLP:CLEAR"
        or catalog.get("license") != "MIT"
        or set(catalog) != {"schema_version", "version", "classification", "license", "cases"}
        or not isinstance(catalog.get("cases"), list)
        or not 1 <= len(catalog["cases"]) <= 25
    ):
        raise CatalogError("Unsupported original-content catalog schema")
    ids: set[str] = set()
    slugs: set[str] = set()
    required = {
        "id",
        "slug",
        "rule",
        "tests",
        "technique",
        "license",
        "rights",
        "source",
        "telemetry",
    }
    for case in catalog["cases"]:
        if not isinstance(case, dict) or set(case) != required:
            raise CatalogError("Case fields must match the catalog schema")
        UUID(case["id"])
        slug = case["slug"]
        if not isinstance(slug, str) or not re.fullmatch(r"[a-z][a-z0-9-]{2,60}", slug):
            raise CatalogError("Case slug must be a safe lowercase identifier")
        if case["id"] in ids or slug in slugs:
            raise CatalogError("Case IDs and slugs must be unique")
        ids.add(case["id"])
        slugs.add(slug)
        if (
            case["license"] != "MIT"
            or case["rights"] != "original_hecate_content"
            or not str(case["source"]).startswith("https://github.com/Hecate-Org/")
            or case["technique"] not in APPROVED_PROCEDURES
            or not isinstance(case["telemetry"], list)
            or not case["telemetry"]
        ):
            raise CatalogError(
                "Original source rights, telemetry, and a pinned procedure are required"
            )
        procedure = APPROVED_PROCEDURES[case["technique"]]
        if procedure.expected_files or procedure.cleanup_command:
            raise CatalogError("This catalog version permits only existing read-only BAS controls")
        expected = {"rule": f"detections/linux/{slug}.yml", "tests": f"validation/{slug}.json"}
        for field, name in expected.items():
            if case[field] != name:
                raise CatalogError("Rules and fixtures must use their dedicated catalog paths")
            files[name] = _read(root, name)
    return catalog, files


def _check_case(case: dict[str, Any], files: dict[str, str]) -> dict[str, Any]:
    text = files[case["rule"]]
    rule = yaml.load(text, Loader=_UniqueLoader)
    if (
        not isinstance(rule, dict)
        or rule.get("id") != case["id"]
        or rule.get("status") != "experimental"
        or rule.get("logsource") != {"product": "linux", "category": "process_creation"}
        or f"attack.{case['technique'].lower()}" not in rule.get("tags", [])
        or not rule.get("falsepositives")
    ):
        raise CatalogError("Initial catalog rules must be experimental Linux process hunting rules")
    SigmaCollection.from_yaml(text)
    fixtures = json.loads(files[case["tests"]])
    if (
        set(fixtures) != {"schema_version", "synthetic", "positive", "negative"}
        or fixtures["schema_version"] != 1
        or fixtures["synthetic"] is not True
        or any(
            not isinstance(fixtures[k], list) or not 1 <= len(fixtures[k]) <= 50
            for k in ("positive", "negative")
        )
    ):
        raise CatalogError("Synthetic positive and negative fixture sets are required")
    for expected, events in ((True, fixtures["positive"]), (False, fixtures["negative"])):
        for event in events:
            if not isinstance(event, dict) or set(event) - {
                "data_source",
                "product",
                "Image",
                "CommandLine",
            }:
                raise CatalogError("Fixtures may contain only public process fields")
            matched = SigmaEvaluator.evaluate_rule(text, [event], []).true_positives > 0
            if matched != expected:
                raise CatalogError(
                    f"{case['slug']}: {'positive' if expected else 'negative'} fixture failed"
                )
    return {
        "positive_cases": len(fixtures["positive"]),
        "negative_cases": len(fixtures["negative"]),
        "scope": "synthetic_rule_matching",
        "production_false_positive_rate": "not_measured",
    }


def verify_catalog(root: Path, settings: Settings, output: Path) -> dict[str, Any]:
    """Use only existing fixed lab procedures; leave controls distinct from hunts."""
    from hecate_runner.bas.runtime import run_approved_validation

    catalog, files = load_catalog(root)
    report: dict[str, Any] = {"schema_version": 1, "catalog_digest": _digest(files), "cases": {}}
    for case in catalog["cases"]:
        _check_case(case, files)
        procedure = APPROVED_PROCEDURES[case["technique"]]
        if procedure.expected_files or procedure.cleanup_command:
            raise CatalogError(
                "Initial release validation permits only the existing read-only controls"
            )
        result = run_approved_validation(settings, "LAB-CHECK", procedure, files[case["rule"]])
        success = (
            result.get("status") == "verified_true_positive"
            and result.get("cleanup_success") is True
            and result.get("telemetry_arrived") is True
            and result.get("rule_triggered") is True
            and int(result.get("sensor_events_count", 0)) > 0
        )
        report["cases"][case["id"]] = {
            "status": "observed_local_match" if success else "failed",
            "scope": "local_sensor_sigma",
            "purpose": "catalog_sensor_control",
            "procedure_id": procedure.ability_id,
            "technique": procedure.technique_id,
            "rule_sha256": hashlib.sha256(files[case["rule"]].encode()).hexdigest(),
            "observed_events": int(result.get("sensor_events_count", 0)),
            "cleanup_confirmed": result.get("cleanup_success") is True,
            "verified_at": result.get("verified_at"),
            "evidence_run_id": result.get("run_id"),
            "agent_image": result.get("agent_image"),
            "controller_image": result.get("controller_image"),
            "siem_ingestion": "not_tested",
            "alert_delivery": "not_tested",
        }
        atomic_write_text(output, json.dumps(report, indent=2), mode=0o600)
        if not success:
            raise CatalogError(f"{case['slug']}: lab validation failed; no further case was run")
    return report


def build_release(
    root: Path, output: Path, *, settings: Settings, evidence: Path | None = None
) -> dict[str, Any]:
    """Build a deterministic archive and index in a fresh private output folder."""
    root = root.resolve()
    output = output.absolute()
    catalog, files = load_catalog(root)
    catalog_digest = _digest(files)
    if output.exists():
        raise CatalogError("Use a new output directory; existing files are never overwritten")
    if (
        output.resolve().is_relative_to(root.resolve())
        and ".hecate" not in output.relative_to(root).parts
    ):
        raise CatalogError(
            "Build outside the public checkout, or inside its ignored .hecate directory"
        )
    observed: dict[str, Any] = {}
    release_inputs = dict(files)
    if evidence:
        evidence_text = evidence.read_text()
        if len(evidence_text.encode()) > 1_000_000:
            raise CatalogError("Evidence report exceeds the release size limit")
        report = json.loads(evidence_text)
        if (
            set(report) != {"schema_version", "catalog_digest", "cases"}
            or report.get("schema_version") != 1
            or report.get("catalog_digest") != catalog_digest
        ):
            raise CatalogError("Lab evidence is for a different catalog snapshot")
        observed = report["cases"]
        if set(observed) != {c["id"] for c in catalog["cases"]}:
            raise CatalogError("Lab evidence must cover exactly the catalog cases")
        release_inputs["catalog/evidence.json"] = evidence_text
    source_digest = _digest(release_inputs)
    artifacts = {name: files[name] for name in ("LICENSE", "LICENSES.md")}
    entries = []
    for case in catalog["cases"]:
        checks = _check_case(case, files)
        slug = case["slug"]
        artifacts[case["rule"]] = files[case["rule"]]
        artifacts[case["tests"]] = files[case["tests"]]
        lab: dict[str, Any] = {
            "scope": "not_tested",
            "siem_ingestion": "not_tested",
            "alert_delivery": "not_tested",
        }
        if observed:
            candidate = observed[case["id"]]
            expected_keys = {
                "status",
                "scope",
                "purpose",
                "procedure_id",
                "technique",
                "rule_sha256",
                "observed_events",
                "cleanup_confirmed",
                "verified_at",
                "evidence_run_id",
                "agent_image",
                "controller_image",
                "siem_ingestion",
                "alert_delivery",
            }
            if (
                set(candidate) != expected_keys
                or candidate["status"] != "observed_local_match"
                or candidate["scope"] != "local_sensor_sigma"
                or candidate["purpose"] != "catalog_sensor_control"
                or candidate["procedure_id"] != APPROVED_PROCEDURES[case["technique"]].ability_id
                or candidate["rule_sha256"]
                != hashlib.sha256(files[case["rule"]].encode()).hexdigest()
                or candidate["cleanup_confirmed"] is not True
                or int(candidate["observed_events"]) < 1
                or candidate["siem_ingestion"] != "not_tested"
                or candidate["alert_delivery"] != "not_tested"
            ):
                raise CatalogError("Lab evidence cannot substantiate this rule and scope")
            lab = candidate
        native = {}
        for target, result in SigmaTranspiler().transpile(files[case["rule"]]).items():
            if result.success and result.query:
                name = f"queries/{slug}/{target}{result.file_extension}"
                artifacts[name] = result.query + "\n"
                native[target] = {
                    "status": "syntax_checked_template",
                    "path": name,
                    "platform_execution": "not_tested",
                }
            else:
                native[target] = {"status": "unsupported", "reason": result.error_message}
        entries.append(
            {
                "id": case["id"],
                "slug": slug,
                "title": yaml.safe_load(files[case["rule"]])["title"],
                "status": "experimental",
                "license": case["license"],
                "source": case["source"],
                "technique": case["technique"],
                "bas_control": {
                    "procedure_id": APPROVED_PROCEDURES[case["technique"]].ability_id,
                    "fixed_command": APPROVED_PROCEDURES[case["technique"]].command,
                    "observed_argv": list(APPROVED_PROCEDURES[case["technique"]].argv),
                    "target": "dedicated isolated Linux lab only",
                },
                "rule": case["rule"],
                "fixtures": case["tests"],
                "telemetry_requirements": case["telemetry"],
                "fixture_validation": checks,
                "lab_validation": lab,
                "native_queries": native,
            }
        )
    index = {
        "schema_version": 1,
        "version": catalog["version"],
        "classification": "TLP:CLEAR",
        "source_digest": source_digest,
        "catalog_digest": catalog_digest,
        "license": "MIT",
        "cases": entries,
    }
    artifacts["index.json"] = json.dumps(index, indent=2, sort_keys=True) + "\n"
    artifacts["README.md"] = (
        "# Hecate experimental Linux hunting pack\n\n"
        "These rules match behaviors also used by administrators and normal software.\n"
        "Review index.json for telemetry requirements, false-positive guidance in each rule,\n"
        "and exact validation scope. Synthetic fixtures are not independent observations.\n"
        "Local lab matches do not establish SIEM ingestion, alert delivery, or malicious intent.\n"
        "Native queries are syntax-checked templates requiring your field mappings and platform tests.\n"
        "Use bounded time ranges and count-first queries before retrieving environment events.\n"
        "No persistence, credential access, payload download, or external traffic is required.\n"
    )
    _validate_public_bundle(settings, artifacts)
    manifest = {
        "schema_version": 1,
        "source_digest": source_digest,
        "version": catalog["version"],
        "files": {
            name: hashlib.sha256(content.encode()).hexdigest()
            for name, content in sorted(artifacts.items())
        },
        "toolchain": {
            name: importlib.metadata.version(name)
            for name in ("hecate-agent", "hecate-runner", "pysigma")
        },
        "toolchain_source_sha256": {
            name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
            for name, path in (
                ("release_builder", __file__),
                ("sigma_transpiler", inspect.getfile(SigmaTranspiler)),
                ("sigma_evaluator", inspect.getfile(SigmaEvaluator)),
            )
        },
    }
    artifacts["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    output.mkdir(parents=True, mode=0o700)
    for name, content in artifacts.items():
        atomic_write_text(output / name, content, mode=0o600)
    archive = output / f"hecate-linux-{catalog['version']}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, content in sorted(artifacts.items()):
            item = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            item.external_attr = 0o100644 << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(item, content.encode())
    archive.chmod(0o600)
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    atomic_write_text(output / "SHA256SUMS", f"{checksum}  {archive.name}\n", mode=0o600)
    return {
        "source_digest": source_digest,
        "archive": str(archive),
        "sha256": checksum,
        "cases": len(entries),
    }
