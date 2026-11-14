"""Regression tests for fail-closed security checks, independent of the application."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "security_checks", Path(__file__).resolve().parents[1] / "scripts" / "security_checks.py"
)
assert SPEC and SPEC.loader
checks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checks)


class SecurityChecksTests(unittest.TestCase):
    def test_all_universal_lock_versions_are_audited(self):
        lock = """
[[package]]
name = "sample"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "sample"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "local-app"
source = { editable = "." }
"""
        self.assertEqual(checks.requirement_batches(lock), [["sample==1.0"], ["sample==2.0"]])

    def test_empty_lock_fails_instead_of_claiming_clean(self):
        with self.assertRaises(ValueError):
            checks.requirement_batches("package = []")

    def test_skipped_package_fails_closed(self):
        with self.assertRaises(RuntimeError):
            checks.audit_findings(
                {"dependencies": [{"name": "sample", "skip_reason": "unavailable"}]}
            )

    def test_advisory_duplicates_are_not_counted_twice(self):
        data = {
            "dependencies": [
                {"name": "sample", "version": "1", "vulns": [{"id": "ADV-1"}, {"id": "ADV-1"}]}
            ]
        }
        self.assertEqual(checks.audit_findings(data), {("sample", "1", "ADV-1")})

    def test_audit_command_failure_is_not_a_clean_result(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(checks, "run") as runner:
            runner.return_value = subprocess.CompletedProcess([], 1, "", "network failure")
            with self.assertRaises(RuntimeError):
                checks.audit(
                    '[[package]]\nname="sample"\nversion="1"\nsource={registry="index"}',
                    Path(tmp),
                    "check",
                )

    def test_secret_exception_is_bound_to_file_type_and_hash(self):
        baseline = {"results": {"fixture.py": [{"type": "Secret Keyword", "hashed_secret": "old"}]}}
        scanned = {
            "results": {
                "fixture.py": [{"type": "Secret Keyword", "hashed_secret": "new"}],
                "production.py": [{"type": "Secret Keyword", "hashed_secret": "old"}],
            }
        }
        self.assertEqual(
            len(checks.secret_fingerprints(scanned) - checks.secret_fingerprints(baseline)), 2
        )

    def test_pr_cannot_authorize_a_secret_through_its_own_baseline(self):
        original = {"results": {}}
        candidate = {
            "results": {"production.py": [{"type": "Secret Keyword", "hashed_secret": "new"}]}
        }
        result = subprocess.CompletedProcess([], 0, json.dumps(candidate), "")
        with (
            patch.object(checks, "run", return_value=result),
            patch.object(checks, "base_file", return_value=json.dumps(original)),
        ):
            self.assertEqual(checks.secrets("base"), 1)

    def test_dependency_regression_fails_and_existing_debt_remains_visible(self):
        previous = {("sample", "1", "ADV-1")}
        current = previous | {("sample", "2", "ADV-1")}
        with (
            patch.object(checks.Path, "read_text", return_value="current lock"),
            patch.object(checks.Path, "write_text") as write,
            patch.object(checks, "base_file", return_value="previous lock"),
            patch.object(checks, "audit", side_effect=[current, previous]),
            patch.dict(checks.os.environ, {"GITHUB_STEP_SUMMARY": ""}),
        ):
            self.assertEqual(checks.dependencies("base"), 1)
            report = json.loads(write.call_args.args[0])
            self.assertEqual(len(report["all_findings"]), 2)
            self.assertEqual(report["blocking_findings"], [["sample", "2", "ADV-1"]])

    def test_scheduled_audit_blocks_existing_advisories(self):
        with (
            patch.object(checks.Path, "read_text", return_value="current lock"),
            patch.object(checks.Path, "write_text"),
            patch.object(checks, "base_file", return_value=None),
            patch.object(checks, "audit", return_value={("sample", "1", "ADV-1")}),
            patch.dict(checks.os.environ, {"GITHUB_STEP_SUMMARY": ""}),
        ):
            self.assertEqual(checks.dependencies(""), 1)


if __name__ == "__main__":
    unittest.main()
