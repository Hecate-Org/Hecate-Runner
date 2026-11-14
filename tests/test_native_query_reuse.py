"""Generation, artifact checks and deployment must share real conversions."""

from __future__ import annotations

from collections import Counter
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from hecate_agent import api
from hecate_agent.agents.llm.sigma_generator import SigmaGenerationOutput, SigmaRule
from hecate_agent.core import sigma_transpiler as st

from hecate_runner.native_queries import transpile_and_write_native, write_query_if_changed
from hecate_runner.orchestrator import Orchestrator

RULE = """title: Suspicious Process Execution
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: selection
"""


@pytest.fixture
def conversions(monkeypatch):
    if not st.PYSIGMA_AVAILABLE:
        pytest.skip("Real backend conversion requires pySigma backends")
    st.SigmaTranspiler.clear_cache()
    calls = Counter()
    original = st.SigmaTranspiler._transpile_single_target

    def convert(self, rule_yaml, target):
        calls[target] += 1
        return original(self, rule_yaml, target)

    monkeypatch.setattr(st.SigmaTranspiler, "_transpile_single_target", convert)
    yield calls
    st.SigmaTranspiler.clear_cache()


def test_core_generation_runner_materialization_and_deployment_convert_once(
    tmp_path, monkeypatch, conversions
):
    output = SigmaGenerationOutput(
        logsources_considered=["process_creation"],
        rules=[
            SigmaRule(
                logsource_category="process_creation", title="Process execution", rule_yaml=RULE
            )
        ],
    )
    result = SimpleNamespace(success=True, data=output, metadata={}, error=None, warnings=[])
    monkeypatch.setattr(
        api, "SigmaGeneratorAgent", lambda **kwargs: SimpleNamespace(execute=lambda payload: result)
    )
    _, files, metadata = api.generate_sigma_with_metrics(
        {"hypothesis": "A loader executes cmd.exe"}, out_dir=tmp_path, hunt_id="H-0001"
    )
    assert metadata["success"]
    rule_path = files[0]
    natives = [file for file in files if file.suffix not in {".yml", ".yaml"}]
    assert len(natives) == len(st.SigmaTranspiler.SUPPORTED_TARGETS)
    before = {file: (file.stat().st_ino, file.stat().st_mtime_ns) for file in natives}
    transpile_and_write_native(rule_path, RULE)
    deploy = Mock(return_value={"target": "test", "status": "dry_run"})
    monkeypatch.setattr(api, "deploy_transpiled_query", deploy)
    engine = SimpleNamespace(settings=SimpleNamespace(siem_deploy_dry_run=True), trail=Mock())
    req = SimpleNamespace(hunt_id="H-0001")
    Orchestrator._deploy_native_queries(engine, req, [{"rule_yaml": RULE}], tmp_path)
    assert deploy.call_count == len(natives)
    assert all(call.kwargs["dry_run"] for call in deploy.call_args_list)
    assert conversions == Counter({target: 1 for target in st.SigmaTranspiler.SUPPORTED_TARGETS})
    assert {file: (file.stat().st_ino, file.stat().st_mtime_ns) for file in natives} == before

    # A tuned rule must replace native content and deploy the new query, while
    # the final artifact/deployment passes still share this second conversion.
    changed = RULE.replace("cmd.exe", "powershell.exe")
    transpile_and_write_native(rule_path, changed)
    Orchestrator._deploy_native_queries(engine, req, [{"rule_yaml": changed}], tmp_path)
    assert all(
        "powershell" in call.kwargs["query"] for call in deploy.call_args_list[len(natives) :]
    )
    assert conversions == Counter({target: 2 for target in st.SigmaTranspiler.SUPPORTED_TARGETS})


def test_missing_and_modified_native_files_are_repaired_without_reconversion(tmp_path, conversions):
    rule_path = tmp_path / "rule.yml"
    results = transpile_and_write_native(rule_path, RULE)
    paths = [
        rule_path.with_suffix(result.file_extension)
        for result in results.values()
        if result.success
    ]
    expected = {path: path.read_text() for path in paths}
    paths[0].unlink()
    paths[1].write_text("manually changed query\n")
    transpile_and_write_native(rule_path, RULE)
    assert {path: path.read_text() for path in paths} == expected
    assert all(count == 1 for count in conversions.values())


def test_older_core_writer_fallback_preserves_unchanged_files(tmp_path, monkeypatch):
    monkeypatch.delattr(st, "write_query_if_changed")
    path = tmp_path / "query.spl"
    assert write_query_if_changed(path, "index=test")
    before = path.stat()
    assert not write_query_if_changed(path, "index=test\n")
    assert (path.stat().st_ino, path.stat().st_mtime_ns) == (before.st_ino, before.st_mtime_ns)


def test_deploy_reuses_cached_transpile_without_reconversion(tmp_path, monkeypatch, conversions):
    rule_path = tmp_path / "rule.yml"
    cached = transpile_and_write_native(rule_path, RULE)
    before = dict(conversions)
    deploy = Mock(return_value={"target": "test", "status": "dry_run"})
    monkeypatch.setattr(api, "deploy_transpiled_query", deploy)
    engine = SimpleNamespace(settings=SimpleNamespace(siem_deploy_dry_run=True), trail=Mock())
    req = SimpleNamespace(hunt_id="H-0001")
    Orchestrator._deploy_native_queries(
        engine, req, [{"rule_yaml": RULE, "_transpile": cached}], tmp_path
    )
    assert deploy.call_count == len(
        [r for r in cached.values() if getattr(r, "success", False) and getattr(r, "query", None)]
    )
    assert conversions == before
