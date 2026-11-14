"""The source deadline must stop real workers, including during classification."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest
from hecate_agent.core.provenance import IndicatorRecord
from hecate_agent.core.source_evidence import SourceArtifact, SourceEvidence

from hecate_runner.hecate_client import HecateClient, HecateError
from hecate_runner.source_evidence_worker import collect

URL = "https://report.example/article"


def test_collect_includes_classification_usage(monkeypatch, settings):
    evidence = SourceEvidence(
        url=URL, text="cmd.exe", artifacts=[SourceArtifact("cmd.exe", "process")]
    )
    record = IndicatorRecord(value="example.org", type="domain", role="c2", source=URL)
    extract = Mock(return_value=evidence)

    def classify(indicators, source, *, session):
        assert indicators == {"domain": ["example.org"]}
        assert source is evidence
        assert session is extract.call_args.kwargs["session"]
        source.usage["llm_calls"] = 2
        return [record]

    monkeypatch.setattr("hecate_agent.core.source_evidence.extract_source_evidence", extract)
    monkeypatch.setattr("hecate_agent.core.source_evidence.build_indicator_records", classify)
    monkeypatch.setattr("hecate_agent.core.workspace.load_workspace_env", lambda: None)
    payload = collect(URL, {"domain": ["example.org"]})
    assert extract.call_args.args == (URL,)
    assert "session" in extract.call_args.kwargs
    assert payload["evidence"]["usage"]["llm_calls"] == 2
    assert payload["records"][0]["value"] == record.value


def test_cache_survives_worker_restarts(tmp_path):
    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir()
    (bootstrap / "sitecustomize.py").write_text("""
import json
import os
from pathlib import Path
from hecate_agent.core import llm_provider, source_evidence

class Provider:
    provider_name = "fake"
    model = "test-v1"

    def complete(self, messages, **kwargs):
        with Path(os.environ["TEST_CALLS"]).open("a") as stream:
            stream.write("call\\n")
        reply = json.dumps({"artifacts": [{"value": "cmd.exe", "kind": "process"}]})
        return llm_provider.LLMResponse(reply, 100, 20, self.model, 1, 0.0)

from hecate_agent.core import llm_router
llm_router.create_router = lambda: Provider()
source_evidence.fetch_page_text = lambda url: "The malware launches cmd.exe."
""")
    calls = tmp_path / "calls.txt"
    client = HecateClient(
        hecate_bin=Path(sys.executable),
        workspace=tmp_path,
        env_overrides={
            "PYTHONPATH": os.pathsep.join(
                filter(None, [str(bootstrap), os.environ.get("PYTHONPATH")])
            ),
            "TEST_CALLS": str(calls),
            "HECATE_RUNNER_SOURCE_EVIDENCE_CACHE_ENABLED": "true",
            "HECATE_RUNNER_SOURCE_EVIDENCE_MAX_CALLS": "1",
        },
    )
    first, _ = client.source_evidence_with_indicators(URL, {}, timeout_sec=10)
    second, _ = client.source_evidence_with_indicators(URL, {}, timeout_sec=10)
    assert first.artifacts == second.artifacts
    assert calls.read_text().splitlines() == ["call"]
    assert second.extraction_metrics["cache_hits"] == 1
    assert second.usage_metadata()["llm_calls"] == 0
    assert (tmp_path / ".hecate" / "source_evidence.db").is_file()


@pytest.fixture
def isolated_client(tmp_path):
    # Patch only the child interpreter, so the actual worker, stdin protocol,
    # environment inheritance and process cleanup run without network access.
    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir()
    (bootstrap / "sitecustomize.py").write_text("""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from hecate_agent.core import source_evidence as source
from hecate_agent.core.provenance import IndicatorRecord

def block(stage):
    if os.environ.get("TEST_BLOCK_STAGE") != stage:
        return
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    Path(os.environ["TEST_MARKER"]).write_text(json.dumps([os.getpid(), child.pid]))
    time.sleep(60)

def extract(url, **kwargs):
    block("extraction")
    print("provider diagnostic on stdout")
    assert os.environ["HECATE_WORKSPACE"] == os.getcwd()
    assert os.environ["TEST_MODEL_SETTING"] == "inherited"
    return source.SourceEvidence(url=url, text="cmd.exe", artifacts=[source.SourceArtifact("cmd.exe", "process")], indicators=[IndicatorRecord(value="example.org", type="domain", source=url)], usage={"llm_calls": 1})

def classify(indicators, evidence, **kwargs):
    block("classification")
    evidence.usage["llm_calls"] += 1
    return [IndicatorRecord(value=indicators["domain"][0], type="domain", source=evidence.url)]

source.extract_source_evidence = extract
source.build_indicator_records = classify
""")
    python_path = os.pathsep.join(filter(None, [str(bootstrap), os.environ.get("PYTHONPATH")]))
    return HecateClient(
        hecate_bin=Path(sys.executable),
        workspace=tmp_path,
        env_overrides={"PYTHONPATH": python_path, "TEST_MODEL_SETTING": "inherited"},
    )


def test_worker_round_trip_keeps_types_usage_and_provider_output_separate(isolated_client):
    evidence, records = isolated_client.source_evidence_with_indicators(
        URL, {"domain": ["example.org"]}, timeout_sec=10
    )
    assert isinstance(evidence, SourceEvidence)
    assert evidence.artifacts == [SourceArtifact("cmd.exe", "process")]
    assert evidence.usage["llm_calls"] == 2
    assert isinstance(evidence.indicators[0], IndicatorRecord)
    assert isinstance(records[0], IndicatorRecord)
    assert records[0].value == "example.org"
    assert records[0].source == URL


@pytest.mark.skipif(sys.platform != "linux", reason="Process state check uses Linux /proc")
@pytest.mark.parametrize("stage", ["extraction", "classification"])
def test_timeout_kills_worker_and_descendants(isolated_client, tmp_path, stage):
    marker = tmp_path / "pids.json"
    isolated_client.env_overrides.update(TEST_BLOCK_STAGE=stage, TEST_MARKER=str(marker))
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="extraction and classification timed out"):
        isolated_client.source_evidence_with_indicators(
            URL, {"domain": ["example.org"]}, timeout_sec=2
        )
    assert time.monotonic() - started < 5
    pids = json.loads(marker.read_text())
    assert len(pids) == 2  # Reached the selected stage and spawned its descendant.
    for pid in pids:
        # An adopted zombie may briefly await PID 1; it is no longer executing.
        status = Path(f"/proc/{pid}/stat")
        deadline = time.monotonic() + 2
        while True:
            try:
                state = status.read_text().split(")", 1)[1].split()[0]
            except FileNotFoundError:
                break
            if state == "Z":
                break
            assert time.monotonic() < deadline, f"Worker descendant {pid} is still executing"
            time.sleep(0.01)


def test_worker_failure_does_not_expose_provider_output(isolated_client):
    with pytest.raises(HecateError, match="worker exited with status") as error:
        isolated_client.source_evidence_with_indicators(URL, {}, timeout_sec=10)
    assert "KeyError" not in str(error.value)
    assert "provider diagnostic" not in str(error.value)
