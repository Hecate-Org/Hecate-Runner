"""Real generation workers must stop before a timed-out stage returns."""

from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from hecate_runner.hecate_client import HecateClient, HecateError
from hecate_runner.metrics import LLMUsage

BOOTSTRAP = r"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace as S
from hecate_agent import api

# Child interpreters do not inherit pytest's monkeypatch network guards.
def offline(*args, **kwargs):
    raise RuntimeError("network forbidden in worker fixture")
socket.socket.connect = offline
socket.socket.connect_ex = offline

def call(stage):
    workspace = Path(os.environ["HECATE_WORKSPACE"])
    assert workspace == Path.cwd()
    assert os.environ["TEST_INHERITED"] == "yes"
    # Both Python and native provider diagnostics must stay out of the protocol.
    print("provider-secret-from-stdout")
    os.write(1, b"native-provider-secret\n")
    os.write(2, b"provider-secret-from-stderr\n")
    mode = os.environ.get("TEST_MODE", "quick")
    (workspace / "entered").write_text(stage)
    if mode == "block":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = subprocess.Popen([sys.executable, "-S", "-c",
            "import sys,time;from pathlib import Path;time.sleep(2);Path(sys.argv[1]).write_text('late');time.sleep(60)",
            str(workspace / "late-grandchild")])
        (workspace / "pids").write_text(json.dumps([os.getpid(), child.pid]))
        time.sleep(2)
        (workspace / "late-worker").write_text("late")
        time.sleep(60)
    if mode == "error":
        error = RuntimeError("provider-secret-credential-and-source")
        error.metadata = {"llm_calls": 2, "input_tokens": 20, "output_tokens": 10}
        raise error
    return workspace

def research(**kwargs):
    call("research")
    return S(research_id="R-TEST", recommended_hypothesis="test", related_work=S(sources=[]),
        llm_calls=2, input_tokens=20, output_tokens=10), Path("research.md")

def hypothesis(**kwargs):
    call("hypothesis")
    return S(hypothesis="test", justification="quote", mitre_techniques=["T1059"],
        data_sources=[], expected_observables=[], known_false_positives=[], actor="", behavior="",
        location="", evidence="", is_threat_report=True, low_confidence_reason="", is_indicator_only=False), {"llm_calls":2, "input_tokens":20, "output_tokens":10}

def sigma(**kwargs):
    workspace = call("sigma")
    return S(rules=[], logsources_considered=["process_creation"], rejected=[], omitted=[], review_gaps=[]), [workspace / "rule.yml"], {"success":True, "llm_calls":2, "input_tokens":20, "output_tokens":10}

api.generate_research = research
api.generate_hypothesis_with_metrics = hypothesis
api.generate_sigma_with_metrics = sigma
"""


@pytest.fixture
def isolated_client(tmp_path):
    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir()
    (bootstrap / "sitecustomize.py").write_text(BOOTSTRAP)
    return HecateClient(
        Path(sys.executable),
        tmp_path,
        env_overrides={
            "PYTHONPATH": os.pathsep.join(
                filter(None, [str(bootstrap), os.environ.get("PYTHONPATH")])
            ),
            "TEST_INHERITED": "yes",
        },
        default_timeout_sec=10,
    )


def invoke(client, stage, timeout=None):
    if stage == "research":
        return client.research_new("offline", timeout_sec=timeout)
    if stage == "hypothesis":
        return client.hypothesis_generator("offline", timeout_sec=timeout)
    return client.sigma_generator({"hunt_id": "H-TEST"}, client.workspace, timeout_sec=timeout)


@pytest.mark.parametrize("stage", ["research", "hypothesis", "sigma"])
def test_round_trip_preserves_results_usage_and_environment(isolated_client, stage):
    result = invoke(isolated_client, stage)
    assert isinstance(result.usage, LLMUsage)
    assert result.usage.input_tokens == 20
    assert (isolated_client.workspace / "entered").read_text() == stage
    if stage == "sigma":
        assert result.files == [isolated_client.workspace / "rule.yml"]
    elif stage == "research":
        assert result.research_id == "R-TEST"
    else:
        assert result.techniques == ["T1059"]


def assert_stopped(pid):
    path = Path(f"/proc/{pid}/stat")
    until = time.monotonic() + 2
    while path.exists():
        try:
            state = path.read_text().split(")", 1)[1].split()[0]
        except FileNotFoundError:
            return
        if state == "Z":
            return
        assert time.monotonic() < until, f"Process {pid} survived cancellation"
        time.sleep(0.01)


@pytest.mark.skipif(sys.platform != "linux", reason="Process state check uses /proc")
@pytest.mark.parametrize("stage", ["research", "hypothesis", "sigma"])
def test_timeout_kills_workers_descendants_and_late_writes(isolated_client, stage):
    isolated_client.env_overrides["TEST_MODE"] = "block"
    start = time.monotonic()
    with pytest.raises(TimeoutError, match=f"{stage} timed out"):
        invoke(isolated_client, stage, timeout=1.5)
    assert time.monotonic() - start < 4
    for pid in json.loads((isolated_client.workspace / "pids").read_text()):
        assert_stopped(pid)
    # A retry must work immediately, while the former provider would still run.
    isolated_client.env_overrides["TEST_MODE"] = "quick"
    invoke(isolated_client, stage)
    time.sleep(2.1)
    assert not (isolated_client.workspace / "late-worker").exists()
    assert not (isolated_client.workspace / "late-grandchild").exists()


@pytest.mark.parametrize("stage", ["research", "hypothesis", "sigma"])
def test_provider_error_is_sanitized_but_usage_survives(isolated_client, stage, caplog):
    isolated_client.env_overrides["TEST_MODE"] = "error"
    with pytest.raises(HecateError, match="API call failed in isolated worker") as error:
        invoke(isolated_client, stage)
    assert error.value.usage.llm_calls == 2
    assert "provider-secret" not in str(error.value)
    assert "provider-secret" not in caplog.text


def test_zero_timeout_still_uses_worker(isolated_client):
    assert isolated_client._resolve_timeout(0) is None
    assert invoke(isolated_client, "research", timeout=0).research_id == "R-TEST"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), "bad"])
def test_invalid_timeouts_fail_closed(isolated_client, value):
    with pytest.raises(ValueError, match="finite"):
        invoke(isolated_client, "research", timeout=value)
    assert not (isolated_client.workspace / "entered").exists()


def test_concurrent_calls_keep_workspaces_separate(isolated_client, tmp_path):
    other_workspace = tmp_path / "other"
    other_workspace.mkdir()
    other = HecateClient(
        Path(sys.executable), other_workspace, env_overrides=isolated_client.env_overrides
    )
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [
            pool.submit(invoke, client, stage)
            for client in (isolated_client, other)
            for stage in ("research", "sigma")
        ]
        for future in futures:
            future.result(timeout=20)
    assert (other_workspace / "entered").exists()
    assert (tmp_path / "entered").exists()


def test_worker_rejects_arbitrary_operations(isolated_client):
    with pytest.raises(HecateError, match="API call failed"):
        isolated_client._run_stage("check_installed", {}, 10)


@pytest.mark.parametrize(
    "output",
    [
        "{}",
        '{"version":1,"ok":true,"result":[]}',
        "partial-json",
        '{"version":1,"ok":true,"result":{"unknown":42}}',
    ],
)
def test_malformed_worker_response_fails_closed(isolated_client, monkeypatch, output):
    import subprocess

    monkeypatch.setattr(
        "hecate_runner.subprocess_utils.run_process_group",
        lambda *a, **kw: subprocess.CompletedProcess([], 0, stdout=output),
    )
    with pytest.raises(HecateError, match="invalid"):
        invoke(isolated_client, "research")


@pytest.mark.skipif(sys.platform != "linux", reason="Signal cancellation uses POSIX groups")
def test_parent_interrupt_cleans_up_worker_group(isolated_client):
    import signal
    import subprocess

    isolated_client.env_overrides["TEST_MODE"] = "block"
    script = (
        "import sys; from pathlib import Path; "
        "from hecate_runner.hecate_client import HecateClient; "
        "HecateClient(Path(sys.executable), Path.cwd()).research_new('offline', timeout_sec=30)"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        cwd=isolated_client.workspace,
        env={
            **os.environ,
            **isolated_client.env_overrides,
            "HECATE_WORKSPACE": str(isolated_client.workspace),
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        until = time.monotonic() + 10
        marker = isolated_client.workspace / "pids"
        while not marker.exists():
            assert process.poll() is None
            assert time.monotonic() < until
            time.sleep(0.02)
        pids = json.loads(marker.read_text())
        process.send_signal(signal.SIGINT)
        process.wait(timeout=5)
        assert process.returncode != 0
        for pid in pids:
            assert_stopped(pid)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_repeated_short_deadlines_do_not_accumulate_threads_or_fds(isolated_client):
    import threading

    threads = threading.active_count()
    descriptors = len(list(Path("/proc/self/fd").iterdir())) if sys.platform == "linux" else None
    for _ in range(12):
        with pytest.raises(TimeoutError):
            invoke(isolated_client, "research", timeout=0.03)
    assert threading.active_count() == threads
    if descriptors is not None:
        assert len(list(Path("/proc/self/fd").iterdir())) <= descriptors + 1
    assert invoke(isolated_client, "research").research_id == "R-TEST"
