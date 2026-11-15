"""The BAS broker exposes a small policy, never a generic Docker endpoint."""

import copy
import json
import os
import socket
import subprocess
import threading
from unittest.mock import Mock

import pytest

from hecate_runner.bas import docker_access
from hecate_runner.bas.docker_broker import FIND, TRACE, Handler, Policy, Server


@pytest.fixture
def docker():
    record = {
        "Id": "a" * 64,
        "Config": {
            "User": "65534:65534",
            "Env": ["PRIVATE_VALUE=" + "fixture"],
            "Labels": {"hecate.role": "caldera-controller", "unrelated": "private"},
        },
        "HostConfig": {
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges=true"],
        },
        "Mounts": [],
    }
    return Mock(
        side_effect=lambda args: subprocess.CompletedProcess(
            args, 0, json.dumps([copy.deepcopy(record)]) if args[0] == "inspect" else "observed", ""
        )
    )


@pytest.mark.parametrize(
    "args",
    [
        ["exec", "agent", "head", "-c", "8192", TRACE],
        ["exec", "agent", "tail", "-c", "4194304", TRACE],
        ["exec", "agent", *FIND],
        ["exec", "agent", "sha256sum", "/tmp/lab-artifact"],
        ["exec", "agent", "rm", "-rf", "/tmp/lab-artifact"],
        ["top", "agent", "-eo", "args"],
    ],
)
def test_fixed_observation_and_cleanup_operations_are_pinned_to_container_id(docker, args):
    assert Policy("agent", "controller", "lab").dispatch(args, docker).returncode == 0
    assert docker.call_args.args[0][1] == "a" * 64


@pytest.mark.parametrize(
    "args",
    [
        ["run", "--privileged", "image"],
        ["start", "agent"],
        ["inspect", "foreign"],
        ["network", "connect", "lab", "agent"],
        ["exec", "agent", "sh", "-c", "id"],
        ["exec", "agent", "cat", "/etc/shadow"],
        ["exec", "agent", "rm", "-rf", TRACE],
        ["exec", "agent", "rm", "-rf", "/tmp/../etc"],
        ["exec", "agent", "rm", "-rf", "/tmp"],
        ["exec", "foreign", "cat", TRACE],
        ["cp", "agent:/tmp/file", "/tmp/host"],
        ["exec", "-u", "0", "agent", "cat", TRACE],
    ],
)
def test_arbitrary_docker_shell_and_host_path_operations_are_refused(docker, args):
    with pytest.raises(ValueError):
        Policy("agent", "controller", "lab").dispatch(args, docker)
    assert all(call.args[0][0] == "inspect" for call in docker.call_args_list)


def test_container_inspection_never_returns_environment_credentials(docker):
    reply = Policy("agent", "controller", "lab").dispatch(["inspect", "controller"], docker)
    config = json.loads(reply.stdout)[0]["Config"]
    assert "Env" not in config
    assert config["Labels"] == {"hecate.role": "caldera-controller"}


def test_weakened_container_is_refused_before_exec(docker):
    original = docker.side_effect

    def weakened(args):
        result = original(args)
        data = json.loads(result.stdout)
        data[0]["Mounts"] = [{"Type": "bind", "Destination": "/host"}]
        result.stdout = json.dumps(data)
        return result

    docker.side_effect = weakened
    with pytest.raises(ValueError):
        Policy("agent", "controller", "lab").dispatch(["exec", "agent", "cat", TRACE], docker)
    assert docker.call_count == 1


def test_configured_broker_failure_never_falls_back_to_raw_docker(monkeypatch, tmp_path):
    monkeypatch.setenv("HECATE_BAS_BROKER_SOCKET", str(tmp_path / "missing.sock"))
    raw = Mock()
    monkeypatch.setattr(docker_access.subprocess, "run", raw)
    with pytest.raises(OSError):
        docker_access.run_docker(["inspect", "agent"])
    raw.assert_not_called()


@pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED"), reason="Linux peer credentials")
@pytest.mark.parametrize("allowed", [True, False])
def test_socket_authorization_uses_the_kernel_peer_identity(tmp_path, allowed):
    endpoint = str(tmp_path / "broker.sock")
    with Server(endpoint, Handler) as server:
        server.allowed_uids = {os.getuid()} if allowed else {os.getuid() + 1}
        server.policy = Mock()
        server.policy.dispatch.return_value = subprocess.CompletedProcess([], 0, "observed", "")
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(2)
                connection.connect(endpoint)
                connection.sendall(json.dumps({"args": ["inspect", "agent"]}).encode() + b"\n")
                try:
                    response = connection.recv(4096)
                except ConnectionResetError:
                    response = b""
            assert bool(response) is allowed
            assert server.policy.dispatch.called is allowed
        finally:
            thread.join(timeout=3)
