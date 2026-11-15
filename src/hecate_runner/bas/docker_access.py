"""Use a narrow local BAS broker when services have no Docker socket access."""

from __future__ import annotations

import json
import os
import socket
import subprocess

MAX_BROKER_REPLY = 20 * 1024 * 1024


def run_docker(
    args: list[str], *, timeout: int = 10, check: bool = False
) -> subprocess.CompletedProcess[str]:
    endpoint = os.environ.get("HECATE_BAS_BROKER_SOCKET")
    if not endpoint:
        return subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=timeout, check=check
        )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout + 2)
        connection.connect(endpoint)
        connection.sendall(json.dumps({"args": args}).encode("utf-8") + b"\n")
        data = bytearray()
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            if len(data) + len(chunk) > MAX_BROKER_REPLY:
                raise ValueError("BAS broker reply exceeds its limit")
            data.extend(chunk)
    reply = json.loads(data)
    result = subprocess.CompletedProcess(
        ["docker", *args], int(reply["returncode"]), str(reply["stdout"]), str(reply["stderr"])
    )
    if check:
        result.check_returncode()
    return result
