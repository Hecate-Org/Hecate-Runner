"""Restricted Docker inspection/temporary-file cleanup for isolated BAS workers.

This service has Docker API access. Callers receive no generic Docker, shell,
container-start, copy, mount, network-connect, or host-filesystem operation.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import socket
import socketserver
import stat
import struct
import subprocess
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import cast

TRACE = "/tmp/hecate-exec.trace"
FIND = ["find", "/tmp", "-maxdepth", "2", "!", "-name", "hecate-exec.trace", "!", "-path", "/tmp"]
MAX_OUTPUT = 8 * 1024 * 1024


def docker(args: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [os.environ.get("HECATE_BAS_DOCKER_BIN", "/usr/bin/docker"), *args],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if len(result.stdout.encode()) + len(result.stderr.encode()) > MAX_OUTPUT:
        raise ValueError("BAS broker output exceeds its limit")
    return result


class Policy:
    def __init__(self, agent: str, controller: str, network: str):
        for value in (agent, controller, network):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
                raise ValueError("Invalid BAS broker identity")
        self.agent = agent
        self.controller = controller
        self.network = network

    @staticmethod
    def tmp_path(value: str) -> bool:
        path = PurePosixPath(value)
        return (
            path.is_absolute()
            and len(path.parts) > 2
            and path.parts[1] == "tmp"
            and ".." not in path.parts
            and value == str(path)
            and value != TRACE
            and "\x00" not in value
        )

    def dispatch(
        self,
        args: list[str],
        execute: Callable[[list[str]], subprocess.CompletedProcess[str]] = docker,
    ) -> subprocess.CompletedProcess[str]:
        if not isinstance(args, list) or not all(
            isinstance(v, str) and len(v) <= 1024 for v in args
        ):
            raise ValueError("Invalid BAS broker request")
        if args == ["network", "inspect", self.network]:
            return execute(args)
        if len(args) == 2 and args[0] == "inspect" and args[1] in {self.agent, self.controller}:
            result = execute(args)
            if result.returncode:
                return result
            records = json.loads(result.stdout)
            # Inspect output must not disclose container environment credentials.
            for record in records:
                labels = record["Config"].get("Labels") or {}
                record["Config"] = {
                    key: value
                    for key, value in record["Config"].items()
                    if key in {"Hostname", "User", "Entrypoint", "Cmd", "WorkingDir", "Image"}
                }
                record["Config"]["Labels"] = {"hecate.role": labels.get("hecate.role")}
                for key in ("Args", "Path", "ConfigFile"):
                    record.pop(key, None)
            result.stdout = json.dumps(records)
            return result
        if len(args) < 3 or args[0] not in {"exec", "top"}:
            raise ValueError("BAS broker operation is not permitted")
        inspected = execute(["inspect", self.agent])
        if inspected.returncode:
            raise ValueError("BAS agent is unavailable")
        record = json.loads(inspected.stdout)[0]
        host = record["HostConfig"]
        if (
            args[1] not in {self.agent, record["Id"]}
            or record["Config"].get("User") != "65534:65534"
            or not host.get("ReadonlyRootfs")
            or host.get("Privileged")
            or record.get("Mounts")
            or "ALL" not in (host.get("CapDrop") or [])
            or host.get("CapAdd")
            or "no-new-privileges=true" not in (host.get("SecurityOpt") or [])
        ):
            raise ValueError("BAS agent identity or isolation is not permitted")
        tail = args[2:]
        if args[0] == "top" and tail in (["-eo", "args"], ["-eo", "pid,args"]):
            return execute(["top", record["Id"], *tail])
        if args[0] == "exec" and (
            tail
            in (
                ["cat", TRACE],
                ["head", "-c", "8192", TRACE],
                ["tail", "-c", "4194304", TRACE],
                FIND,
            )
            or (len(tail) == 2 and tail[0] == "sha256sum" and self.tmp_path(tail[1]))
            or (len(tail) == 3 and tail[:2] == ["rm", "-rf"] and self.tmp_path(tail[2]))
        ):
            return execute(["exec", record["Id"], *tail])
        raise ValueError("BAS broker command is not permitted")


class Server(socketserver.UnixStreamServer):
    policy: Policy
    allowed_uids: set[int]


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server = cast(Server, self.server)
        self.connection.settimeout(2)
        _pid, uid, _gid = struct.unpack(
            "3i",
            self.connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            ),
        )
        if uid not in server.allowed_uids:
            return
        try:
            raw = self.rfile.readline(16385)
            if len(raw) > 16384 or not raw.endswith(b"\n"):
                raise ValueError("BAS broker request exceeds its limit")
            request = json.loads(raw)
            if set(request) != {"args"}:
                raise ValueError("Invalid BAS broker request")
            result = server.policy.dispatch(request["args"])
            reply = {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            reply = {"returncode": 1, "stdout": "", "stderr": "BAS broker refused the operation"}
        self.wfile.write(json.dumps(reply, ensure_ascii=False).encode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--allowed-user", action="append", required=True)
    parser.add_argument("--agent", default="hecate-bas-agent")
    parser.add_argument("--controller", default="caldera")
    parser.add_argument("--network", default="hecate-bas-lab")
    args = parser.parse_args()
    if os.path.lexists(args.socket):
        if (
            not stat.S_ISSOCK(os.lstat(args.socket).st_mode)
            or os.lstat(args.socket).st_uid != os.getuid()
        ):
            raise ValueError("Refusing to replace an unowned broker path")
        os.unlink(args.socket)
    policy = Policy(args.agent, args.controller, args.network)
    users = {pwd.getpwnam(user).pw_uid for user in args.allowed_user}
    with Server(args.socket, Handler) as server:
        server.policy = policy
        server.allowed_uids = users
        os.chmod(args.socket, 0o660)
        server.serve_forever()


if __name__ == "__main__":
    main()
