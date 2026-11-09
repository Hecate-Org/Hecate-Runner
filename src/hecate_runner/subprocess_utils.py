"""Subprocess execution utilities with process group isolation and leak prevention."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def run_process_group(
    cmd: Sequence[str] | str,
    *,
    timeout: float | None = None,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    text: bool = True,
    shell: bool = False,
    input: str | bytes | None = None,
    check: bool = False,
) -> subprocess.CompletedProcess[Any]:
    """Execute a subprocess inside a dedicated process group.

    On POSIX systems, `start_new_session=True` ensures the child process and all
    of its descendants belong to a distinct process group. If the execution
    times out, `SIGKILL` is delivered to the entire process group (`os.killpg`)
    to prevent orphaned grandchild background processes from leaking.
    """
    kwargs: dict[str, Any] = {
        "cwd": str(cwd) if cwd is not None else None,
        "env": env,
        "text": text,
        "shell": shell,
        "stdin": subprocess.PIPE if input is not None else None,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    if os.name == "posix":
        kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **kwargs)
    stdout: Any = "" if text else b""
    stderr: Any = "" if text else b""
    try:
        stdout, stderr = proc.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if os.name == "posix" and hasattr(os, "killpg"):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
        with contextlib.suppress(Exception):
            stdout, stderr = proc.communicate(timeout=2.0)
        raise subprocess.TimeoutExpired(
            cmd=cmd,
            timeout=timeout or 0,
            output=stdout,
            stderr=stderr,
        ) from exc
    except BaseException:
        if os.name == "posix" and hasattr(os, "killpg"):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
        with contextlib.suppress(Exception):
            proc.wait(timeout=2.0)
        raise

    retcode = proc.poll()
    if check and retcode:
        raise subprocess.CalledProcessError(retcode, cmd, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(
        args=cmd,
        returncode=retcode if retcode is not None else 0,
        stdout=stdout,
        stderr=stderr,
    )
