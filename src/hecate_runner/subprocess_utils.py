"""Subprocess execution utilities with process group isolation and leak prevention."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from hecate_agent.core.subprocess_utils import run_process_group as _run_process_group

__all__ = ["run_process_group"]


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
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    return cast(
        subprocess.CompletedProcess[str],
        _run_process_group(
            cmd,
            timeout=timeout,
            cwd=cwd,
            env=env,
            text=text,
            shell=shell,
            input=input,
            check=check,
            **kwargs,
        ),
    )
