"""Nonblocking process locks for independent workers on one workspace."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path
from types import ModuleType
from typing import IO

_fcntl: ModuleType | None
try:
    _fcntl = import_module("fcntl")
except ImportError:
    _fcntl = None


def acquire_work_lock(path: Path) -> IO[str] | None:
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = path.open("a")
    if _fcntl is None:
        return stream
    try:
        _fcntl.flock(stream.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        stream.close()
        return None
    except BaseException:
        stream.close()
        raise
    return stream  # Closing all copies releases the lock, including after crashes.
