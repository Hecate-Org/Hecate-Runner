"""Nonblocking process locks for independent workers on one workspace."""

from __future__ import annotations

import fcntl
from pathlib import Path
from typing import IO


def acquire_work_lock(path: Path) -> IO[str] | None:
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = path.open("a")
    try:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        stream.close()
        return None
    except BaseException:
        stream.close()
        raise
    return stream  # Closing all copies releases the lock, including after crashes.
