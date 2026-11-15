"""Permissions for owner-private data and the isolated workers' private group."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def _shared_gid() -> int:
    try:
        import grp

        return grp.getgrnam("hecate-data").gr_gid
    except (ImportError, KeyError) as exc:
        raise PermissionError("Isolated data requires the hecate-data group") from exc


def _shared_policy(path: Path, *, directory: bool) -> bool:
    if os.environ.get("HECATE_SERVICE_ISOLATED") == "1":
        return True
    # Operator CLI commands must preserve a tree explicitly provisioned for the
    # private data group, even when they run outside a service environment.
    anchor = path if directory and path.exists() else path.parent
    try:
        info = anchor.lstat()
        return bool(
            stat.S_ISDIR(info.st_mode)
            and info.st_gid == _shared_gid()
            and info.st_mode & stat.S_ISGID
            and not info.st_mode & 0o007
        )
    except OSError:
        return False


def _mode(path: Path, *, directory: bool) -> int:
    if _shared_policy(path, directory=directory):
        return 0o2770 if directory else 0o660
    return 0o700 if directory else 0o600


def _protect(path: Path, *, directory: bool) -> None:
    info = path.lstat()
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid_type:
        raise PermissionError("Private data must use regular files and directories")
    if _shared_policy(path, directory=directory) and info.st_gid != _shared_gid():
        raise PermissionError("Isolated data must belong to hecate-data")
    expected = _mode(path, directory=directory)
    # Migrated objects retain their original owner. A different worker must
    # accept an already-correct group policy without attempting owner-only chmod.
    if stat.S_IMODE(info.st_mode) != expected:
        path.chmod(expected)
    final = path.lstat()
    if stat.S_IMODE(final.st_mode) != expected:
        raise PermissionError("Could not enforce private data permissions")


def prepare_directory(path: Path) -> None:
    path.mkdir(mode=_mode(path, directory=True), parents=True, exist_ok=True)
    _protect(path, directory=True)


def protect_file(path: Path) -> None:
    _protect(path, directory=False)
