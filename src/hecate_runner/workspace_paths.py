"""Workspace paths and descriptor-based I/O for untrusted hunt artifacts."""

from __future__ import annotations

import os
import re
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path, PurePosixPath

MAX_ARTIFACT_BYTES = 4 * 1024 * 1024


def normalize_hunt_id(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Invalid hunt ID")
    value = value.strip().upper()
    if not re.fullmatch(r"H-[0-9]{1,12}", value):
        raise ValueError("Invalid hunt ID")
    return value


def workspace_path(workspace: Path, *parts: str) -> Path:
    root = workspace.resolve()
    relative = PurePosixPath(*parts)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"..", "."} or "\\" in part or "\x00" in part for part in relative.parts)
    ):
        raise ValueError("Artifact path must stay inside the selected workspace")
    path = root
    for component in relative.parts:
        path = path / component
        if path.is_symlink():
            raise ValueError("Artifact paths must not contain symlinks")
    if not path.resolve().is_relative_to(root):
        raise ValueError("Artifact path escapes the selected workspace")
    return path


def query_directory(workspace: Path, hunt_id: str) -> Path:
    return workspace_path(workspace, "queries", normalize_hunt_id(hunt_id))


def _relative(workspace: Path, path: Path) -> Path:
    for root in (workspace.absolute(), workspace.resolve()):
        try:
            return path.absolute().relative_to(root)
        except ValueError:
            continue
    raise ValueError("Artifact path escapes the selected workspace")


@contextmanager
def _parent(workspace: Path, path: Path) -> Iterator[tuple[Path, int | None]]:
    relative = _relative(workspace, path)
    checked = workspace_path(workspace, relative.as_posix())
    if not relative.parts:
        raise ValueError("Artifact must be a regular file")
    if os.name != "posix":
        yield checked, None
        return
    # Pin every directory descriptor. A rename/symlink race cannot redirect
    # the final open or replacement outside the selected workspace.
    descriptors = []
    try:
        fd = os.open(workspace.resolve(), os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(fd)
        for component in relative.parts[:-1]:
            fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
        yield checked, fd
    except OSError as exc:
        raise ValueError("Artifact path is not a safe workspace path") from exc
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def read_artifact(path: Path, workspace: Path) -> str:
    raw: bytes
    with _parent(workspace, path) as (checked, parent_fd):
        if parent_fd is None:
            with checked.open("rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("Artifact must be a regular file")
                raw = stream.read(MAX_ARTIFACT_BYTES + 1)
        else:
            try:
                fd = os.open(
                    checked.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd
                )
            except OSError as exc:
                raise ValueError("Artifact is not a safe regular file") from exc
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("Artifact must be a regular file")
                raw = stream.read(MAX_ARTIFACT_BYTES + 1)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise ValueError("Artifact exceeds its byte limit")
        return raw.decode("utf-8")


def write_artifact(path: Path, content: str, workspace: Path) -> None:
    raw = content.encode("utf-8")
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ValueError("Artifact exceeds its byte limit")
    with _parent(workspace, path) as (checked, parent_fd):
        if parent_fd is None:
            from hecate_runner.atomic_write import atomic_write_text

            atomic_write_text(checked, content)
            return
        temporary = f".{checked.name}.{secrets.token_hex(12)}.tmp"
        try:
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o660,
                dir_fd=parent_fd,
            )
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            # Replacing a raced-in final symlink removes the link, never its target.
            os.replace(temporary, checked.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=parent_fd)
