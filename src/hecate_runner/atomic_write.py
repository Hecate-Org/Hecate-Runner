"""Shared atomic-write helper."""

from __future__ import annotations

from hecate_agent.core.atomic_write import (
    DEFAULT_FILE_MODE,
    atomic_write_text,
    default_file_mode,
)

__all__ = ["DEFAULT_FILE_MODE", "atomic_write_text", "default_file_mode"]
