"""Shared HTTP keep-alive connection pool."""

from __future__ import annotations

from hecate_agent.core.http_pool import (
    close_shared_clients,
    get_shared_client,
    is_mocked,
    pooled_get,
    pooled_post,
    pooled_request,
)

__all__ = [
    "close_shared_clients",
    "get_shared_client",
    "is_mocked",
    "pooled_get",
    "pooled_post",
    "pooled_request",
]
