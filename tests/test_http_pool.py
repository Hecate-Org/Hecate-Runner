"""Tests for shared HTTP keep-alive connection pool."""

from __future__ import annotations

from hecate_runner.http_pool import close_shared_clients, get_shared_client


def test_get_shared_client_reuses_instance() -> None:
    c1 = get_shared_client(pool_name="test_pool", timeout=10.0)
    c2 = get_shared_client(pool_name="test_pool", timeout=10.0)
    assert c1 is c2
    assert not c1.is_closed


def test_get_shared_client_differentiates_params() -> None:
    c1 = get_shared_client(pool_name="pool_a", timeout=10.0)
    c2 = get_shared_client(pool_name="pool_b", timeout=10.0)
    assert c1 is not c2


def test_close_shared_clients_closes_all() -> None:
    c1 = get_shared_client(pool_name="close_test_1", timeout=5.0)
    c2 = get_shared_client(pool_name="close_test_2", timeout=5.0)
    assert not c1.is_closed
    assert not c2.is_closed

    close_shared_clients()
    assert c1.is_closed
    assert c2.is_closed
