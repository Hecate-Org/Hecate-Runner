"""Keep the default Runner suite isolated from operator credentials and networks."""

import socket
import tempfile
from contextlib import contextmanager
from contextvars import ContextVar
from io import StringIO
from pathlib import Path

import httpx
import pytest
from dotenv.main import DotEnv

try:
    import requests
except ImportError:
    requests = None


@pytest.fixture(autouse=True)
def _isolate_dotenv_and_network(monkeypatch: pytest.MonkeyPatch, request) -> None:
    """Only test-owned dotenv files and mocked network transports are allowed."""
    from hecate_agent.core.http_pool import close_shared_clients

    close_shared_clients()
    request.addfinalizer(close_shared_clients)
    original_stream = DotEnv._get_stream
    temporary_root = Path(tempfile.gettempdir()).resolve()

    @contextmanager
    def test_stream(dotenv: DotEnv):
        path = Path(dotenv.dotenv_path).resolve() if dotenv.dotenv_path else None
        if path is not None and not path.is_relative_to(temporary_root):
            yield StringIO("")
        else:
            with original_stream(dotenv) as stream:
                yield stream

    original_socketpair = socket.socketpair
    creating_socketpair = ContextVar("creating_socketpair", default=False)

    def local_socketpair(*args, **kwargs):
        # Windows implements this local IPC primitive with a loopback connection.
        token = creating_socketpair.set(True)
        try:
            return original_socketpair(*args, **kwargs)
        finally:
            creating_socketpair.reset(token)

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def guarded_connect(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6) and not creating_socketpair.get():
            pytest.fail("Unit tests must mock network I/O; live connections are forbidden")
        return original_connect(sock, address)

    def guarded_connect_ex(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6) and not creating_socketpair.get():
            pytest.fail("Unit tests must mock network I/O; live connections are forbidden")
        return original_connect_ex(sock, address)

    def reject_request(*args, **kwargs):
        pytest.fail("Unit tests must mock network I/O; live requests are forbidden")

    async def reject_async_request(*args, **kwargs):
        pytest.fail("Unit tests must mock network I/O; live requests are forbidden")

    monkeypatch.setattr(DotEnv, "_get_stream", test_stream)
    if request.node.get_closest_marker("network"):
        if request.config.getoption("markexpr").strip() != "network":
            pytest.skip("External service check: explicitly opt in with -m network")
    else:
        monkeypatch.setattr(httpx.HTTPTransport, "handle_request", reject_request)
        monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", reject_async_request)
        if requests is not None:
            monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", reject_request)
        monkeypatch.setattr(socket, "socketpair", local_socketpair)
        monkeypatch.setattr(socket.socket, "connect", guarded_connect)
        monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
