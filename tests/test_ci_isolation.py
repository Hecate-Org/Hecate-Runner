"""The default unit suite must stay offline and ignore operator dotenv files."""

from io import StringIO
from pathlib import Path

import httpx
import pytest
from dotenv import dotenv_values
from dotenv.main import DotEnv


def test_operator_dotenv_path_is_blocked_even_with_a_supplied_stream():
    outside = Path(Path(__file__).resolve().anchor) / "hecate-ci-operator-probe" / ".env"
    values = DotEnv(outside, stream=StringIO("HECATE_CI_PROBE=fixture-only\n")).dict()
    assert "HECATE_CI_PROBE" not in values


def test_temporary_dotenv_fixture_is_supported(tmp_path):
    fixture = tmp_path / ".env"
    fixture.write_text("HECATE_CI_PROBE=fixture-only\n", encoding="utf-8")
    assert dotenv_values(fixture)["HECATE_CI_PROBE"] == "fixture-only"


def test_unmocked_network_request_is_rejected_before_transport():
    with pytest.raises(pytest.fail.Exception, match="live requests are forbidden"):
        httpx.get("https://example.invalid/ci-guard-probe")
