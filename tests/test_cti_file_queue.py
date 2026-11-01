"""FileQueueProvider tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti import FileQueueProvider, MispProvider, get_provider
from hecate_runner.cti.base import CTIItem


def test_returns_none_when_empty(tmp_path: Path) -> None:
    provider = FileQueueProvider(queue_dir=tmp_path / "q")
    provider.ensure_dirs()
    assert provider.next_item() is None


def test_returns_none_for_empty_file(tmp_path: Path) -> None:
    q = tmp_path / "q"
    q.mkdir()
    (q / "next.txt").write_text("   \n\n")
    provider = FileQueueProvider(queue_dir=q)
    assert provider.next_item() is None


def test_reads_and_returns_content(tmp_path: Path) -> None:
    q = tmp_path / "q"
    q.mkdir()
    (q / "next.txt").write_text("APT actor X observed")
    provider = FileQueueProvider(queue_dir=q)
    item = provider.next_item()
    assert item is not None
    assert item.content == "APT actor X observed"
    assert item.source == "file"


def test_acknowledge_archives(tmp_path: Path) -> None:
    q = tmp_path / "q"
    q.mkdir()
    (q / "next.txt").write_text("some intel")
    provider = FileQueueProvider(queue_dir=q)
    item = provider.next_item()
    assert item is not None
    provider.acknowledge(item)
    assert not (q / "next.txt").exists()
    processed = list((q / "processed").glob("cti-*.txt"))
    assert len(processed) == 1
    assert processed[0].read_text() == "some intel"


def test_acknowledge_when_no_file(tmp_path: Path) -> None:
    q = tmp_path / "q"
    q.mkdir()
    provider = FileQueueProvider(queue_dir=q)
    # Should not raise even if the file was already removed
    provider.acknowledge(CTIItem(content="stale", received_at=datetime.now(UTC)))


def test_spool_and_fifo_consumption(tmp_path: Path) -> None:
    q = tmp_path / "q"
    provider = FileQueueProvider(queue_dir=q)
    provider.ensure_dirs()

    # Spool two items
    f1 = provider.spool("Report 1: Cobalt Strike", filename="01_report.txt")
    f2 = provider.spool("Report 2: Akira Ransomware", filename="02_report.txt")

    assert len(provider.pending_items()) == 2

    # First item
    item1 = provider.next_item()
    assert item1 is not None
    assert item1.content == "Report 1: Cobalt Strike"
    assert item1.identifier == "01_report.txt"

    provider.acknowledge(item1)
    assert not f1.exists()

    # Second item
    item2 = provider.next_item()
    assert item2 is not None
    assert item2.content == "Report 2: Akira Ransomware"
    assert item2.identifier == "02_report.txt"

    provider.acknowledge(item2)
    assert not f2.exists()
    assert provider.next_item() is None


def test_spool_structured_json(tmp_path: Path) -> None:
    q = tmp_path / "q"
    provider = FileQueueProvider(queue_dir=q)
    data = {
        "title": "Novel Lateral Movement",
        "content": "Adversary used DCOM execution",
        "source_url": "https://threat.example/intel",
        "metadata": {"tlp": "amber", "confidence": "high"},
    }
    provider.spool(data, filename="intel.json")

    item = provider.next_item()
    assert item is not None
    assert item.title == "Novel Lateral Movement"
    assert item.content == "Adversary used DCOM execution"
    assert item.source_url == "https://threat.example/intel"
    assert item.metadata["tlp"] == "amber"

    provider.acknowledge(item)
    assert provider.next_item() is None


def test_next_txt_takes_priority_over_spool(tmp_path: Path) -> None:
    q = tmp_path / "q"
    provider = FileQueueProvider(queue_dir=q)
    provider.ensure_dirs()

    # Spool an item
    provider.spool("Spooled item", filename="spool_1.txt")
    # Also write legacy next.txt
    (q / "next.txt").write_text("Urgent next item")

    # next.txt is yielded first
    first = provider.next_item()
    assert first is not None
    assert first.content == "Urgent next item"
    provider.acknowledge(first)

    # then spooled item
    second = provider.next_item()
    assert second is not None
    assert second.content == "Spooled item"
    provider.acknowledge(second)


def test_factory_returns_file_provider(settings: Settings) -> None:
    provider = get_provider("file", settings=settings)
    assert isinstance(provider, FileQueueProvider)


def test_factory_returns_misp_provider(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MISP_BASE_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_API_KEY", "test-key")
    misp_settings = Settings(_env_file=None)  # type: ignore[call-arg]
    provider = get_provider("misp", settings=misp_settings)
    assert isinstance(provider, MispProvider)


def test_factory_unknown_raises(settings: Settings) -> None:
    try:
        get_provider("bigquery", settings=settings)
    except ValueError as e:
        assert "bigquery" in str(e)
    else:
        raise AssertionError("expected ValueError")
