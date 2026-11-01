"""Tests for poison-pill Dead-Letter Queue (DLQ)."""

from __future__ import annotations

from pathlib import Path

from hecate_runner.cti import CTIItem
from hecate_runner.dead_letter import (
    clear_dead_letters,
    clear_retry,
    dead_letter_dir,
    get_dead_letter,
    get_retry_count,
    list_dead_letters,
    quarantine,
    record_failure,
    restore_dead_letter,
)


def test_retry_counter_and_clear(tmp_path: Path) -> None:
    item = CTIItem(content="Malicious payload", identifier="sample_01.txt")

    assert get_retry_count(tmp_path, item) == 0

    att1 = record_failure(tmp_path, item, "HecateError: timeout")
    assert att1 == 1
    assert get_retry_count(tmp_path, item) == 1

    att2 = record_failure(tmp_path, item, "HecateError: timeout again")
    assert att2 == 2
    assert get_retry_count(tmp_path, item) == 2

    clear_retry(tmp_path, item)
    assert get_retry_count(tmp_path, item) == 0


def test_quarantine_moves_item_to_dead_letter(tmp_path: Path) -> None:
    item = CTIItem(
        content="Poison pill payload crashing AST parser",
        title="Poison Report",
        source="rss",
        source_url="https://threat.test/poison",
        identifier="poison.txt",
    )

    path = quarantine(tmp_path, item, "SyntaxError: invalid AST", attempts=3)
    assert path.exists()
    assert dead_letter_dir(tmp_path).is_dir()

    # Retry count cleared upon quarantine
    assert get_retry_count(tmp_path, item) == 0

    items = list_dead_letters(tmp_path)
    assert len(items) == 1
    dl = items[0]
    assert dl.title == "Poison Report"
    assert dl.attempts == 3
    assert "SyntaxError" in dl.last_error
    assert dl.content == item.content

    # get by exact or prefix
    fetched = get_dead_letter(tmp_path, dl.dead_letter_id)
    assert fetched is not None
    assert fetched.dead_letter_id == dl.dead_letter_id

    # Restore item back to next.txt
    restored = restore_dead_letter(tmp_path, dl.dead_letter_id)
    assert restored is not None
    assert restored.name == "next.txt"
    assert restored.read_text().strip() == item.content
    assert not path.exists()
    assert len(list_dead_letters(tmp_path)) == 0


def test_clear_dead_letters(tmp_path: Path) -> None:
    item1 = CTIItem(content="Pill 1", identifier="pill1.txt")
    item2 = CTIItem(content="Pill 2", identifier="pill2.txt")

    quarantine(tmp_path, item1, "error 1", 3)
    quarantine(tmp_path, item2, "error 2", 3)

    assert len(list_dead_letters(tmp_path)) == 2
    cleared = clear_dead_letters(tmp_path)
    assert cleared == 2
    assert len(list_dead_letters(tmp_path)) == 0


def test_restore_dead_letter_spools_when_next_occupied(tmp_path: Path) -> None:
    # Pre-occupy next.txt
    next_file = tmp_path / "next.txt"
    next_file.write_text("Existing unacknowledged item\n")

    item = CTIItem(content="Quarantined item", identifier="pill.txt", title="Test Title")
    quarantine(tmp_path, item, "parse error", 3)
    items = list_dead_letters(tmp_path)
    assert len(items) == 1

    restored = restore_dead_letter(tmp_path, items[0].dead_letter_id)
    assert restored is not None
    assert restored != next_file
    assert restored.parent.name == "spool"
    assert "Existing unacknowledged item" in next_file.read_text()
    assert "Quarantined item" in restored.read_text()
