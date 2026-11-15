"""Process-lifetime ATT&CK technique metadata cache."""

from __future__ import annotations

from pathlib import Path

from hecate_runner.hecate_client import HecateClient


def test_lookup_technique_caches_and_reuses_parent(tmp_path: Path, monkeypatch) -> None:
    HecateClient.clear_technique_cache()
    calls: list[str] = []

    def fake_lookup(*, technique_id: str):
        calls.append(technique_id)
        if technique_id == "T1059.001":
            return {
                "technique_id": "T1059.001",
                "tactics": ["execution"],
                "platforms": ["Windows"],
                "found": True,
                "superseded_from": "",
                "name": "PowerShell",
            }
        if technique_id == "T1059":
            return {
                "technique_id": "T1059",
                "tactics": ["execution"],
                "platforms": ["Windows"],
                "found": True,
                "superseded_from": "",
                "name": "Command and Scripting Interpreter",
            }
        return {"technique_id": technique_id, "found": False}

    monkeypatch.setattr("hecate_agent.api.lookup_technique", fake_lookup)
    client = HecateClient(hecate_bin=tmp_path / "hecate", workspace=tmp_path)
    client._with_context = lambda fn, **kwargs: fn(**kwargs)  # type: ignore[method-assign]

    first = client.lookup_technique("T1059.001")
    assert first.name == "PowerShell"
    assert first.parent_name == "Command and Scripting Interpreter"
    assert calls == ["T1059.001", "T1059"]

    second = client.lookup_technique("t1059.001")
    assert second is first
    assert calls == ["T1059.001", "T1059"]

    parent = client.lookup_technique("T1059")
    assert parent.name == "Command and Scripting Interpreter"
    assert calls == ["T1059.001", "T1059"]

    HecateClient.clear_technique_cache()
