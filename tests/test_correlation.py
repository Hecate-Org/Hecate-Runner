"""Tests for threat entity correlation, campaign clustering, and incremental hunt enrichment."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from hecate_runner.config import Settings
from hecate_runner.correlation import (
    IncrementalEnricher,
    ThreatEntityCorrelator,
    ThreatEntityExtractor,
)
from hecate_runner.cti.base import CTIItem
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.state import OrchestratorState


def test_extract_cves() -> None:
    text = "Report on active exploitation of CVE-2026-1234 and CVE-2025-99999 by adversaries."
    metadata = {"indicators": {"cve": ["cve-2026-5555"]}}
    cves = ThreatEntityExtractor.extract_cves(text, metadata)
    assert cves == {"CVE-2026-1234", "CVE-2025-99999", "CVE-2026-5555"}


def test_extract_actor_aliases() -> None:
    # Built-in alias dictionary matches Fancy Bear to APT28
    actors1 = ThreatEntityExtractor.extract_actors(
        "Campaign observed by Fancy Bear and Forest Blizzard."
    )
    assert any("APT28" in a for a in actors1)

    # Midnight Blizzard matches APT29
    actors2 = ThreatEntityExtractor.extract_actors("Token theft activity by Midnight Blizzard.")
    assert any("APT29" in a for a in actors2)

    # Volt Typhoon matches
    actors3 = ThreatEntityExtractor.extract_actors("Living-off-the-land activity by Volt Typhoon.")
    assert any("Volt Typhoon" in a for a in actors3)


def test_extract_network_iocs_and_filters() -> None:
    text = """
    C2 beaconing observed to 198.51.100.25 and evil-c2-network.org.
    Local test was 127.0.0.1 and internal was 10.0.0.1 or 192.168.1.50.
    Documentation link: https://github.com/project/code.py and https://google.com/search.
    """
    metadata = {
        "indicators": {
            "ipv4": ["203.0.113.15", "172.16.1.1"],
            "domain": ["secondary-payload-domain.com", "virustotal.com"],
        }
    }
    iocs = ThreatEntityExtractor.extract_network_iocs(text, metadata)

    # Public IPs and external domains included
    assert "198.51.100.25" in iocs
    assert "203.0.113.15" in iocs
    assert "evil-c2-network.org" in iocs
    assert "secondary-payload-domain.com" in iocs

    # Private/loopback IPs filtered out
    assert "127.0.0.1" not in iocs
    assert "10.0.0.1" not in iocs
    assert "192.168.1.50" not in iocs
    assert "172.16.1.1" not in iocs

    # Benign domains and python file lookalikes filtered out
    assert "github.com" not in iocs
    assert "google.com" not in iocs
    assert "virustotal.com" not in iocs
    assert "code.py" not in iocs


def test_extract_file_hashes() -> None:
    text = "Dropped binary hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    metadata = {
        "indicators": {
            "sha256": ["ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"]
        }
    }
    hashes = ThreatEntityExtractor.extract_file_hashes(text, metadata)
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in hashes
    assert "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in hashes


def test_correlator_matches_existing_hunt_cve(tmp_path: Path) -> None:
    hunts_dir = tmp_path / "hunts" / "2026"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0001.md"
    hunt_file.write_text(
        """---
hunt_id: H-0001
title: "Exploitation of CVE-2026-4444 in VPN Gateways"
techniques: ["T1190"]
---
# H-0001: CVE-2026-4444
Vulnerability in edge appliances.
""",
        encoding="utf-8",
    )

    correlator = ThreatEntityCorrelator(hunts_dir)
    item = CTIItem(
        source="misp",
        identifier="item-01",
        title="New PoC released for CVE-2026-4444",
        content="Adversaries observed actively exploiting CVE-2026-4444 in the wild.",
        metadata={"indicators": {"cve": ["CVE-2026-4444"]}},
    )

    match = correlator.correlate(item)
    assert match is not None
    assert match.hunt_id == "H-0001"
    assert match.match_type == "cve"
    assert "CVE-2026-4444" in match.matched_entities
    assert match.confidence >= 0.85


def test_correlator_matches_existing_hunt_actor_alias(tmp_path: Path) -> None:
    hunts_dir = tmp_path / "hunts" / "2026"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0010.md"
    hunt_file.write_text(
        """---
hunt_id: H-0010
title: "APT28 Credential Harvesting Campaign"
actor: "APT28"
techniques: ["T1003"]
---
# H-0010: Russian GRU APT28 Operations
Targeting defense organizations.
""",
        encoding="utf-8",
    )

    correlator = ThreatEntityCorrelator(hunts_dir)
    # Incoming CTI cites the alias 'Fancy Bear'
    item = CTIItem(
        source="rss",
        identifier="item-02",
        title="Fancy Bear spearphishing campaign against European entities",
        content="Threat intelligence update detailing Fancy Bear activity using malicious attachments.",
    )

    match = correlator.correlate(item)
    assert match is not None
    assert match.hunt_id == "H-0010"
    assert match.match_type == "actor_alias"
    assert any("APT28" in e for e in match.matched_entities)
    assert match.confidence >= 0.80


def test_correlator_matches_existing_hunt_shared_c2(tmp_path: Path) -> None:
    hunts_dir = tmp_path / "hunts" / "2026"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0020.md"
    hunt_file.write_text(
        """---
hunt_id: H-0020
title: "Command and Control Infrastructure"
techniques: ["T1071.001"]
---
# H-0020: Cobalt Strike Operations
Observed C2 domains: `update-check-service.com`
""",
        encoding="utf-8",
    )

    correlator = ThreatEntityCorrelator(hunts_dir)
    item = CTIItem(
        source="abuse_ch",
        identifier="item-03",
        title="ThreatFox IOC update",
        content="New beacon callback IP resolving to update-check-service.com on port 443.",
        metadata={"indicators": {"domain": ["update-check-service.com"]}},
    )

    match = correlator.correlate(item)
    assert match is not None
    assert match.hunt_id == "H-0020"
    assert match.match_type == "shared_c2_ioc"
    assert "update-check-service.com" in match.matched_entities
    assert match.confidence >= 0.90


def test_correlator_ignores_unrelated_cti(tmp_path: Path) -> None:
    hunts_dir = tmp_path / "hunts" / "2026"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0030.md"
    hunt_file.write_text(
        """---
hunt_id: H-0030
title: "SolarWinds Supply Chain"
techniques: ["T1195.002"]
---
# H-0030: Supply Chain
SUNBURST backdoor.
""",
        encoding="utf-8",
    )

    correlator = ThreatEntityCorrelator(hunts_dir)
    item = CTIItem(
        source="rss",
        identifier="item-04",
        title="Unrelated Ransomware targeting healthcare",
        content="Novel ransomware strain deploying via compromised RDP with no shared indicators.",
    )

    match = correlator.correlate(item)
    assert match is None


def test_incremental_enricher_appends_indicators_and_rules(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    hunts_dir = workspace / "hunts" / "2026"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0001.md"
    hunt_file.write_text(
        """---
hunt_id: H-0001
title: "Adversaries exploiting CVE-2026-9000"
status: planning
techniques: ["T1190"]
---
# H-0001: CVE-2026-9000
Initial report on vulnerability.

## Queries / Detection Rules
Placeholder for queries.
""",
        encoding="utf-8",
    )

    correlator = ThreatEntityCorrelator(hunts_dir)
    item = CTIItem(
        source="misp",
        identifier="misp-01",
        title="New C2 infrastructure for CVE-2026-9000",
        source_url="https://misp.example.com/events/100",
        content="Observed new C2 callback domain new-c2-beacon.org and hash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        metadata={
            "indicators": {
                "cve": ["CVE-2026-9000"],
                "domain": ["new-c2-beacon.org"],
                "sha256": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            },
            "techniques": ["T1071.001"],
        },
    )

    match = correlator.correlate(item)
    assert match is not None

    result = IncrementalEnricher.enrich(item, match, workspace)
    assert result.hunt_id == "H-0001"
    assert result.new_indicators_count >= 2
    assert "T1071.001" in result.added_techniques

    # Check updated markdown file
    updated_text = hunt_file.read_text(encoding="utf-8")
    assert "last_enriched_at:" in updated_text
    assert 'techniques: ["T1071.001", "T1190"]' in updated_text
    assert "## Incremental Threat Intel Update" in updated_text
    assert "new-c2-beacon.org" in updated_text
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in updated_text

    # Check rule file created in queries/H-0001/
    queries_dir = workspace / "queries" / "H-0001"
    assert queries_dir.exists()
    rule_files = list(queries_dir.glob("*.yml"))
    assert len(rule_files) >= 1


def test_incremental_enricher_updates_indicator_sweep_inventory(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    hunts_dir = workspace / "hunts" / "2026"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0005.md"
    hunt_file.write_text(
        """---
hunt_id: H-0005
title: "Indicators published in Daily ThreatFox"
---
# H-0005: Daily ThreatFox Sweep
Attributes (2 total): domain (2)

Indicators:
- c2-alpha.net
- c2-beta.net
""",
        encoding="utf-8",
    )

    correlator = ThreatEntityCorrelator(hunts_dir)
    item = CTIItem(
        source="misp",
        identifier="misp-02",
        title="Daily ThreatFox delta",
        content="""
MISP Event: Daily ThreatFox delta
Attributes (3 total): domain (1), ip-dst (2)
""",
        metadata={
            "indicators": {
                "domain": ["c2-alpha.net", "c2-gamma.net"],
                "ip-dst": ["198.51.100.99", "198.51.100.100"],
            }
        },
    )

    # Shared domain c2-alpha.net correlates to H-0005
    match = correlator.correlate(item)
    assert match is not None
    assert match.hunt_id == "H-0005"

    IncrementalEnricher.enrich(item, match, workspace)
    updated_text = hunt_file.read_text(encoding="utf-8")

    # Inventory line counts updated
    assert "Attributes (5 total): domain (3), ip-dst (2)" in updated_text


def test_orchestrator_incremental_enrichment_flow(tmp_path: Path, monkeypatch: Any) -> None:
    workspace = tmp_path / "workspace"
    hunts_dir = workspace / "hunts" / "2026"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0001.md"
    hunt_file.write_text(
        """---
hunt_id: H-0001
title: "Exploitation of CVE-2026-7777"
techniques: ["T1190"]
---
# H-0001
Initial hunt.
""",
        encoding="utf-8",
    )

    settings = Settings(  # type: ignore[call-arg]
        _env_file=None,
        hecate_workspace=workspace,
        hunts_dir=workspace / "hunts",
        campaign_clustering_enabled=True,
        cti_provider="file",
    )

    matching_item = CTIItem(
        source="rss",
        identifier="rss-01",
        title="Further attacks observed for CVE-2026-7777",
        content="Adversaries using CVE-2026-7777 with new C2 domain novel-c2-beacon.org",
        metadata={
            "indicators": {
                "cve": ["CVE-2026-7777"],
                "domain": ["novel-c2-beacon.org"],
            }
        },
    )

    mock_cti = MagicMock()
    mock_cti.next_item.side_effect = [matching_item, None]

    mock_hecate = MagicMock()
    orch = Orchestrator(settings, mock_hecate, mock_cti)
    state = OrchestratorState()

    result = orch._run_body(state, dry_run=False)

    assert result.outcome == "incremental_enrichment"
    assert result.hunt_id == "H-0001"
    assert result.ok is True
    # CTI item was acknowledged
    mock_cti.acknowledge.assert_called_once_with(matching_item)

    # Hunt file was enriched
    updated = hunt_file.read_text(encoding="utf-8")
    assert "novel-c2-beacon.org" in updated
    assert "## Incremental Threat Intel Update" in updated


def test_threat_entity_profile_caching(tmp_path: Path) -> None:
    ThreatEntityCorrelator.clear_cache()
    from hecate_runner.correlation import _HUNT_PROFILE_CACHE

    assert len(_HUNT_PROFILE_CACHE) == 0

    hunts_dir = tmp_path / "hunts"
    hunts_dir.mkdir()
    hunt_file = hunts_dir / "H-0001.md"
    hunt_file.write_text(
        """---
title: Test Hunt 1
techniques: [T1059.001]
---
# Test Hunt 1
Active campaign using CVE-2026-1111 and C2 domain evil-c2-domain.com.
""",
        encoding="utf-8",
    )

    # Instance 1 indexes hunts
    correlator1 = ThreatEntityCorrelator(hunts_dir)
    profiles1 = correlator1.index_hunts()
    assert len(profiles1) == 1
    assert "CVE-2026-1111" in profiles1[0].cves
    assert len(_HUNT_PROFILE_CACHE) == 1

    # Instance 2 indexes hunts (reuses cached profile without reparsing)
    correlator2 = ThreatEntityCorrelator(hunts_dir)
    profiles2 = correlator2.index_hunts()
    assert len(profiles2) == 1
    assert profiles2[0] is profiles1[0]  # Exact same cached object

    # Now update hunt file
    hunt_file.write_text(
        """---
title: Test Hunt 1 Updated
techniques: [T1059.001]
---
# Test Hunt 1 Updated
Active campaign using CVE-2026-2222 and C2 domain evil-c2-domain.com.
""",
        encoding="utf-8",
    )

    correlator3 = ThreatEntityCorrelator(hunts_dir)
    profiles3 = correlator3.index_hunts()
    assert len(profiles3) == 1
    assert "CVE-2026-2222" in profiles3[0].cves
    assert profiles3[0].title == "Test Hunt 1 Updated"

    # clear_cache clears the profile cache
    ThreatEntityCorrelator.clear_cache()
    assert len(_HUNT_PROFILE_CACHE) == 0
