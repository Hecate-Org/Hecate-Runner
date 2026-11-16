"""Evidence-backed validation (#1) and living-dossier review hygiene (#2)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from hecate_runner.bas.forwarder import resolve_splunk_verify_ssl
from hecate_runner.bas.rule_selection import (
    load_sigma_from_query_dirs,
    select_primary_sigma_rule,
    sigma_rule_rank,
)
from hecate_runner.bas.siem_verifier import SiemAlertVerifier
from hecate_runner.config import Settings
from hecate_runner.correlation import EnrichmentResult
from hecate_runner.cti.base import CTIItem
from hecate_runner.github_publisher import (
    PromotionOutbox,
    public_hunt_text_for_promotion,
    snapshot_hunt_artifacts,
)
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.state import OrchestratorState


CORE_PHP = """
title: PHP Web Server Spawning Shell
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains: /php-fpm
  selection_child:
    Image|endswith: /bin/sh
  condition: selection_parent and selection_child
level: high
tags:
  - attack.t1505.003
"""

COMMAND_QUOTE = """
title: 'Command the source shows being run: python3 tooling/checker'
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: /python3
    CommandLine|contains: tooling/checker
  condition: selection
level: low
tags:
  - attack.t1505.003
"""

INCREMENTAL = """
title: H-0032 Incremental Campaign Detection (domain)
logsource:
  product: windows
  category: dns_query
detection:
  selection:
    QueryName: junk.example
  condition: selection
tags:
  - attack.t1505.003
"""


def _write_ranked_hunt(root: Path, hunt_id: str = "H-0032") -> Path:
    q = root / "queries" / hunt_id
    q.mkdir(parents=True)
    # Alphabetical first would be the command-quote / incremental names.
    (q / "aaa_command_the_source_shows.yml").write_text(COMMAND_QUOTE, encoding="utf-8")
    (q / "aaa_command_the_source_shows.spl").write_text(
        'Image="*python3*" CommandLine="*tooling/checker*"', encoding="utf-8"
    )
    (q / "dns__incremental_domain_1.yml").write_text(INCREMENTAL, encoding="utf-8")
    (q / "process_creation__php_shell.yml").write_text(CORE_PHP, encoding="utf-8")
    (q / "process_creation__php_shell.spl").write_text(
        'ParentImage="*php-fpm*" Image="*/bin/sh"', encoding="utf-8"
    )
    return q


def test_shared_ranking_prefers_behavioral_core_over_alphabetical() -> None:
    path = Path("process_creation__php_shell.yml")
    assert sigma_rule_rank(path, CORE_PHP)[0] < sigma_rule_rank(
        Path("aaa_command_the_source_shows.yml"), COMMAND_QUOTE
    )[0]
    assert sigma_rule_rank(Path("dns__incremental_domain_1.yml"), INCREMENTAL)[0] >= 100


def test_select_primary_and_siem_verifier_agree(tmp_path: Path) -> None:
    _write_ranked_hunt(tmp_path)
    selected = select_primary_sigma_rule(tmp_path / "queries" / "H-0032")
    assert selected is not None
    assert selected.name == "process_creation__php_shell.yml"
    assert "php-fpm" in selected.yaml_text
    assert "php-fpm" in selected.spl_query

    query, name, yaml_text = SiemAlertVerifier(tmp_path).resolve_candidate_rule("H-0032")
    assert name == selected.name
    assert query == selected.spl_query
    assert "php-fpm" in yaml_text

    loaded, path = load_sigma_from_query_dirs([tmp_path], "H-0032")
    assert path is not None and path.name == selected.name
    assert "php-fpm" in loaded


def test_loopback_ssl_defaults_align() -> None:
    assert resolve_splunk_verify_ssl({}, host_url="https://localhost:8089") is False
    assert resolve_splunk_verify_ssl({}, host_url="https://127.0.0.1:8089") is False
    assert resolve_splunk_verify_ssl({"SPLUNK_VERIFY_SSL": "true"}, host_url="https://localhost:8089")
    assert resolve_splunk_verify_ssl({}, host_url="https://splunk.example.com:8089") is True


def test_verify_synthetic_lab_query_reports_match(tmp_path: Path, monkeypatch: Any) -> None:
    _write_ranked_hunt(tmp_path)
    verifier = SiemAlertVerifier(tmp_path)

    class _Client:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

        def create_search_job(self, **kwargs: Any) -> str:
            assert "index=hecate_synthetic" in kwargs["query"]
            assert "php-fpm" in kwargs["query"]
            return "job-1"

        def get_search_job_status(self, sid: str) -> dict[str, Any]:
            return {"entry": [{"content": {"isDone": True}}]}

        def get_search_results(self, sid: str, count: int = 10) -> list[dict[str, Any]]:
            return [{"Image": "/bin/sh"}]

    monkeypatch.setenv("SPLUNK_HOST", "https://localhost:8089")
    monkeypatch.setenv("SPLUNK_PASSWORD", "changeme")
    monkeypatch.setattr(
        "hecate_agent.core.splunk_client.SplunkClient",
        _Client,
    )
    monkeypatch.setattr(
        "hecate_agent.core.splunk_credentials.splunk_token",
        lambda *_a, **_k: "",
    )

    result = verifier.verify_synthetic_lab_query(
        "H-0032", index="hecate_synthetic", settle_sec=0, max_attempts=1
    )
    assert result["ok"] is True
    assert result["status"] == "lab_query_match"
    assert result["rule"] == "process_creation__php_shell.yml"
    assert result["matched"] == 1


def test_outbox_supersedes_stale_awaiting_review(tmp_path: Path) -> None:
    outbox = PromotionOutbox(tmp_path / "outbox.sqlite3")
    outbox.enqueue("H-0001", "digest-a", {"hunts/x.md": "a\n"}, reviewed=False)
    outbox.enqueue("H-0001", "digest-b", {"hunts/x.md": "b\n"}, reviewed=False)
    with outbox._connect() as conn:
        rows = list(conn.execute("SELECT digest, status FROM promotions ORDER BY id"))
    assert rows[0]["status"] == "superseded"
    assert rows[1]["status"] == "awaiting_review"
    latest = outbox.latest_awaiting_review()
    assert latest[0]["digest"] == "digest-b"
    assert latest[0]["awaiting_count"] == 1


def test_public_snapshot_strips_ioc_appendices(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    hunts = workspace / "hunts" / "2026" / "Q4"
    hunts.mkdir(parents=True)
    queries = workspace / "queries" / "H-0001"
    queries.mkdir(parents=True)
    hunt_body = """---
hunt_id: H-0001
title: Test
status: planning
last_enriched_at: 2026-11-15T12:00:00+00:00
techniques: ["T1190"]
---
# H-0001
Behavioral core narrative.

---

## Incremental Threat Intel Update (2026-11-15T12:00:00Z)

> **Source:** [rss](https://example.com)
> **Correlation Match:** `cve` on `CVE-2026-1` (Confidence: 0.90)
> **Summary:** More IOCs

### Newly Added Campaign Indicators

| Type | Value | First Observed |
|---|---|---|
| Domain | `evil.example` | 2026-11-15 |

### Detection Notes
_IOCs recorded in this dossier only. Behavioral Sigma under ``queries/H-0001/`` is not auto-extended with incremental IOC stubs._
"""
    (hunts / "H-0001.md").write_text(hunt_body, encoding="utf-8")
    (queries / "core.yml").write_text(
        "title: Core\ndetection:\n  selection:\n    a: 1\n  condition: selection\n",
        encoding="utf-8",
    )
    settings = Settings(_env_file=None, hecate_workspace=workspace)  # type: ignore[call-arg]

    stripped = public_hunt_text_for_promotion(hunt_body)
    assert "Incremental Threat Intel Update" not in stripped
    assert "evil.example" not in stripped
    assert "last_enriched_at" not in stripped
    assert "Behavioral core narrative" in stripped

    files, digest1 = snapshot_hunt_artifacts(settings, "H-0001")
    assert "Incremental Threat Intel Update" not in files["hunts/2026/Q4/H-0001.md"]

    # Further IOC-only enrich does not change the publish digest.
    (hunts / "H-0001.md").write_text(
        hunt_body
        + "\n---\n\n## Incremental Threat Intel Update (2026-11-15T13:00:00Z)\n\nmore iocs\n",
        encoding="utf-8",
    )
    _files2, digest2 = snapshot_hunt_artifacts(settings, "H-0001")
    assert digest1 == digest2


def test_enrichment_skips_github_publish_keeps_misp(tmp_path: Path, monkeypatch: Any) -> None:
    workspace = tmp_path / "workspace"
    hunts_dir = workspace / "hunts" / "2026"
    hunts_dir.mkdir(parents=True)
    (hunts_dir / "H-0001.md").write_text(
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
        github_publishing_enabled=True,
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
    orch = Orchestrator(settings, MagicMock(), mock_cti)
    calls: list[str] = []
    monkeypatch.setattr(orch, "_publish_github", lambda hid: calls.append(f"gh:{hid}"))
    monkeypatch.setattr(orch, "_publish_misp", lambda hid: calls.append(f"misp:{hid}"))
    monkeypatch.setattr(orch, "_notify_cycle", lambda result: calls.append("notify"))

    result = orch._run_body(OrchestratorState(), dry_run=False)
    assert result.outcome == "incremental_enrichment"
    assert "gh:H-0001" not in calls
    assert "misp:H-0001" in calls
    assert "notify" in calls


def test_material_for_public_promote_requires_rules() -> None:
    base = EnrichmentResult(
        hunt_id="H-0001",
        hunt_path=Path("x"),
        new_indicators_count=2,
        new_rules_count=0,
        added_techniques=[],
        rule_paths=[],
        details="ioc only",
        changed=True,
    )
    assert base.material_for_public_promote is False
    with_rules = EnrichmentResult(
        hunt_id="H-0001",
        hunt_path=Path("x"),
        new_indicators_count=0,
        new_rules_count=1,
        added_techniques=[],
        rule_paths=["queries/H-0001/a.yml"],
        details="rule",
        changed=True,
    )
    assert with_rules.material_for_public_promote is True


# --- Edge cases ---


def test_incremental_only_dir_does_not_become_primary(tmp_path: Path) -> None:
    q = tmp_path / "queries" / "H-0099"
    q.mkdir(parents=True)
    (q / "dns__incremental_domain_1.yml").write_text(INCREMENTAL, encoding="utf-8")
    (q / "dns__incremental_domain_1.spl").write_text('QueryName="junk"', encoding="utf-8")
    assert select_primary_sigma_rule(q) is None
    # Falls through to native .spl (non-incremental only — incremental .spl skipped)
    query, name, yaml_text = SiemAlertVerifier(tmp_path).resolve_candidate_rule("H-0099")
    assert yaml_text == ""
    assert query == ""  # incremental .spl also skipped
    assert name == ""


def test_technique_filter_ranks_among_matches_only(tmp_path: Path) -> None:
    q = tmp_path / "queries" / "H-0042"
    q.mkdir(parents=True)
    (q / "process_creation__php_shell.yml").write_text(CORE_PHP, encoding="utf-8")
    (q / "process_creation__php_shell.spl").write_text("php", encoding="utf-8")
    other = """
title: Whoami
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: /whoami
  condition: selection
level: high
tags:
  - attack.t1033
"""
    (q / "t1033_whoami.yml").write_text(other, encoding="utf-8")
    (q / "t1033_whoami.spl").write_text("whoami", encoding="utf-8")
    # Without filter, php parent→child ranks better than plain process_creation.
    assert select_primary_sigma_rule(q).name == "process_creation__php_shell.yml"
    # With T1033 filter, only whoami competes.
    selected = select_primary_sigma_rule(q, technique_id="T1033")
    assert selected is not None
    assert selected.name == "t1033_whoami.yml"
    query, name, _ = SiemAlertVerifier(tmp_path).resolve_candidate_rule("H-0042", "T1033")
    assert name == "t1033_whoami.yml"
    assert query == "whoami"


def test_skips_non_sigma_and_unreadable(tmp_path: Path) -> None:
    q = tmp_path / "queries" / "H-0050"
    q.mkdir(parents=True)
    (q / "readme.yml").write_text("just notes\nno detection here\n", encoding="utf-8")
    (q / "core.yml").write_text(CORE_PHP, encoding="utf-8")
    bad = q / "locked.yml"
    bad.write_text(CORE_PHP, encoding="utf-8")
    bad.chmod(0o000)
    try:
        selected = select_primary_sigma_rule(q)
        assert selected is not None
        assert selected.name == "core.yml"
    finally:
        bad.chmod(0o644)


def test_native_only_skips_incremental_spl(tmp_path: Path) -> None:
    q = tmp_path / "queries" / "H-0051"
    q.mkdir(parents=True)
    (q / "zzz_incremental_ioc.spl").write_text('QueryName="evil"', encoding="utf-8")
    (q / "t1033.spl").write_text('Image="*whoami*"', encoding="utf-8")
    query, name, yaml_text = SiemAlertVerifier(tmp_path).resolve_candidate_rule(
        "H-0051", "T1033"
    )
    assert name == "t1033.spl"
    assert query == 'Image="*whoami*"'
    assert yaml_text == ""


def test_lab_proof_no_credentials_and_no_spl(tmp_path: Path, monkeypatch: Any) -> None:
    q = tmp_path / "queries" / "H-0052"
    q.mkdir(parents=True)
    (q / "core.yml").write_text(CORE_PHP, encoding="utf-8")
    # No companion .spl
    monkeypatch.delenv("SPLUNK_HOST", raising=False)
    monkeypatch.delenv("SPLUNK_URL", raising=False)
    monkeypatch.delenv("SPLUNK_PASSWORD", raising=False)
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    result = SiemAlertVerifier(tmp_path).verify_synthetic_lab_query("H-0052")
    assert result["ok"] is False
    assert result["status"] == "no_companion_spl"

    (q / "core.spl").write_text("ParentImage=*php-fpm*", encoding="utf-8")
    result2 = SiemAlertVerifier(tmp_path).verify_synthetic_lab_query("H-0052")
    assert result2["ok"] is False
    assert result2["status"] == "unconfigured_credentials"


def test_normalize_spl_respects_lab_index() -> None:
    v = SiemAlertVerifier(Path("/tmp"))
    assert v._normalize_spl_query('Image="*x*"').startswith("index=* |")
    assert v._normalize_spl_query('Image="*x*"', index="hecate_synthetic").startswith(
        "index=hecate_synthetic |"
    )
    # Lab proof rewrites a pinned production index so synthetic events are visible.
    forced = v._normalize_spl_query("index=main Image=*x*", index="hecate_synthetic")
    assert forced.startswith("index=hecate_synthetic")
    assert "Image=*x*" in forced
    assert "index=main" not in forced

    # Idempotent: do not double-wrap already-normalized lab SPL.
    once = v._force_lab_index('Image="*x*"', "hecate_synthetic")
    twice = v._force_lab_index(once, "hecate_synthetic")
    assert once == twice
    assert once.count("| spath | search") == 1

    # Preserve pipelines; do not stuff tstats under spath/search.
    piped = v._force_lab_index("index=main | tstats count where index=main", "hecate_synthetic")
    assert piped == "index=hecate_synthetic | tstats count where index=main"

    # Leading INDEX= (case variants) must still pin the lab index.
    upper = v._force_lab_index("INDEX=main Image=x", "hecate_synthetic")
    assert upper == "index=hecate_synthetic | spath | search Image=x"
    assert v._force_lab_index(upper, "hecate_synthetic") == upper
    assert v._force_lab_index("", "hecate_synthetic") == "index=hecate_synthetic"


def test_strip_ioc_without_horizontal_rule_and_multi() -> None:
    text = """---
hunt_id: H-0001
last_enriched_at: 2026-11-15T12:00:00+00:00
---
# H-0001
Core stays.

## Incremental Threat Intel Update (2026-11-15T12:00:00Z)

orphan block without ---

---

## Incremental Threat Intel Update (2026-11-15T13:00:00Z)

second block
"""
    stripped = public_hunt_text_for_promotion(text)
    assert "Incremental Threat Intel Update" not in stripped
    assert "orphan" not in stripped
    assert "second block" not in stripped
    assert "last_enriched_at" not in stripped
    assert "Core stays." in stripped


def test_enqueue_revives_superseded_digest_and_spares_queued(
    tmp_path: Path,
) -> None:
    outbox = PromotionOutbox(tmp_path / "outbox.sqlite3")
    outbox.enqueue("H-0001", "digest-a", {"a": "1"}, reviewed=False)
    outbox.enqueue("H-0001", "digest-b", {"b": "2"}, reviewed=False)
    # digest-a superseded; promote a queued sibling that must survive.
    outbox.enqueue("H-0001", "digest-queued", {"q": "3"}, reviewed=True)
    with outbox._connect() as conn:
        by_digest = {
            r["digest"]: r["status"]
            for r in conn.execute("SELECT digest, status FROM promotions")
        }
    assert by_digest["digest-a"] == "superseded"
    assert by_digest["digest-b"] == "superseded"  # awaiting tip cleared by queued enqueue
    assert by_digest["digest-queued"] == "queued"

    # Oscillate back to digest-a content → revive as awaiting_review tip.
    assert outbox.enqueue("H-0001", "digest-a", {"a": "1"}, reviewed=False) == "awaiting_review"
    with outbox._connect() as conn:
        by_digest = {
            r["digest"]: r["status"]
            for r in conn.execute("SELECT digest, status FROM promotions")
        }
    assert by_digest["digest-a"] == "awaiting_review"
    assert by_digest["digest-queued"] == "queued"  # must not be superseded
    latest = outbox.latest_awaiting_review()
    assert latest[0]["digest"] == "digest-a"
    assert latest[0]["awaiting_count"] == 1


def test_enqueue_approve_revives_superseded_to_queued(tmp_path: Path) -> None:
    outbox = PromotionOutbox(tmp_path / "outbox.sqlite3")
    outbox.enqueue("H-0001", "digest-a", {"a": "1"}, reviewed=False)
    outbox.enqueue("H-0001", "digest-b", {"b": "2"}, reviewed=False)
    assert outbox.enqueue("H-0001", "digest-a", {"a": "1"}, reviewed=True) == "queued"
    with outbox._connect() as conn:
        statuses = {
            r["digest"]: r["status"]
            for r in conn.execute("SELECT digest, status FROM promotions")
        }
    assert statuses["digest-a"] == "queued"
    assert statuses["digest-b"] == "superseded"


def test_snapshot_stable_when_only_last_enriched_changes(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    hunts = workspace / "hunts" / "2026" / "Q4"
    hunts.mkdir(parents=True)
    (hunts / "H-0001.md").write_text(
        "---\nhunt_id: H-0001\ntitle: T\nstatus: planning\n---\n# H-0001\nBody.\n",
        encoding="utf-8",
    )
    settings = Settings(_env_file=None, hecate_workspace=workspace)  # type: ignore[call-arg]
    _f1, d1 = snapshot_hunt_artifacts(settings, "H-0001")
    (hunts / "H-0001.md").write_text(
        "---\nhunt_id: H-0001\ntitle: T\nstatus: planning\n"
        "last_enriched_at: 2026-11-15T99:00:00+00:00\n---\n# H-0001\nBody.\n",
        encoding="utf-8",
    )
    _f2, d2 = snapshot_hunt_artifacts(settings, "H-0001")
    assert d1 == d2


def test_dual_workspace_roots_prefer_best_rank(tmp_path: Path) -> None:
    ws = tmp_path / "private"
    pub = tmp_path / "public"
    for root, body, name in (
        (ws, COMMAND_QUOTE, "aaa.yml"),
        (pub, CORE_PHP, "zzz_php.yml"),
    ):
        q = root / "queries" / "H-0032"
        q.mkdir(parents=True)
        (q / name).write_text(body, encoding="utf-8")
    text, path = load_sigma_from_query_dirs([ws, pub], "H-0032")
    assert path is not None
    assert path.name == "zzz_php.yml"
    assert "php-fpm" in text


def test_empty_query_dir_and_missing_hunt(tmp_path: Path) -> None:
    (tmp_path / "queries" / "H-0000").mkdir(parents=True)
    assert select_primary_sigma_rule(tmp_path / "queries" / "H-0000") is None
    assert SiemAlertVerifier(tmp_path).resolve_candidate_rule("H-MISSING") == ("", "", "")
    assert load_sigma_from_query_dirs([tmp_path], "H-MISSING") == ("", None)


def test_lab_proof_uses_explicit_rule_not_reranked_primary(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Synthesizing a non-primary YAML must lab-search that rule's companion SPL."""
    _write_ranked_hunt(tmp_path)
    jobs: list[str] = []

    class _Client:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def create_search_job(self, **kwargs: Any) -> str:
            jobs.append(kwargs["query"])
            return "job-x"

        def get_search_job_status(self, sid: str) -> dict[str, Any]:
            return {"entry": [{"content": {"isDone": True}}]}

        def get_search_results(self, sid: str, count: int = 10) -> list[dict[str, Any]]:
            return [{"ok": 1}]

    monkeypatch.setenv("SPLUNK_HOST", "https://localhost:8089")
    monkeypatch.setenv("SPLUNK_PASSWORD", "changeme")
    monkeypatch.setattr("hecate_agent.core.splunk_client.SplunkClient", _Client)
    monkeypatch.setattr(
        "hecate_agent.core.splunk_credentials.splunk_token", lambda *_a, **_k: ""
    )

    explicit = 'CommandLine="*tooling/checker*"'
    result = SiemAlertVerifier(tmp_path).verify_synthetic_lab_query(
        "H-0032",
        index="hecate_synthetic",
        spl_query=explicit,
        rule_name="aaa_command_the_source_shows.yml",
        settle_sec=0,
        max_attempts=1,
    )
    assert result["ok"] is True
    assert result["rule"] == "aaa_command_the_source_shows.yml"
    assert "tooling/checker" in jobs[0]
    assert "php-fpm" not in jobs[0]


def test_lab_proof_caps_splunk_job_creation(tmp_path: Path, monkeypatch: Any) -> None:
    _write_ranked_hunt(tmp_path)
    creates = {"n": 0}

    class _Client:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def create_search_job(self, **kwargs: Any) -> str:
            creates["n"] += 1
            return f"job-{creates['n']}"

        def get_search_job_status(self, sid: str) -> dict[str, Any]:
            return {"entry": [{"content": {"isDone": True}}]}

        def get_search_results(self, sid: str, count: int = 10) -> list[dict[str, Any]]:
            return []  # miss every time → should still cap attempts

    monkeypatch.setenv("SPLUNK_HOST", "https://localhost:8089")
    monkeypatch.setenv("SPLUNK_PASSWORD", "changeme")
    monkeypatch.setattr("hecate_agent.core.splunk_client.SplunkClient", _Client)
    monkeypatch.setattr(
        "hecate_agent.core.splunk_credentials.splunk_token", lambda *_a, **_k: ""
    )

    SiemAlertVerifier(tmp_path).verify_synthetic_lab_query(
        "H-0032",
        index="hecate_synthetic",
        settle_sec=0,
        max_attempts=3,
        max_wait_sec=30,
    )
    assert creates["n"] == 3


def test_technique_token_does_not_prefix_match() -> None:
    from hecate_runner.bas.rule_selection import rule_matches_technique

    path = Path("t1003_lsass.yml")
    content = "tags: [attack.t1003.001]\n"
    assert rule_matches_technique(path, content, "T1003") is True
    assert rule_matches_technique(path, content, "T1003.001") is True
    assert rule_matches_technique(path, content, "T100") is False
    assert rule_matches_technique(Path("other.yml"), "mentions t1003.001 elsewhere", "T1059") is False


def test_await_review_supersedes_sibling_awaiting(tmp_path: Path) -> None:
    outbox = PromotionOutbox(tmp_path / "outbox.sqlite3")
    outbox.enqueue("H-0001", "digest-new", {"a": "2"}, reviewed=True)
    with outbox._connect() as conn:
        # Legacy/race: another awaiting_review sibling exists beside the tip.
        conn.execute(
            """INSERT INTO promotions
               (hunt_id,digest,payload,status,branch,created_at,updated_at)
               VALUES ('H-0001','digest-stale','{}','awaiting_review','b','t','t')"""
        )
        row = conn.execute(
            "SELECT id FROM promotions WHERE digest='digest-new'"
        ).fetchone()
    outbox.await_review(int(row["id"]))
    with outbox._connect() as conn:
        statuses = {
            r["digest"]: r["status"]
            for r in conn.execute("SELECT digest, status FROM promotions")
        }
    assert statuses["digest-new"] == "awaiting_review"
    assert statuses["digest-stale"] == "superseded"


def test_load_sigma_does_not_match_longer_hunt_id_prefix(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    (root / "queries" / "H-00320").mkdir(parents=True)
    (root / "queries" / "H-00320" / "core.yml").write_text(CORE_PHP, encoding="utf-8")
    # No H-0032 dir — recursive fallback must not pick H-00320 via H-0032* glob.
    text, path = load_sigma_from_query_dirs([root], "H-0032")
    assert text == ""
    assert path is None


def test_snapshot_permission_error_is_publisher_error(tmp_path: Path) -> None:
    from hecate_runner.github_publisher import PublisherError

    workspace = tmp_path / "workspace"
    hunts = workspace / "hunts" / "2026" / "Q4"
    hunts.mkdir(parents=True)
    hunt = hunts / "H-0001.md"
    hunt.write_text(
        "---\nhunt_id: H-0001\ntitle: T\nstatus: planning\n---\n# H-0001\nBody.\n",
        encoding="utf-8",
    )
    settings = Settings(_env_file=None, hecate_workspace=workspace)  # type: ignore[call-arg]
    mode = hunt.stat().st_mode
    hunt.chmod(0o000)
    try:
        try:
            snapshot_hunt_artifacts(settings, "H-0001")
            raise AssertionError("expected PublisherError")
        except PublisherError as exc:
            assert "permission or io error" in str(exc).lower()
        except PermissionError as exc:  # pragma: no cover - regression guard
            raise AssertionError(f"leaked PermissionError: {exc}") from exc
    finally:
        hunt.chmod(mode)


def test_select_primary_survives_unreadable_companion_spl(tmp_path: Path) -> None:
    q = tmp_path / "queries" / "H-0001"
    q.mkdir(parents=True)
    (q / "core.yml").write_text(CORE_PHP, encoding="utf-8")
    spl = q / "core.spl"
    spl.write_text('Image="*/bin/sh"', encoding="utf-8")
    mode = spl.stat().st_mode
    spl.chmod(0o000)
    try:
        selected = select_primary_sigma_rule(q)
        assert selected is not None
        assert selected.name == "core.yml"
        assert selected.spl_query == ""
        query, name, yaml_text = SiemAlertVerifier(tmp_path).resolve_candidate_rule("H-0001")
        assert name == "core.yml"
        assert query == ""
        assert "php-fpm" in yaml_text
    finally:
        spl.chmod(mode)


def test_enqueue_revives_retry_but_not_publishing(tmp_path: Path) -> None:
    outbox = PromotionOutbox(tmp_path / "outbox.sqlite3")
    outbox.enqueue("H-0001", "digest-a", {"a": "1"}, reviewed=True)
    with outbox._connect() as conn:
        conn.execute("UPDATE promotions SET status='retry' WHERE digest='digest-a'")
    assert outbox.enqueue("H-0001", "digest-a", {"a": "1"}, reviewed=True) == "queued"

    with outbox._connect() as conn:
        conn.execute("UPDATE promotions SET status='publishing' WHERE digest='digest-a'")
    assert outbox.enqueue("H-0001", "digest-a", {"a": "1"}, reviewed=True) == "publishing"


def test_strip_handles_crlf_incremental_blocks() -> None:
    text = (
        "---\r\nhunt_id: H-0001\r\n---\r\n# H-0001\r\nCore.\r\n\r\n"
        "---\r\n\r\n## Incremental Threat Intel Update (2026-11-15T12:00:00Z)\r\n\r\nioc\r\n"
    )
    stripped = public_hunt_text_for_promotion(text)
    assert "Incremental Threat Intel Update" not in stripped
    assert "ioc" not in stripped
    assert "Core." in stripped
    assert "\r" not in stripped


def test_strip_preserves_following_non_incremental_section() -> None:
    text = """---
hunt_id: H-0001
---
# H-0001
Core.

---

## Incremental Threat Intel Update (2026-11-15T12:00:00Z)

ioc

---

## Detection Logic

Keep me.
"""
    stripped = public_hunt_text_for_promotion(text)
    assert "Detection Logic" in stripped
    assert "Keep me." in stripped
    assert "ioc" not in stripped


def test_compact_heals_legacy_stacked_awaiting(tmp_path: Path) -> None:
    """Pre-hygiene outboxes stacked awaiting_review without superseding."""
    outbox = PromotionOutbox(tmp_path / "outbox.sqlite3")
    with outbox._connect() as conn:
        now = "2026-11-15T00:00:00+00:00"
        for i, digest in enumerate(("old", "mid", "tip")):
            conn.execute(
                """INSERT INTO promotions
                   (hunt_id,digest,payload,status,branch,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    "H-0001",
                    digest,
                    "{}",
                    "awaiting_review",
                    f"branch-{i}",
                    now,
                    now,
                ),
            )
    assert outbox.compact_stale_awaiting_review() == 2
    latest = outbox.latest_awaiting_review()
    assert latest[0]["digest"] == "tip"
    assert latest[0]["awaiting_count"] == 1
    with outbox._connect() as conn:
        statuses = {
            r["digest"]: r["status"]
            for r in conn.execute("SELECT digest, status FROM promotions")
        }
    assert statuses == {"old": "superseded", "mid": "superseded", "tip": "awaiting_review"}
