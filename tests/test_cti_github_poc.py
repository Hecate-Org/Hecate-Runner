"""Unit tests for GitHub PoC Monitor CTI provider."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti import get_provider
from hecate_runner.cti.github_poc import (
    GitHubPocCursorState,
    GitHubPocProvider,
)


@pytest.fixture
def temp_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir(parents=True)
    return ws


def test_github_poc_cursor_persistence(temp_workspace: Path) -> None:
    cursor_file = temp_workspace / ".cursors" / "github_poc_cursor.json"
    state = GitHubPocCursorState.from_file(cursor_file)
    assert state.seen_repos == []

    state.record_repo("vuln-researcher/cve-2026-1234-poc", cursor_file)
    assert cursor_file.exists()

    reloaded = GitHubPocCursorState.from_file(cursor_file)
    assert "vuln-researcher/cve-2026-1234-poc" in reloaded.seen_repos

    # Record duplicate
    reloaded.record_repo("vuln-researcher/cve-2026-1234-poc", cursor_file)
    assert len(reloaded.seen_repos) == 1


def test_github_poc_search_api_parsing(temp_workspace: Path) -> None:
    provider = GitHubPocProvider(workspace=temp_workspace)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "items": [
            {
                "full_name": "attacker/CVE-2026-8888-rce",
                "html_url": "https://github.com/attacker/CVE-2026-8888-rce",
                "description": "Functional RCE exploit for CVE-2026-8888 in Apache Solr",
                "stargazers_count": 5,
                "updated_at": "2026-10-21T02:00:00Z",
            },
            {
                "full_name": "boring/non-cve-repo",
                "html_url": "https://github.com/boring/non-cve-repo",
                "description": "Just some random code",
                "stargazers_count": 0,
            },
        ]
    }

    with patch("httpx.get", return_value=mock_resp):
        candidates = provider._fetch_from_search_api()
        assert len(candidates) == 1
        cand = candidates[0]
        assert cand["full_name"] == "attacker/CVE-2026-8888-rce"
        assert "CVE-2026-8888" in cand["cves"]
        assert cand["stars"] == 5


def test_github_poc_search_api_rate_limit_fallback(temp_workspace: Path) -> None:
    provider = GitHubPocProvider(workspace=temp_workspace)

    r403 = MagicMock(status_code=403)
    r_curated = MagicMock(status_code=200)
    r_curated.text = (
        "### CVE-2026-5555 (2026-10-20)\n"
        "<code>Remote code execution flaw in Ivanti Connect Secure</code>\n"
        "- [exploit-author/ivanti-poc](https://github.com/exploit-author/ivanti-poc)\n"
    )

    def fake_get(url, *args, **kwargs):
        if "api.github.com/search" in url:
            return r403
        elif "raw.githubusercontent.com" in url:
            return r_curated
        return MagicMock(status_code=404)

    with patch("httpx.get", side_effect=fake_get):
        candidates = provider._fetch_from_search_api()
        assert len(candidates) == 1
        assert candidates[0]["full_name"] == "exploit-author/ivanti-poc"
        assert candidates[0]["cves"] == ["CVE-2026-5555"]


def test_extract_poc_artifacts_and_blurb(temp_workspace: Path) -> None:
    provider = GitHubPocProvider(workspace=temp_workspace)

    repo_data = {
        "full_name": "rapid7/CVE-2026-7777-poc",
        "html_url": "https://github.com/rapid7/CVE-2026-7777-poc",
        "description": "Proof of concept exploit for CVE-2026-7777 authentication bypass in FortiOS",
        "stars": 12,
    }

    readme = """
# CVE-2026-7777 FortiOS Exploit

This vulnerability allows unauthenticated attackers to achieve Remote Code Execution.

## Usage

```bash
python3 exploit.py -u https://target:8443/api/v2/cmdb -c id
```

Target port is 8443.
    """

    artifacts = provider._extract_poc_artifacts(repo_data, readme)
    assert artifacts["cve"] == "CVE-2026-7777"
    assert "Remote Code Execution" in artifacts["vuln_type"]
    assert [c for c, _ in artifacts["commands"]] == [
        "python3 exploit.py -u https://target:8443/api/v2/cmdb -c id"
    ]
    assert [e for e, _ in artifacts["endpoints"]] == ["/api/v2/cmdb"]
    assert "8443" in [p for p, _ in artifacts["ports"]]

    blurb = provider._build_blurb(repo_data, artifacts)
    assert "Title: GitHub repository referencing CVE-2026-7777" in blurb
    assert "Source: GitHub PoC Monitor (rapid7/CVE-2026-7777-poc)" in blurb
    assert "python3 exploit.py -u https://target:8443/api/v2/cmdb -c id" in blurb
    assert "MITRE ATT&CK Techniques: T1190 (Exploit Public-Facing Application)" in blurb
    assert "T1059" not in blurb


def _artifacts(readme: str, full_name: str = "someone/CVE-2026-1111-poc", desc: str = ""):
    provider = GitHubPocProvider(workspace=Path("/nonexistent"))
    repo = {
        "full_name": full_name,
        "html_url": f"https://github.com/{full_name}",
        "description": desc,
    }
    artifacts = provider._extract_poc_artifacts(repo, readme)
    return artifacts, provider._build_blurb(repo, artifacts)


def test_no_command_is_invented_when_readme_has_none() -> None:
    artifacts, blurb = _artifacts(
        "# Draft\n\n```sh\n$ make\n$ git push origin main\n```\n",
        full_name="researcher/intra-handshake-fail",
        desc="Early Attestation Considered Very Harmful (CVE-2026-100833)",
    )

    assert artifacts["commands"] == []
    assert artifacts["endpoints"] == []
    assert "exploit.py" not in blurb
    assert "quotes no runnable command" in blurb
    assert artifacts["vuln_type"] == "Unclassified"
    assert "MITRE ATT&CK Techniques:" not in blurb
    assert "functional" not in blurb.lower()


def test_fences_pair_correctly_after_non_shell_block() -> None:
    readme = (
        "```php\n$msg = preg_replace('/%%(.+?)%%/i', '', $msg);\n```\n\n"
        "Payload:\n\n```text\n<%%x%%?php echo 1; ?>\n```\n\n"
        "```bash\npython3 poc.py https://wordpress.lab\n```\n"
    )
    artifacts, _ = _artifacts(readme)
    assert [c for c, _ in artifacts["commands"]] == ["python3 poc.py https://wordpress.lab"]


def test_repo_names_reference_links_and_loopback_are_not_targets() -> None:
    readme = (
        "[stars](https://github.com/someone/CVE-2026-1111-poc/stargazers)\n\n"
        "```bash\n"
        "python3 poc.py https://victim.lab --http-proxy http://127.0.0.1:8080\n"
        "# docs: https://example.org/docs/hardening\n"
        "```\n\n"
        "```text\n[+] wrote https://victim.lab/cve_test.php\n```\n"
    )
    artifacts, _ = _artifacts(readme)

    assert [e for e, _ in artifacts["endpoints"]] == ["/cve_test.php"]
    assert artifacts["ports"] == []


def test_lab_setup_commands_are_skipped_and_exploit_ranked_first() -> None:
    readme = (
        "```bash\npython3 setup.py\npython3 setup.py --teardown\n"
        "python3 check.py http://192.0.2.10:1880\n```\n\n"
        "```bash\npython3 poc.py http://192.0.2.10:1880 --cmd id    # runs `id`\n```\n\n"
        "The admin API listens on TCP/1880. Exploit sends `POST /flows`.\n"
    )
    artifacts, blurb = _artifacts(readme, desc="Node-RED unauthenticated RCE")

    assert [c for c, _ in artifacts["commands"]] == [
        "python3 poc.py http://192.0.2.10:1880 --cmd id",
        "python3 check.py http://192.0.2.10:1880",
    ]
    assert [p for p, _ in artifacts["ports"]] == ["1880"]
    assert "/flows" in [e for e, _ in artifacts["endpoints"]]
    assert '"The admin API listens on TCP/1880. Exploit sends `POST /flows`."' in blurb


def test_commands_quoted_only_in_usage_sections_are_not_marked_active() -> None:
    """H-0019's blurb listed the tester's own `python3 poc.py` run as active."""
    readme = (
        "## Usage\n\n```bash\npython3 poc.py http://192.0.2.10:1880\n```\n\n"
        "## Downstream Impact\n\n```bash\ncurl -s http://device:1880/flows\n```\n\n"
        "The admin API listens on TCP/1880. Exploit sends `POST /flows`.\n"
    )
    _, blurb = _artifacts(readme, desc="Node-RED unauthenticated RCE")
    assert (
        "| `python3 poc.py http://192.0.2.10:1880` | command_line | attacker_tooling | unknown |"
        in blurb
    )
    assert (
        "| `curl -s http://device:1880/flows` | command_line | attacker_tooling | active |" in blurb
    )
    assert "| `/flows` | url_path | target_endpoint | active |" in blurb


def test_cve_row_does_not_ask_for_rules() -> None:
    _, blurb = _artifacts("```bash\n./exploit --escalate\n```\n", desc="Linux kernel LPE")
    assert "none: an identifier, not a log observable" in blurb
    assert "T1068 (Exploitation for Privilege Escalation)" in blurb


def test_next_item_and_acknowledge(temp_workspace: Path) -> None:
    provider = GitHubPocProvider(workspace=temp_workspace)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "items": [
            {
                "full_name": "sec-team/CVE-2026-9001-exploit",
                "html_url": "https://github.com/sec-team/CVE-2026-9001-exploit",
                "description": "LPE exploit for CVE-2026-9001 in Linux Kernel",
                "stargazers_count": 3,
                "updated_at": "2026-10-21T03:00:00Z",
            }
        ]
    }

    mock_readme = MagicMock()
    mock_readme.status_code = 200
    mock_readme.json.return_value = {
        "content": "IyBFeHBsb2l0CgpgLi9wb2MgLS1lc2NhbGF0ZQpg"  # "# Exploit\n`./poc --escalate`"
    }

    def fake_get(url, *args, **kwargs):
        if "api.github.com/search" in url:
            return mock_resp
        elif "api.github.com/repos" in url and "readme" in url:
            return mock_readme
        return MagicMock(status_code=404)

    with patch("httpx.get", side_effect=fake_get):
        item = provider.next_item()
        assert item is not None
        assert item.source == "github_poc"
        assert item.identifier == "sec-team/CVE-2026-9001-exploit"
        assert item.metadata["cve_id"] == "CVE-2026-9001"

        # Acknowledge the item
        provider.acknowledge(item)

        # Calling next_item again should return None because it is now seen
        assert provider.next_item() is None


def test_get_provider_factory(temp_workspace: Path) -> None:
    settings = Settings(
        hecate_workspace=temp_workspace,
        cti_provider="github_poc",
        github_token="ghp_test12345",
    )
    p = get_provider("github_poc", settings=settings)
    assert isinstance(p, GitHubPocProvider)
    assert p.github_token == "ghp_test12345"


def test_technique_evidence_from_a_poc_readme_leaves_out_its_tooling_and_html() -> None:
    """H-0018 took T1105 from the lab setup and T1059.006 from a badge's alt text."""
    from types import SimpleNamespace

    from hecate_runner.cti.base import CTIItem
    from hecate_runner.orchestrator import Orchestrator

    readme = (
        '<p><img src="https://img.shields.io/badge/python-3.8-blue" alt="Python"></p>\n\n'
        "## Lab setup\n\nDownloads npm-shrinkwrap.json and builds the image.\n\n"
        "## Impact\n\nUnauthenticated remote code execution as root.\n"
    )
    orch = Orchestrator.__new__(Orchestrator)
    orch._source_evidence = SimpleNamespace(text=readme)
    text = orch._technique_text(CTIItem(content="blurb", source="github_poc"))
    assert "remote code execution" in text
    assert "Downloads" not in text and "Python" not in text
    assert "Downloads" in orch._technique_text(CTIItem(content="blurb", source="blog"))


def test_state_changing_requests_outside_usage_sections_become_reference_requests() -> None:
    """H-0019 had no rule for its main technique: the README's `POST /flows` deploy."""
    from hecate_runner.cti.reference_rules import reference_candidates

    readme = (
        "## Usage\n\n`POST /api/lab-reset` resets the lab.\n\n"
        "## The Bug\n\nAnyone can read flows with `GET /flows` and deploy one through "
        "`POST /flows`; the PoC sends POST http://127.0.0.1:1880/flows again to restore.\n"
    )
    artifacts, _ = _artifacts(readme, desc="Node-RED unauthenticated RCE")
    assert artifacts["http_requests"] == [
        {"method": "POST", "path": ["/flows"], "origin": "readme"}
    ]
    [rule] = reference_candidates({"http_requests": artifacts["http_requests"]})
    assert rule["title"] == "Hunting lead: POST /flows as the PoC README documents"
    assert rule["detection"]["selection"] == {"cs-method": "POST", "cs-uri-stem": "/flows"}


def test_a_readme_request_is_a_low_severity_lead_not_an_alert() -> None:
    """H-0021 and H-0025 shipped `POST /flows` at medium severity, but every
    legitimate Node-RED deploy sends it; the source's signature was the missing
    Authorization header, which web server logs do not record."""
    from hecate_runner.cti.reference_rules import reference_candidates

    [rule] = reference_candidates(
        {"http_requests": [{"method": "POST", "path": ["/flows"], "origin": "readme"}]}
    )
    assert rule["level"] == "low"
    assert "Authorization" in rule["falsepositives"]
    [nuclei] = reference_candidates({"http_requests": [{"method": "POST", "path": ["/flows"]}]})
    assert nuclei["level"] == "medium" and "falsepositives" not in nuclei


def test_the_poc_repository_itself_is_listed_without_a_rule() -> None:
    """H-0020 shipped a high-severity proxy rule for the repository it was drafted from."""
    from hecate_agent.core.provenance import IndicatorRecord, mark_source_pages

    from hecate_runner.hunt_writer import _rule_placements

    record = IndicatorRecord(
        value="https://github.com/al4n4n/CVE-2026-58115", type="url", source="cti"
    )
    assert _rule_placements(record.to_dict()) == "proxy"
    mark_source_pages([record], ["https://github.com/al4n4n/CVE-2026-58115"])
    assert _rule_placements(record.to_dict()) == "none: the source's own page, not an indicator"
