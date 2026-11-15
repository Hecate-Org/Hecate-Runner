"""GitHub PoC Exploit Monitor CTI Provider.

Monitors GitHub for newly published Proof-of-Concept (PoC) exploit repositories
targeting emerging CVEs, 0-days, and 1-days. Provides early exploit weaponization
intelligence weeks before vulnerabilities are cataloged by CISA KEV.

Features:
- Primary ingestion via GitHub REST Search API (keyless or authenticated via GITHUB_TOKEN).
- Keyless raw failover via curated nomi-sec/PoC-in-GitHub feed when Search API is rate-limited.
- README artifact extraction: vulnerability category (RCE, Auth Bypass, LPE) plus the
  commands, target paths and ports the README actually quotes, each with its source line.
- Persistent cursor state preventing duplicate hunt drafting.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider

log = logging.getLogger(__name__)

CVE_REGEX = re.compile(r"\bCVE-(?:1999|20\d{2})-\d{4,7}\b", re.IGNORECASE)

VULN_TYPE_PATTERNS = [
    (
        "Remote Code Execution (RCE)",
        re.compile(r"\b(remote\s+code\s+execution|rce|code\s+execution)\b", re.I),
    ),
    (
        "Authentication Bypass",
        re.compile(r"\b(authentication\s+bypass|auth\s+bypass|bypass\s+auth)\b", re.I),
    ),
    (
        "Privilege Escalation (LPE)",
        re.compile(r"\b(privilege\s+escalation|elevation\s+of\s+privilege|lpe|privesc)\b", re.I),
    ),
    ("SQL Injection (SQLi)", re.compile(r"\b(sql\s+injection|sqli)\b", re.I)),
    (
        "Server-Side Request Forgery (SSRF)",
        re.compile(r"\b(server[\s-]side\s+request\s+forgery|ssrf)\b", re.I),
    ),
    ("Command Injection", re.compile(r"\b(command\s+injection|os\s+command\s+injection)\b", re.I)),
    (
        "Path Traversal / Arbitrary File Read",
        re.compile(
            r"\b(path\s+traversal|directory\s+traversal|arbitrary\s+file\s+read|lfi)\b", re.I
        ),
    ),
    (
        "Denial of Service (DoS)",
        re.compile(r"\b(denial\s+of\s+service|dos|buffer\s+overflow|overflow)\b", re.I),
    ),
]

UNKNOWN_VULN_TYPE = "Unclassified"

# Classes too vague to map (DoS, Unclassified) name no technique rather than a guessed one.
VULN_TYPE_TECHNIQUES = {
    "Remote Code Execution (RCE)": "T1190 (Exploit Public-Facing Application)",
    "Authentication Bypass": "T1190 (Exploit Public-Facing Application)",
    "SQL Injection (SQLi)": "T1190 (Exploit Public-Facing Application)",
    "Server-Side Request Forgery (SSRF)": "T1190 (Exploit Public-Facing Application)",
    "Command Injection": "T1190 (Exploit Public-Facing Application)",
    "Path Traversal / Arbitrary File Read": "T1190 (Exploit Public-Facing Application)",
    "Privilege Escalation (LPE)": "T1068 (Exploitation for Privilege Escalation)",
}

_GENERIC_REPO_WORDS = re.compile(
    r"\b(poc|pocs|exploit|exploits|scanner|checker|check|rce|lpe|lab|research|analysis)\b", re.I
)
_FENCE = re.compile(r"^\s*(`{3,}|~{3,})\s*([\w+-]*)")
_SHELL_FENCE_LANGS = {
    "",
    "bash",
    "sh",
    "shell",
    "console",
    "zsh",
    "terminal",
    "powershell",
    "ps1",
    "pwsh",
    "cmd",
    "bat",
}
_PROMPT = re.compile(r"^\s*(?:\$|>|PS[^>]*>)\s*")
_TRAILING_COMMENT = re.compile(r"\s+#\s.*$")
_COMMAND_PREFIXES = (
    "python3 ",
    "python ",
    "curl ",
    "wget ",
    "bash ",
    "sh ",
    "./",
    "perl ",
    "go run ",
    "ruby ",
    "node ",
    "java -jar ",
    "nuclei ",
)
_LAB_COMMAND = re.compile(r"\b(setup|install|teardown|requirements|venv|build)\b", re.I)
_EXPLOIT_COMMAND = re.compile(r"\b(poc|exploit|exp|pwn|rce|attack)\b", re.I)
_URL = re.compile(r"\bhttps?://(<[^>\s]+>|[^\s/:'\"`<>]+)(?::(\d{1,5}))?(/[^\s'\"`<>)\]]*)?", re.I)
_REQUEST_LINE = re.compile(r"\b(?:GET|POST|PUT|PATCH|DELETE)\s+(/[^\s'\"`<>,;)\]]*)")
_PORT_PHRASE = re.compile(r"\b(?:tcp|udp)/(\d{2,5})\b|\bport\s+(\d{2,5})\b", re.I)
_LOOPBACK_HOST = re.compile(r"^(localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\])$", re.I)
# Hosts READMEs link for reference; paths on them are documentation, not targets.
_REFERENCE_HOSTS = (
    "github.com",
    "githubusercontent.com",
    "github.io",
    "githubassets.com",
    "shields.io",
    "nvd.nist.gov",
    "cve.org",
    "mitre.org",
    "ietf.org",
    "pypi.org",
    "npmjs.com",
)


def _cell(text: str, limit: int = 200) -> str:
    text = " ".join(str(text).split()).replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _code_blocks(readme: str) -> list[tuple[str, list[str]]]:
    """Fenced code blocks as (language, lines), pairing each opening fence with its close."""
    blocks: list[tuple[str, list[str]]] = []
    fence: str | None = None
    lang = ""
    body: list[str] = []
    for line in readme.splitlines():
        match = _FENCE.match(line)
        if fence is None:
            if match:
                fence, lang, body = match.group(1), match.group(2).lower(), []
        elif (
            match
            and not match.group(2)
            and match.group(1)[0] == fence[0]
            and len(match.group(1)) >= len(fence)
        ):
            blocks.append((lang, body))
            fence = None
        else:
            body.append(line)
    return blocks


def _readme_commands(blocks: list[tuple[str, list[str]]]) -> list[tuple[str, str]]:
    """Up to three runnable commands from shell blocks, exploit invocations first, lab setup skipped."""
    found: dict[str, str] = {}
    for lang, body in blocks:
        if lang not in _SHELL_FENCE_LANGS:
            continue
        for raw in body:
            command = _TRAILING_COMMENT.sub("", _PROMPT.sub("", raw)).strip()
            if (
                command.startswith(_COMMAND_PREFIXES)
                and len(command) < 160
                and not _LAB_COMMAND.search(command)
            ):
                found.setdefault(command, raw.strip())
    ranked = sorted(found.items(), key=lambda item: not _EXPLOIT_COMMAND.search(item[0]))
    return ranked[:3]


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith(("#", "//"))


def _is_target_host(host: str) -> bool:
    host = host.lower()
    if _LOOPBACK_HOST.match(host):
        return False
    return not any(host == ref or host.endswith("." + ref) for ref in _REFERENCE_HOSTS)


def _readme_endpoints(readme: str, blocks: list[tuple[str, list[str]]]) -> list[tuple[str, str]]:
    """Target request paths: HTTP request lines anywhere, or URL paths on target hosts in code."""
    found: dict[str, str] = {}
    for line in readme.splitlines():
        for match in _REQUEST_LINE.finditer(line):
            path = match.group(1).rstrip(".,:`?")
            if len(path) > 1:
                found.setdefault(path, line.strip())
    for _, body in blocks:
        for line in body:
            if _is_comment(line):
                continue
            for match in _URL.finditer(line):
                path = (match.group(3) or "").rstrip(".,:`?")
                if len(path) > 1 and _is_target_host(match.group(1)):
                    found.setdefault(path, line.strip())
    return list(found.items())[:4]


#: A request line the README quotes: "deploy a new flow through `POST /flows`".
_REQUEST_RE = re.compile(
    r"(?<![\w/])(POST|PUT|PATCH|DELETE)\s+`?(?:https?://[^\s/`]+)?(/[\w\-./]*[\w/])(?![\w/])"
)


def _readme_requests(text: str) -> list[dict[str, Any]]:
    """State-changing requests ``text`` shows sent to the target, for literal webserver rules.

    A bare GET (``GET /settings``) is every page load of the product's own UI,
    so only requests that change the target are taken.
    """
    seen: dict[tuple[str, str], None] = {}
    for match in _REQUEST_RE.finditer(text):
        seen.setdefault((match[1], match[2]), None)
    return [{"method": m, "path": [p], "origin": "readme"} for m, p in seen]


def _readme_ports(readme: str, blocks: list[tuple[str, list[str]]]) -> list[tuple[str, str]]:
    """Target ports: explicit ports on target URLs in code, or 'TCP/n' / 'port n' in prose."""
    found: dict[str, str] = {}
    for _, body in blocks:
        for line in body:
            if _is_comment(line):
                continue
            for match in _URL.finditer(line):
                if match.group(2) and _is_target_host(match.group(1)):
                    found.setdefault(match.group(2), line.strip())
    for line in readme.splitlines():
        for match in _PORT_PHRASE.finditer(line):
            found.setdefault(match.group(1) or match.group(2), line.strip())
    return [(p, ev) for p, ev in found.items() if 0 < int(p) < 65536][:3]


@dataclass
class GitHubPocCursorState:
    seen_repos: list[str] = field(default_factory=list)
    max_history: int = 5000

    def to_json(self) -> str:
        return json.dumps({"seen_repos": self.seen_repos[-self.max_history :]})

    @classmethod
    def from_file(cls, path: Path) -> GitHubPocCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            seen = data.get("seen_repos", [])
            if isinstance(seen, list):
                return cls(seen_repos=seen)
            return cls()
        except (OSError, ValueError):
            return cls()

    def record_repo(self, repo_full_name: str, path: Path) -> None:
        clean = repo_full_name.strip().lower()
        if clean and clean not in self.seen_repos:
            self.seen_repos.append(clean)
            if len(self.seen_repos) > self.max_history:
                self.seen_repos = self.seen_repos[-self.max_history :]
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                atomic_write_text(path, self.to_json())
            except Exception as e:
                log.warning("Failed to save GitHub PoC cursor state: %s", e)


class GitHubPocProvider(CTIProvider):
    """Provides CTI items from newly published GitHub Proof-of-Concept exploit repositories."""

    name = "github_poc"

    def __init__(
        self,
        workspace: Path,
        github_token: str | None = None,
        cursor_file: Path | None = None,
        request_timeout_sec: float = 10.0,
        min_stars: int = 0,
    ) -> None:
        self.workspace = workspace
        self.github_token = github_token
        self.cursor_file = cursor_file or (self.workspace / ".cursors" / "github_poc_cursor.json")
        self.request_timeout_sec = request_timeout_sec
        self.min_stars = min_stars
        self.cursor_state = GitHubPocCursorState.from_file(self.cursor_file)

    def _headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": "Hecate-Runner/1.0",
            "Accept": "application/vnd.github.v3+json",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    def _fetch_from_search_api(self) -> list[dict[str, Any]]:
        """Search GitHub for recently created or updated CVE exploit repositories."""
        current_year = datetime.now(UTC).year
        prev_year = current_year - 1
        query = f"CVE-{current_year} OR CVE-{prev_year} fork:false"
        url = f"https://api.github.com/search/repositories?q={query}&sort=updated&order=desc&per_page=15"

        try:
            from hecate_runner.http_pool import pooled_get

            resp = pooled_get(
                url,
                pool_name="cti:github_poc",
                headers=self._headers(),
                timeout=float(self.request_timeout_sec),
            )
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items") or []
                results = []
                for item in items:
                    full_name = item.get("full_name") or ""
                    desc = item.get("description") or ""
                    stars = item.get("stargazers_count", 0)
                    if stars < self.min_stars:
                        continue
                    cves = CVE_REGEX.findall(f"{full_name} {desc}")
                    if cves:
                        results.append(
                            {
                                "full_name": full_name,
                                "html_url": item.get("html_url")
                                or f"https://github.com/{full_name}",
                                "description": desc,
                                "cves": sorted(set(c.upper() for c in cves)),
                                "stars": stars,
                                "updated_at": item.get("updated_at") or "",
                                "source_method": "search_api",
                            }
                        )
                return results
            elif resp.status_code in (403, 429):
                log.info("GitHub Search API rate-limited; falling back to curated raw feed.")
                return self._fetch_from_curated_feed()
            else:
                log.warning("GitHub Search API error HTTP %s", resp.status_code)
                return self._fetch_from_curated_feed()
        except Exception as e:
            log.warning("Failed to query GitHub Search API (%s); falling back to curated feed.", e)
            return self._fetch_from_curated_feed()

    def _fetch_from_curated_feed(self) -> list[dict[str, Any]]:
        """Fallback to raw nomi-sec/PoC-in-GitHub README feed (zero rate limit)."""
        url = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/README.md"
        try:
            from hecate_runner.http_pool import pooled_get

            resp = pooled_get(
                url,
                pool_name="cti:github_poc",
                headers={"User-Agent": "Hecate-Runner/1.0"},
                timeout=float(self.request_timeout_sec),
            )
            if resp.status_code != 200:
                log.warning("Curated PoC feed returned HTTP %s", resp.status_code)
                return []

            results = []
            current_cve: str | None = None
            current_desc: str = ""

            for line in resp.text.splitlines():
                line_str = line.strip()
                if line_str.startswith("### CVE-"):
                    match = CVE_REGEX.search(line_str)
                    if match:
                        current_cve = match.group(0).upper()
                        current_desc = ""
                elif line_str.startswith("<code>") and current_cve:
                    current_desc = line_str.replace("<code>", "").replace("</code>", "").strip()
                elif line_str.startswith("- [") and current_cve and "github.com/" in line_str:
                    link_match = re.search(
                        r"https://github\.com/([a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+)", line_str
                    )
                    if link_match:
                        full_name = link_match.group(1).rstrip(")")
                        results.append(
                            {
                                "full_name": full_name,
                                "html_url": f"https://github.com/{full_name}",
                                "description": current_desc,
                                "cves": [current_cve],
                                "stars": 0,
                                "updated_at": "",
                                "source_method": "curated_feed",
                            }
                        )
                        if len(results) >= 20:
                            break
            return results
        except Exception as e:
            log.warning("Failed to fetch curated PoC feed: %s", e)
            return []

    def _fetch_readme_text(self, repo_full_name: str) -> str:
        """Fetch README content via GitHub API or raw githubusercontent."""
        from hecate_runner.http_pool import pooled_get

        # Try GitHub API first
        api_url = f"https://api.github.com/repos/{repo_full_name}/readme"
        try:
            resp = pooled_get(
                api_url,
                pool_name="cti:github_poc",
                headers=self._headers(),
                timeout=float(self.request_timeout_sec),
            )
            if resp.status_code == 200:
                content_b64 = resp.json().get("content")
                if content_b64:
                    return base64.b64decode(content_b64).decode("utf-8", errors="replace")
        except Exception:
            pass

        # Raw fallback
        for branch in ("main", "master"):
            raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/{branch}/README.md"
            try:
                resp = pooled_get(
                    raw_url,
                    pool_name="cti:github_poc",
                    headers={"User-Agent": "Hecate-Runner/1.0"},
                    timeout=float(self.request_timeout_sec),
                )
                if resp.status_code == 200:
                    return str(resp.text)
            except Exception:
                pass
        return ""

    def _extract_poc_artifacts(self, repo_data: dict[str, Any], readme: str) -> dict[str, Any]:
        """Extract the CVE, vulnerability class, and README-quoted commands, paths and ports.

        Commands, endpoints and ports come only from the README, each with the
        line it was quoted from. Nothing is synthesized when the README has none.
        """
        name_and_desc = f"{repo_data.get('full_name', '')}\n{repo_data.get('description', '')}"
        combined_text = f"{name_and_desc}\n{readme}"

        # 1. Target CVE(s), preferring the one the repository is named or described for
        cves = list(dict.fromkeys(c.upper() for c in CVE_REGEX.findall(combined_text)))
        primary_cve = cves[0] if cves else "CVE-UNKNOWN"

        # 2. Vulnerability Category
        vuln_type = UNKNOWN_VULN_TYPE
        for name, pattern in VULN_TYPE_PATTERNS:
            if pattern.search(combined_text):
                vuln_type = name
                break

        # 3. Target software from the repo name, minus CVE IDs and generic PoC words
        repo_name = repo_data.get("full_name", "").split("/")[-1]
        clean_name = re.sub(r"cve[-_]?\d{4}[-_]?\d+", "", repo_name, flags=re.I)
        clean_name = _GENERIC_REPO_WORDS.sub("", clean_name.replace("_", "-"))
        clean_name = re.sub(r"-{2,}", "-", clean_name).strip("-_. ")
        software = clean_name if len(clean_name) > 2 else ""

        from hecate_agent.core.command_rules import without_operator_sections

        blocks = _code_blocks(readme)
        commands = _readme_commands(blocks)
        # A command quoted only in the usage, lab or scanner sections is the
        # tester's own run, not something seen on a target.
        on_target = " ".join(without_operator_sections(readme).split())
        return {
            "cve": primary_cve,
            "all_cves": cves,
            "software": software,
            "vuln_type": vuln_type,
            "commands": commands,
            "tester_commands": [c for c, ev in commands if " ".join(ev.split()) not in on_target],
            "http_requests": _readme_requests(without_operator_sections(readme)),
            "endpoints": _readme_endpoints(readme, blocks),
            "ports": _readme_ports(readme, blocks),
            "readme_excerpt": readme[:1000].strip(),
        }

    def _build_blurb(self, repo_data: dict[str, Any], artifacts: dict[str, Any]) -> str:
        """Render a CTI blurb that claims no more than the repository shows."""
        cve = artifacts["cve"]
        software = artifacts["software"]
        vuln_type = artifacts["vuln_type"]
        repo_url = repo_data.get("html_url")
        full_name = repo_data.get("full_name")
        desc = repo_data.get("description") or artifacts.get(
            "readme_excerpt", "No description provided."
        )
        stars = repo_data.get("stars", 0)

        technique = VULN_TYPE_TECHNIQUES.get(vuln_type)
        tags = ["exploit-repository", "github", cve.lower()]
        short = re.search(r"\(([^)]+)\)", vuln_type)
        if short:
            tags.append(short.group(1).lower())

        classified = (
            f"Keyword matching on its name, description and README suggests **{vuln_type}**"
            + (f" in **{software}**." if software else ".")
            if vuln_type != UNKNOWN_VULN_TYPE
            else "Keyword matching found no vulnerability class in its name, description or README."
        )
        lines = [
            f"Title: GitHub repository referencing {cve}" + (f" ({software})" if software else ""),
            f"Source: GitHub PoC Monitor ({full_name})",
            f"URL: {repo_url}",
            "Adversary/Attribution: Unattributed; a public repository, not observed attacker activity",
            f"Tags: {', '.join(tags)}",
            "",
            "### Threat Context",
            f"A public GitHub repository ({full_name}) references **{cve}**. {classified} "
            "Whether it contains a working exploit has not been verified, and its publication "
            "is not evidence of exploitation in the wild.",
            "",
            "Repository Details:",
            f"- **Repository:** [{full_name}]({repo_url}) ({stars} stars)",
            f"- **Primary CVE:** {cve}",
            f"- **Vulnerability Class:** {vuln_type}",
            f"- **Description:** {desc}",
            "",
            "### README Excerpts",
            "",
        ]

        tester = set(artifacts.get("tester_commands") or ())
        rows = (
            [
                (
                    cmd,
                    "command_line",
                    "attacker_tooling",
                    "unknown" if cmd in tester else "active",
                    ev,
                )
                for cmd, ev in artifacts["commands"]
            ]
            + [
                (ep, "url_path", "target_endpoint", "active", ev)
                for ep, ev in artifacts["endpoints"]
            ]
            + [(port, "port", "network_target", "active", ev) for port, ev in artifacts["ports"]]
        )
        if rows:
            lines += [
                "Each artifact below is quoted verbatim from the repository README.",
                "",
                "| Artifact | Kind | Role | Status | Evidence |",
                "|---|---|---|---|---|",
            ]
            for value, kind, role, status, evidence in rows:
                lines.append(
                    f'| `{_cell(value)}` | {kind} | {role} | {status} | "{_cell(evidence)}" |'
                )
        else:
            lines.append(
                "The README quotes no runnable command, target request path or target port."
            )

        lines += [
            "",
            "**Indicators by role** (the feed's indicators, typed against the report):",
            "",
            "| Indicator | Type | Role | Status | Confidence | Rules |",
            "|---|---|---|---|---|---|",
            f"| `{cve}` | cve | vulnerability | active | high | none: an identifier, not a log observable |",
        ]
        if technique:
            lines += ["", f"{ATTACK_TECHNIQUE_LINE} {technique}"]

        return "\n".join(lines)

    def next_item(self) -> CTIItem | None:
        """Return the next unprocessed GitHub PoC repository."""
        seen = set(self.cursor_state.seen_repos)
        candidates = self._fetch_from_search_api()

        for cand in candidates:
            full_name = cand["full_name"].strip().lower()
            if full_name in seen:
                continue

            readme = self._fetch_readme_text(cand["full_name"])
            artifacts = self._extract_poc_artifacts(cand, readme)
            blurb = self._build_blurb(cand, artifacts)

            cve = artifacts["cve"]
            software = artifacts["software"]

            return CTIItem(
                content=blurb,
                source="github_poc",
                received_at=datetime.now(UTC),
                identifier=cand["full_name"],
                metadata={
                    "cve_id": cve,
                    "repo_full_name": cand["full_name"],
                    "stars": cand.get("stars", 0),
                    "vuln_type": artifacts["vuln_type"],
                    **(
                        {"http_requests": artifacts["http_requests"]}
                        if artifacts["http_requests"]
                        else {}
                    ),
                },
                title=f"PoC: {cve} - {software or 'unspecified software'} ({cand['full_name']})",
                source_url=cand["html_url"],
            )

        return None

    def acknowledge(self, item: CTIItem | str) -> None:
        """Mark repository as processed in the cursor state."""
        ident = item.identifier if isinstance(item, CTIItem) else str(item)
        if ident:
            self.cursor_state.record_repo(ident, self.cursor_file)
