"""Cross-source campaign clustering and incremental hunt updates.

Correlates incoming CTI against existing hunts in Hecate-Workspace using
extracted CVE IDs, threat actor aliases, and shared C2/IOC infrastructure,
evolving existing dossiers with net-new IOCs/techniques instead of duplicate
drafts. Empty correlations leave dossiers untouched; IOC stubs are not written
under ``queries/``.
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import re
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import CTIItem
from hecate_runner.indicator_sweep import parse_indicator_inventory

log = logging.getLogger(__name__)

#: Regular expressions for entity extraction
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")
_DOMAIN_RE = re.compile(
    r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b"
)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

#: Benign / vendor domains to ignore in C2 clustering
_BENIGN_DOMAINS = {
    "google.com",
    "cloud.google.com",
    "microsoft.com",
    "msrc.microsoft.com",
    "github.com",
    "github.io",
    "githubusercontent.com",
    "raw.githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "virustotal.com",
    "mitre.org",
    "cisa.gov",
    "vulncheck.com",
    "shodan.io",
    "censys.io",
    "attack.mitre.org",
    "example.com",
    "example.org",
    "example.net",
    "wordpress.org",
    "apache.org",
    "nginx.org",
    "schema.org",
    "w3.org",
    "tavily.com",
    "alienvault.com",
    "abuse.ch",
    "nvd.nist.gov",
    "nist.gov",
    "exploit-db.com",
    "cve.org",
    "projectdiscovery.io",
    "rapid7.com",
    "ciac.org",
    "ibmcloud.com",
    "ibm.com",
    "tenable.com",
    "qualys.com",
    "jfrog.com",
    "snyk.io",
    "veracode.com",
    "checkpoint.com",
    "fortinet.com",
    "paloaltonetworks.com",
    "mandiant.com",
    "crowdstrike.com",
    "sentinelone.com",
    "bleepingcomputer.com",
    "thehackernews.com",
    "securityweek.com",
    "darkreading.com",
    "oracle.com",
    "openjdk.org",
    "redhat.com",
    "canonical.com",
    "ubuntu.com",
    "debian.org",
    "kernel.org",
}

#: Known file extensions mistaken for domains
_IGNORE_EXTENSIONS = {
    ".py",
    ".php",
    ".phtml",
    ".phar",
    ".jsp",
    ".asp",
    ".aspx",
    ".html",
    ".htm",
    ".css",
    ".js",
    ".yml",
    ".yaml",
    ".json",
    ".exe",
    ".dll",
    ".txt",
    ".md",
    ".tar",
    ".gz",
    ".zip",
    ".sh",
    ".so",
    ".bin",
    ".log",
    ".snp",
    ".component",
    ".shtml",
    ".action",
    ".do",
    ".class",
    ".jar",
    ".war",
    ".ear",
    ".iso",
    ".img",
    ".dmg",
    ".deb",
    ".rpm",
    ".apk",
    ".msi",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".getdecoder",
}

#: Reserved or special-use domain suffixes to ignore as external IOCs
_SPECIAL_USE_TLDS = {
    ".example",
    ".test",
    ".invalid",
    ".local",
    ".localhost",
    ".internal",
}

#: Canonical threat actor aliases mapping normalized alias -> canonical group ID / name
_CANONICAL_ACTOR_ALIASES: dict[str, tuple[str, str]] = {
    # (canonical_id, canonical_name)
    "apt28": ("G0007", "APT28"),
    "fancy bear": ("G0007", "APT28"),
    "forest blizzard": ("G0007", "APT28"),
    "sednit": ("G0007", "APT28"),
    "sofacy": ("G0007", "APT28"),
    "strontium": ("G0007", "APT28"),
    "pawn storm": ("G0007", "APT28"),
    "tsar team": ("G0007", "APT28"),
    "apt29": ("G0016", "APT29"),
    "cozy bear": ("G0016", "APT29"),
    "midnight blizzard": ("G0016", "APT29"),
    "nobelium": ("G0016", "APT29"),
    "the dukes": ("G0016", "APT29"),
    "sandworm": ("G0034", "Sandworm Team"),
    "sandworm team": ("G0034", "Sandworm Team"),
    "seashell blizzard": ("G0034", "Sandworm Team"),
    "telebots": ("G0034", "Sandworm Team"),
    "voodoo bear": ("G0034", "Sandworm Team"),
    "blackenergy": ("G0034", "Sandworm Team"),
    "volt typhoon": ("G1017", "Volt Typhoon"),
    "bronze silhouette": ("G1017", "Volt Typhoon"),
    "vanguard panda": ("G1017", "Volt Typhoon"),
    "lazarus": ("G0032", "Lazarus Group"),
    "lazarus group": ("G0032", "Lazarus Group"),
    "hidden cobra": ("G0032", "Lazarus Group"),
    "zinc": ("G0032", "Lazarus Group"),
    "diamond sleet": ("G0032", "Lazarus Group"),
    "scattered spider": ("G1015", "Scattered Spider"),
    "octo tempest": ("G1015", "Scattered Spider"),
    "unc3944": ("G1015", "Scattered Spider"),
    "muddled libra": ("G1015", "Scattered Spider"),
    "lockbit": ("G0140", "LockBit"),
    "lockbit 2.0": ("G0140", "LockBit"),
    "lockbit 3.0": ("G0140", "LockBit"),
    "lockbit black": ("G0140", "LockBit"),
    "blackcat": ("G0138", "BlackCat"),
    "alphv": ("G0138", "BlackCat"),
    "akira": ("G0144", "Akira"),
    "fin7": ("G0046", "FIN7"),
    "carbanak": ("G0008", "Carbanak"),
}


_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

#: Documentation and benchmark networks to exclude from cross-campaign correlation
_DOC_OR_BENCHMARK_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("100.64.0.0/10"),
)

_PLACEHOLDER_OR_RESOLVER_IPS = {
    "0.0.0.0",
    "1.1.1.1",
    "1.2.3.4",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "255.255.255.255",
}


def _is_public_ip(ip_str: str) -> bool:
    """True if ip_str is a valid external IP address (excluding loopback, multicast, link-local, private LANs, and common placeholders)."""
    cleaned = ip_str.strip()
    if cleaned in _PLACEHOLDER_OR_RESOLVER_IPS:
        return False
    try:
        ip = ipaddress.ip_address(cleaned)
        if (
            ip.is_loopback
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_link_local
            or ip.is_reserved
        ):
            return False
        return all(ip not in net for net in _RFC1918_NETWORKS)
    except ValueError:
        return False


def _is_c2_correlation_candidate(ioc: str) -> bool:
    """True if ioc is a valid external candidate for linking separate campaigns as shared C2 infrastructure."""
    try:
        ip = ipaddress.ip_address(ioc.strip())
        if str(ip) in _PLACEHOLDER_OR_RESOLVER_IPS:
            return False
        return not any(ip in net for net in _DOC_OR_BENCHMARK_NETWORKS)
    except ValueError:
        return True


def _is_relevant_domain(domain_str: str) -> bool:
    """True if domain_str is likely an external IOC rather than benign tooling/doc."""
    dom = domain_str.strip().lower().rstrip(".")
    if any(dom.endswith(ext) for ext in _IGNORE_EXTENSIONS):
        return False
    if dom in _BENIGN_DOMAINS or any(dom.endswith(f".{b}") for b in _BENIGN_DOMAINS):
        return False
    if any(dom.endswith(tld) for tld in _SPECIAL_USE_TLDS):
        return False
    # Ignore standalone numbers or single-label
    parts = dom.split(".")
    if len(parts) < 2 or any(len(p) == 0 for p in parts):
        return False
    # Avoid IP fragments parsed as domains
    if all(p.isdigit() for p in parts):
        return False
    # TLD must be valid alphabetic or punycode label (excludes version strings like 5.6-7.4)
    tld = parts[-1]
    return bool(re.match(r"^(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9]+)$", tld))


def _extract_cve_years(cves: set[str]) -> set[int]:
    """Extract 4-digit years from CVE identifiers."""
    years: set[int] = set()
    for c in cves:
        m = re.match(r"CVE-(\d{4})-", c, re.IGNORECASE)
        if m:
            with contextlib.suppress(ValueError):
                years.add(int(m.group(1)))
    return years


_VERSION_CONTEXT_PREFIX_RE = re.compile(
    r"(?i)(?:version|versions|ver|v\.?|jdk|openjdk|build|update|release|patch|rev|revision|glibc|kernel|openssl|python|node|ruby|go|curl|git|linux|apache|nginx|tomcat|software|lib[\w-]*|fixed\s+in|affected(?:\s+versions?)?|upgrade\s+to|released\s+in)(?:\s+[\w.-]+){0,2}\s*[:=vV-]?\s*[-*]?\s*(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:[,\s\-*]+|and|or|\/)+)*$"
)
_VERSION_CONTEXT_SUFFIX_RE = re.compile(
    r"(?i)^(?:\.GA|\.Final|-ea|-rc\d*|-beta\d*|-alpha\d*|\.tar|\.zip|\.gz|\.deb|\.rpm|\+[\w.-]+)"
)


def _is_version_context(text: str, start: int, end: int) -> bool:
    """True if the IPv4 match at text[start:end] is in a software version or URL path context."""
    prefix = text[max(0, start - 150) : start]
    suffix = text[end : min(len(text), end + 60)]

    # Preceding version indicators (e.g. 'version 17.0.21.1', 'v1.2.3.4', 'JDK 17.0.21.1', bullet points)
    if _VERSION_CONTEXT_PREFIX_RE.search(prefix):
        return True

    # Immediate 'v' or 'V' prefix (e.g. v17.0.21.1)
    if start > 0 and text[start - 1] in "vV":
        return True

    # Trailing version indicators (e.g. 17.0.21.1-ea, 17.0.21.1+1)
    if _VERSION_CONTEXT_SUFFIX_RE.search(suffix):
        return True

    # Non-host URL path segment (e.g. /advisories/2026-11-17/17.0.21.1/...)
    # An IP is only a host in a URL if preceded by '://' or '://user:pass@'
    if start > 0 and text[start - 1] == "/":
        scheme_idx = prefix.rfind("://")
        if scheme_idx == -1 or ("/" in prefix[scheme_idx + 3 :]):
            return True

    # Inside a markdown table row (e.g. '| JDK 17 | 17.0.1.0 | 17.0.21.1 |')
    line_start = text.rfind("\n", 0, start)
    line_start = 0 if line_start == -1 else line_start + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end == -1 else line_end
    line = text[line_start:line_end]
    if line.count("|") >= 2:
        window = text[max(0, start - 250) : min(len(text), end + 250)].lower()
        if any(
            term in window
            for term in (
                "version",
                "baseline",
                "fixed",
                "patch",
                "build",
                "release",
                "openjdk",
                "jdk",
            )
        ):
            return True

    # Markdown table column or link header indicating version
    # e.g. "| 17.0.21.1 |" or "[17.0.21.1]"
    if start > 0 and text[start - 1] in "|[" and suffix.startswith((" |", "]", "|")):
        window = text[max(0, start - 200) : min(len(text), end + 200)].lower()
        if any(
            term in window
            for term in ("version", "fixed in", "affected", "openjdk", "jdk", "release")
        ):
            return True

    return False


class ThreatEntityExtractor:
    """Extracts and normalizes CVEs, threat actor aliases, and network/hash IOCs."""

    @staticmethod
    def extract_cves(text: str, metadata: dict[str, Any] | None = None) -> set[str]:
        """Return standardized uppercase CVE IDs."""
        cves: set[str] = set()
        if text:
            for match in _CVE_RE.finditer(text):
                cves.add(match.group(0).upper())
        if metadata:
            for c in (metadata.get("indicators") or {}).get("cve", []):
                if isinstance(c, str) and c.strip():
                    cves.add(c.strip().upper())
            for c in metadata.get("cves") or []:
                if isinstance(c, str) and c.strip():
                    cves.add(c.strip().upper())
        return cves

    @staticmethod
    def extract_actors(
        text: str, title: str | None = None, metadata: dict[str, Any] | None = None
    ) -> set[str]:
        """Return canonical threat actor group names or IDs."""
        found: set[str] = set()

        # 1. Try hecate_agent attack_matrix STIX lookup
        try:
            from hecate_agent.api import find_group, search_groups_in_text

            candidates: list[str] = []
            if metadata and metadata.get("actor"):
                candidates.append(str(metadata["actor"]))
            if title:
                candidates.append(title)
            for c in candidates:
                res = find_group(c)
                if res and "name" in res:
                    found.add(f"{res['name']} ({res.get('id', '')})".strip())

            if text:
                matches = search_groups_in_text(text[:4096])
                for g in matches:
                    if "name" in g:
                        found.add(f"{g['name']} ({g.get('id', '')})".strip())
        except Exception as exc:
            log.debug(
                "attack_matrix group lookup error (%s); falling back to alias dictionary", exc
            )

        # 2. Check built-in canonical alias lookup
        combined_text = f"{title or ''} {text or ''}".lower()
        if metadata and metadata.get("actor"):
            combined_text += f" {str(metadata['actor']).lower()}"

        for alias, (gid, gname) in _CANONICAL_ACTOR_ALIASES.items():
            pattern = r"\b" + re.escape(alias) + r"\b"
            if re.search(pattern, combined_text):
                found.add(f"{gname} ({gid})")

        return found

    @staticmethod
    def extract_network_iocs(text: str, metadata: dict[str, Any] | None = None) -> set[str]:
        """Return public IPv4 addresses and candidate C2 domains."""
        iocs: set[str] = set()

        # Extract from metadata indicators
        if metadata and "indicators" in metadata:
            ind = metadata["indicators"]
            for ip in ind.get("ip-dst", []) + ind.get("ipv4", []) + ind.get("ip-src", []):
                if isinstance(ip, str) and _is_public_ip(ip):
                    cleaned_ip = ip.strip()
                    if text and cleaned_ip in text:
                        m_pos = text.find(cleaned_ip)
                        if m_pos != -1 and _is_version_context(
                            text, m_pos, m_pos + len(cleaned_ip)
                        ):
                            continue
                    iocs.add(cleaned_ip)
            for dom in ind.get("domain", []) + ind.get("hostname", []):
                if isinstance(dom, str) and _is_relevant_domain(dom):
                    iocs.add(dom.strip().lower())

        # Extract from text
        if text:
            for m in _IPV4_RE.finditer(text):
                ip = m.group(0)
                if _is_public_ip(ip) and not _is_version_context(text, m.start(), m.end()):
                    iocs.add(ip.strip())
            for dom in _DOMAIN_RE.findall(text):
                if _is_relevant_domain(dom):
                    iocs.add(dom.strip().lower())

        return iocs

    @staticmethod
    def extract_file_hashes(text: str, metadata: dict[str, Any] | None = None) -> set[str]:
        """Return SHA256, SHA1, and MD5 file hashes."""
        hashes: set[str] = set()
        if metadata and "indicators" in metadata:
            ind = metadata["indicators"]
            for h in (
                ind.get("sha256", [])
                + ind.get("filehash-sha256", [])
                + ind.get("sha1", [])
                + ind.get("filehash-sha1", [])
                + ind.get("md5", [])
                + ind.get("filehash-md5", [])
            ):
                if isinstance(h, str) and h.strip():
                    hashes.add(h.strip().lower())

        if text:
            for h in _SHA256_RE.findall(text):
                hashes.add(h.lower())
            for h in _SHA1_RE.findall(text):
                hashes.add(h.lower())
            for h in _MD5_RE.findall(text):
                hashes.add(h.lower())

        return hashes


@dataclass
class HuntEntityProfile:
    """Structured entity inventory of an existing hunt dossier."""

    hunt_id: str
    path: Path
    title: str
    cves: set[str] = field(default_factory=set)
    actors: set[str] = field(default_factory=set)
    network_iocs: set[str] = field(default_factory=set)
    file_hashes: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    inventory: dict[str, int] = field(default_factory=dict)
    #: URLs referenced in the hunt (replaces storing the full body in memory).
    source_refs: set[str] = field(default_factory=set)


@dataclass
class CorrelationMatch:
    """Result of correlating incoming CTI against an existing hunt."""

    hunt_id: str
    hunt_path: Path
    match_type: str  # "cve", "actor_alias", "shared_ioc", "multi_entity"
    matched_entities: list[str]
    confidence: float
    existing_hunt_title: str


_HUNT_PROFILE_CACHE: dict[str, tuple[int, HuntEntityProfile]] = {}
_HUNT_CACHE_LOCK = threading.Lock()


class ThreatEntityCorrelator:
    """Indexes workspace hunts and clusters incoming CTI by campaign entities."""

    def __init__(self, hunts_root: Path):
        self.hunts_root = hunts_root
        self._profiles: list[HuntEntityProfile] = []
        self._indexed = False

    @classmethod
    def clear_cache(cls) -> None:
        """Clear in-memory threat entity profile cache."""
        with _HUNT_CACHE_LOCK:
            _HUNT_PROFILE_CACHE.clear()

    def index_hunts(self, force: bool = False) -> list[HuntEntityProfile]:
        """Scan and profile existing hunts in hunts_root with mtime caching."""
        if self._indexed and not force:
            return self._profiles

        profiles: list[HuntEntityProfile] = []
        if not self.hunts_root.exists():
            self._profiles = profiles
            self._indexed = True
            return profiles

        for path in self.hunts_root.rglob("H-*.md"):
            try:
                stat = path.stat()
                mtime_ns = stat.st_mtime_ns
                key = str(path.resolve())

                cached: tuple[int, HuntEntityProfile] | None = None
                if not force:
                    with _HUNT_CACHE_LOCK:
                        cached = _HUNT_PROFILE_CACHE.get(key)

                if cached is not None and cached[0] == mtime_ns:
                    profiles.append(cached[1])
                    continue

                text = path.read_text(encoding="utf-8")
                hunt_id = path.stem
                title = ""
                m_title = re.search(r"^title:\s*[\"']?(.*?)[\"']?$", text, re.MULTILINE)
                if m_title:
                    title = m_title.group(1).strip()
                elif text.startswith("# "):
                    title = text.splitlines()[0].lstrip("# ").strip()

                cves = ThreatEntityExtractor.extract_cves(text)
                actors = ThreatEntityExtractor.extract_actors(text, title=title)
                network_iocs = ThreatEntityExtractor.extract_network_iocs(text)
                file_hashes = ThreatEntityExtractor.extract_file_hashes(text)

                # Extract techniques from frontmatter
                techniques: set[str] = set()
                m_tech = re.search(r"techniques:\s*\[(.*?)\]", text)
                if m_tech:
                    for t in m_tech.group(1).split(","):
                        clean_t = t.strip().strip("'\"").upper()
                        if clean_t:
                            techniques.add(clean_t)

                inv = parse_indicator_inventory(text)
                source_refs = {m.group(0).rstrip(").,];'\"") for m in _URL_RE.finditer(text)}

                prof = HuntEntityProfile(
                    hunt_id=hunt_id,
                    path=path,
                    title=title,
                    cves=cves,
                    actors=actors,
                    network_iocs=network_iocs,
                    file_hashes=file_hashes,
                    techniques=techniques,
                    inventory=inv,
                    source_refs=source_refs,
                )
                with _HUNT_CACHE_LOCK:
                    _HUNT_PROFILE_CACHE[key] = (mtime_ns, prof)
                profiles.append(prof)
            except OSError as exc:
                log.warning("Could not read hunt document %s: %s", path, exc)
                continue

        self._profiles = profiles
        self._indexed = True
        return self._profiles

    def correlate(
        self,
        item: CTIItem,
        threshold: float = 0.75,
    ) -> CorrelationMatch | None:
        """Find the best existing hunt match for the incoming CTI item."""
        profiles = self.index_hunts()
        if not profiles:
            return None

        item_cves = ThreatEntityExtractor.extract_cves(item.content, item.metadata)
        item_actors = ThreatEntityExtractor.extract_actors(
            item.content, title=item.title, metadata=item.metadata
        )
        item_network_iocs = ThreatEntityExtractor.extract_network_iocs(item.content, item.metadata)
        item_hashes = ThreatEntityExtractor.extract_file_hashes(item.content, item.metadata)

        best_match: CorrelationMatch | None = None
        best_score = 0.0

        for prof in profiles:
            score = 0.0
            matched_types: list[str] = []
            matched_items: list[str] = []

            # Check temporal CVE disparity:
            # If both the incoming item and hunt have CVEs, and the minimum publication
            # year gap exceeds 3 years (e.g. 2001 vs 2026), suppress infrastructure/URL
            # correlation to prevent reference link poisoning unless there is explicit
            # CVE or actor overlap.
            item_cve_years = _extract_cve_years(item_cves)
            prof_cve_years = _extract_cve_years(prof.cves)
            has_temporal_disparity = False
            if item_cve_years and prof_cve_years:
                min_year_gap = min(abs(y1 - y2) for y1 in item_cve_years for y2 in prof_cve_years)
                if min_year_gap > 3:
                    has_temporal_disparity = True

            # 0. Direct Source URL match (against extracted refs, not full body)
            url = (item.source_url or "").strip()
            if (
                url
                and (
                    url in prof.source_refs
                    or any(url in ref or ref in url for ref in prof.source_refs)
                )
                and not (
                    has_temporal_disparity
                    and not (item_cves & prof.cves)
                    and not (item_actors & prof.actors)
                )
            ):
                score += 1.0
                matched_types.append("source_url")
                matched_items.append(url)

            # 1. CVE overlap
            shared_cves = item_cves & prof.cves
            if shared_cves:
                score += 0.90
                matched_types.append("cve")
                matched_items.extend(sorted(shared_cves))

            # 2. Threat Actor / Alias overlap
            shared_actors = item_actors & prof.actors
            if shared_actors:
                score += 0.85
                matched_types.append("actor_alias")
                matched_items.extend(sorted(shared_actors))

            # 3. Network IOC overlap (shared C2)
            shared_net = {
                ioc
                for ioc in (item_network_iocs & prof.network_iocs)
                if _is_c2_correlation_candidate(ioc)
            }
            if shared_net and not (
                has_temporal_disparity and not shared_cves and not shared_actors
            ):
                score += 0.95
                matched_types.append("shared_c2_ioc")
                matched_items.extend(sorted(shared_net))

            # 4. File hash overlap
            shared_hash = item_hashes & prof.file_hashes
            if shared_hash:
                score += 0.95
                matched_types.append("shared_file_hash")
                matched_items.extend(sorted(shared_hash))

            confidence = min(1.0, score)
            if confidence >= threshold and confidence > best_score:
                best_score = confidence
                match_label = (
                    "multi_entity"
                    if len(matched_types) > 1
                    else (matched_types[0] if matched_types else "unknown")
                )
                best_match = CorrelationMatch(
                    hunt_id=prof.hunt_id,
                    hunt_path=prof.path,
                    match_type=match_label,
                    matched_entities=matched_items,
                    confidence=confidence,
                    existing_hunt_title=prof.title,
                )

        return best_match


@dataclass
class EnrichmentResult:
    """Outcome of incrementally enriching an existing hunt document."""

    hunt_id: str
    hunt_path: Path
    new_indicators_count: int
    new_rules_count: int
    added_techniques: list[str]
    rule_paths: list[str]
    details: str
    changed: bool = True

    @property
    def material_for_public_promote(self) -> bool:
        """True when enrichment wrote behavioral Sigma worth a public review."""
        return self.changed and self.new_rules_count > 0


class IncrementalEnricher:
    """Enriches an existing hunt dossier with net-new indicators and techniques."""

    @classmethod
    def enrich(
        cls,
        item: CTIItem,
        match: CorrelationMatch,
        workspace: Path,
    ) -> EnrichmentResult:
        """Enrich an existing hunt with net-new indicators/techniques only.

        Correlated CTI that adds nothing leaves the dossier untouched so
        publication digests and review queues are not churned. New IOCs are
        recorded in the hunt markdown; correlator no longer emits
        ``*__incremental_*`` Sigma stubs (those were noise for BAS/synth and
        public promotion).
        """
        hunt_path = match.hunt_path
        text = hunt_path.read_text(encoding="utf-8")

        # 1. Discover net-new indicators / techniques
        item_cves = ThreatEntityExtractor.extract_cves(item.content, item.metadata)
        item_net = ThreatEntityExtractor.extract_network_iocs(item.content, item.metadata)
        item_hashes = ThreatEntityExtractor.extract_file_hashes(item.content, item.metadata)
        item_techniques = {
            str(t).strip().upper()
            for t in (item.metadata.get("techniques") or [])
            if str(t).strip()
        }

        new_cves = [c for c in item_cves if c not in text]
        new_net = [n for n in item_net if n not in text]
        new_hashes = [h for h in item_hashes if h not in text]

        existing_techniques: set[str] = set()
        m_tech = re.search(r"techniques:\s*\[(.*?)\]", text)
        if m_tech:
            existing_techniques = {
                t.strip().strip("'\"").upper()
                for t in m_tech.group(1).split(",")
                if t.strip().strip("'\"")
            }
        added_techniques = sorted(item_techniques - existing_techniques)
        total_new_indicators = len(new_cves) + len(new_net) + len(new_hashes)

        if total_new_indicators == 0 and not added_techniques:
            return EnrichmentResult(
                hunt_id=match.hunt_id,
                hunt_path=hunt_path,
                new_indicators_count=0,
                new_rules_count=0,
                added_techniques=[],
                rule_paths=[],
                details=(
                    f"Correlated {match.hunt_id} but found no net-new indicators "
                    "or techniques; left dossier unchanged."
                ),
                changed=False,
            )

        # 2. Update Indicator Inventory line if present
        existing_inv = parse_indicator_inventory(text)
        new_inv = parse_indicator_inventory(item.content)
        if existing_inv and new_inv:
            merged_inv = dict(existing_inv)
            for k, v in new_inv.items():
                merged_inv[k] = merged_inv.get(k, 0) + v
            total_inv = sum(merged_inv.values())
            counts_str = ", ".join(f"{k} ({merged_inv[k]})" for k in sorted(merged_inv))
            new_line = f"Attributes ({total_inv} total): {counts_str}"
            text = re.sub(
                r"^(?:Attributes|Indicators) \(\d+ total\):\s*.+$",
                new_line,
                text,
                flags=re.MULTILINE,
            )

        # 3. Update Frontmatter
        now_iso = datetime.now(UTC).isoformat()
        if added_techniques:
            all_tech = sorted(existing_techniques | set(added_techniques))
            tech_yaml = "[" + ", ".join(f'"{t}"' for t in all_tech) + "]"
            text = re.sub(r"techniques:\s*\[.*?\]", f"techniques: {tech_yaml}", text)

        if "last_enriched_at:" in text:
            text = re.sub(r"last_enriched_at:\s*.*", f"last_enriched_at: {now_iso}", text)
        else:
            text = re.sub(r"^---\n", f"---\nlast_enriched_at: {now_iso}\n", text)

        # 4. Append chronological campaign update (IOCs in dossier only — no stub rules)
        indicator_rows = []
        for c in new_cves:
            indicator_rows.append(f"| CVE | `{c}` | {now_iso[:10]} |")
        for n in new_net:
            indicator_rows.append(
                f"| {'IPv4' if _IPV4_RE.match(n) else 'Domain'} | `{n}` | {now_iso[:10]} |"
            )
        for h in new_hashes:
            indicator_rows.append(f"| File Hash | `{h}` | {now_iso[:10]} |")

        table_text = (
            "\n| Type | Value | First Observed |\n|---|---|---|\n" + "\n".join(indicator_rows)
            if indicator_rows
            else "_No net-new unique indicators in this update._"
        )

        update_block = f"""

---

## Incremental Threat Intel Update ({now_iso[:19]}Z)

> **Source:** [{item.source}]({item.source_url or "internal-feed"})
> **Correlation Match:** `{match.match_type}` on `{", ".join(match.matched_entities)}` (Confidence: {match.confidence:.2f})
> **Summary:** {item.title or "Incremental campaign intelligence"}

### Newly Added Campaign Indicators
{table_text}

### Detection Notes
_IOCs recorded in this dossier only. Behavioral Sigma under ``queries/{match.hunt_id}/`` is not auto-extended with incremental IOC stubs._
"""
        text += update_block
        atomic_write_text(hunt_path, text)

        return EnrichmentResult(
            hunt_id=match.hunt_id,
            hunt_path=hunt_path,
            new_indicators_count=total_new_indicators,
            new_rules_count=0,
            added_techniques=added_techniques,
            rule_paths=[],
            details=(
                f"Enriched {match.hunt_id} with {total_new_indicators} new indicator(s) "
                f"and {len(added_techniques)} technique(s); no incremental rule stubs written."
            ),
            changed=True,
        )
