"""CTI tradecraft extraction, technique derivation, and platform scoping helpers."""

from __future__ import annotations

import re
from typing import Any

from hecate_runner.cti import ATTACK_TECHNIQUE_LINE, CTIItem
from hecate_runner.indicator_sweep import parse_indicator_inventory

# MITRE technique IDs embedded in raw CTI text, e.g. "T1003.001" or "T1053.005".
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# `hecate-agent research new --topic` expects a short label, not a raw CTI paragraph.
_TOPIC_MAX_LEN = 100

# A technique whose ATT&CK platform list is this broad (of the ~10 platforms
# ATT&CK currently defines) doesn't meaningfully scope a hunt -- e.g. T1078
# "Valid Accounts" and T1098 "Account Manipulation" both list all 10. Left
# in the union unconditionally, one such technique in a hypothesis's
# technique list (alongside genuinely narrow ones, e.g. a Windows-only
# technique) was enough to make `platform` list every ATT&CK platform verbatim
# regardless of what the CTI actually described -- 37% of one drafting batch.
# See `_resolve_ttps`.
_NON_SCOPING_PLATFORM_THRESHOLD = 8

#: The indicator-sweep hypothesis template is "Indicators published in
#: [source] appear in [telemetry] on [target]". A model that leaves [source]
#: empty yields "published in  appear" -- which reaches the draft twice, as
#: the frontmatter title and as the Hypothesis Statement, and reads like a
#: truncation bug rather than a missing value. The CTI item's own title is
#: exactly the value that belongs in that slot, so fill it here rather than
#: hoping the model stops omitting it.
#: Platform names ATT&CK uses, keyed by how a hypothesis is likely to spell
#: them. Used to scope a draft's platform list by what the hypothesis actually
#: claims: a union across every technique the CTI asserted returned
#: ESXi/Linux/macOS/Network Devices/Windows for a hypothesis whose own text
#: said "compromised Windows systems" and whose ABLE Location said "Windows
#: domain-joined endpoints".
_PLATFORM_MENTIONS: dict[str, str] = {
    "windows": "Windows",
    "linux": "Linux",
    "macos": "macOS",
    "mac os": "macOS",
    "esxi": "ESXi",
    "network device": "Network Devices",
    "network devices": "Network Devices",
    "container": "Containers",
    "containers": "Containers",
    "kubernetes": "Containers",
    "docker": "Containers",
    "k8s": "Containers",
    "identity provider": "Identity Provider",
    "entra id": "Identity Provider",
    "entra": "Identity Provider",
    "azure ad": "Identity Provider",
    "okta": "Identity Provider",
    "office suite": "Office Suite",
    "office 365": "Office Suite",
    "m365": "Office Suite",
    "saas": "SaaS",
    "iaas": "IaaS",
    "aws": "IaaS",
    "azure": "IaaS",
    "gcp": "IaaS",
    "cloud": "IaaS",
    "android": "Android",
    "ios": "iOS",
    "mobile": "Mobile",
}

#: Artifacts that exist on one platform only, read from the *intel* (never the
#: hypothesis) when the hypothesis names no platform. DarkMe's pulse never says
#: "Windows", but it describes PIF executables, MSI installers and COM objects;
#: without these the draft was scoped to every platform its techniques run on,
#: ESXi and SaaS included. Each entry must be unambiguous: "bash" and "cron"
#: run on both Linux and macOS, so they are absent.
_PLATFORM_ARTIFACTS: dict[str, str] = {
    "powershell": "Windows",
    "msiexec": "Windows",
    "msi": "Windows",
    "rundll32": "Windows",
    "regsvr32": "Windows",
    "mshta": "Windows",
    "wmic": "Windows",
    "lsass": "Windows",
    "exe": "Windows",
    "dll": "Windows",
    "pif": "Windows",
    "lnk": "Windows",
    "hta": "Windows",
    "docx": "Windows",
    "doc": "Windows",
    "wscript": "Windows",
    "cscript": "Windows",
    "schtasks": "Windows",
    "launchdaemon": "macOS",
    "launchagent": "macOS",
    "applescript": "macOS",
    "osascript": "macOS",
    "gatekeeper": "macOS",
    "elf": "Linux",
    "systemd": "Linux",
    "auditd": "Linux",
    "nsenter": "Containers",
    "kubectl": "Containers",
    "containerd": "Containers",
    "cloudtrail": "IaaS",
    "assumerole": "IaaS",
    "oauth": "Identity Provider",
    "apk": "Android",
    "dex": "Android",
    "aab": "Android",
    "dalvik": "Android",
    "ipa": "iOS",
}

#: Telemetry a technique implies, by ID prefix so sub-techniques inherit. Uses
#: the same four category names the research document and hypothesis agent
#: already speak, so a derived source and a model-proposed one are comparable.
_TECHNIQUE_DATA_SOURCES: dict[str, tuple[str, ...]] = {
    "T1059": ("process_execution",),
    "T1106": ("process_execution",),
    "T1204": ("process_execution",),
    "T1140": ("process_execution",),
    "T1620": ("process_execution",),
    "T1027": ("process_execution", "file_operations"),
    "T1005": ("file_operations", "process_execution"),
    "T1083": ("file_operations", "process_execution"),
    "T1070": ("file_operations",),
    "T1574": ("file_operations",),
    "T1105": ("network_connections", "file_operations"),
    "T1041": ("network_connections",),
    "T1071": ("network_connections",),
    "T1090": ("network_connections",),
    "T1547": ("registry_events",),
    "T1543": ("registry_events", "process_execution"),
    "T1112": ("registry_events",),
}

#: Indicator type -> telemetry that could match it. Covers both providers'
#: spellings (MISP's "ip-dst", OTX's "IPv4"); lookups lowercase the type.
_INDICATOR_DATA_SOURCES: dict[str, tuple[str, ...]] = {
    "ip-dst": ("network_connections",),
    "ip-src": ("network_connections",),
    "ipv4": ("network_connections",),
    "ipv6": ("network_connections",),
    "domain": ("network_connections",),
    "hostname": ("network_connections",),
    "url": ("network_connections",),
    "uri": ("network_connections",),
    "filename": ("file_operations", "process_execution"),
    "filepath": ("file_operations",),
    "md5": ("file_operations",),
    "sha1": ("file_operations",),
    "sha256": ("file_operations",),
    "filehash-md5": ("file_operations",),
    "filehash-sha1": ("file_operations",),
    "filehash-sha256": ("file_operations",),
    "regkey": ("registry_events",),
    "mutex": ("process_execution",),
}


def merge_techniques(cti_techniques: list[str], hypothesis_techniques: list[str]) -> list[str]:
    """Combine what the CTI asserted with what the hypothesis reasoned about.

    The hypothesis agent returns the two or three techniques it wrote prose
    around, and generalises sub-techniques while doing it -- a source event
    naming T1059.003 (Windows Command Shell) reached the draft as bare T1059.
    That is a real loss: T1059.003 is Windows-only, T1059 spans five
    platforms, so the imprecision propagates straight into the platform list.

    The CTI's list leads because it is the asserted evidence; the
    hypothesis's own additions follow. A bare parent is dropped when a
    sub-technique of it is present, so T1059 + T1059.003 collapses to the
    specific one rather than carrying both.
    """
    merged: list[str] = []
    for technique in [*cti_techniques, *hypothesis_techniques]:
        normalised = str(technique).upper().strip()
        if normalised and normalised not in merged:
            merged.append(normalised)

    parents_with_children = {t.split(".", 1)[0] for t in merged if "." in t}
    return [t for t in merged if "." in t or t not in parents_with_children]


_TRADECRAFT_SECTION_RE = re.compile(
    r"^## 2\. Adversary Tradecraft.*?$(.*?)(?=^## \d+\.|\Z)", re.MULTILINE | re.DOTALL
)


def research_tradecraft_text(research_doc: str) -> str:
    """The research document's Adversary Tradecraft section.

    What the retrieved sources said adversaries did. The rest of the document
    is model speculation -- gaps, focus areas, telemetry -- whose wording must
    not be able to put a technique on a hunt.
    """
    match = _TRADECRAFT_SECTION_RE.search(research_doc or "")
    return match.group(1) if match else ""


#: A markdown link or a bare URL. Research lists the pages its web search
#: returned, and their titles are not the intel: R-0012's list carried a
#: Kubernetes article and a Linux rule link, which scoped a Windows DLL
#: hijacking hunt to Linux and Containers too.
_LINK_RE = re.compile(r"\[[^\]]*\]\([^)]*\)|https?://\S+")


def platforms_evidenced_in(*texts: str) -> list[str]:
    """Platforms the intel names outright or implies by a platform-only artifact.

    Links and URLs are ignored: they cite where something was read, not where
    the activity happened. Attacker-side passages in actor-material reports
    (e.g. operator's workstation or toolkit files) are ignored.
    """
    from hecate_agent.core.technique_evidence import (
        actor_material_report,
        attacker_side,
        sentences,
    )

    clean_texts: list[str] = []
    for t in texts:
        if not t:
            continue
        cleaned = _LINK_RE.sub(" ", t)
        if actor_material_report(cleaned):
            observed_sentences = [
                s for s in sentences(cleaned) if not attacker_side(s.lower(), actor_material=True)
            ]
            clean_texts.append(" ".join(observed_sentences))
        else:
            clean_texts.append(cleaned)

    named = platforms_named_in(*clean_texts)
    haystack = " ".join(clean_texts).lower()
    for artifact, platform in _PLATFORM_ARTIFACTS.items():
        if platform not in named and re.search(r"\b" + re.escape(artifact) + r"\b", haystack):
            named.append(platform)
    return named


def platforms_named_in(*texts: str) -> list[str]:
    """Platforms a hypothesis explicitly claims, in ATT&CK's spelling."""
    haystack = " ".join(t for t in texts if t).lower()
    named: list[str] = []
    for mention, platform in _PLATFORM_MENTIONS.items():
        pattern = r"\b" + re.escape(mention) + r"\b"
        if re.search(pattern, haystack) and platform not in named:
            named.append(platform)
    return named


def derive_data_sources(techniques: list[str], indicator_types: list[str]) -> list[str]:
    """Telemetry this hunt needs, from its techniques and indicator types.

    Deterministic, and independent of both the model's vocabulary and the
    environment profile. The hypothesis agent's own list is kept and merged
    with this -- it was reaching the draft as `["process_execution"]` alone
    for a hunt whose CTI carried two C2 hostnames, four IPs and nine URLs.
    """
    found: list[str] = []
    for technique in techniques or []:
        normalised = str(technique).upper().strip()
        for prefix, sources in _TECHNIQUE_DATA_SOURCES.items():
            if normalised.startswith(prefix):
                found.extend(s for s in sources if s not in found)
    for indicator_type in indicator_types or []:
        for source in _INDICATOR_DATA_SOURCES.get(str(indicator_type).lower().strip(), ()):
            if source not in found:
                found.append(source)
    return found


#: Telemetry that only exists on a given platform. The hypothesis agent
#: proposes its own data_sources list and nothing checked it against the
#: platform the techniques actually resolved to, so a macOS hunt shipped asking
#: for `registry_events` -- telemetry macOS does not have. A reviewer scoping
#: that hunt has to notice and discard it, and an automated consumer cannot.
_PLATFORM_ONLY_DATA_SOURCES: dict[str, frozenset[str]] = {
    "registry_events": frozenset({"windows"}),
}
#: Data sources only a host sensor produces. A hunt scoped only to appliances
#: (sigma_generator.appliance_only) cannot use them: H-0830's NetScaler draft
#: listed process_execution and file_operations.
_HOST_SENSOR_DATA_SOURCES = frozenset(
    {"process_execution", "file_operations", "registry_events", "endpoint_data", "windows_logs"}
)
_NETWORK_DATA_SOURCES = frozenset({"network_connections", "network_logs"})


#: Telemetry category names the model returns as if they were observations.
#: A draft came back with "What Suspicious Looks Like" reading "Process
#: execution / Network connections / File operations" -- the data source list
#: retitled, which tells a reviewer nothing about what to look for and reads
#: as if the section had been filled in.
_DATA_SOURCE_RESTATEMENTS = frozenset(
    {
        "process execution",
        "process executions",
        "process creation",
        "file operations",
        "file operation",
        "file events",
        "network connections",
        "network connection",
        "network traffic",
        "registry events",
        "registry event",
        "dns queries",
        "dns query",
        "authentication events",
    }
)


#: Template values the model writes in place of an observation. H-0018 listed
#: `C:\path\to\malware.ps1`, `C:\path\to\rat.exe` and
#: `http://maliciousdomain.com/malware.bin` as what suspicious looks like; they
#: read as indicators, and the Sigma step, which is handed the observables,
#: wrote the first into a rule.
_PLACEHOLDER_OBSERVABLE_RE = re.compile(
    r"[\\/]path[\\/]to[\\/]"
    r"|\b(?:malicious-?domain|your-?domain|attacker-?domain)\b"
    r"|\bexample\.(?:com|org|net|test)\b"
    r"|(?:^|[\\/\s])(?:malware|malicious|rat|evil|badfile|payload)\.(?:exe|dll|ps1|bin|sh|bat|vbs|js|msi)\b"
    r"|<[a-z][a-z _-]*>",
    re.IGNORECASE,
)


_NO_OBSERVABLES = "[none proposed - human to populate]"


#: Values in a rule that are indicators, not behaviour: IPv4 addresses and MD5/SHA-1/SHA-256 hashes.
_RULE_IOC_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{64}\b|\b[0-9a-f]{40}\b|\b[0-9a-f]{32}\b"
)


def _merge_indicator_record(records: list[Any], rec: Any) -> bool:
    """Deduplicate an indicator record into records.

    If records already has an entry for rec.value, update existing status/role/ports
    if rec has more information, but do NOT add a duplicate unreviewed record that
    could override a historical/target classification.
    """
    rec_val = str(getattr(rec, "value", "")).strip().lower()
    for existing in records:
        if str(getattr(existing, "value", "")).strip().lower() == rec_val:
            if (
                getattr(existing, "status", "unknown") == "unknown"
                and getattr(rec, "status", "unknown") != "unknown"
            ):
                existing.status = rec.status
            if (
                getattr(existing, "role", "unknown") == "unknown"
                and getattr(rec, "role", "unknown") != "unknown"
            ):
                existing.role = rec.role
            if hasattr(rec, "ports") and rec.ports:
                existing_ports = set(getattr(existing, "ports", []) or [])
                existing.ports = sorted(existing_ports | set(rec.ports))
            return False
    records.append(rec)
    return True


def substantive_observables(observables: list[str]) -> list[str]:
    """Drop "observables" that restate the telemetry category or are templates.

    Kept deliberately narrow: an entry is dropped only when the whole string is
    a bare category name, or it contains a template value. "Process execution
    of an unsigned binary from /tmp" describes something a hunter can look for
    and stays.
    """
    kept: list[str] = []
    for observable in observables:
        text = str(observable).strip()
        normalised = text.lower().rstrip(".").replace("_", " ")
        if normalised in _DATA_SOURCE_RESTATEMENTS:
            continue
        if _PLACEHOLDER_OBSERVABLE_RE.search(text):
            continue
        if text:
            kept.append(text)
    return kept


def platform_consistent_data_sources(data_sources: list[str], platforms: list[str]) -> list[str]:
    """Drop telemetry that cannot exist on any of this hunt's platforms.

    Only drops when the platform list is non-empty and unambiguous about it.
    An empty platform list means scope is unknown, not that everything is
    excluded, so nothing is removed there -- the draft is a starting point for
    a human, and silently narrowing telemetry on no evidence is worse than
    leaving a source a reviewer can strike out.
    """
    if not platforms:
        return data_sources
    known = {str(p).strip().lower() for p in platforms if str(p).strip()}
    if not known:
        return data_sources

    from hecate_agent.agents.llm.sigma_generator import appliance_only

    appliance = appliance_only(platforms)
    kept: list[str] = []
    for source in data_sources:
        name = str(source).strip().lower()
        required = _PLATFORM_ONLY_DATA_SOURCES.get(name)
        if required is not None and not (known & required):
            continue
        if appliance and name in _HOST_SENSOR_DATA_SOURCES:
            continue
        kept.append(source)
    if appliance and not any(str(s).strip().lower() in _NETWORK_DATA_SOURCES for s in kept):
        # An appliance's own access and system logs, and what the network sees.
        kept.append("network_logs")
    return kept


_EMPTY_SOURCE_SLOT = re.compile(r"(published in)\s{2,}(appear)", re.IGNORECASE)


def _fill_empty_source_slot(hypothesis: str, source_title: str | None) -> str:
    """Repair an indicator-sweep hypothesis whose [source] slot came back empty."""
    if not _EMPTY_SOURCE_SLOT.search(hypothesis):
        return hypothesis
    source = (source_title or "").strip() or "the source feed"
    return _EMPTY_SOURCE_SLOT.sub(lambda m: f"{m.group(1)} {source} {m.group(2)}", hypothesis)


# ATT&CK's own STIX data uses the literal platform value "PRE" for
# Reconnaissance/Resource-Development techniques (e.g. T1598 "Phishing for
# Information") that happen before the adversary has a foothold on any
# actual system -- there's no OS/environment to name yet. Surfaced verbatim,
# a hunt file's `platform: ["PRE"]` reads as a parsing bug or an unknown
# abbreviation, not what it actually means, to a human who has to scope a
# query against it. Translated at the same point _resolve_ttps already
# builds the platform list, not hardcoded as a special case in the template.
_PLATFORM_LABELS = {"PRE": "Pre-Compromise (reconnaissance/targeting -- not endpoint/OS-specific)"}


def derive_research_topic(cti_content: str, title: str | None = None) -> tuple[str, str | None]:
    """Best-effort (topic, technique) pair from a raw CTI blob.

    No NLP here on purpose — this only has to be good enough to seed the
    research agent's web searches; the research + hypothesis steps do the
    actual analysis.

    ``title`` should be the provider's clean, single-field title (e.g.
    RSS entry title, OTX pulse name, MISP event info) when the caller has
    one. Preferred over flattening/truncating ``cti_content`` -- that blob
    is "RSS: <title>\\nSource: <feed>\\nTags: ...\\nSummary: ...\\nLink:
    ...", and truncating *that whole string* at a fixed char count landed
    mid-"Source:"/"Summary:" label whenever the title alone was long,
    producing both a garbled `topic` field and a research doc contaminated
    with docs about "Source" website features whose name got the title
    pulled from the title alone. Falls back to the old flatten+truncate
    behavior only when no clean title is available.

    Known accepted limitation: for a title from a recurring series (e.g. a
    vendor's weekly "This Week in Cybersecurity"-style digest, republished
    under a near-identical title every week), the bare title alone doesn't
    disambiguate *which* edition the CTI item actually is -- the resulting
    ``topic`` can cause the research skills' web search (see
    search_system_internals/search_adversary_tradecraft in hecate's
    web_search.py) to ground against a *different* edition of the same
    series than the one this CTI item is actually about, since none of
    ``cti_content``'s more specific/disambiguating text (a summary
    mentioning the edition's actual stories) reaches the search query --
    only this function's ``topic`` return value does. Observed case: CTI
    title "The Good, the Bad and the Ugly in Cybersecurity - Week 32
    (2026)" (real content: a Snowflake breach plea, "Mythos 5", and
    ChainDrop's npm worm) produced a research doc grounded on a different
    week's edition entirely (CISO Assistant, "khunt", "The Com" takedown).
    Left unfixed for now: the actual hunt hypothesis stayed accurate in
    every observed case regardless, because hypothesis-generator weighs
    the raw CTI text over the research doc's synthesis when they diverge
    -- only the research doc itself (not the hunt) ends up describing the
    wrong content. Revisit if a bad research grounding ever does end up
    steering a hunt wrong, not just looking wrong on its own.
    """
    technique_match = _TECHNIQUE_RE.search(cti_content)
    technique = technique_match.group(0) if technique_match else None

    topic = (title or " ".join(cti_content.split())).strip()
    if len(topic) > _TOPIC_MAX_LEN:
        truncated = topic[:_TOPIC_MAX_LEN]
        # Prefer cutting on a word boundary so we don't hand the agent a
        # half-word topic.
        if " " in truncated:
            truncated = truncated.rsplit(" ", 1)[0]
        topic = truncated
    return topic or "Untitled CTI", technique


_ATTRIBUTION_RE = re.compile(r"^\s*Adversary/Attribution:\s*(.+?)\s*$", re.MULTILINE)
_NO_ATTRIBUTION = frozenset({"unknown", "none", "n/a", "unattributed", "-"})


def attributed_actor(cti_content: str) -> str:
    """The actor the intel's own attribution line names, or "".

    OTX pulses carry an ``Adversary/Attribution:`` line, and the hypothesis
    model left the ABLE Actor cell empty even when it named TraderTraitor
    (H-0007) or Water Hydra (H-0012). The publisher's attribution is the
    source's claim, not an inference, so it fills the cell only when the
    model offered nothing.
    """
    match = _ATTRIBUTION_RE.search(cti_content)
    if not match:
        return ""
    value = match.group(1).strip()
    return "" if value.lower() in _NO_ATTRIBUTION else value


_NARRATIVE_HEADER_RE = re.compile(
    r"(?im)^#{1,4}\s+.*(summary|analysis|tradecraft|context|background|lifecycle|overview|threat|technical|details|behavior|activity|intrusion|campaign|investigation|findings|execution|kill\s*chain|detection)"
)

_IOC_LINE_RE = re.compile(
    r"^[-*]?\s*([0-9a-f]{32,64}|\d{1,3}(?:\.\d{1,3}){3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|https?://\S+)\s*$",
    re.IGNORECASE,
)


def _has_substantive_prose(text: str, min_words: int = 40) -> bool:
    """True if text contains multi-word prose sentences beyond metadata fields and bare IOCs."""
    prose_words = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("```", "http://", "https://")):
            continue
        if re.match(r"^[A-Za-z0-9 _/-]{1,30}:\s", line) and not (
            line.startswith("Description:") or line.startswith("Summary:")
        ):
            continue
        if re.match(r"^(attributes|indicators)\s*\(\d+", line, re.IGNORECASE):
            continue
        if _IOC_LINE_RE.match(line):
            continue
        words = [
            w for w in line.split() if len(w) > 1 and not w.startswith(("http://", "https://"))
        ]
        if len(words) >= 3:
            prose_words += len(words)
            if prose_words >= min_words:
                return True
    return False


def has_narrative(cti_content: str) -> bool:
    """Whether ``cti_content`` carries substance beyond a bare indicator dump.

    All three CTI providers build their blurb around a "does this item have
    a human-written description" branch: RSS's ``_entry_to_blurb`` appends a
    ``Summary:`` line only when the entry has one, OTX's ``_pulse_to_blurb``
    appends a ``Description:`` line only when the pulse has one, and MISP's
    ``_event_to_blurb`` has no narrative field to append at all -- a MISP
    event carries a title (``info``) and structured metadata, not prose.

    An explicit ``MITRE ATT&CK Techniques:`` line counts too, and all three
    providers emit it under that same label. It is not prose, but the
    question this gates is not "is there prose" -- it is "is there anything
    here besides an IOC dump and a title." A stated technique list is an
    analyst asserting observed behavior, which is the strongest form of that
    evidence available short of prose, and it is precisely what a bulk
    indicator dump cannot produce: ThreatFox-style events carry no galaxy
    cluster, so they reach no such line.

    Without this, every MISP event failed the check no matter how well
    curated -- classified as an indicator sweep, routed past research, and
    rendered with ``techniques: []`` even though the event had just handed
    us fifteen technique IDs. That silently cancelled out the galaxy filter
    and org allowlist, whose whole purpose is selecting ATT&CK-mapped events.

    Gates two things, both failing the same way for the same reason -- a
    bare IOC-count blurb gives each step nothing real to work from, and both
    fill the gap from background knowledge rather than leaving it empty:

    - Web search during research. Tavily has nothing of substance to match,
      so it grounds on whatever else shares the topic's generic/templated
      title -- observed fabricating malware family names ("PureRAT and
      Overlord RAT") that propagated into the hunt file, unlike the
      recurring-digest-title case in `derive_research_topic` where the hunt
      stayed accurate because the CTI still had real text to fall back on.
    - Hypothesis generation. The agent's default template obliges the model
      to name a behavior, so against a list of domains it invented one --
      "phishing emails" as the delivery vector, "stolen credentials ...
      lateral movement" as follow-on activity, plus an unsupported ATT&CK
      technique. See `HecateClient.hypothesis_generator`'s indicators_only.
    """
    return (
        "Description:" in cti_content
        or "Summary:" in cti_content
        or ATTACK_TECHNIQUE_LINE in cti_content
        or bool(_NARRATIVE_HEADER_RE.search(cti_content))
        or _has_substantive_prose(cti_content)
    )


def _indicator_only_source(item: CTIItem) -> bool:
    """Whether provider metadata says this item contains sample/IOC facts only.

    Some integrations synthesize readable summaries from hashes, malware
    family names and file types. That generated prose must not turn catalog
    metadata into a behavioral report.
    """
    return bool(item.metadata.get("indicator_only")) or item.metadata.get("evidence_profile") in {
        "sample_metadata",
        "indicator_only",
    }


#: How many non-actionable items one cycle may walk past before giving up.
#: A feed of nothing but vendor blog posts should cost a single cycle, not an
#: unbounded walk through the archive.
_MAX_SKIPS_PER_CYCLE = 5


#: Field prefixes the providers emit. Everything a blurb says about itself
#: rather than about the threat.
_BLURB_FIELD_PREFIXES = (
    "RSS:",
    "OTX Pulse:",
    "MISP Event:",
    "Source:",
    "Link:",
    "Tags:",
    "Org:",
    "TLP:",
    "Threat Level:",
    "Adversary/Attribution:",
    "References:",
    "Indicators (",
    "Key indicators:",
    ATTACK_TECHNIQUE_LINE,
)


def _carries_free_text(cti_content: str) -> bool:
    """Whether anything here is prose rather than a provider metadata field.

    This is what separates "the blurb had no narrative field" from "there is
    no narrative". The file queue takes free-form text a human wrote --
    "APT actor X observed dumping LSASS via comsvcs.dll" -- which carries no
    `Summary:` marker and would otherwise read as empty.
    """
    for line in cti_content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Indented lines continue the field above them (values under
        # "Key indicators:").
        if line[:1].isspace():
            continue
        if stripped.startswith(_BLURB_FIELD_PREFIXES):
            continue
        return True
    return False


def is_actionable(cti_content: str) -> bool:
    """Whether there is anything here to build a hunt from.

    Three ways to qualify, and an item needs only one: a narrative field a
    hypothesis can be grounded in, a parseable indicator inventory a sweep can
    be built from, or free-form prose that is not provider metadata.

    The third clause is load-bearing. ``has_narrative`` recognises the
    *markers* provider blurbs use, so its absence is not evidence that no
    narrative exists -- and treating it as such discarded the file queue's
    hand-written CTI outright when this gate was first written.

    What is left over is the case this exists for: a blurb that is nothing but
    its own metadata. H-0630 was four lines -- title, source, tags, link --
    off a vendor marketing post, and became "Indicators published in Teaching
    AI to Reason Through Detection Triage appear in telemetry", a sweep for
    indicators that do not exist.

    This is a floor, not a quality bar. It does not ask whether the prose is
    *about* a specific threat; a conference write-up passes. That is the
    harder half of C4 and is deliberately still open.
    """
    return (
        has_narrative(cti_content)
        or bool(parse_indicator_inventory(cti_content))
        or _carries_free_text(cti_content)
    )
