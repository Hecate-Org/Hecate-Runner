"""Canonical Sigma rule selection for BAS synthesize and SIEM verification.

Synthesize and live verify must pick the same primary behavioral rule so a
green lab result means the detection you actually care about fired — not
whichever ``*.yml`` sorts first alphabetically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


def looks_like_sigma_yaml(text: str) -> bool:
    lowered = text.lstrip()
    return "detection:" in lowered and ("title:" in lowered or "logsource:" in lowered)


def is_incremental_stub(path: Path, text: str = "") -> bool:
    """Correlator IOC stubs must never win as the primary behavioral rule."""
    name = path.name.lower()
    if "incremental" in name:
        return True
    lowered = text.lower()
    return "incremental campaign detection" in lowered or "correlation-engine" in lowered


def sigma_rule_rank(path: Path, text: str) -> tuple[int, str]:
    """Lower rank = better. Prefer behavioral cores over incremental IOC stubs."""
    name = path.name.lower()
    if is_incremental_stub(path, text):
        return (100, name)
    score = 50
    lowered = text.lower()
    if "category: process_creation" in lowered:
        # Parent→child process chains beat single-field command quotes.
        if "parentimage" in lowered and ("selection_child" in lowered or "image|" in lowered):
            score = 5
        else:
            score = 10
    elif "category: webserver" in lowered:
        score = 11
    elif "category: file_event" in lowered or "category: network_connection" in lowered:
        score = 12
    elif "category: dns_query" in lowered:
        score = 40
    if "correlation-engine" in lowered or "incremental campaign detection" in lowered:
        score += 50
    if "command the source shows" in lowered or "command_the_source" in name:
        score += 40
    if "level: low" in lowered:
        score += 5
    if "level: high" in lowered or "level: critical" in lowered:
        score -= 2
    return (score, name)


def _technique_names(technique_id: str) -> tuple[str, ...]:
    technique = technique_id.lower()
    return (technique, technique.replace(".", "_"), technique.replace(".", ""))


def _technique_token_re(technique_id: str) -> re.Pattern[str]:
    """Match ATT&CK IDs as tokens so ``T100`` does not hit ``T1003.001``."""
    technique = technique_id.lower()
    body = technique[1:] if technique.startswith("t") and technique[1:2].isdigit() else technique
    return re.compile(rf"(?<![0-9a-z])(?:attack\.)?t{re.escape(body)}(?![0-9a-z])", re.I)


def rule_matches_technique(path: Path, content: str, technique_id: str | None) -> bool:
    """Whether a Sigma file is eligible for the given technique filter."""
    if not technique_id:
        return True
    token_re = _technique_token_re(technique_id)
    stem = path.stem.lower()
    for name in _technique_names(technique_id):
        start = 0
        while True:
            idx = stem.find(name, start)
            if idx < 0:
                break
            before = stem[idx - 1] if idx > 0 else ""
            after = stem[idx + len(name)] if idx + len(name) < len(stem) else ""
            if (not before.isalnum()) and (not after.isalnum()):
                return True
            start = idx + 1
    return bool(token_re.search(content))


@dataclass(frozen=True)
class SelectedSigmaRule:
    """Primary rule chosen for synthesize / verify."""

    path: Path
    name: str
    yaml_text: str
    spl_query: str
    rank: tuple[int, str]


def iter_sigma_rule_files(query_dir: Path) -> list[Path]:
    if not query_dir.is_dir():
        return []
    return sorted([*query_dir.glob("*.yml"), *query_dir.glob("*.yaml")])


def select_primary_sigma_rule(
    query_dir: Path,
    *,
    technique_id: str | None = None,
) -> SelectedSigmaRule | None:
    """Pick the best behavioral Sigma YAML under ``queries/<hunt>/``.

    When ``technique_id`` is set, only technique-matching rules compete. If none
    match and the directory has exactly one Sigma file, that file is used when it
    already carries an ATT&CK tag (legacy single-rule hunts).
    """
    rules = iter_sigma_rule_files(query_dir)
    if not rules:
        return None

    candidates: list[tuple[tuple[int, str], Path, str]] = []
    for path in rules:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if not looks_like_sigma_yaml(content):
            continue
        if is_incremental_stub(path, content):
            # Never synthesize/verify against IOC stubs when selecting a primary.
            continue
        if technique_id:
            matches = rule_matches_technique(path, content, technique_id)
            if not matches:
                # Legacy single-rule hunts: accept the sole YAML when only 1 exists
                if len(rules) == 1:
                    matches = True
                else:
                    continue
        candidates.append((sigma_rule_rank(path, content), path, content))

    if not candidates:
        return None

    candidates.sort(key=lambda item: item[0])
    rank, path, content = candidates[0]
    companion = path.with_suffix(".spl")
    spl = ""
    try:
        if companion.is_file():
            spl = companion.read_text(encoding="utf-8").strip()
    except OSError:
        # Unreadable companion: still return the Sigma rule; lab proof can report
        # no_companion_spl instead of crashing synthesize/verify selection.
        spl = ""
    return SelectedSigmaRule(
        path=path,
        name=path.name,
        yaml_text=content,
        spl_query=spl,
        rank=rank,
    )


def load_sigma_from_query_dirs(roots: list[Path], hunt_id: str) -> tuple[str, Path | None]:
    """Prefer authoritative Sigma under ``queries/<hunt_id>/`` across workspace roots."""
    candidates: list[tuple[tuple[int, str], Path, str]] = []
    seen: set[Path] = set()
    for root in roots:
        hunt_dir = root / "queries" / hunt_id
        paths: list[Path] = []
        if hunt_dir.is_dir():
            paths.extend(hunt_dir.glob("*.yml"))
            paths.extend(hunt_dir.glob("*.yaml"))
        # Only fall back to recursive name globs when the canonical dir is empty.
        # Avoid ``H-0032*.yml`` also matching ``H-00320`` and re-reading hunt_dir.
        if not paths:
            queries_root = root / "queries"
            if queries_root.is_dir():
                paths.extend(queries_root.glob(f"**/{hunt_id}.yml"))
                paths.extend(queries_root.glob(f"**/{hunt_id}.yaml"))
                paths.extend(queries_root.glob(f"**/{hunt_id}__*.yml"))
                paths.extend(queries_root.glob(f"**/{hunt_id}__*.yaml"))
        for path in paths:
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            if not looks_like_sigma_yaml(text):
                continue
            if is_incremental_stub(path, text):
                continue
            candidates.append((sigma_rule_rank(path, text), path, text))
    if not candidates:
        return "", None
    candidates.sort(key=lambda item: item[0])
    _rank, path, text = candidates[0]
    return text, path


def load_sigma_from_hunt_markdown(roots: list[Path], hunt_id: str) -> tuple[str, Path | None]:
    """Last-resort: extract a Sigma fence from the hunt markdown body."""
    import re

    for root in roots:
        matches = (
            sorted((root / "hunts").glob(f"**/{hunt_id}.md")) if (root / "hunts").exists() else []
        )
        matches += sorted(root.glob(f"**/{hunt_id}.md"))
        for path in matches:
            try:
                content = path.read_text(encoding="utf-8")
            except OSError:
                continue
            for block in re.findall(r"```ya?ml\s*\n(.*?)```", content, re.DOTALL | re.IGNORECASE):
                if looks_like_sigma_yaml(block):
                    return str(block).strip() + "\n", path
    return "", None
