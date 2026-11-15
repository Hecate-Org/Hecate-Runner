"""Monthly STIX technique/procedure deltas scoped to uncovered corpus techniques."""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import CTIItem, CTIProvider
from hecate_runner.integration_health import record_health


class AttackDeltaProvider(CTIProvider):
    name = "attack_deltas"

    def __init__(
        self,
        workspace: Path,
        *,
        client: httpx.Client | None = None,
        interval_seconds: int = 30 * 86400,
        **kwargs: Any,
    ):
        self.workspace = workspace
        if client is not None:
            self.client = client
            self.owns_client = False
        else:
            from hecate_runner.http_pool import get_shared_client

            self.client = get_shared_client(pool_name="cti:attack_deltas", timeout=60.0)
            self.owns_client = False
        self.interval_seconds = interval_seconds
        self.headers = {"User-Agent": "Hecate-Runner/1.0"}
        if kwargs.get("github_token"):
            self.headers["Authorization"] = f"Bearer {kwargs['github_token']}"
        self.cursor_file = workspace / ".cursors" / "attack_deltas_cursor.json"
        self._covered_cache: tuple[tuple[tuple[str, int], ...], frozenset[str]] | None = None

    def close(self) -> None:
        # Shared pool clients are process-owned; injected clients are caller-owned.
        if self.owns_client:
            self.client.close()

    def _hunts_fingerprint(self) -> tuple[tuple[str, int], ...]:
        hunts_dir = self.workspace / "hunts"
        if not hunts_dir.exists():
            return ()
        entries: list[tuple[str, int]] = []
        for path in hunts_dir.rglob("H-*.md"):
            try:
                entries.append((str(path), path.stat().st_mtime_ns))
            except OSError:
                continue
        return tuple(sorted(entries))

    def covered(self) -> set[str]:
        fingerprint = self._hunts_fingerprint()
        if self._covered_cache is not None and self._covered_cache[0] == fingerprint:
            return set(self._covered_cache[1])

        covered: set[str] = set()
        for path_str, _mtime in fingerprint:
            path = Path(path_str)
            try:
                text = path.read_text(encoding="utf-8")
                meta = yaml.safe_load(text.split("---", 2)[1])
                status = str(meta.get("status") or "").lower()
                if status not in {"archived", "retired"}:
                    covered.update(str(t).upper() for t in (meta.get("techniques") or []) if t)
            except (IndexError, AttributeError, OSError, UnicodeError, yaml.YAMLError):
                continue
        self._covered_cache = (fingerprint, frozenset(covered))
        return covered

    def save(self, state: dict[str, Any]) -> None:
        atomic_write_text(self.cursor_file, json.dumps(state))

    def next_item(self) -> CTIItem | None:
        try:
            state = (
                json.loads(self.cursor_file.read_text(encoding="utf-8"))
                if self.cursor_file.exists()
                else {}
            )
            if (
                not state.get("pending")
                and time.time() - state.get("checked", 0) >= self.interval_seconds
            ):
                covered = self.covered()
                head = self.client.get(
                    "https://api.github.com/repos/mitre-attack/attack-stix-data/commits/master",
                    headers=self.headers,
                )
                head.raise_for_status()
                revision = str(head.json()["sha"])
                if not re.fullmatch("[a-f0-9]{40}", revision):
                    raise ValueError("invalid ATT&CK revision")

                # Same ATT&CK revision + existing fingerprints → skip multi-MB downloads.
                if (
                    revision == state.get("revision")
                    and isinstance(state.get("fingerprints"), dict)
                    and state["fingerprints"]
                ):
                    state["checked"] = time.time()
                    self.save(state)
                    record_health(
                        self.workspace,
                        self.name,
                        True,
                        "ATT&CK revision unchanged; STIX re-download skipped",
                    )
                else:
                    fingerprints, objects = {}, {}
                    for domain in ("enterprise-attack", "ics-attack"):
                        url = (
                            f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                            f"{revision}/{domain}/{domain}.json"
                        )
                        r = self.client.get(url, headers=self.headers)
                        r.raise_for_status()
                        if len(r.content) > 80_000_000:
                            raise ValueError("STIX bundle exceeds size limit")
                        bundle = r.json()
                        if bundle.get("type") != "bundle" or not isinstance(
                            bundle.get("objects"), list
                        ):
                            raise ValueError("invalid STIX bundle")
                        for obj in bundle["objects"]:
                            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                                continue
                            if obj.get("type") == "attack-pattern" or (
                                obj.get("type") == "relationship"
                                and obj.get("relationship_type") == "uses"
                                and obj.get("description")
                            ):
                                objects[obj["id"]] = {
                                    **obj,
                                    "_source_url": url,
                                    "_revision": revision,
                                }
                                fingerprints[obj["id"]] = hashlib.sha256(
                                    json.dumps(
                                        {
                                            k: v
                                            for k, v in obj.items()
                                            if k
                                            not in {
                                                "modified",
                                                "created",
                                                "x_mitre_version",
                                                "x_mitre_attack_spec_version",
                                            }
                                        },
                                        sort_keys=True,
                                    ).encode()
                                ).hexdigest()
                    if not any(o.get("type") == "attack-pattern" for o in objects.values()):
                        raise ValueError("STIX has no techniques")
                    pending = []
                    if "fingerprints" in state:
                        changed = {
                            k for k, v in fingerprints.items() if state["fingerprints"].get(k) != v
                        }
                        targets = {k for k in changed if objects[k].get("type") == "attack-pattern"}
                        targets.update(
                            objects[k].get("target_ref")
                            for k in changed
                            if objects[k].get("type") == "relationship"
                        )
                        for target in sorted(t for t in targets if t in objects):
                            obj = objects[target]
                            tid = next(
                                (
                                    ref.get("external_id")
                                    for ref in obj.get("external_references", [])
                                    if re.fullmatch(
                                        r"T\d{4}(?:\.\d{3})?", str(ref.get("external_id", ""))
                                    )
                                ),
                                None,
                            )
                            if not tid or tid in covered:
                                continue
                            procedures = [
                                o
                                for k, o in objects.items()
                                if k in changed and o.get("target_ref") == target
                            ]
                            pending.append(
                                {
                                    "technique": obj,
                                    "technique_id": tid,
                                    "procedures": procedures,
                                    "reason": (
                                        "changed ATT&CK technique/procedure has no "
                                        "non-archived hunt coverage"
                                    ),
                                }
                            )
                    state = {
                        "fingerprints": fingerprints,
                        "revision": revision,
                        "checked": time.time(),
                        "pending": pending,
                    }
                    self.save(state)
                    record_health(
                        self.workspace,
                        self.name,
                        True,
                        "enterprise and ICS STIX baseline/delta validated",
                    )
            # Corpus coverage may have changed while a monthly batch was pending.
            if not state.get("pending"):
                return None
            covered = self.covered()
            while state.get("pending") and state["pending"][0]["technique_id"] in covered:
                state["pending"].pop(0)
                self.save(state)
            if not state.get("pending"):
                return None
            change = state["pending"][0]
            obj = change["technique"]
            tid = change["technique_id"]
            content = (
                f"Title: ATT&CK delta: {tid} {obj['name']}\n"
                f"MITRE ATT&CK Techniques: {tid}\nReason: {change['reason']}\n"
                "Reference taxonomy and documented procedure examples; not a newly observed incident.\n"
                + json.dumps(change, ensure_ascii=False)
            )
            return CTIItem(
                content=content,
                title=f"ATT&CK delta: {tid} {obj['name']}",
                source=self.name,
                source_url=f"{obj['_source_url']}#{obj['id']}",
                received_at=datetime.now(UTC),
                identifier=f"{tid}:{obj.get('modified', '')}:{hashlib.sha256(content.encode()).hexdigest()[:16]}",
                metadata={
                    "processing_track": "deep",
                    "evidence_profile": "taxonomy_delta",
                    "technique_id": tid,
                    "delta": change,
                    "source_revision": obj["_revision"],
                    "reference_only": True,
                },
            )
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            record_health(
                self.workspace,
                self.name,
                False,
                "STIX fetch/schema failure; prior baseline retained",
            )
            raise

    def acknowledge(self, item: CTIItem) -> None:
        state = json.loads(self.cursor_file.read_text(encoding="utf-8"))
        state["pending"] = [v for v in state["pending"] if v != item.metadata["delta"]]
        self.save(state)
