"""Replay a draft's Sigma rules against the report's own artifacts.

This is not emulation. The events are synthesised from what the primary report
verifiably names -- typed indicators and behaviour artifacts -- one event per
artifact, shaped for the log source that could observe it. A rule "validates"
only when it matches at least one event for its own log source and none of a
small fixed benign sample. That catches rules that cannot match what the source
describes (wrong field, broken condition, over-tight filter); it says nothing
about false positives in a real environment.

The stage it replaces built its events from attributes that did not exist
(``CTIItem.indicators``, ``SourceEvidence.commands``), so every rule was
replayed against nothing and marked validated: H-0830's five rules, one of them
with a condition naming selections it did not have, were reported as "verified
against attack telemetry" with "0 false positives".
"""

from __future__ import annotations

import copy
import hashlib
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

#: Benign baseline samples partitioned by category/platform to provide realistic,
#: noise-floor negative testing for rules without cross-platform false alarms.
#:
#: NOTE: These samples provide a local sanity gate and noise-floor smoke check for
#: automated rule tuning. They do not constitute an operational false-positive rate
#: for production telemetry, which requires an independent holdout corpus.

BENIGN_SAMPLE_LINUX: list[dict[str, Any]] = [
    {"Image": "/usr/sbin/cron", "CommandLine": "/usr/sbin/cron -f", "User": "root"},
    {
        "Image": "/usr/sbin/anacron",
        "CommandLine": "/usr/sbin/anacron -s /etc/cron.d",
        "User": "root",
    },
    {"Image": "/usr/bin/curl", "CommandLine": "curl https://pypi.org/simple", "User": "app"},
    {
        "Image": "/usr/lib/systemd/systemd-journald",
        "CommandLine": "/usr/lib/systemd/systemd-journald",
        "User": "root",
    },
    {
        "Image": "/usr/sbin/logrotate",
        "CommandLine": "logrotate /etc/logrotate.conf",
        "User": "root",
    },
    {
        "Image": "/bin/bash",
        "CommandLine": "/bin/bash /etc/profile.d/lang.sh",
        "User": "root",
    },
    {
        "TargetFilename": "/var/log/syslog",
        "User": "syslog",
    },
]

BENIGN_SAMPLE_WINDOWS: list[dict[str, Any]] = [
    {
        "Image": "C:\\Windows\\System32\\svchost.exe",
        "CommandLine": "svchost.exe -k netsvcs",
        "User": "SYSTEM",
    },
    {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -File C:\\Program Files\\Monitoring\\agent.ps1",
        "User": "SYSTEM",
    },
    {
        "Image": "C:\\Windows\\explorer.exe",
        "CommandLine": "C:\\Windows\\explorer.exe",
        "User": "CORP\\alice",
    },
    {
        "Image": "C:\\Windows\\System32\\taskhostw.exe",
        "CommandLine": "taskhostw.exe {2227A56E-0000-0000-0000-000000000000}",
        "User": "SYSTEM",
    },
    {
        "TargetObject": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Start",
        "Details": "2",
        "Image": "services.exe",
    },
    {
        "TargetFilename": "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "User": "SYSTEM",
    },
]

BENIGN_SAMPLE_WEBSERVER: list[dict[str, Any]] = [
    {
        "cs-method": "GET",
        "cs-uri-stem": "/index.html",
        "sc-status": "200",
        "cs-user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    },
    {
        "cs-method": "GET",
        "cs-uri-stem": "/healthz",
        "sc-status": "200",
        "cs-user-agent": "kube-probe/1.28",
    },
    {
        "cs-method": "GET",
        "cs-uri-stem": "/robots.txt",
        "sc-status": "200",
        "cs-user-agent": "Googlebot/2.1",
    },
    {
        "cs-method": "GET",
        "cs-uri-stem": "/favicon.ico",
        "sc-status": "200",
        "cs-user-agent": "Mozilla/5.0",
    },
    {
        "cs-method": "GET",
        "cs-uri-stem": "/static/css/main.css",
        "sc-status": "200",
        "cs-user-agent": "Mozilla/5.0",
    },
    {
        "cs-method": "POST",
        "cs-uri-stem": "/api/v1/auth",
        "sc-status": "200",
        "cs-user-agent": "Mozilla/5.0",
    },
]

BENIGN_SAMPLE_NETWORK: list[dict[str, Any]] = [
    {"DestinationIp": "8.8.8.8", "DestinationPort": 53, "QueryName": "microsoft.com"},
    {
        "c-uri": "https://www.google.com/search?q=weather",
        "cs-host": "www.google.com",
        "cs-method": "GET",
    },
    {
        "DestinationIp": "1.1.1.1",
        "DestinationPort": 443,
        "Protocol": "tcp",
    },
]

BENIGN_SAMPLE_CLOUD: list[dict[str, Any]] = [
    {
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/developer"},
    },
    {
        "operationName": "Sign-in activity",
        "result": "success",
        "initiatedBy": {"user": {"userPrincipalName": "developer@example.com"}},
    },
]

BENIGN_SAMPLE_CONTAINER: list[dict[str, Any]] = [
    {
        "Image": "k8s.gcr.io/pause:3.6",
        "ContainerName": "pause",
        "CommandLine": "/pause",
        "Privileged": "false",
    },
]

#: Benign events every rule must not match. Deliberately small and generic: it
#: is a sanity floor, not a model of anyone's environment.
BENIGN_SAMPLE: list[dict[str, Any]] = (
    BENIGN_SAMPLE_LINUX
    + BENIGN_SAMPLE_WINDOWS
    + BENIGN_SAMPLE_WEBSERVER
    + BENIGN_SAMPLE_NETWORK
    + BENIGN_SAMPLE_CLOUD
    + BENIGN_SAMPLE_CONTAINER
)


def get_benign_sample_for_rule(rule_yaml: str) -> list[dict[str, Any]]:
    """Return a baseline event sample tailored to the rule's logsource category and product.

    Falls back to `BENIGN_SAMPLE` if the logsource is unknown or cannot be parsed.
    """
    if not rule_yaml or not isinstance(rule_yaml, str):
        return BENIGN_SAMPLE

    try:
        import yaml

        doc = yaml.safe_load(rule_yaml)
        if not isinstance(doc, dict):
            return BENIGN_SAMPLE
        logsource = doc.get("logsource") or {}
        if not isinstance(logsource, dict):
            return BENIGN_SAMPLE
    except Exception:
        return BENIGN_SAMPLE

    product = str(logsource.get("product") or "").lower().strip()
    category = str(logsource.get("category") or "").lower().strip()
    service = str(logsource.get("service") or "").lower().strip()

    if category in ("webserver", "apache", "nginx", "iis") or service in (
        "apache",
        "nginx",
        "iis",
        "webserver",
    ):
        return BENIGN_SAMPLE_WEBSERVER + BENIGN_SAMPLE_NETWORK

    if category in ("network_connection", "dns_query", "dns", "firewall", "jarm") or service in (
        "dns",
        "firewall",
    ):
        return BENIGN_SAMPLE_NETWORK

    if product in ("aws", "azure", "gcp", "cloud") or service in (
        "cloudtrail",
        "signin",
        "signinlogs",
    ):
        return BENIGN_SAMPLE_CLOUD

    if product in ("kubernetes", "k8s") or category in ("container", "k8s"):
        return BENIGN_SAMPLE_CONTAINER

    if (
        product == "windows"
        or category in _REGISTRY_CATEGORIES
        or service
        in (
            "security",
            "system",
            "powershell",
        )
    ):
        return BENIGN_SAMPLE_WINDOWS

    if product == "linux":
        return BENIGN_SAMPLE_LINUX

    # If category is process_creation or file_event without specific product, include OS baselines
    if category in ("process_creation", "file_event"):
        return BENIGN_SAMPLE_LINUX + BENIGN_SAMPLE_WINDOWS

    return BENIGN_SAMPLE


#: Roles and statuses that are not this intrusion's infrastructure.
_NOT_INFRASTRUCTURE = {"historical", "target"}
#: Hash roles no process or module event carries: a token or revision ID, a
#: hash of something only in memory or only on the wire. H-0018's hash rule
#: "validated" against Node-RED flow revision IDs replayed as process hashes.
_NOT_A_FILE_HASH = {"non_file", "memory_only", "network_content"}
#: Artifact statuses the source does not tie to this intrusion; a PoC README's
#: own files and test output are demoted to "unknown".
_NOT_THIS_INTRUSION = {"historical", "unknown"}
_HASH_LABELS = {"md5": "MD5", "sha1": "SHA1", "sha256": "SHA256", "imphash": "IMPHASH"}
_REGISTRY_CATEGORIES = ("registry_set", "registry_add", "registry_event")


def _posted(path: str, text: str) -> bool:
    """Whether the source shows ``path`` requested with POST: "deploy a new flow through `POST /flows`"."""
    if not path or not text:
        return False
    return bool(
        re.search(rf"\bPOST\s+[`'\"]?(?:https?://[^\s/]+)?{re.escape(path)}(?![\w/.-])", text)
    )


def replay_events(
    records: Iterable[Any],
    artifacts: Iterable[Any],
    cti_text: str = "",
    techniques: Iterable[str] = (),
    enable_atomic: bool = True,
    platforms: list[str] | None = None,
    http_requests: list[dict[str, Any]] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """``{logsource category: [event, ...]}`` from typed indicators, behaviour artifacts,
    and synthetic Atomic Red Team definitions.

    ``records`` are IndicatorRecord-shaped (value, type, role, status, ports);
    ``artifacts`` are SourceArtifact-shaped (value, kind, status).
    ``cti_text`` optionally provides raw source text for contextual cloud and identity telemetry.
    ``techniques`` optionally provides ATT&CK technique IDs for synthetic Atomic Red Team samples.
    """
    from hecate_agent.core.provenance import split_host_port, url_parts

    events: dict[str, list[dict[str, Any]]] = {}

    def add(category: str, event: dict[str, Any]) -> None:
        bucket = events.setdefault(category, [])
        if event not in bucket:
            bucket.append(event)

    for record in records:
        value = str(getattr(record, "value", "") or "").strip()
        rtype = str(getattr(record, "type", "") or "").lower()
        if (
            not value
            or getattr(record, "status", "") == "historical"
            or getattr(record, "role", "") in _NOT_INFRASTRUCTURE
        ):
            continue
        if rtype in ("ipv4", "ipv6") and getattr(record, "role", "") == "inbound":
            # The attack source: the client in web logs, the far end of an accepted connection.
            host, _ = split_host_port(value)
            add("webserver", {"c-ip": host})
            add("network_connection", {"SourceIp": host, "Initiated": "false"})
        elif rtype in ("ipv4", "ipv6"):
            host, port = split_host_port(value)
            ports = [port] if port else list(getattr(record, "ports", None) or [])
            for p in ports or [None]:
                add(
                    "network_connection",
                    {"DestinationIp": host, **({"DestinationPort": p} if p else {})},
                )
        elif rtype in ("domain", "hostname"):
            add("dns_query", {"QueryName": value})
            add("network_connection", {"DestinationHostname": value})
        elif rtype == "url":
            host, path, query = url_parts(value)
            add("proxy", {"c-uri": value, **({"cs-host": host} if host else {})})
            add(
                "webserver",
                {
                    "cs-method": "POST"
                    if any(w in value.lower() for w in ("api", "upload", "audit", "login", "auth"))
                    else "GET",
                    "cs-uri-stem": path or "/",
                    **({"cs-uri-query": query} if query else {}),
                    "c-uri": value,
                    **({"cs-host": host} if host else {}),
                },
            )
        elif rtype in _HASH_LABELS and getattr(record, "role", "") not in _NOT_A_FILE_HASH:
            hashes = f"{_HASH_LABELS[rtype]}={value}"
            add("process_creation", {"Hashes": hashes})
            add("image_load", {"Hashes": hashes})
        elif rtype in ("jarm", "ja4", "ja4s", "ja3"):
            add("network_connection", {rtype: value})

    for artifact in artifacts:
        value = str(getattr(artifact, "value", "") or "").strip()
        kind = str(getattr(artifact, "kind", "") or "")
        if not value or getattr(artifact, "status", "") in _NOT_THIS_INTRUSION:
            continue
        if kind == "file_path":
            add("file_event", {"TargetFilename": value})
            if any(
                ext in value.lower()
                for ext in (".php", ".jsp", ".action", ".do", ".aspx", "/api/", "/oa_", "/console")
            ):
                path = value.split("?")[0]
                query = value.split("?", 1)[1] if "?" in value else ""
                add(
                    "webserver",
                    {
                        "cs-method": "POST"
                        if any(
                            w in value.lower() for w in ("api", "upload", "audit", "login", "auth")
                        )
                        else "GET",
                        "cs-uri-stem": path if path.startswith("/") else f"/{path}",
                        **({"cs-uri-query": query} if query else {}),
                        "c-uri": value,
                    },
                )
        elif kind in ("url", "uri_path", "url_path", "endpoint", "web_path"):
            path = value.split("?")[0]
            query = value.split("?", 1)[1] if "?" in value else ""
            add(
                "webserver",
                {
                    "cs-method": "POST"
                    if any(w in value.lower() for w in ("api", "upload", "audit", "login", "auth"))
                    or _posted(path, cti_text)
                    else "GET",
                    "cs-uri-stem": path if path.startswith("/") else f"/{path}",
                    **({"cs-uri-query": query} if query else {}),
                    "c-uri": value,
                },
            )
            add("proxy", {"c-uri": value})
        elif kind == "command_line":
            add("process_creation", {"CommandLine": value, "Image": value.split()[0]})
        elif kind == "process":
            add("process_creation", {"Image": value})
        elif kind == "registry_key":
            for category in _REGISTRY_CATEGORIES:
                add(category, {"TargetObject": value})

    # Synthesize cloud_audit and identity_audit events when cloud indicators or text are present
    raw_cti = cti_text if isinstance(cti_text, str) else ""
    raw_artifacts = "\n".join(
        str(v)
        for a in artifacts
        if (v := getattr(a, "value", "")) and isinstance(v, (str, int, float))
    )
    combined_intel = f"{raw_cti}\n{raw_artifacts}".strip()
    lowered_intel = combined_intel.lower()

    if any(
        k in lowered_intel
        for k in (
            "assumerole",
            "sts:assumerole",
            "sts:assumerolewithwebidentity",
            "sts.amazonaws.com",
            "federateddevopsadmin",
        )
    ):
        add(
            "cloud_audit",
            {
                "eventSource": "sts.amazonaws.com",
                "eventName": "AssumeRole",
            },
        )
        add(
            "cloud_audit",
            {
                "eventSource": "sts.amazonaws.com",
                "eventName": "AssumeRoleWithWebIdentity",
            },
        )

    if any(k in lowered_intel for k in ("s3:", "aws s3", "s3.amazonaws.com", "s3://")):
        add(
            "cloud_audit",
            {
                "eventSource": "s3.amazonaws.com",
                "eventName": "ListObjects",
            },
        )

    if any(
        k in lowered_intel
        for k in (
            "directory.readwrite.all",
            "rolemanagement.readwrite.directory",
            "mail.readwrite",
            "createapplication",
            "updateapplication",
            "oauth",
            "consent",
        )
    ):
        scopes = " ".join(
            scope
            for scope in (
                "Directory.ReadWrite.All",
                "RoleManagement.ReadWrite.Directory",
                "Mail.ReadWrite",
            )
            if scope.lower() in lowered_intel
        )
        if "consent" in lowered_intel:
            add(
                "identity_audit",
                {
                    "operationName": "Consent to application",
                    **({"targetResources.modifiedProperties.newValue": scopes} if scopes else {}),
                },
            )

    # Only include container properties actually described by the source.
    if any(k in lowered_intel for k in ("kubernetes", "k8s")) and any(
        k in lowered_intel for k in ("deployed", "create pod", "created pod")
    ):
        add(
            "kubernetes_audit",
            {
                "verb": "create",
                "resource": "pods",
                **(
                    {"requestObject.spec.containers.securityContext.privileged": "true"}
                    if "privileged" in lowered_intel
                    else {}
                ),
            },
        )

    # Synthesize webserver and proxy events when web endpoints or paths are present in CTI
    from hecate_runner.cti.reference_rules import template_requests

    for request in template_requests(http_requests or []):
        path, _, query = request["uri"].partition("?")
        add(
            "webserver",
            {
                "cs-method": request["method"],
                "cs-uri-stem": path,
                **({"cs-uri-query": query} if query else {}),
                "c-uri": request["uri"],
            },
        )
    web_endpoints: list[str] = []
    if not http_requests:
        # Extract endpoints with known sensitive API prefixes
        web_endpoints.extend(
            re.findall(
                r"/(?:api|v\d+|wp-admin|console|owa|autodiscover|actuator|oa_servlets|OA_HTML|scripts|logon|vpn|nitro|mgmt|rest)/[a-zA-Z0-9_\-./?=&#%]+",
                combined_intel,
            )
        )
        # Extract script endpoints (.php, .jsp, .action, .do, .aspx, .cgi, .phtml)
        web_endpoints.extend(
            re.findall(
                r"/(?:[a-zA-Z0-9_\-./]+/)*[a-zA-Z0-9_\-]+\.(?:php|jsp|action|do|aspx|cgi|phtml|ashx)(?:\?[a-zA-Z0-9_\-./?=&#%]*)?",
                combined_intel,
            )
        )
        # Extract URL paths from embedded HTTP/HTTPS URLs
        for m_url in re.findall(
            r"https?://[a-zA-Z0-9_\-.:]+(/[a-zA-Z0-9_\-./?=&#%]*)", combined_intel
        ):
            if m_url and m_url not in web_endpoints:
                web_endpoints.append(m_url)

    for ep in web_endpoints:
        path = ep.split("?")[0]
        query = ep.split("?", 1)[1] if "?" in ep else ""
        add(
            "webserver",
            {
                **({"cs-method": "POST"} if _posted(path, cti_text) else {}),
                "cs-uri-stem": path,
                **({"cs-uri-query": query} if query else {}),
                "c-uri": ep,
            },
        )
        add("proxy", {"c-uri": ep})

    # Process events must come from extracted artifacts or explicitly synthetic
    # Atomic definitions. RCE alone does not establish a command or account.

    # Dynamic Adversary Emulation via Atomic Red Team
    if enable_atomic and techniques:
        try:
            from hecate_agent.api import synthesize_atomic_telemetry

            for raw_tid in techniques:
                tid = str(raw_tid).strip().upper()
                if not tid:
                    continue
                if tid.startswith("ATTACK."):
                    tid = tid[7:]
                atomic_by_cat = synthesize_atomic_telemetry(tid, platforms=platforms)
                for cat, evts in atomic_by_cat.items():
                    for evt in evts:
                        add(cat, evt)
        except Exception as exc:
            log.debug("Atomic telemetry synthesis skipped for %s: %s", tid, exc)

    return events


@dataclass
class ReplayResult:
    # "self_consistent" means the rule matched events synthesised from the report and
    # none of the benign sample. It is not validation: nothing was executed.
    status: str  # "self_consistent" | "no_match" | "baseline_match" | "no_replay_events" | "error"
    replay_events: int = 0
    true_positives: int = 0
    false_positives: int = 0
    tuned: bool = False
    final_rule: str = ""
    notes: list[str] = field(default_factory=list)
    emulation_type: str = "static"  # "static" | "atomic_red_team" | "hybrid"
    emulated_techniques: list[str] = field(default_factory=list)
    atomic_tests: list[str] = field(default_factory=list)
    baseline_scope: str = "smoke_check_noise_floor"
    evaluation_scope: str = "replay_sanity"
    training_metrics: dict[str, Any] = field(default_factory=dict)
    holdout: dict[str, Any] = field(default_factory=lambda: {"status": "unavailable"})
    tuning_rejected: bool = False

    @property
    def matched(self) -> bool:
        return self.status == "self_consistent"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "matched": self.matched,
            "tuned": self.tuned,
            "replay_events": self.replay_events,
            "tp": self.true_positives,
            "fp": self.false_positives,
            "emulation_type": self.emulation_type,
            "emulated_techniques": self.emulated_techniques,
            "atomic_tests": self.atomic_tests,
            "baseline_scope": self.baseline_scope,
            "evaluation_scope": self.evaluation_scope,
            "training_metrics": self.training_metrics,
            "holdout": self.holdout,
            "tuning_rejected": self.tuning_rejected,
            "notes": list(self.notes),
        }


def replay_rule(
    rule_yaml: str,
    events: list[dict[str, Any]],
    baseline: list[dict[str, Any]] | None = None,
    tuner: Any = None,
    emulated_techniques: list[str] | None = None,
    atomic_tests: list[str] | None = None,
) -> ReplayResult:
    """Tune on training groups and grade a frozen candidate on withheld groups once.

    With insufficient independent groups, perform the original replay sanity
    check without automatic tuning or an independent-quality claim. The tuner
    never receives held-out positives, negatives, or their scoring feedback.
    """
    from hecate_agent.core.sigma_evaluator import SigmaEvaluator

    from hecate_runner.replay_holdout import reserve_holdout

    if baseline is None:
        baseline = get_benign_sample_for_rule(rule_yaml)
    em_type = "atomic_red_team" if (emulated_techniques or atomic_tests) else "static"
    common: dict[str, Any] = {
        "emulation_type": em_type,
        "emulated_techniques": list(emulated_techniques or []),
        "atomic_tests": list(atomic_tests or []),
    }
    if not events:
        return ReplayResult(status="no_replay_events", final_rule=rule_yaml, **common)
    split = reserve_holdout(events, baseline)
    notes: list[str] = []
    holdout: dict[str, Any] = {"status": "unavailable", "reason": split.reason}

    def metrics(report: Any, positive_count: int, benign_count: int) -> dict[str, Any]:
        return {
            "positive_events": positive_count,
            "benign_events": benign_count,
            "tp": report.true_positives,
            "fp": report.false_positives,
            "fn": report.false_negatives,
            "tn": report.true_negatives,
            "recall": report.recall,
            "false_positive_rate": report.false_positives / benign_count if benign_count else None,
        }

    try:
        result = SigmaEvaluator.evaluate_rule(rule_yaml, split.positive, split.benign)
    except Exception as exc:
        return ReplayResult(
            status="error",
            replay_events=len(events),
            final_rule=rule_yaml,
            notes=[str(exc)],
            holdout=holdout,
            **common,
        )
    final_rule, tuned = rule_yaml, False
    if not split.available:
        notes.append("Independent holdout unavailable; automatic tuning disabled. " + split.reason)
    elif result.false_positives and result.true_positives and tuner is not None:
        matched = [
            e
            for e in split.positive
            if SigmaEvaluator.evaluate_rule(rule_yaml, [e], []).true_positives
        ]
        try:
            tuning = tuner.tune(rule_yaml, copy.deepcopy(matched), copy.deepcopy(split.benign))
            candidate = SigmaEvaluator.evaluate_rule(
                tuning.final_rule, split.positive, split.benign
            )
            if (
                tuning.final_rule != rule_yaml
                and not candidate.errors
                and candidate.false_positives == 0
                and candidate.true_positives >= result.true_positives
            ):
                final_rule, tuned, result = tuning.final_rule, True, candidate
        except Exception as exc:
            notes.append(f"Training-only tuning failed; original rule retained: {exc}")
    training_metrics = metrics(result, len(split.positive), len(split.benign))
    tuning_rejected = False
    evaluation_scope = "replay_sanity"
    if split.available:
        evaluation_scope = "synthetic_holdout"
        frozen_digest = hashlib.sha256(final_rule.encode()).hexdigest()
        try:
            # One evaluation after model selection is complete. Never offer
            # failures back to the tuner, and never test another candidate here.
            held = SigmaEvaluator.evaluate_rule(
                final_rule, split.holdout_positive, split.holdout_benign
            )
            passed = not held.errors and held.is_perfect
            holdout = {
                "status": "passed" if passed else "failed",
                "scope": "reserved_synthetic_samples",
                "split_digest": split.digest,
                "evaluated_rule_sha256": frozen_digest,
                **metrics(held, len(split.holdout_positive), len(split.holdout_benign)),
            }
            if not passed and tuned:
                tuning_rejected = True
                final_rule, tuned = rule_yaml, False
                notes.append(
                    "Frozen candidate failed the untouched holdout; no retry or automatic rule replacement."
                )
                return ReplayResult(
                    status="holdout_failed",
                    replay_events=len(events),
                    true_positives=held.true_positives,
                    false_positives=held.false_positives,
                    final_rule=final_rule,
                    training_metrics=training_metrics,
                    holdout=holdout,
                    evaluation_scope=evaluation_scope,
                    tuning_rejected=tuning_rejected,
                    notes=notes,
                    **common,
                )
            if not passed:
                notes.append(
                    "Original rule did not cover all withheld source-event groups; independent score failed. Replay matching is reported separately."
                )
        except Exception as exc:
            return ReplayResult(
                status="error",
                replay_events=len(events),
                final_rule=rule_yaml,
                holdout={
                    "status": "error",
                    "reason": str(exc),
                    "evaluated_rule_sha256": frozen_digest,
                },
                training_metrics=training_metrics,
                evaluation_scope=evaluation_scope,
                notes=["Holdout evaluation failed; original rule retained."],
                **common,
            )
    if split.available:
        # Keep the existing descriptive replay counts (some named source
        # artifacts may target different rules). This is a frozen-rule sanity
        # report after training, never feedback to the tuner or holdout score.
        result = SigmaEvaluator.evaluate_rule(final_rule, events, baseline)
    if result.true_positives == 0:
        status = "no_match"
    elif result.false_positives:
        status = "baseline_match"
    else:
        status = "self_consistent"
    return ReplayResult(
        status=status,
        replay_events=len(events),
        true_positives=result.true_positives,
        false_positives=result.false_positives,
        tuned=tuned,
        final_rule=final_rule,
        training_metrics=training_metrics,
        holdout=holdout,
        evaluation_scope=evaluation_scope,
        notes=notes,
        **common,
    )
