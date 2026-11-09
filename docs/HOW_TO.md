# Hecate Developer How-To Guide

A practical handbook of step-by-step developer recipes for setting up, extending, and operating Hecate.

---

## Table of Contents
1. [Recipe 1: Local Developer Environment Setup](#recipe-1-local-developer-environment-setup)
2. [Recipe 2: Running a Manual Threat Hunt](#recipe-2-running-a-manual-threat-hunt)
3. [Recipe 3: Adding a New CTI Feed Provider](#recipe-3-adding-a-new-cti-feed-provider)
4. [Recipe 4: Adding or Customizing a SIEM/EDR Backend](#recipe-4-adding-or-customizing-a-siemedr-backend)
5. [Recipe 5: Running Local Evals and Telemetry Replays](#recipe-5-running-local-evals-and-telemetry-replays)
6. [Recipe 6: Operating the Autonomous Perpetual Daemon](#recipe-6-operating-the-autonomous-perpetual-daemon)
7. [Recipe 7: Configuring ChatOps & The Slack Bot](#recipe-7-configuring-chatops--the-slack-bot)
8. [Recipe 8: Approved Query Execution against Sentinel, Elastic, and LogScale](#recipe-8-approved-query-execution-against-sentinel-elastic-and-logscale)
9. [Recipe 9: SIEM Drift Detection & Alert Reminders](#recipe-9-siem-drift-detection--alert-reminders)
10. [Recipe 10: LLM Metrics & Token Estimation](#recipe-10-llm-metrics--token-estimation)

---

## Recipe 1: Local Developer Environment Setup

Hecate uses [uv](https://docs.astral.sh/uv/) for lightning-fast, reproducible dependency management. Python 3.11 or newer is required.

### 1.1 Clone the Three Repositories Side-by-Side
```bash
mkdir -p ~/betas && cd ~/betas

git clone https://github.com/Hecate-Org/Hecate-Core.git
git clone https://github.com/Hecate-Org/Hecate-Runner.git
git clone https://github.com/Hecate-Org/Hecate-Public.git Hecate-Workspace
```

### 1.2 Initialize Virtual Environments & Install Dependencies
```bash
# Setup Hecate-Core
cd ~/betas/Hecate-Core
uv sync --all-extras

# Setup Hecate-Runner (automatically links Hecate-Core in-process)
cd ~/betas/Hecate-Runner
uv sync --all-extras
```

### 1.3 Configure Environment Variables
Copy `.env.example` into `Hecate-Workspace/.env` (which Runner symlinks to):
```bash
cd ~/betas/Hecate-Workspace
cp .env.example .env
```
Edit `.env` to configure your preferred LLM provider:
```dotenv
# Choose your model provider
HECATE_AI_PROVIDER=anthropic      # options: anthropic, openai, bedrock, ollama
ANTHROPIC_API_KEY=sk-ant-...

# Web Grounding & Search (Required for deep research)
TAVILY_API_KEY=tvly-...

# Workspace Root
HECATE_WORKSPACE=/path/to/hecate-public
```

### 1.4 Verify Installation & Run Tests
```bash
# Run Core tests
cd ~/betas/Hecate-Core
uv run pytest -q

# Run Runner tests
cd ~/betas/Hecate-Runner
uv run pytest -q
```

---

## Recipe 2: Running a Manual Threat Hunt

You do not need to wait for autonomous feeds to draft a hunt. You can trigger on-demand analysis from any text snippet, URL, or CVE.

### Option A: From Raw Intelligence Text
```bash
cd ~/betas/Hecate-Runner
uv run hecate-runner draft \
  --title "Salt Typhoon Cisco Router Compromise" \
  --content "Adversaries deployed a custom backdoor named GhostHook via CVE-2026-1934 into /tmp/gh.elf..." \
  --source-url "https://threatintel.example.com/reports/salt-typhoon"
```

### Option B: Dropping Intelligence into the Intake Queue
```bash
cat << 'EOF' > ~/betas/Hecate-Workspace/cti_queue/urgent_cve.txt
Title: CVE-2026-44321 Apache Struts OGNL RCE
Adversaries are actively exploiting CVE-2026-44321 using crafted Content-Type headers
containing multipart boundaries with OGNL expressions to execute /bin/sh commands.
EOF

# Process queued items immediately
cd ~/betas/Hecate-Runner
uv run hecate-runner run --source file
```

### Option C: Transpiling Sigma to SIEM Dialects
Once a hunt is drafted (e.g. `H-0885`), export it to all supported query targets:
```bash
cd ~/betas/Hecate-Core
uv run hecate-agent hunt promote --hunt H-0885 --output splunk
uv run hecate-agent hunt promote --hunt H-0885 --output sentinel
uv run hecate-agent hunt promote --hunt H-0885 --output crowdstrike
```

Core reuses successful native conversion text across generation, final artifact
checks, deployment, and tuning. Its in-memory cache holds up to 256 exact
Sigma-YAML/target pairs; changed YAML gets a fresh conversion. Every use still
runs the current syntax validator and returns independent result objects. Failed
or invalid conversions are not retained. Native query files are rewritten only
when their canonical contents differ; missing or modified files are repaired
from the Sigma rule.

The cache lasts for the current process, so new processes convert their first
use of a rule normally. Restart Core/Runner after backend package changes. When
changing backend mappings or pipelines inside a running Python process, call
`SigmaTranspiler.clear_cache()` to invalidate both query and backend caches.

---

## Recipe 3: Adding a New CTI Feed Provider

All intelligence ingestors implement the `CTIProvider` interface in [`hecate_runner.cti.base`](file:///home/chemch/betas/Hecate-Runner/src/hecate_runner/cti/base.py).

### Step 1: Create the Provider Class
Create `src/hecate_runner/cti/my_feed.py`:
```python
from typing import List
from hecate_runner.cti.base import CTIItem, CTIProvider

class MyFeedProvider(CTIProvider):
    name = "my_feed"

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key
        self.base_url = base_url or "https://api.myfeed.example.com/v1"

    def poll(self, max_items: int = 10) -> List[CTIItem]:
        # 1. Fetch raw data from API
        raw_entries = self._fetch_api(max_items)
        items = []

        for entry in raw_entries:
            # 2. Normalize into standard CTIItem
            item = CTIItem(
                source_id=f"my_feed:{entry['id']}",
                title=entry["title"],
                content=entry["description"],
                source_url=entry["url"],
                published=entry["timestamp"],
                entry_tags=entry.get("tags", []),
                raw_indicators=entry.get("iocs", []),
            )
            items.append(item)

        return items
```

### Step 2: Register the Provider
1. Add the provider class to `src/hecate_runner/cti/__init__.py`.
2. Add provider configuration settings in `src/hecate_runner/config.py`.
3. Add a CLI source flag in `src/hecate_runner/cli.py`.

### Step 3: Add Unit Tests
Create `tests/test_cti_my_feed.py` and mock external HTTP requests using `unittest.mock`.

---

## Recipe 4: Adding or Customizing a SIEM/EDR Backend

Query generation is governed by pySigma transpilation in [`hecate_agent.core.sigma_transpiler`](file:///home/chemch/betas/Hecate-Core/hecate_agent/core/sigma_transpiler.py).

### Step 1: Install the pySigma Backend Plugin
Add the target pySigma plugin to `pyproject.toml` in both `Hecate-Core` and `Hecate-Runner`:
```toml
# Example: Adding pySigma-backend-qradar
dependencies = [
    "pysigma>=0.11.0",
    "pysigma-backend-splunk>=1.0.0",
    "pysigma-backend-kusto>=1.0.0",
    "pysigma-backend-qradar>=1.0.0",
]
```

### Step 2: Register the Dialect in `sigma_transpiler.py`
In `hecate_agent/core/sigma_transpiler.py`:
```python
SUPPORTED_TARGETS = {
    "splunk": "Splunk SPL",
    "sentinel": "Microsoft Sentinel KQL",
    "crowdstrike": "CrowdStrike Falcon LogScale",
    "elastic": "Elasticsearch EQL",
    "qradar": "IBM QRadar AQL",
}
```
Define backend initialization and pipeline options inside `_transpile_single_target()`.

---

## Recipe 5: Running Local Evals and Telemetry Replays

Hecate includes a deterministic evaluation harness to verify that detection logic catches adversary behaviors without false positives.

### 5.1 Run Replay Against Golden Eval Pulses
```bash
cd ~/betas/Hecate-Core
uv run python evals/replay.py --pulse evals/pulses/vshell-fake-resume.json
```

### 5.2 Test Synthetic Purple Team Replay
Test how synthetic telemetry generation validates a Sigma rule:
```bash
cd ~/betas/Hecate-Runner
uv run python -c "
from hecate_runner.purple_team import emulate_technique_telemetry
events = emulate_technique_telemetry('T1059.001', 'powershell.exe -enc AAAA...')
print(f'Generated {len(events)} synthetic telemetry events')
"
```

### 5.3 Live Adversary Emulation & Breach Simulation (BAS)

Hecate provides automated Level 4 Purple Teaming to detonate adversary techniques and verify detection rules against real or synthetic security telemetry.

#### 5.3.1 Configuration & Environment Setup
Add the BAS configuration parameters to `Hecate-Workspace/.env`:

```bash
# BAS Mode: 'caldera', 'stratus', or 'mock'
HECATE_BAS_ENABLED=true
HECATE_BAS_MODE=caldera
HECATE_BAS_AUTO_EXECUTE_LIVE=false

# Allowlisted Target Hosts & Cloud Accounts (Safety Guardrail)
HECATE_BAS_ALLOWED_HOSTS=hecate-bas-lab
HECATE_BAS_LINUX_HOST=hecate-bas-lab
HECATE_BAS_ALLOWED_ACCOUNTS=

# Live requests must fail if a live target is unavailable
HECATE_BAS_FALLBACK_TO_MOCK=false

# CALDERA Configuration
CALDERA_URL=http://127.0.0.1:8888
CALDERA_API_KEY=<your-private-caldera-api-key>
CALDERA_AGENT_GROUP=hecate-local-lab
CALDERA_TIMEOUT_SEC=120

# Stratus Red Team Configuration
STRATUS_BINARY_PATH=stratus-red-team
STRATUS_CLEANUP_ON_FINISH=true
```

#### 5.3.2 Setting up the Hardened CALDERA Environment
For live endpoint adversary emulation on Linux:

1. **Run the CALDERA C2 Server bound strictly to loopback (`127.0.0.1`):**
   ```bash
   docker run -d --name caldera --restart unless-stopped -p 127.0.0.1:8888:8888 caldera-local:latest
   ```

2. **Create the isolated agent container and enable its user service:**
   Install [`systemd/caldera-sandcat.service`](file:///home/chemch/betas/Hecate-Runner/systemd/caldera-sandcat.service) to `~/.config/systemd/user/`:
   ```bash
   scripts/setup-bas-lab.sh ../sandcat
   mkdir -p ~/.config/systemd/user
   cp systemd/caldera-sandcat.service ~/.config/systemd/user/
   systemctl --user daemon-reload
   systemctl --user enable --now caldera-sandcat.service
   ```

   The service supervises a nonroot container with no host mounts, a read-only root filesystem, dropped capabilities, no new privileges, resource limits, and an internal Docker network. Run `scripts/check-bas-isolation.sh` to inspect the deployed controls. Configure `HECATE_BAS_ALLOWED_HOSTS=hecate-bas-lab`, `HECATE_BAS_LINUX_HOST=hecate-bas-lab`, `CALDERA_AGENT_GROUP=hecate-local-lab`, and `HECATE_BAS_FALLBACK_TO_MOCK=false`. Unattended live execution also requires the separate `HECATE_BAS_AUTO_EXECUTE_LIVE=true` opt-in; leave it false for manual operation.

#### 5.3.3 Running On-Demand Adversary Detonations (`bas-detonate`)
Execute techniques on target systems across Linux, Windows, or Cloud:

```bash
# 1. Live Linux detonation via CALDERA (executes on hecate-bas-lab)
hecate-runner bas-detonate T1033 -p caldera --host hecate-bas-lab --platform linux --env lab

# 2. Windows detonation with automatic Mock fallback (when only Linux agent is connected)
hecate-runner bas-detonate T1059.001 -p caldera --host lab-win10 --platform windows --env lab

# 3. Cloud adversary emulation via Stratus Red Team (AWS / GCP / Azure)
hecate-runner bas-detonate T1562.008 -p stratus --platform aws --env staging --account-id 123456789012

# 4. Pure offline mock detonation (fast in-process simulation)
hecate-runner bas-detonate T1059.001 -p mock --env lab
```

#### 5.3.4 Running Closed-Loop Detection Verification (`bas-verify`)
Verify whether candidate Sigma rules fire on real adversary telemetry:

```bash
# Run verification without modifying files
hecate-runner bas-verify H-0804 -p caldera --host lab-win10 --env lab --no-write-back

# Run verification and write results back to hunt markdown frontmatter and body
hecate-runner bas-verify H-0804 -p caldera --host lab-win10 --env lab --write-back
```

#### 5.3.5 Safety Controls & Production Rejection
Hecate strictly prohibits running emulation operations against production environments:
```bash
# This command is immediately blocked and exits with code 1
hecate-runner bas-detonate T1033 --env production
# Output: Configuration / Safety Error: Detonation rejected: Target environment 'production' is strictly prohibited.
```

#### 5.3.6 Managing and Troubleshooting the Agent
```bash
# Check Sandcat systemd service status
systemctl --user status caldera-sandcat.service

# View live agent logs
journalctl --user -u caldera-sandcat.service -f

# Check active agents registered with CALDERA
curl -s -H "KEY: $CALDERA_API_KEY" http://127.0.0.1:8888/api/agents | jq .
```

---

## Recipe 6: Operating the Autonomous Perpetual Daemon

The autonomous runner runs as a resident Linux systemd service.

### 6.1 Daemon Commands
```bash
# Check daemon status
sudo systemctl status hecate-runner-daemon.service hecate-runner-maintenance.service

# View live daemon logs
sudo journalctl -u hecate-runner-daemon.service -f

# Restart daemon after updating code
sudo systemctl restart hecate-runner-daemon.service hecate-runner-maintenance.service

# Stop daemon
sudo systemctl stop hecate-runner-daemon.service
```

### 6.2 Running the Daemon Interactively in Foreground
For debugging or testing without systemd:
```bash
cd ~/betas/Hecate-Runner
uv run hecate-runner daemon --interval 60 --max-cycles 0
```

In a separate terminal, run `uv run hecate-runner maintenance`. Hunt cycles only
snapshot and queue publication work; they never wait for GitHub/MISP synchronization
or SIEM drift sweeps. Manual `publish`, `misp publish`, and `audit-siem` commands
remain synchronous when explicitly requested.

For system services, review workspace paths in `systemd/`, run
`sudo ./scripts/install-systemd.sh`, then
`sudo systemctl enable --now hecate-runner-maintenance.service`.
The supplied hunting daemon unit also requests the maintenance service at startup.
Update installed units when upgrading; starting the CLI hunting daemon alone does
not start maintenance. To stop all automatic work, stop both services.

The legacy hourly orchestration service and timer are retired. The installer
backs up and removes those two units instead of reinstalling them. For an existing
deployment that only needs cleanup, run:

```bash
sudo bash scripts/retire-legacy-services.sh
```

This preserves the running daemon, maintenance, Slack bot, BAS agent and firewall.
Prior unit files are archived under `/var/backups/hecate-retired-systemd/`.

Maintenance uses independent worker processes for GitHub, MISP, SIEM audits, and
drift-alert delivery. A slow target cannot block the others or hunt scheduling.
Each publisher handles one due item per `HECATE_RUNNER_MAINTENANCE_INTERVAL_SEC`
(default 60 seconds), retaining its existing durable per-item retry policy. Drift
delivery handles up to 20 cards per batch. SIEM audits use
`HECATE_RUNNER_SIEM_DRIFT_AUDIT_INTERVAL_SEC` (default 3600; `0` disables audits).
Per-workspace process locks prevent overlapping jobs across multiple schedulers.

`HECATE_RUNNER_MAINTENANCE_JOB_TIMEOUT_SEC` (default 900 seconds) bounds each worker;
timeouts kill and reap its process group and apply retry backoff. Configure this
deadline for the size and response times of the SIEM catalog: an audit must finish
to publish a new full report. Interrupted audits do not clear prior alert state.
Last job durations, outcomes and next-run times are stored in
`.hecate/maintenance/<job>.json`; worker output is in `logs/maintenance.log`.
Use `hecate-runner maintenance --once` to process currently due work and exit,
or add `--dry-run` to list enabled jobs without starting workers.

### 6.3 Checking Pipeline Health & Metrics
```bash
# Inspect current queue status and quotas
cd ~/betas/Hecate-Runner
uv run hecate-runner status

# Launch the live curses TUI dashboard
cd ~/betas/Hecate-Core
uv run hecate-agent monitor
```

---

## Recipe 7: Configuring ChatOps & The Slack Bot

The Hecate Slack Bot provides real-time notifications with interactive human-in-the-loop review cards.

### 7.1 Setup App Credentials
In `.env`:
```dotenv
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
SLACK_CHANNEL_ID=C0123456789
```

### 7.2 Run the Bot Service
```bash
# Run standalone
cd ~/betas/Hecate-Runner
uv run hecate-runner slack-bot

# Or install/manage the user service (review paths in the template first)
mkdir -p ~/.config/systemd/user
cp systemd/hecate-slack-bot.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now hecate-slack-bot.service
```

### 7.3 Available Slash Commands in Slack
- `/hecate status`: Returns active queue depth, recent hunts, and daily quota consumption.
- `/hecate hunt H-0882`: Returns the summary, hypothesis, and candidate Sigma rules for hunt `H-0882`.
- `/hecate promote H-0882`: Triggers the CI promotion check and generates a pull request.

---

## Recipe 8: Approved Query Execution against Sentinel, Elastic, and LogScale

Hecate supports live query validation against enterprise SIEM backends using a strict "propose, don't execute" approval gate:

```bash
# Propose a bounded query
hecate-runner propose H-0001 --data-source sentinel --query 'SecurityEvent | where EventID == 4688' --time-range-days 1 --limit 100

# Explicitly approve and execute
hecate-runner approve H-0001
```

### Supported Providers & Configuration

Set `HECATE_RUNNER_QUERY_PROVIDER` to `sentinel`, `elastic`, or `crowdstrike`. Credentials can be supplied through `.env` or environment variables:

| Provider | Required Configuration | Query Dialect |
| :--- | :--- | :--- |
| `sentinel` | `SENTINEL_WORKSPACE_ID`, `SENTINEL_BEARER_TOKEN` (or `AZURE_ACCESS_TOKEN`) | Azure Monitor Logs (KQL) |
| `elastic` | `ELASTIC_URL`, `ELASTIC_API_KEY`, `ELASTIC_INDEX` | Elasticsearch EQL |
| `crowdstrike` | `FALCON_LOGSCALE_URL`, `FALCON_LOGSCALE_REPO`, `FALCON_LOGSCALE_TOKEN` | LogScale CQL |

- **Guardrails:** Adapters independently enforce maximum lookbacks (`HECATE_RUNNER_MAX_QUERY_TIME_RANGE_DAYS`) and result caps (`HECATE_RUNNER_MAX_QUERY_LIMIT`).
- **Redaction:** `hecate-runner config` automatically redacts query tokens, API keys, and secrets.
- **Diagnostics:** `hecate-runner doctor` checks configuration completeness without contacting the remote services.

---

## Recipe 9: SIEM Drift Detection & Alert Reminders

The runner audits committed workspace queries against deployed SIEM states to detect drift, orphaned rules, or missing detections:

```bash
# Run SIEM drift audit
hecate-runner audit-siem

# Audit and dispatch Slack notifications for drifted queries
hecate-runner audit-siem --alert-slack
```

- **Workspace Scoping:** `HECATE_WORKSPACE` must point to the target detection repository containing `hunts/` and `queries/`.
- **Deduplicated Alerts:** Maintenance queues a single consolidated card per affected hunt. Unchanged drift states are suppressed across restarts.
- **Reminder Frequency:** Controlled by `HECATE_RUNNER_SIEM_DRIFT_ALERT_REMINDER_SEC` (default: 86400s / 24 hours; `0` disables reminders). Stored locally in `.hecate/siem/drift_alerts.db`.

Drift cards are durable outbox records. Observation, claim, and acknowledgement
use short SQLite transactions; Slack requests run after commit. A per-hunt process
lock prevents concurrent sends even if a slow request exceeds its claim lease.
Failures retry with backoff; crashed claims become retryable after five minutes.
Acknowledgements cannot suppress a newer condition or a resolved condition's
recurrence. Existing suppression records migrate automatically. As with any
nontransactional remote delivery, a crash after Slack accepts a message but before
the local acknowledgement can result in a retry of that message.

---

## Recipe 10: LLM Metrics & Token Estimation

Track LLM resource consumption, stage latencies, and token allocations across pipeline cycles:

```bash
# Show 7-day token usage breakdown
hecate-runner metrics --days 7

# Export raw JSON metrics with sample counts and maximums
hecate-runner metrics --days 7 --json
```

- **Request Tracking:** Logs full-request prompt and completion usage after each LLM call. The reported largest prompt is the maximum across individual requests, not a cumulative sum.
- **Pre-Run Payload Estimates:** The runner logs pre-run payload character counts and token estimates for recognized model tokenizers prior to dispatching prompts.

Primary-source extraction re-fetches the report before looking up cached replies.
The cache key includes the source URL and content, extractor version, prompts,
and model settings. Cached replies are checked against the source again; malformed,
ungrounded, or failed responses are not reused. The workspace stores up to 512
entries in `.hecate/source_evidence.db`, with a default maximum age of 24 hours.
Set `HECATE_RUNNER_SOURCE_EVIDENCE_CACHE_ENABLED=false` to disable reuse, or adjust
`HECATE_RUNNER_SOURCE_EVIDENCE_CACHE_TTL_SEC` (`0` also disables it).

Extraction, recovery attempts, and indicator classification share
`HECATE_RUNNER_SOURCE_EVIDENCE_MAX_CALLS` (default `16`) and
`HECATE_RUNNER_SOURCE_EVIDENCE_MAX_TOKENS` (default `256000`). The token limit
reserves conservative UTF-8 prompt bytes and capped output allowances; these
reservations are separate from provider-reported or billed tokens. Failed calls
consume their reservation, and cache hits spend no model budget. Original source
chunks run before recovery attempts. On budget exhaustion, verified artifacts are
retained and diagnostics flag incomplete coverage or unclassified indicators.

In `logs/stage_metrics.jsonl`, the `source_evidence` stage's `details` field records
per-chunk/classification duration, retry depth, cache status, reported input/output
tokens, and budget status. Cache hits do not repeat the original token usage or
cost. The existing `HECATE_RUNNER_LLM_TIMEOUT_SEC` remains the shared hard deadline
for fetching, extraction, and classification.

### Catalog indexing

Core maintains a disposable `.hecate/catalog.sqlite3` beside the workspace's
`hunts/`, `research/`, and `sessions/` directories. Runner's source-link/CVE
deduplication, research listing/reuse, and similarity corpus loading share this
index. It is built automatically; update Core and Runner together to use the
indexed intake path. Older Core versions retain the original source-file scan.

Readers still discover files and check size, inode, nanosecond modification and
change timestamps on each lookup. Only new or changed files are read; a content
hash avoids reparsing touched files whose contents did not change. Added, renamed,
deleted, and manually edited files are reflected without a cache TTL. Research
selection keeps its existing age, topic, and technique rules. Source deduplication
keeps literal URL matching and the 72-hour CVE window.

Similarity search reuses unchanged parsed hunt and session components. A metadata
or results-only edit updates returned metadata without refitting TF-IDF when the
searchable text is identical. Changes to searchable text or document membership
still refit TF-IDF to preserve vocabulary, IDF weights, and ranking behavior.
The fitted matrices are held in process memory for up to 16 workspaces; a fresh
process rebuilds its matrix from the persisted parsed corpus.

The index is a cache, not hunt or research history. If it is unavailable or cannot
be written, readers use the current source files. Damaged cached payloads are
rebuilt, and malformed source files never retain an older cached interpretation.
It is safe to remove the cache database while readers are stopped; the next
lookup rebuilds it. This is separate from the source-extraction cache and requires
no model calls or scheduled maintenance service.
