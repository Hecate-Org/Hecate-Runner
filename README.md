# Hecate-Runner

> **The Autonomous Threat Hunting & Detection Engineering Daemon.**
> Continuous 24/7 CTI intake, dual-track scheduling, adversary emulation, automated rule tuning, and PR publishing.

[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Daemon: systemd](https://img.shields.io/badge/service-systemd-green.svg)](systemd/hecate-runner-daemon.service)
[![Feeds: 20+ Sources](https://img.shields.io/badge/CTI-20%2B%20Feeds-orange.svg)](src/hecate_runner/cti)

---

## 🧭 Overview

**Hecate-Runner** (`hecate_runner`) is the autonomous driver of the Hecate platform. Operating as a perpetual daemon service, it continuously monitors threat intelligence feeds, triages and dedupes incoming advisories, executes purple-team adversary emulation, synthesizes detection logic through [Hecate-Core](https://github.com/Hecate-Org/Hecate-Core), and opens pull requests into [Hecate-Workspace](https://github.com/Hecate-Org/Hecate-Public).

> [!TIP]
> **New to Hecate-Runner?** Check out the [Onboarding Guide](docs/ONBOARDING.md) for a step-by-step walkthrough of local setup, adversary emulation, and daily workflows.

It enforces strict operational guardrails:
- **Zero-Unattended Production Execution:** Detections are drafted in `status: planning` requiring human approval.
- **Dual-Track Scheduling:** High-velocity indicator feeds use fast deterministic sweeps; narrative reports receive deep agentic research.
- **Automated Self-Remediation:** Detection rules failing syntax, logsource, or platform tests are automatically remediated before saving.
- **Durable Outbox:** Atomic writes and SQLite outboxes guarantee no duplicate drafts or leaked quotas across system reboots.

---

## 🏛 Ecosystem Architecture

```mermaid
flowchart LR
    FEEDS["20+ Threat Feeds<br/>(OTX, MISP, RSS, KEV...)"] --> RUNNER["Hecate-Runner<br/>(Autonomous Daemon)"]
    RUNNER -- "imports in-process" --> CORE["Hecate-Core<br/>(Reasoning & Sigma Engine)"]
    RUNNER -- "adversary emulation" --> PURPLE["Purple Team & BAS<br/>(CALDERA, Stratus, Sysmon)"]
    RUNNER -- "publishes atomic PRs" --> WS["Hecate-Workspace<br/>(Hecate-Org/Hecate-Public)"]
    RUNNER -- "interactive cards" --> SLACK["Slack ChatOps Bot<br/>(Thread Actions & Commands)"]
```

- **[Hecate-Core](https://github.com/Hecate-Org/Hecate-Core)**: Sibling library providing the LLM agents, ATT&CK STIX matrix, Sigma drafting, and pySigma transpilers.
- **[Hecate-Runner](https://github.com/Hecate-Org/Hecate-Runner)** *(this repo)*: Autonomous perpetual daemon, multi-feed CTI triage, purple-team emulation, and Slack bot.
- **[Hecate-Workspace](https://github.com/Hecate-Org/Hecate-Public)**: Version-controlled detection repository holding hunts (`hunts/`), queries (`queries/`), research dossiers (`research/`), and promotion gates.

---

## 📂 File & Directory Structure

```text
Hecate-Runner/
├── src/hecate_runner/           # Primary Python package
│   ├── bas/                     # Breach & Attack Simulation (CALDERA, Stratus, Mock, Verifier)
│   ├── correlation.py           # Campaign clustering & incremental hunt updater
│   ├── cti/                     # 20+ CTI feed providers (OTX, MISP, RSS, KEV, AnyRun...)
│   ├── orchestrator.py          # Central autonomous coordinator loop & factory
│   ├── orchestrator_intake.py   # CTI feed polling, dedup, and dead-letter retry/quarantine
│   ├── orchestrator_grounding.py # Primary evidence collection & claim auditing
│   ├── orchestrator_rules.py    # Multi-pass Sigma generation, gap synthesis & SIEM deployment
│   ├── orchestrator_publishing.py # GitHub and MISP outbox enqueuing & notifications
│   ├── purple_team.py           # Adversary emulation & synthetic telemetry replay
│   ├── rule_tuner.py            # Automated reviewer self-remediation feedback loop
│   ├── indicator_sweep.py       # Zero-token deterministic sweep engine
│   ├── github_publisher.py      # Durable SQLite outbox & GitHub PR publisher
│   ├── misp_publisher.py        # MISP event & attribute publisher
│   ├── slack_bot.py             # Interactive Slack Bot with Block Kit UI
│   ├── hunt_writer.py           # Atomic LOCK markdown and Sigma YAML writer
│   ├── config.py                # Environment and quota configuration
│   └── cli.py                   # Typer CLI entrypoint (`hecate-runner`)
├── systemd/                     # Systemd service unit files
│   ├── hecate-runner-daemon.service    # Resident event-driven worker daemon
│   ├── hecate-runner-maintenance.service # Independent publishing, audits & alerts
│   ├── hecate-slack-bot.service        # Interactive Slack bot (user service)
│   └── caldera-sandcat.service         # Isolated BAS agent (user service)
├── docs/                        # Complete technical documentation
│   ├── ONBOARDING.md            # Step-by-step developer onboarding guide
│   ├── ARCHITECTURE.md          # 3-repo architecture blueprint & data flow
│   ├── FEATURES.md              # Exhaustive feature matrix and subsystem details
│   ├── BAS_SAFETY_AUDIT.md      # Safety guarantees & lab isolation boundaries
│   ├── CHALLENGES.md            # Technical challenges solved (hallucinations, token quotas)
│   ├── HOW_TO.md                # Developer recipes & step-by-step guides
│   └── COMMUNITY_RELEASES.md    # Community release guidelines and controls
├── scripts/                     # Operational scripts (systemd installer, lab setup)
└── tests/                       # 1,360+ unit and integration tests
```

---

## 🚀 5-Minute Quick Install & Getting Started

### Prerequisites
- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- An LLM API key (Anthropic, OpenAI, AWS Bedrock) or a local [Ollama](https://ollama.com) instance

### Step 1: Clone Repositories Side-by-Side
```bash
mkdir -p ~/betas && cd ~/betas

git clone https://github.com/Hecate-Org/Hecate-Core.git
git clone https://github.com/Hecate-Org/Hecate-Runner.git
git clone https://github.com/Hecate-Org/Hecate-Public.git Hecate-Workspace
```

### Step 2: Install Dependencies with `uv`
```bash
# Install Hecate-Runner (automatically links sibling ../Hecate-Core in-process)
cd ~/betas/Hecate-Runner
uv sync --all-extras
```

### Step 3: Configure Environment
Copy `.env.example` into `Hecate-Workspace/.env` (Runner automatically symlinks to it):
```bash
cd ~/betas/Hecate-Workspace
cp .env.example .env
```

Ensure your configuration includes your API keys and quotas:
```dotenv
# Threat Intelligence Feeds
OTX_API_KEY=...
MISP_BASE_URL=https://misp.example.com
MISP_API_KEY=...
MISP_OUTPUT_API_KEY=...             # optional dedicated writer credential
HECATE_RUNNER_MISP_PUBLISHING_ENABLED=true

# Model & Search API
HECATE_AI_PROVIDER=anthropic      # or openai, bedrock, ollama
ANTHROPIC_API_KEY=sk-ant-...
TAVILY_API_KEY=tvly-...

# Autonomous Scheduler & Quotas
HECATE_RUNNER_SOURCES=multi       # polls all configured feeds
HECATE_RUNNER_MAX_DRAFTS_PER_DAY=12
HECATE_RUNNER_SWEEP_COOLDOWN_SECONDS=30
HECATE_RUNNER_DEEP_COOLDOWN_SECONDS=180

# GitHub Publishing (Optional PR integration)
HECATE_RUNNER_GITHUB_PUBLISHING_ENABLED=true
HECATE_RUNNER_GITHUB_APP_ID=...
HECATE_RUNNER_GITHUB_INSTALLATION_ID=...
HECATE_RUNNER_GITHUB_APP_PRIVATE_KEY_PATH=/run/secrets/hecate-publisher.pem
HECATE_RUNNER_GITHUB_PUBLISHING_REPOSITORY=Hecate-Org/Hecate-Public
```

### Step 4: Run a Test Hunt or Launch the Daemon

GitHub publication defaults to a private target. A public destination requires
`target_visibility: public` in its promotion policy, `risk.tlp_amber: block`, and
no `allow_private` risk actions. Explicitly allowing unmarked source material
uses `risk.unknown_tlp: allow`. Restricted TLP markings and credentials are
checked before the first public GitHub write, including on retries.

To retain local hunt history while changing the remote destination, set
`HECATE_RUNNER_GITHUB_PUBLISHING_REPOSITORY` to the new repository,
`HECATE_RUNNER_GITHUB_PUBLISHING_POLICY_PATH` to its local policy file, and
`HECATE_RUNNER_GITHUB_PUBLISHING_OUTBOX_PATH` to a fresh queue database. This
keeps previous queued exports separate. Install the publisher App on the new
repository and enable its promotion workflow, required checks, and auto-merge
before switching the service configuration.

MISP output is independent of the MISP intake source. After the final hunt and
Sigma steps, the Runner queues the hunt, linked research, and detection files in
a durable local outbox. Each hunt has one organization-only, unpublished MISP
event, with readable reports and file attachments. Typed indicators retain their
provenance and have `to_ids=false` pending review. Retries reconcile stable UUIDs
and verify the stored content; an unavailable MISP does not cause a hunt to be
drafted again. Hecate-generated events are excluded from MISP intake.

```bash
hecate-runner misp enable          # requires MISP_BASE_URL and a writer API key
hecate-runner misp publish H-0911  # explicitly export an existing hunt
hecate-runner misp sync            # retry due exports without running a hunt
hecate-runner misp status --json   # confirmed event IDs and pending failures
hecate-runner sources disable opencti
```

```bash
# Option A: Draft a hunt immediately from raw CTI text
uv run hecate-runner draft \
  --title "Test Adversary Activity" \
  --content "Adversaries executed powershell -enc with beaconing to 198.51.100.5"

# Option B: Run a single cycle against active feeds
uv run hecate-runner run

# Option C: Start the autonomous resident daemon in the foreground
uv run hecate-runner daemon --interval 60
```

---

## ⚙️ Operating the Autonomous Daemon

### Running via Systemd (Recommended for Production)

Hecate-Runner includes a production-grade systemd service unit:

```bash
# Install system services (review workspace paths in systemd/ first)
sudo ./scripts/install-systemd.sh

# Start independent maintenance and the hunting daemon
sudo systemctl enable --now hecate-runner-maintenance.service
sudo systemctl start hecate-runner-daemon.service

# Inspect live status
sudo systemctl status hecate-runner-daemon.service hecate-runner-maintenance.service

# View streaming journal logs
sudo journalctl -u hecate-runner-daemon.service -f
```

### Running Interactively in Foreground
For local development, testing, or debugging:

```bash
# Run daemon continuously with a 60-second polling interval
uv run hecate-runner daemon --interval 60

# In a separate terminal: publishing, SIEM audits, and queued drift alerts
uv run hecate-runner maintenance

# Run a single cycle against active feeds
uv run hecate-runner run

# Run a single cycle against a specific feed
uv run hecate-runner run --source cisa_kev
uv run hecate-runner run --source otx
```

### On-Demand Manual Drafting
Draft a hunt immediately from custom threat intelligence text:

```bash
uv run hecate-runner draft \
  --title "Akira Ransomware PerfLogs Staging" \
  --content "Adversaries deployed gost tunnel and rclone into C:\PerfLogs\ to exfiltrate data..." \
  --source-url "https://news.sophos.com/akira-perflogs"
```

### Live Adversary Emulation & Breach Simulation (BAS)

For unattended operation restricted to reviewed Linux lab procedures and real
local process observation, see [approved BAS automation](docs/BAS_AUTOMATION.md).
Execute on-demand adversary emulation or run closed-loop detection verification across Linux, Windows, or Cloud:

```bash
# Live Linux detonation via CALDERA on local agent
uv run hecate-runner bas-detonate T1033 --provider caldera --host hecate-bas-lab --platform linux --env lab

# Windows detonation with automatic Mock fallback (when no active Windows agent is connected)
uv run hecate-runner bas-detonate T1059.001 --provider caldera --host lab-win10 --platform windows --env lab

# Cloud adversary emulation via Stratus Red Team (AWS / GCP / Azure)
uv run hecate-runner bas-detonate T1562.008 --provider stratus --platform aws --env staging --account-id 123456789012

# Run closed-loop detection verification against a hunt draft and update frontmatter
uv run hecate-runner bas-verify H-0804 --provider caldera --host lab-win10 --env lab --write-back
```

---

## 💬 ChatOps & Slack Bot

Launch the interactive Slack Bot to receive real-time notifications with interactive review actions:

```bash
# Run Slack Bot
uv run hecate-runner slack-bot
```

- **Interactive Cards:** Every drafted hunt sends a Block Kit card with title, hypothesis summary, ATT&CK techniques, and candidate Sigma rules.
- **One-Click Actions:** Security engineers can trigger validation replays or request AI rule tuning directly from Slack threads.
- **Slash Commands:** Use `/hecate status`, `/hecate hunt <ID>`, or `/hecate promote <ID>`.

---

## 🔍 Structured CTI Sources & Health Monitoring

Enable or disable individual threat sources via `hecate-runner sources enable <name>`. Sources poll periodically, compare immutable revisions, and queue changed entries durably:

| Provider | Intake & Enrichment Scope |
| :--- | :--- |
| `lolbas` | [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) YAML procedures, including decoded commands, ATT&CK IDs, and binary enrichment. |
| `loldrivers` | [LOLDrivers](https://github.com/magicsword-io/LOLDrivers) driver entries and vulnerable hashes via daily snapshot cache. |
| `gtfobins` | [GTFOBins](https://github.com/GTFOBins/GTFOBins.github.io) Unix binary commands, functions, and privilege contexts. |
| `nuclei` | [Nuclei HTTP templates](https://github.com/projectdiscovery/nuclei-templates), prioritized beside KEV with live EPSS score gating (`min_epss=0.5`). |
| `cisa_advisories` | Official [CISA advisory feed](https://www.cisa.gov/cybersecurity-advisories/all.xml) with article retrieval for AA/CSA reports and CSAF IT deltas. |
| `cisa_ics` | CISA CSAF Industrial Control Systems (OT) advisories, mapping legacy TLP:WHITE to TLP:CLEAR. |
| `attack_deltas` | Monthly pinned [MITRE ATT&CK STIX](https://github.com/mitre-attack/attack-stix-data) deltas, queuing changed techniques for uncovered TTPs. |

- **Health Verification:** `hecate-runner sources check` performs read-only connectivity and schema checks without advancing cursors. The daemon refreshes health status hourly.
- **Evidence Boundaries:** Catalog and template definitions represent reference capabilities rather than observed intrusions; placeholders are strictly excluded from incident IOC extraction.

---

## 📦 Reviewed Community Releases

Hecate supports vetted community detection packaging via `hecate-runner release build` and isolated verification via `hecate-runner release verify`.
- **Review Gate:** Public hunt snapshots remain in `awaiting_review` in the local outbox until approved via `hecate-runner publish-review <ID> --approve` with verified privacy and license checks.
- **Isolation:** Private archives, sessions, and operational traces are strictly excluded from exported release bundles. See [the community release guide](docs/COMMUNITY_RELEASES.md) for details.

---

## 🧪 Testing & Verification

The complete 1,360+ test suite runs offline with deterministic mocks:

```bash
# Run full test suite
uv run pytest -q

# Run specific subsystem tests
uv run pytest tests/test_orchestrator.py
uv run pytest tests/test_purple_team_pipeline.py
uv run pytest tests/test_cti_multi.py
uv run pytest tests/test_daemon.py
```

---

## 📚 Complete Documentation

- **[System Architecture](docs/ARCHITECTURE.md)**: 3-repo design, lifecycle diagrams, and pipeline stage mixins.
- **[Feature Reference](docs/FEATURES.md)**: Breakdown of CTI ingestion, dual-track scheduling, and evaluation.
- **[Engineering Challenges](docs/CHALLENGES.md)**: Hallucination defense, token economics, and telemetry synthesis.
- **[Developer How-To Guides](docs/HOW_TO.md)**: Step-by-step recipes for CTI feeds, SIEM targets, and local evals.
- **[Adversary Emulation & BAS](docs/BAS_AUTOMATION.md)**: Approved Linux lab procedures and isolation controls.

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
