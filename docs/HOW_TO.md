# Runner operating and developer recipes

Use the installed CLIs in the same environment and export an absolute
`HECATE_WORKSPACE`. Start with [onboarding](ONBOARDING.md) for the shared source
installation and private-workspace model. Never overwrite an existing `.env`
when copying examples.

## Existing-hunt execution

Configure the backend endpoint, token and verified field mappings in the private
workspace. Keep the query provider `mock` for practice and analyst approval on.
Replace `H-0001` with an existing ID:

```bash
hecate-agent hunt list
hecate-agent context --hunt H-0001 --format json
hecate-agent hunt update H-0001 --status active
hecate-runner sweep stage --hunt-id H-0001 --days 1
hecate-runner sweep pending
hecate-runner sweep approve <SWEEP-ID>
```

Use `sweep reject <SWEEP-ID>` to cancel. Continuous scheduling uses `sweep daemon`
and the `HECATE_AUTO_HUNT_*` settings. Count-first gates and fetch ceilings apply.
This workflow does not run CTI-to-hunt generation. Optional finding analysis,
pivots and tuning may call models.

## Supply intelligence and draft

```bash
hecate-runner draft --file /path/to/intelligence.txt --dry-run
hecate-runner draft --file /path/to/intelligence.txt --title "Primary report"
```

`draft` also accepts positional text or stdin. Use `--url` for primary report
retrieval. Generation consumes configured model/search resources and draft/research
quotas. To process files, set `HECATE_RUNNER_CTI_PROVIDER=file`, create
`cti_queue/` in the selected workspace and add a `.txt` source, then run
`hecate-runner run`. Provider selection is configuration, not a `run --source` flag.
For supported feeds, inspect `hecate-runner sources list` and configure only those
with the necessary credentials. `sources check` makes connectivity checks without
advancing intake cursors. Use `daemon --interval 60` for continuous intake.

## Detection conversion

`hecate-agent hunt promote --hunt H-0001 --output sigma` exports hunt content;
`--output spl` or `--output kql` exports a snippet. For native Sigma conversion,
use `hecate_agent.api.transpile_sigma_rule` with real target IDs such as
`splunk_spl` and `sentinel_kql`. There is no `hecate-agent sigma convert` command.
Backend registration is in Core's `core/sigma_transpiler.py`; query-provider and
deployment support are separate concerns.

Core caches successful exact YAML/target conversions in-process and revalidates
results on use. Changed YAML requires conversion; missing or altered native
artifacts are repaired from the canonical rule. Restart after backend package
changes; `SigmaTranspiler.clear_cache()` invalidates caches for deliberate changes
inside an already running process.

## Synthetic replay and BAS

Replay uses source-derived samples and synthetic Atomic definitions. It executes
no Atomic commands and cannot verify a real alert. Only `simulation` is accepted
for `HECATE_RUNNER_PURPLE_TEAM_ATOMIC_MODE`.

For live lab execution, follow [BAS automation](BAS_AUTOMATION.md) and
[host protections](HOST_HARDENING.md), configure allowlists and independent sensors,
and keep `HECATE_BAS_FALLBACK_TO_MOCK=false` when requiring live execution. The
unattended path supports the pinned Linux catalog; Windows/cloud need separate
manual prerequisites and are not established by a Linux sensor check.

```bash
# Executes a reviewed command in the configured isolated lab, not a health check
hecate-runner bas-detonate T1033 --provider caldera --host hecate-bas-lab --platform linux --env lab
# Requires an actual hunt rule; writes verification metadata only when requested
hecate-runner bas-verify H-0001 --provider caldera --host hecate-bas-lab --env lab --write-back
```

The host above is an example lab identity; it must match your allowlisted target.
`bas-check` also executes configured lab procedures. Use the deployment isolation
script and authenticated catalog/agent inspection for read-only readiness checks.
A query match is not fired-alert proof. Smoke checks and mock results never receive
technique-validation credit. See the BAS guide for Splunk correlation requirements.

## Services

Foreground processes can run independently in shells using the same environment:

| Command | Responsibility |
| --- | --- |
| `hecate-runner daemon` | CTI intake and planning-hunt generation |
| `hecate-runner maintenance` | Publication retries, drift audits and alert reminders |
| `hecate-runner sweep daemon` | Active-hunt sweep scheduling and execution policy |
| `hecate-runner slack-bot` | Slack Socket Mode interactions |
| `hecate-agent monitor` | Interactive terminal dashboard |

Linux templates in `systemd/` contain host-specific usernames, working directories,
uv executable paths, environment files, log paths and optional Ollama dependencies.
Review and edit them for your installation before running any installer. A hosted
model does not require an Ollama service; remove that dependency in your unit.
Service environments need absolute paths and do not inherit your interactive shell.
Do not run duplicate system and user copies against the same workspace.

```bash
# From Hecate-Runner, after adapting the templates; installs SYSTEM units
sudo ./scripts/install-systemd.sh
sudo systemctl enable --now hecate-runner-maintenance.service
sudo systemctl enable --now hecate-runner-daemon.service
sudo systemctl status hecate-runner-daemon.service hecate-runner-maintenance.service
```

The installer invokes legacy-service retirement and does not install Slack or
Sandcat. The current generation path is the resident daemon, not a legacy
orchestrator timer. Inspect each unit's `StandardOutput`/`StandardError`: templates
can append to files, so `journalctl` may not contain application logs.

Install the adapted Slack USER unit separately:

```bash
mkdir -p ~/.config/systemd/user
cp systemd/hecate-slack-bot.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now hecate-slack-bot.service
systemctl --user status hecate-slack-bot.service
```

The optional `caldera-sandcat.service` is a user unit supervising the prepared
agent container; it does not install CALDERA or establish isolation by itself.
Restart the corresponding system/user services after environment or code updates,
and reopen existing monitor sessions.

## Slack and publication

Incoming notifications need a bot token or webhook. Interactive actions additionally
need a Socket Mode App token and the configured application permissions/events.
Use the feature stubs and `HECATE_RUNNER_SLACK_CHANNEL_*` destinations in
[.env.example](../.env.example); no hardcoded fallback channel is assumed.

Generation completion and synthetic replay cards do not claim that a rule was
published or validated live. Test notification commands send real Slack messages;
run them only when deliberately checking that integration.

GitHub publication requires `HECATE_RUNNER_GITHUB_PUBLISHING_REPOSITORY=owner/repo`,
App installation credentials and the destination's promotion policy. Public
snapshots need privacy/redistribution approval for the exact byte snapshot before
upload. Changing the destination invalidates approval; use a new outbox when
switching from private to public exports. See [community releases](COMMUNITY_RELEASES.md).
MISP publication is independent, opt-in, organization-only and unpublished;
`to_ids=false` is retained pending review.

## SIEM queries, deployment and drift

`HECATE_RUNNER_QUERY_PROVIDER=mock` means no live hunt query. Native execution
providers include Splunk, Sentinel, Elastic and CrowdStrike LogScale; use the
backend's credential stubs. Conversion/deployment also cover targets that are
not native execution providers.

`HECATE_RUNNER_SIEM_DEPLOY_ENABLED` and `HECATE_RUNNER_SIEM_DEPLOY_DRY_RUN` control
saved-query deployment independently. Dry-run validates a payload without writing.
An explicitly live operation with missing credentials returns an error rather
than silently simulating. Live Splunk operations require an explicit
`SPLUNK_HOST` or `SPLUNK_URL`. Creating a saved search does not enable a scheduled
alert or prove that it fired.

Maintenance runs configured drift audits and queued reminders. Use
`HECATE_RUNNER_SIEM_DRIFT_AUDIT_INTERVAL_SEC=0` to disable periodic audits;
`HECATE_RUNNER_SIEM_DRIFT_ALERT_REMINDER_SEC` controls repeated reminders. Update
settings and restart maintenance for long-running deployments. Treat mock/dry-run
state separately from an authenticated live drift comparison.

## Development and offline checks

Implement feed providers against [CTIProvider](../src/hecate_runner/cti/base.py),
register their configuration/factory wiring and add fixture-driven tests. Native
Sigma targets belong in Core, with matching conversion and validation coverage;
Runner's queries, deployment and publication must preserve target identity.

```bash
# From each respective source repository, with the shared venv active
python -m pytest tests/ -q
```

Default suites block live dotenv files and unmocked network I/O. Use temporary
`.env` fixtures and mock transports; do not remove the guard to make a test pass.
External-service checks require explicit `-m network` and test-specific credentials.
Core's [gold evaluation guide](https://github.com/Hecate-Org/Hecate-Core/blob/main/evals/README.md)
describes deterministic scoring and model-assisted scratch-workspace replay.

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
