# Hecate-Runner

Hecate-Runner coordinates threat intelligence intake, hunt generation, scheduled
hunt execution, lab validation, publication and Slack operations. It imports
[Hecate-Core](https://github.com/Hecate-Org/Hecate-Core) in-process.

## Repository responsibilities

| Repository or directory | Responsibility |
| --- | --- |
| Hecate-Core | Agents, research, Sigma generation/transpilation, query tooling, CLI and monitor |
| Hecate-Runner | Scheduling, intake, execution approvals, BAS providers, integrations and publishers |
| [Hecate-Public](https://github.com/Hecate-Org/Hecate-Public) | Shared hunt catalog, queries, research and starter knowledge |
| Your private workspace | Enterprise knowledge, ignored credentials, findings, execution records and runtime state |
| [.github](https://github.com/Hecate-Org/.github) | Organization documentation; optional to clone |

Sibling checkouts make source development convenient. Their physical location
does not select where hunts or knowledge are read. `HECATE_WORKSPACE` selects
that directory. Public can seed a private workspace; directories are not merged
automatically. See [onboarding](docs/ONBOARDING.md).

## Source installation and offline first run

Use Python 3.11+, Git, Bash on Linux/macOS or WSL, and uv. No credentials or live
services are needed for the bundled demo or for listing existing hunts.

```bash
mkdir hecate-dev
cd hecate-dev
git clone https://github.com/Hecate-Org/Hecate-Core.git
git clone https://github.com/Hecate-Org/Hecate-Runner.git
git clone https://github.com/Hecate-Org/Hecate-Public.git
uv venv .venv
source .venv/bin/activate
uv pip install -e './Hecate-Core[all,dev]' -e './Hecate-Runner[dev]'
export HECATE_WORKSPACE="$PWD/Hecate-Public"
export HECATE_BIN="$PWD/.venv/bin/hecate-agent"
cd Hecate-Public
hecate-runner demo
hecate-agent hunt list
```

The demo uses an ephemeral fixture workspace and mock clients. It does not create
a new production hunt or prove live detection coverage. An LLM provider is needed
for model-assisted generation, not for installing the packages or browsing hunts.

For a fresh shell, reactivate `hecate-dev/.venv` and export the same absolute
workspace and binary paths. Use the installed commands from that environment;
`uv run --directory` can select a different project's environment.

## Configure only the features you need

From the selected workspace, copy `.env.example` to `.env` if it does not already
exist. Fill in the stubs for the features you enable. Keep credentials and
enterprise details out of public Git history.

- Export `HECATE_WORKSPACE` before running either CLI. Both read that workspace's
  `.env`; an existing process environment wins, and a cwd `.env` is a local override.
- Runner does not automatically create a `.env` symlink. A symlink is optional;
  it is not needed when the selected workspace is explicit.
- LLM settings use `HECATE_LLM_PROVIDER`, `HECATE_LLM_MODEL` and, where applicable,
  `HECATE_LLM_BASE_URL`. See [the complete stub file](.env.example).
- Feed selection uses `HECATE_RUNNER_CTI_PROVIDER` (`file`, `multi`, or a supported
  provider) and `HECATE_RUNNER_CTI_MULTI_PROVIDERS`. Inspect `hecate-runner sources list`.
- Query execution defaults to `HECATE_RUNNER_QUERY_PROVIDER=mock`. Live queries,
  live deployment and live BAS are separate configurations.
- Publication is opt-in. Set an explicit `owner/repository`, App credentials and
  destination policy before enabling GitHub publishing. There is no default repo.

## Run existing hunts without generating new ones

Use a private workspace seeded with the catalog for live enterprise use. Complete
its `knowledge/environment.md` with verified telemetry and field mappings. Replace
`H-0001` below with an ID returned by `hunt list`.

```bash
hecate-agent hunt list
hecate-agent context --hunt H-0001 --format json
hecate-agent hunt update H-0001 --status active
hecate-runner sweep stage --hunt-id H-0001 --days 1
hecate-runner sweep pending
hecate-runner sweep approve <SWEEP-ID>
```

Keep `HECATE_AUTO_HUNT_APPROVAL_REQUIRED=true` for analyst approval. The mock query
provider does not query your SIEM. Choose and configure a supported live backend
before treating execution results as operational findings. `sweep daemon` is the
continuous scheduler; `HECATE_AUTO_HUNT_EXECUTION_ENABLED` controls its opt-in.
Neither `sweep` nor catalog navigation requires running the CTI drafting daemon.
Optional finding triage, pivots and tuning may use models.

## Generate hunts from intelligence

Configure the model and optional search/feed credentials first:

```bash
hecate-runner draft --file /path/to/intelligence.txt --dry-run
hecate-runner draft --file /path/to/intelligence.txt --title "Reviewed source report"
hecate-runner run
hecate-runner daemon --interval 60
```

`draft` takes positional text, `--file`, or stdin; a source report is supplied
with `--url`. `run` consumes configured intake and has no `--source` option.
Generation writes planning hunts to the selected workspace and consumes configured
quotas. A generated or synthetically matched rule is not a deployed detection.

## Validation and BAS

Synthetic replay evaluates rule logic against source-derived samples and optional
Atomic Red Team definitions. It executes no Atomic commands and does not measure
production false-positive rates. `HECATE_RUNNER_PURPLE_TEAM_ATOMIC_MODE` supports
`simulation` only.

Live unattended BAS is limited to compatible rules and reviewed pinned Linux lab
procedures. Keep `HECATE_BAS_FALLBACK_TO_MOCK=false` when a live request should
fail or skip instead of producing a synthetic probe. A local sensor/Sigma match,
a smoke check, a native query match and a correlated SIEM alert are distinct
outcomes. See [BAS automation and limits](docs/BAS_AUTOMATION.md).

`bas-check` executes configured procedures; it is not a read-only health command.
Lab setup and cloud/manual operations require their own allowlists and prerequisites.
Do not infer Windows/cloud validation from a working Linux lab.

## Services

| Command | Purpose |
| --- | --- |
| `hecate-runner daemon` | Resident intake and planning-hunt generation |
| `hecate-runner maintenance` | Independent publication retries, drift audits and reminders |
| `hecate-runner sweep daemon` | Scheduling and approval/execution of active hunts |
| `hecate-runner slack-bot` | Interactive Slack Socket Mode actions |
| `hecate-agent monitor` | Foreground terminal dashboard for the selected workspace |

The Linux installer installs system units for the daemon and maintenance. Slack
and the optional isolated agent have separate user-unit templates. Templates
contain deployment-specific users, paths and service dependencies; edit them
before installation. They do not configure a fresh host automatically. See
[service installation](docs/HOW_TO.md#services).

## Tests

Run from this repository in the development environment:

```bash
python -m pytest tests/ -q --no-cov
ruff check src tests
```

The default suite blocks live network requests and operator dotenv files. Test
`.env` fixtures must be temporary. External checks require an explicit `-m network`
selection and their documented test configuration. Do not weaken the guard to
make an unmocked call pass; fixture IDs such as `H-9999` must never reach Slack.

## Documentation

- [Onboarding](docs/ONBOARDING.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Feature boundaries](docs/FEATURES.md)
- [Operating and developer recipes](docs/HOW_TO.md)
- [BAS automation](docs/BAS_AUTOMATION.md)
- [Community release and public-review gates](docs/COMMUNITY_RELEASES.md)
- [Host protections](docs/HOST_HARDENING.md)

Original code and documentation use the MIT license. Imported intelligence and
catalog content may have different terms; see [LICENSES.md](LICENSES.md).
