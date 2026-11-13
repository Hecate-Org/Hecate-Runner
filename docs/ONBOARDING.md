# Runner onboarding

Use this guide for a source installation. Core provides the engine, Runner
coordinates it, and the selected workspace provides knowledge and stores results.
You can browse or run existing hunts without enabling CTI-to-hunt generation.

## Install once into a shared environment

Use Python 3.11+, Git, uv and Bash on Linux/macOS or WSL:

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

Keep the default repository directory names. The optional organization `.github`
repository can be a sibling; neither application imports it. Source code can live
elsewhere when paths and imports are configured explicitly.

Create `env.sh` in the parent `hecate-dev` directory for subsequent Bash shells:

```bash
# Source this file; do not execute it in a child shell.
HECATE_DEV_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$HECATE_DEV_ROOT/.venv/bin/activate"
export HECATE_WORKSPACE="$HECATE_DEV_ROOT/Hecate-Public"
export HECATE_BIN="$HECATE_DEV_ROOT/.venv/bin/hecate-agent"
```

Then run `source /absolute/path/to/hecate-dev/env.sh` from a new shell. For an
enterprise workspace, change only the exported workspace path and keep using
the same installed packages. Avoid mixing this shared-environment setup with
`uv run --directory` examples that create or select another project's venv.

## Workspace and secrets

Run configuration/content commands from the selected workspace where practical.
Both applications read `<HECATE_WORKSPACE>/.env`; existing environment variables
win, and a cwd `.env` can override workspace values. Runner does not create a
symlink automatically. A new process or service restart is required after
changing configuration used by a long-running process.

Copy the workspace `.env.example` to `.env` only when a configuration file does
not already exist. `HECATE_WORKSPACE` should be exported by the launching shell or
service so the correct workspace is selected before discovery. Use absolute
paths in service environments. Protect credentials with owner-only permissions.
Do not source arbitrary `.env` files as shell scripts; not all dotenv syntax is
valid shell syntax.

For enterprise adoption, use a private workspace. Copy the reviewed hunts,
queries, research and starter knowledge you need from Public. Complete
`knowledge/environment.md` with verified telemetry and edit
`knowledge/hunting-knowledge.md` for local guidance. Logs, `.hecate/`, findings
and private evidence stay there. Core's bundled reference data is not a measured
description of your enterprise.

## Choose a workflow

### Offline evaluation

`hecate-runner demo` creates and removes an isolated fixture workspace. No model,
SIEM, Slack or BAS connection is needed. `hecate-agent hunt list` reads the
selected catalog. `doctor` checks configured dependencies/providers and can
report missing optional capabilities; it is not an execution test.

### Existing-hunt execution

Choose a query provider in `.env`. Keep `mock` for practice; for live searches,
provide the backend's endpoint and credentials from the example file. Keep
`HECATE_AUTO_HUNT_APPROVAL_REQUIRED=true`.

```bash
hecate-agent hunt list
hecate-agent context --hunt H-0001 --format json
hecate-agent hunt update H-0001 --status active
hecate-runner sweep stage --hunt-id H-0001 --days 1
hecate-runner sweep pending
hecate-runner sweep approve <SWEEP-ID>
```

Use an actual hunt and sweep ID. Approval executes through the count-first gate;
large result sets are constrained by configured fetch limits. Continuous
scheduling uses `sweep daemon` and the `HECATE_AUTO_HUNT_*` settings. This workflow
does not need CTI polling or newly generated H files. Optional analysis/pivots
can use models; basic native query execution is separate from generation.

### Model-assisted generation

Configure `HECATE_LLM_PROVIDER`, `HECATE_LLM_MODEL`, and the provider's endpoint/key
as needed. Optional web research uses its own search configuration. The example
files list feature-specific stubs; do not use `HECATE_AI_PROVIDER`.

```bash
hecate-runner draft --file /path/to/intelligence.txt --dry-run
hecate-runner draft --file /path/to/intelligence.txt
```

`--url` supplies the primary report URL, and `--title` supplies a research topic.
For queued intake, configure `HECATE_RUNNER_CTI_PROVIDER=file`, place a `.txt`
item in `<workspace>/cti_queue/`, and run `hecate-runner run`. Select supported
feeds with configuration or `sources` commands, not a nonexistent `run --source`.
`hecate-runner daemon` continuously processes configured intake under quotas.

## Validation, publishing and services

- [BAS automation](BAS_AUTOMATION.md) explains the pinned Linux catalog, sensors,
  cleanup, simulation fidelity and fired-alert proof. `bas-check` executes lab
  procedures; it is not a diagnostic-only command.
- [Community releases](COMMUNITY_RELEASES.md) explains public snapshot review,
  permissions and separate release approval. Supply an explicit publication repo.
- [Operating recipes](HOW_TO.md#services) distinguishes system daemon/maintenance
  units from user Slack/agent units. Edit the host-specific templates first.
- `hecate-agent monitor` reads the same selected workspace. Reopen an existing
  monitor after updating Core; a running Python process does not reload code.

## Contribute and verify

From each source repository with the shared venv active:

```bash
python -m pytest tests/ -q
ruff check .
```

Default tests use temporary dotenv fixtures and reject unmocked network I/O.
Explicit external checks require `-m network` and their test-specific settings.
Do not remove isolation guards or reuse operator Slack/SIEM credentials in tests.
Core's mirrored guide updates also require `python scripts/sync_docs.py --check`.
