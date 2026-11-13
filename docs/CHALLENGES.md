# Engineering constraints and failure handling

## Evidence and model limits

Source extraction and grounding distinguish primary-source facts, inference and
capability references. They can reduce hallucinations but cannot guarantee factual
correctness. The selected workspace must supply verified telemetry mappings;
generic schema references and starter profiles do not establish enterprise coverage.
Synthetic replay no longer invents enterprise account IDs, roles, buckets,
applications, agent versions or process identities from a generic keyword.

## Replay, BAS and SIEM evidence

Synthetic samples can test rule logic without executing commands. Training/holdout
partitioning prevents tuning against withheld samples but remains a synthetic
exercise, not a production false-positive measurement. Insufficient data is reported
as unavailable. The `simulation` Atomic mode does not provide subprocess execution.

The unattended BAS path has a bounded, pinned Linux procedure catalog. Compatibility
selection favors behavioral checks; limited smoke checks remain separately labeled.
Actual validation requires independent scoped observations and confirmed cleanup.
The isolated lab cannot demonstrate physical-host visibility or enterprise coverage.

Native query matches are separate from authoritative SIEM alert firing. Splunk
proof needs the expected saved search, a post-run fired-alert record and results
from that alert job correlated to the specific run. Deployment alone does not
configure alert scheduling. See [the complete BAS contract](BAS_AUTOMATION.md).

## Resource use and resumability

Quotas, bounded extraction budgets, cached exact-input results and reusable catalog
indexes limit repeated work. Reservations and cache hits are distinct from
provider-reported billable tokens; missing usage remains unknown. Model calls,
provider latency and source-document size still influence runtime.

Atomic file replacement, locks, SQLite state and durable outboxes support retry
and recovery. They do not replace backups or public-release review. Keep private
state in the selected workspace and use a separate outbox when changing a private
publication destination to public.

## Test isolation and deployment

Unit tests must not reload operator dotenv files or contact Slack/SIEM implicitly.
Fixtures use temporary paths and mocked transports. Fixture hunt IDs are not
production hunts. Optional external checks require an explicit test selection and
separate test credentials; do not remove isolation guards to make a suite green.

Core and Runner share an interpreter for in-process calls. Update/test compatible
source revisions together, restart relevant application services and reopen
monitors. Generic installers do not adapt hardcoded deployment unit paths or
install all external service prerequisites automatically.
