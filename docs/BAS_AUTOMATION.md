# Approved Linux lab automation

Unattended BAS uses the reviewed, pinned catalog in
[`bas/approved.py`](../src/hecate_runner/bas/approved.py). It does not execute
commands from CTI, generated rules, or arbitrary technique lookup. The current
catalog contains 30 procedures; the table records their actual fidelity.
Some commands exercise only an inert local behavior, and smoke checks never
establish technique coverage. Procedure names/ATT&CK tags are not a claim of
realistic enterprise attack emulation.

| Technique | Fidelity | Pinned Linux command |
| --- | --- | --- |
| T1033 | `behavioral` | `whoami` |
| T1057 | `behavioral` | `ps` |
| T1083 | `behavioral` | `ls` |
| T1082 | `behavioral` | `uname -a` |
| T1016 | `behavioral` | `ip address show` |
| T1087.001 | `behavioral` | `cut -d: -f1 /etc/passwd` |
| T1069.001 | `behavioral` | `groups` |
| T1124 | `behavioral` | `date -u +"%Y-%m-%dT%H:%M:%SZ"` |
| T1059.004 | `behavioral` | `sh -c 'printf hecate-bas-shell-probe'` |
| T1140 | `behavioral` | `printf 'aGVjYXRlLWJhcy1wcm9iZQ==' \| base64 -d` |
| T1070.004 | `behavioral` | `sh -c 'touch /tmp/hecate-t1070-canary.tmp && rm -f /tmp/hecate-t1070-canary.tmp'` |
| T1027 | `behavioral` | `sh -c 'printf aGVjYXRlLWJhcw== \| base64 -d > /tmp/hecate-t1027.tmp'` |
| T1005 | `behavioral` | `sh -c 'uname -a > /tmp/hecate-t1005.tmp'` |
| T1053.003 | `behavioral` | `sh -c 'printf "* * * * * true # hecate-t1053\n" > /tmp/hecate-t1053.tmp && crontab /tmp/hecate-t1053.tmp'` |
| T1105 | `behavioral` | `sh -c 'curl -f -sS -m 2 http://127.0.0.1:8888/ -o /tmp/hecate-t1105.tmp && test -s /tmp/hecate-t1105.tmp'` |
| T1049 | `behavioral` | `ss -tan` |
| T1007 | `behavioral` | `systemctl list-units --type=service --state=running` |
| T1518.001 | `behavioral` | `systemctl status ufw` |
| T1018 | `behavioral` | `arp -a` |
| T1222.002 | `behavioral` | `sh -c 'touch /tmp/hecate-t1222.tmp && chmod 644 /tmp/hecate-t1222.tmp && rm -f /tmp/hecate-t1222.tmp'` |
| T1036.005 | `behavioral` | `sh -c 'touch /tmp/hecate-t1036-crond.tmp && rm -f /tmp/hecate-t1036-crond.tmp'` |
| T1543.002 | `smoke_check` | `systemctl is-active cron` |
| T1552.001 | `behavioral` | `grep -s 'BEGIN PRIVATE KEY' /etc/ssl/certs/` |
| T1003.008 | `behavioral` | `head -n 1 /etc/passwd` |
| T1046 | `behavioral` | `nc -z -v -w 1 127.0.0.1 22` |
| T1526 | `behavioral` | `curl -s -m 1 http://127.0.0.1:80/latest/meta-data/` |
| T1613 | `behavioral` | `cat /proc/1/cgroup` |
| T1071.001 | `smoke_check` | `curl -sI https://localhost/` |
| T1190 | `smoke_check` | `curl -s http://127.0.0.1:80/` |
| T1041 | `smoke_check` | `sh -c 'printf hecate-exfil-test \| wc -c'` |

Run `hecate-runner bas-install-procedures` to install missing managed definitions.
This writes definitions to CALDERA; it does not detonate them. Existing content
is validated first, and altered executable metadata is refused. Commands, cleanup
and version determine managed IDs; exact IDs and exemptions remain in source.

A hunt must have Linux scope and a compatible Sigma rule in the supported
`process_creation`, `file_event`, `file_change` or `network_connection` category,
with the exact approved technique. Predicate compatibility is an eligibility
check, not validation evidence. Behavioral procedures are preferred; a compatible
smoke check can be selected only when no behavioral match exists, and keeps its
limited fidelity. The actual independent observations must match the hunt rule.

With `HECATE_BAS_FALLBACK_TO_MOCK=false`, unsupported hunts record a skip and
unavailable live execution fails. Explicitly enabled fallback is a synthetic
probe with mock provenance; it cannot become live technique/alert proof. Windows
and cloud unattended automation remain unsupported.

## Real process observation

The agent image runs Sandcat under `strace`. `lab_process` evaluates successful
`execve` observations; `lab_fusion` additionally derives supported file/network
events from traced syscalls. Expected filenames and CALDERA receipts are not
substitutes for independent time-scoped observations. The tracer works as UID/GID 65534 without added
capabilities, privileged mode, host mounts, host PID access, or a relaxed
seccomp profile. The existing internal network and resource limits remain.
The temporary filesystem is `noexec`, core dumps are disabled, open descriptors
are capped at 256, and file sizes are bounded at 16 MiB. Preflight refuses a lab
that loses these controls. CALDERA server resource limits are configured
separately; the installed server has a 1 GiB memory limit, one CPU, and 128 PIDs.
The controller is also required to run as nonroot with a read-only root, dropped
capabilities, private named volumes, and loopback-only API publishing. A reverted
or weakened controller is refused before automatic BAS execution. Migration and
recovery are documented in [host protections](HOST_HARDENING.md).

Before scheduling, Hecate checks the exact container identity, hostname, agent
arguments, tracer entrypoint, read-only root, nonroot user, dropped capabilities,
security options, lack of mounts and published ports, resource limits, and
internal network. Missing sensor readiness prevents execution. Workspace locking and the shared lab lease prevent overlapping lab operations.

Only successful observed executions of the exact approved command inside the
detonation's time window are evaluated. CALDERA link receipts are excluded from
sensor evidence. The actual hunt rule is evaluated against these events using
the Sigma evaluator. A rule miss remains a miss; no synthetic events are added
to make it pass.

This verifies **local sensor observation and Sigma matching**. It does not claim
that a SIEM ingested an event or fired an alert. No organizational SIEM/EDR
connection is required or implied.

## Configuration and checks

Keep configuration and credentials in the workspace's ignored `.env`:

```dotenv
HECATE_BAS_ENABLED=true
HECATE_BAS_MODE=caldera
HECATE_BAS_AUTO_EXECUTE_LIVE=true
HECATE_BAS_AUTO_TECHNIQUES=T1033,T1057,T1083 # Begin with a reviewed subset
HECATE_BAS_TELEMETRY=lab_process
HECATE_BAS_SENSOR_CONTAINER=hecate-bas-agent
HECATE_BAS_LAB_NETWORK=hecate-bas-lab
HECATE_BAS_LAB_PAW=hecate-local-sandbox
HECATE_BAS_AGENT_SERVER_URL=http://caldera:8888
HECATE_BAS_CALDERA_CONTAINER=caldera
HECATE_BAS_ALLOWED_HOSTS=hecate-bas-lab
HECATE_BAS_LINUX_HOST=hecate-bas-lab
HECATE_BAS_FALLBACK_TO_MOCK=false
CALDERA_URL=http://127.0.0.1:8888
CALDERA_API_KEY=replace-with-your-private-caldera-api-key
CALDERA_AGENT_GROUP=hecate-local-lab
```

The CALDERA group must contain exactly one trusted agent matching the lab host.
Automation accepts only a loopback CALDERA endpoint. The configured group, paw,
network, host, agent server URL and controller container must match the lab
profile. The defaults above describe the reviewed local stack; adopters may
configure identities without removing isolation/image checks.
Build the sensor-equipped image using `scripts/setup-bas-lab.sh` for a new lab;
that installer refuses to replace an existing container. Existing deployments
must retain their previous stopped container while replacing the agent with the
same isolation settings and agent arguments.

Use `scripts/check-bas-isolation.sh` and authenticated catalog/agent reads for
read-only readiness checks. After reviewing the configured procedures, an
execution test can be requested with:

```bash
.venv/bin/hecate-runner bas-check
```

This executes the configured approved procedures against a dedicated sensor
control rule and saves results locally. Sensor controls are explicitly separated
from hunt rule checks in the monitor. They do not modify or publish hunts.

Every automation result is saved with mode 0600 beneath
`<workspace>/.hecate/bas/runs/`. The monitor reads these records, deduplicates any
matching hunt frontmatter result by run ID, and shows automation mode, scope,
observed events, failures, and skips. The `.hecate` directory must remain ignored
by Git. Halt unattended execution by setting
`HECATE_BAS_AUTO_EXECUTE_LIVE=false` and restarting the Runner daemon.

## Quarantine and reset

Manual lab detonation and automatic validation use the same workspace execution
lock. Reset acquires that lock too and uses the workspace's `.hecate/bas/`
quarantine state. Failed process inspection, unexpected processes, or
unconfirmed tmpfs cleanup keep the lab quarantined and cause a nonzero exit.
Unexpected processes require operator recovery; reset does not claim to kill them.

An active lease timer quarantines overdue execution. The execution lock stays
held until the worker exits, and overdue results cannot count as success. Remote
execution still depends on the provider's timeout and stop request; the lease
cannot prove that an unreachable controller stopped. Exceptions and abandoned
leases require a successful audit before subsequent execution.

File validation uses successful, time-scoped syscall observations. Expected
filenames, post-run hashes, and historical `lab_file_delta` records cannot serve
as creation/deletion evidence.

## Simulation results and manual hunt verification

Mock BAS produces a `simulation_match` when synthetic events match the hunt's
Sigma rule. This is a logic probe: it does not set `bas_verified`, populate
`bas_verified_rules`, increment BAS or purple-team validated-rule counters, or
record a live detection latency. A successful synthetic replay without a match
can report `simulation_no_match`; it is not a live detection miss. Synthetic events are never forwarded to a live
SIEM by the verification path. Arbitrary native queries cannot be evaluated by
the offline Sigma evaluator and return `simulation_unsupported`.

`bas-verify` requires an actual matching Sigma detection under
`queries/<hunt-id>/`. Missing or invalid rules cause refusal before detonation.
Live SIEM verification additionally requires that rule's same-stem `.spl` file;
Hecate does not manufacture fallback detections or substitute a sensor control
rule. Search time windows use the detonation's UTC timestamp, independently of
the monotonic timer used to measure elapsed time.

## Manual cloud identity checks

Stratus execution and explicit cleanup require an allowlisted account or context,
a matching request/target platform and ability, and a successful authenticated
identity check. `AWS_ACCOUNT_ID` and other target labels are not proof of access;
`HECATE_SKIP_CLOUD_IDENTITY_CHECK` cannot bypass verification. Identity checks and
all lifecycle subprocesses share a captured environment.

- AWS uses `aws sts get-caller-identity` and compares the returned account ID.
- Azure pins `AZURE_SUBSCRIPTION_ID` and `ARM_SUBSCRIPTION_ID` to the requested
  subscription and verifies access using an authenticated ARM request through
  `az rest`. This check supports Azure CLI authentication. Alternative Azure
  credential-chain environment settings cause refusal until they have a matching
  credential-specific identity probe.
- GCP pins `GOOGLE_PROJECT` and `GOOGLE_CLOUD_PROJECT`, obtains an application
  default credential token with `gcloud auth application-default print-access-token`,
  and verifies the project through Cloud Resource Manager. Custom
  `GOOGLE_APPLICATION_CREDENTIALS` files cause refusal because this CLI probe
  cannot establish that it used the same credential file as Stratus.
- Kubernetes checks the current context and requires a successful authenticated
  `kubectl auth whoami`. A context label alone is insufficient; kubectl must
  support this command.

These checks do not extend unattended cloud automation, which remains unsupported.

## SIEM search matches and fired-alert proof

A successful native search records `query_match` and `query_match_latency_sec`.
It does not set `siem_alert_fired`, populate an alert timestamp, or count toward
verified-alert metrics. A local Sigma pass cannot override a native-query miss.
Local sensor verification continues to use the `local_sensor_sigma` scope.

For Splunk, alert proof requires all of the following:

- The exact hunt rule's deployed saved-search name and unchanged native query.
  The verifier uses Hecate's deterministic deployment identifier and the same
  `SPLUNK_USER` / `SPLUNK_APP` namespace as deployment.
- An authoritative record from Splunk's
  [`alerts/fired_alerts/{name}` API](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/9.1/search-endpoints/search-endpoint-descriptions),
  identifying the saved search, alert search ID, and trigger time after this
  execution began.
- A time-scoped event in that alert search's own results carrying this run's
  unique `hecate_bas_run_id` and `hecate_hunt_id` markers. The verifier adds these
  markers to copies of independently observed events when forwarding them.

The alert search ID is saved separately from the ad hoc search ID. Alert latency
uses the server's trigger timestamp relative to the provider's execution start;
query-match timing remains a separate elapsed-time measurement. CLI output,
hunt frontmatter, SQLite history, and private run evidence retain this distinction.
Old history rows without alert proof remain readable and do not count as verified
alerts. Schema migration occurs when the drift database is initialized.

Deploying a saved search alone does not configure a scheduled alert. The adopter
must configure scheduling and triggered-alert retention in Splunk and grant the
verifier access to the saved search, fired-alert records, and their job results.
Missing permissions or records leave alert firing unverified. Searches that
aggregate away the run markers, events that were not forwarded with those
markers, and markers outside the first 100 alert result rows cannot establish
correlation with this verifier. It does not enable scheduling or alert actions.

## CALDERA cleanup evidence

A finished operation or a zero exit status from its attack command does not prove
cleanup. Cleanup requires completed, successful cleanup receipts for the selected
agent, with executable commands and finish timestamps. Missing or pending receipts
leave cleanup `unconfirmed`; failed cleanup is reported as `failed`. Either prevents
an overall successful detonation, hunt verification, or a zero exit from the BAS
commands. Approved automation retains its quarantine and filesystem audit checks.

An explicit catalog of reviewed artifact-free procedures may record cleanup as
`not_required`. This exemption requires the validated pinned ability, successful
execution of its exact command, and no declared files or cleanup command. New or
unreviewed abilities do not receive this exemption from an absent cleanup definition.

## Command failures and smoke-check fidelity

The T1105 transfer procedure now requires a successful HTTP request and a nonempty
download. Connection errors, HTTP errors and timeouts propagate as failures;
there is no fallback that creates an empty file. Its fixed local endpoint must
serve the intended inert content inside the lab for a successful transfer test.
The T1053.003 cron procedure propagates installation errors, and its cleanup
propagates errors from both crontab removal and temporary-file removal. These
procedures remain restricted to the dedicated lab; failure may require an audit
and reset before further execution.

Changing these commands changes their deterministic managed ability IDs. Before
using them in a live lab, run `hecate-runner bas-install-procedures` to install the
new definitions. Existing definitions are not silently overwritten or used as
fallbacks for the new commands.

A `smoke_check_match` reports a locally observed rule match without claiming the
associated attack technique was exercised. Selection prefers a compatible
behavioral procedure and can fall back to a compatible pinned smoke check. Smoke
checks are excluded from verified-rule lists, BAS and purple-team validated rule
counts, hunt `bas_verified` metadata, and community technique-validation credit.
They are also available to `bas-check` and explicit manual verification. An actual SIEM alert on a smoke check remains visible as
alert evidence and does not upgrade it to technique-validation credit.

The following controls are classified as smoke checks:

| Technique | What the fixed command actually checks |
| --- | --- |
| T1543.002 | Whether the cron service is active; it does not create a service. |
| T1190 | A normal HTTP request; it does not exercise an exploit. |
| T1071.001 | A local HTTP header request; it does not establish command and control. |
| T1041 | Local output piped to a byte counter; it does not transfer data away. |

The catalog digest includes fidelity classification. Verification uses the most
restrictive scope from the reviewed procedure, execution metadata and caller;
requesting `behavioral` cannot upgrade a pinned smoke check. Rendering older
records also checks the current pinned procedure before granting validation credit.

## Purple-team replay execution mode

`HECATE_RUNNER_PURPLE_TEAM_ATOMIC_MODE` supports only `simulation`, its default.
Replay synthesizes telemetry from source artifacts and Atomic Red Team test
definitions; it does not launch Atomic commands or apply a Bubblewrap sandbox.
The former `subprocess` and `bwrap` values now cause a configuration error with
migration instructions, including when replay is disabled. Remove those values
or set `HECATE_RUNNER_PURPLE_TEAM_ATOMIC_MODE=simulation`.

Live execution remains a separately configured BAS capability. Use
`HECATE_BAS_MODE=caldera` and the reviewed lab configuration described above;
changing the replay mode does not enable BAS or opt into live execution.

## Independent replay holdouts

Before automatic tuning, replay groups are deduplicated by event content while
ignoring clocks, process identifiers and record identifiers. Positive and benign
groups are partitioned deterministically: 25% of each class (at least one group)
is withheld. The partition depends on event content, not the rule's match results.
The tuner receives copies of training positives it already matches and training
benign samples; withheld events and their scores are never supplied to it.

A candidate must first improve training noise without losing training matches.
That candidate is then frozen and scored once on the withheld positive and benign
groups. Every withheld positive must match, and no withheld benign event may match.
A failed candidate is rejected without another tuning attempt or replacement of
the original rule. Stale replay/tuning success annotations are cleared.

At least two distinct positive groups and two distinct benign groups are needed.
Insufficient data or contradictory positive/benign labels disable automatic tuning
and report the holdout as unavailable. Basic replay can still describe whether the
original rule matches any named source artifacts. This descriptive match is
separate from held-out coverage: a category can contain artifacts intended for
other rules, so an original rule may match the report and fail the broader holdout.

Per-rule reports retain training and holdout metrics, cohort counts, split digest,
and the exact evaluated candidate's YAML digest. Hunt summaries, trail output and
manual replay summaries distinguish passed, failed and unavailable holdouts.
The persisted Sigma annotation is `x_hecate_synthetic_holdout_status`.

These are reserved **synthetic replay samples**, not a representative production
corpus. A passing score does not validate a technique, establish live SIEM alerting,
or estimate a production false-positive rate. Production acceptance still requires
independently collected, labeled telemetry from the adopter's environment.


## Deployment and notification status

Mock query execution, deployment dry-run, synthetic replay and BAS mode are
independent settings. `HECATE_RUNNER_QUERY_PROVIDER=mock` never queries an
enterprise SIEM. Deployment dry-run writes no saved search; an explicitly live
operation with missing credentials returns an error. Live Splunk operations
require an explicit endpoint as well as authentication.

Slack synthetic replay cards describe synthetic samples rather than captured
logs or verified detections. Monitor readers separate simulation/query/smoke
matches, local behavioral checks and correlated fired alerts. Legacy mock
`verified_true_positive` labels are displayed as simulations; a backend string
or latency snapshot alone cannot establish a fired alert. Local BAS counts stay
separate from the synthetic replay scorecard.
