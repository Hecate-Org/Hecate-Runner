# Platform capabilities and limits

| Capability | Implementation | Boundary |
| --- | --- | --- |
| Multi-source CTI intake | `src/hecate_runner/cti/` | Enable supported sources and supply required credentials; reference catalogs are not intrusion evidence |
| Intake deduplication and quotas | `orchestrator_intake.py`, workspace state | Reduces redundant work; reference/source revisions still require evidence checks |
| Existing-hunt sweeps | `commands/sweep.py`, execution scheduler | Uses active workspace hunts, backend mappings, count-first gates and approval policy; independent of generation |
| Indicator sweep generation | `indicator_sweep.py` | Deterministic indicator-rule generation avoids model calls for that step, not all optional processing |
| Research and hypothesis generation | Core agents/API | Requires configured models and optional search; output is planning content |
| Sigma review/transpilation | Core tooling, Runner rule pipeline | Syntax and compatibility checks do not prove production data coverage |
| Synthetic purple-team replay | `purple_team.py` | Uses samples/Atomic definitions only; no Atomic command execution or live validation |
| Replay holdouts/tuning | `purple_team.py`, `rule_tuner.py` | Independent reserved synthetic groups; unavailable with insufficient groups; no production FP estimate |
| Approved Linux BAS | `bas/approved.py`, `bas/runtime.py` | Pinned procedures, compatible rules, allowlists, isolation, sensors, cleanup and fidelity gates |
| Manual CALDERA / Stratus | `bas/caldera.py`, `bas/stratus.py` | Separate platform/account/identity prerequisites; not unattended Windows/cloud support |
| SIEM alert verification | `bas/siem_verifier.py` | Native matches and fired-alert proof remain distinct; current authoritative correlation is Splunk-specific |
| Native query deployment | Core `query_deployer.py`, Runner commands | Six supported target IDs; explicit live requests without configuration fail; dry-run is not deployment |
| GitHub and MISP outboxes | `github_publisher.py`, `misp_publisher.py` | Opt-in destinations and review; public snapshots need privacy/redistribution approval |
| Slack operations | `notifications.py`, `slack_bot.py` | Bot/webhook notifications; Socket Mode credentials/config needed for interactive actions |
| Monitor | Core `commands/monitor*.py` | Reads selected workspace evidence; mock/legacy labels cannot establish a fired alert |
| Community catalog releases | `release` commands | Explicit original catalog/fixtures only, sanitized evidence and separate publishing approval |

## Query capability matrices

Native conversion and saved-query deployment use `splunk_spl`, `sentinel_kql`,
`crowdstrike_cql`, `rapid7_leql`, `sentinelone_s1ql` and `elastic_eql`, subject to
backend support for the rule. Native hunt execution providers are configured
separately (`mock`, `splunk`, `sentinel`, `elastic`, `crowdstrike`). Do not infer
Rapid7/SentinelOne query execution or QRadar support from a conversion example.

## Defaults and opt-ins

The example configuration uses mock query execution, analyst sweep approval,
disabled automatic hunt execution, disabled deployment and deployment dry-run.
Generation, sweeps, deployment, publication and live BAS have separate settings.
The code default enables BAS in mock mode, with unattended live execution off;
set `HECATE_BAS_ENABLED=false` to disable that offline BAS step too. The Public
starter explicitly disables BAS. Installed operator settings may differ from examples. Changing one does not
silently enable the others.

For operational setup see [onboarding](ONBOARDING.md) and [recipes](HOW_TO.md).
For actual evidence and platform limits see [BAS automation](BAS_AUTOMATION.md).
