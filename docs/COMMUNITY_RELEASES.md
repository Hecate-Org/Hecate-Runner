# Community detection releases

The community pipeline builds only catalog/catalog.yaml and its explicitly
listed original rules and synthetic fixtures. It never exports the workspace
hunt/research archive, operator sessions, raw BAS traces, credentials, or local
runtime state. LICENSES.md defines the content-license scope.

## Local preparation

From Hecate-Runner, with its environment installed:

```bash
hecate-runner release build --catalog ../Hecate-Public --output /tmp/hecate-catalog-fixture-build
```

The new private directory contains index.json, a checksummed manifest, four
Sigma rules, positive and negative fixtures, supported native query templates,
a deterministic ZIP, and SHA256SUMS. Existing output directories are refused.
Only conversions that pass syntax validation are included; unsupported targets
are listed explicitly. Native templates still require verified field mappings,
bounded time windows, and testing on the target platform before use.

## Optional independent BAS observation

With the existing isolated Linux BAS lab configured:

```bash
hecate-runner release verify --catalog ../Hecate-Public --output ../Hecate-Public/.hecate/releases/evidence.json
hecate-runner release build --catalog ../Hecate-Public --output /tmp/hecate-catalog-observed-build --evidence ../Hecate-Public/.hecate/releases/evidence.json
```

Validation selects existing pinned procedures; it cannot accept an executable
command from the catalog. The initial four cases use only read-only procedures.
The configured allowlist, isolation/image checks, lab lifecycle checks, and
independent process observation still apply. A failed case stops the sequence.
Evidence is saved privately; only a strict summary schema can enter a release.

These are catalog sensor controls, not completed hunts. An observed local Sigma
match proves neither SIEM ingestion nor alert delivery. Synthetic fixture tests
are labeled separately, and production false-positive rates remain unmeasured.
The rules intentionally match routine administrative behavior and remain
experimental hunting building blocks.

## Public GitHub release

1. Review the original source catalog, licenses, fixtures, and sanitized evidence.
2. If desired, copy only the sanitized evidence JSON to catalog/evidence.json;
   the builder rejects extra fields and evidence for another source snapshot.
3. Merge the reviewed catalog and builder changes. The Core and Runner refs used
   by the workflow must contain this implementation. Repository variables
   HECATE_CORE_REF and HECATE_RUNNER_REF can pin reviewed toolchain commits.
4. Run the Community catalog workflow without publication first and inspect its
   artifact, source digest, checksums, template limitations, and toolchain record.
5. Dispatch it from main with publish=true and the exact expected_source_digest.
6. Inspect that run's artifact and approve the community-release environment.

The environment must have required human reviewers. The publish job checks that
this protection exists and fails closed if it does not. It verifies manifest
checksums, then creates catalog-v<version> once; it does not overwrite an
existing release. Build jobs have read-only repository permissions. Only the
approved publish job receives contents:write. Workflow artifacts are available
to repository readers, so only original catalog content belongs in the build.
The ZIP is reproducible with the same inputs and toolchain; manifest.json
records package versions and hashes of the builder/evaluator/transpiler source.

## Hunt snapshots need review before public upload

The hunt publisher's content-quality PR review is separate from permission to
release source material publicly. A public PR already exposes its files.

```bash
hecate-runner publish H-0001
hecate-runner publish-review H-0001
```

Unapproved public snapshots remain in the private outbox as awaiting_review.
The second command prints an exact review digest and an owner-only preview path.
Review all those files, including source quotations and native queries. Then an
operator can authorize that exact destination and byte snapshot:

```bash
hecate-runner publish-review H-0001 --approve --digest "<inspected-digest>" --reviewer "<operator>" --rights "<actual source redistribution permission>" --privacy-checked --redistribution-checked
```

Approval requeues the snapshot; publish-sync or the next Runner cycle may then
upload it. Any file, promotion-manifest, or destination change invalidates the
approval. GitHub's independent content-quality approval still applies.
Approvals are trusted local operator records, not signatures or proof against
a compromised account with access to the same credentials and filesystem.
Private MISP storage is unaffected: events remain organization-only,
unpublished, and to_ids=false. Community MISP sharing remains a later, separate
opt-in exporter; this implementation does not enable any external feed writer.

## Adding a case

Add an original licensed rule, two-sided synthetic fixtures, source attribution,
telemetry requirements and a fixed existing procedure reference to the catalog.
No CTI/LLM command, private evidence, session object or arbitrary source path is
accepted. The initial schema deliberately permits only experimental Linux
process rules. Broader rule types require a reviewed schema/safety change.
Release eligibility must not be inferred from an ATT&CK tag or one successful
control; keep the case's actual scope and failure/unsupported states visible.
