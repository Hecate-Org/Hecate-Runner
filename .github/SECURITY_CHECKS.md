# Automated codebase checks

These tools run only in GitHub Actions. They add no runtime dependency and
are outside the packaged application.

- Existing CI runs lint, type checks, and tests. The stable `CI required`
  result fails if any required job fails, is cancelled, or is skipped.
- `Security checks` scans tracked files for secrets, runs Bandit at high
  severity, and audits every registry package/version in `uv.lock`, including
  optional, development, and alternate-platform entries. Audited packages
  are never installed or imported.
- Both workflows run on pushes and pull requests. Security also runs weekly
  and can be started manually.

## Dependency policy

PR and push audits compare exact package/version/advisory triples with the
base commit using the same advisory feed. New matches fail. Existing debt
stays in the artifact and job summary; it is not a global advisory ignore.
A changed package version with the same advisory still fails.

Weekly and manual runs have no comparison baseline: any advisory fails the
full audit. Review the dependency-audit artifact, assess feature reachability,
and fix affected packages. Scanner/API failures and skipped packages fail
closed. The local Hecate project is source-scanned, while its locked registry
dependencies are dependency-scanned.

## Secret policy

`.secrets.baseline` records reviewed fixture values and CTI hashes by file,
detector type, and one-way hash. It contains no raw secrets. Existing exceptions
do not authorize a changed value or the same value in another file.

A PR uses the base branch's exceptions, so adding a baseline entry in the same
PR cannot authorize a new candidate. Scanner plugins and filters are fixed
by the check; baseline configuration and inline allowlist comments cannot
disable them. During initial installation only, the checked-in reviewed
baseline seeds the exceptions.

Never baseline a real credential. Revoke and remove it instead. An intentional
new fixture should use a clearly synthetic value; investigate any failure
before changing exceptions. Do not automatically refresh the baseline in CI.

## Required checks

The main-branch rule requires `CI required` and `Security checks` from GitHub
Actions. Changes must use a pull request; force pushes and branch deletion
are blocked. No additional human review count is imposed by this CI rule.
GitHub secret scanning/push protection and dependency alerts provide additional
repository-level checks.
