# Dependency security maintenance

The November 2026 refresh updates the production lock and raises the direct
PyJWT requirement to 2.15.0. uv constraints preserve security floors for affected
HTTP, TLS, HTML selector, image-processing and file-locking dependencies without
installing additional optional features. Python **3.11.5 or newer** is required
by fixed Soup Sieve releases; the supported Python minor versions are unchanged.

Run `uv sync --locked --dev` against a sibling Core checkout with matching
dependency metadata. Rebuild production runtimes from `uv.lock` without the dev
group, using built Core/Runner wheels rather than editable installs. Services
execute their protected installed runtime, so pulling a source update does not
deploy dependency fixes. Use the runtime updater and retain its recovery snapshot.

## Remaining upstream advisory

DiskCache 5.6.3 is still required by pySigma 1.x and has an unresolved unsafe
pickle-deserialization advisory:
[GHSA-w8v5-vhqr-4h9v](https://github.com/advisories/GHSA-w8v5-vhqr-4h9v).
pySigma 2 replaces that dependency, but the current Kusto, CrowdStrike and
Elasticsearch backends require pySigma below 2. Do not force incompatible versions
or accept untrusted cache databases to clear a scanner result.

The finding is not ignored. Full scheduled/manual audits continue reporting it;
PR checks block new matches. Service homes and private state directories restrict
cache writers, but are not a fix for the underlying package. Revisit the migration
when compatible backends are released.
