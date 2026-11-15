# Isolated service installation

The daemon, publication/maintenance worker, and Slack bot run as separate
nologin system accounts: hecate-reader, hecate-writer, and hecate-slack.
None belongs to the operator's desktop, sudo, Docker, or LXD groups.

Application code and a standalone Python runtime live in administrator-owned
releases under /opt/hecate. Services execute installed wheels, never editable
source checkouts or uv synchronization at startup. Their only shared writable
data is the selected workspace, mounted at /var/lib/hecate/workspace.
The original workspace remains available to the desktop operator.

Home directories, user session sockets, Docker/LXD sockets, device access,
capabilities, and namespace creation are restricted. Credential files are
separate per role; the workspace .env is ignored in isolated mode. Shared hunt
data uses the private hecate-data group, while credentials and SDK homes are
private to their role. Workspace files are not executable.

## Prepare without root

Build the service runtime as your ordinary user. Dependencies are installed
from the frozen, hashed Runner lock; any source builds happen without root.
Core and Runner wheels are built from the selected checkouts.

    scripts/prepare-service-runtime.sh ../Hecate-Core /path/to/new-runtime-stage

The Core wheel includes its Sigma, enrichment, and orchestrator subpackages;
editable installs previously masked omissions in the explicit package list.

Create an owner-only directory containing reader.env, writer.env, and
slack.env. Start from deploy/service-env/*.env.example and copy the applicable
non-secret configuration and correctly scoped credentials from the current
workspace configuration. Do not copy the entire operator environment.

- Reader: CTI/model credentials, SPLUNK_READ_TOKEN, an optional restricted
  SPLUNK_INGEST_TOKEN for lab telemetry, and optional GITHUB_READ_TOKEN.
- Writer: publishing credentials, SPLUNK_WRITE_TOKEN, and SPLUNK_READ_TOKEN
  for drift/audit operations.
- Slack: Slack tokens and only the publishing/deployment credentials its
  enabled commands require.
- Reader must not receive the writer token, GitHub publishing App key,
  MISP output key, or Slack app/socket token.
- GitHub App private-key files can remain in their current private location
  during preparation; the installer copies them into a role-protected /etc
  directory and rewrites their configured paths.
- Preserve integration endpoint, model, policy, and automation settings.
  Rebase workspace-relative absolute configuration paths onto
  /var/lib/hecate/workspace.

Use a Splunk principal restricted to searching the intended indexes for the
reader token, and a separate principal with only the necessary saved-search
management rights for the writer token. Do not rename the same administrator
token into both fields. If lab ingestion is enabled, its distinct ingestion
token must be a distinct HTTP Event Collector (HEC) token with only the lab
index allowed. Set SPLUNK_HEC_URL to its HTTPS base URL (for this host,
https://localhost:8088). Isolated ingestion requires HEC and never falls back
to the broad management receiver or password authentication. The installer verifies that the
read/write values differ; administrators must verify their actual server-side
permissions. GitHub's read token should also be restricted to the repositories
and read operations the intake sources require.

Each file must have mode 0600. Do not define HOME, PATH, Python/loader variables,
legacy SPLUNK_TOKEN/SPLUNK_PASSWORD, or the isolation/workspace/broker variables
in these files: the service units own those settings. Values containing spaces
or JSON must be quoted. The examples leave credentials blank intentionally.

Validate inputs without changing the host:

    python scripts/install-isolated-services.py --check \
      --runtime-stage /path/to/runtime-stage \
      --workspace /path/to/Hecate-Public \
      --env-dir /path/to/private-role-env \
      --docker-socket /path/to/docker.sock

## Apply with administrator access

Install the host's acl package if setfacl/getfacl are unavailable. Then:

    sudo scripts/install-systemd.sh \
      --runtime-stage /path/to/runtime-stage \
      --workspace /path/to/Hecate-Public \
      --env-dir /path/to/private-role-env \
      --docker-socket /path/to/docker.sock \
      --operator YOUR_DESKTOP_ACCOUNT

For this host Docker Desktop uses
/home/chemch/.docker/desktop/docker.sock. Native Docker usually uses
/var/run/docker.sock. Use the socket for the existing reviewed lab, not a
different Docker context. The CLI defaults to /usr/bin/docker; supply --docker
if its administrator-owned executable is elsewhere.

The installer validates inputs, creates the dedicated accounts and root-owned
runtime, snapshots installed units/configuration and workspace permissions,
then stops the old daemon/maintenance and desktop Slack service before
switching identities. It enables system services for all three workers.
The desktop operator joins only the shared hecate-data group and must open a
new login session to access new worker-owned files. Existing artifact owners
are preserved; private .env/key files are excluded
from the shared-group permission changes. Unexpected artifact symlinks or
unmanaged systemd overrides stop the migration. To retire a reviewed legacy
override, supply its exact path with --retire-dropin (repeatable); the snapshot
preserves it for restoration. On this host the daemon has
90-hecate-maintenance.conf and 90-public-workspace.conf under
/etc/systemd/system/hecate-runner-daemon.service.d. They must be retired
because they reintroduce the shared environment and writable source paths.

On activation failure it attempts to restore prior units, configuration,
runtime selection, workspace permissions, socket ACL, and previously active
services and enablement settings. The recovery snapshot is root-only under
/var/backups/hecate-service-isolation. Runtime releases and newly created
inactive accounts may remain after rollback. Inspect the snapshot and service
health before retrying; do not delete original workspace data.

## BAS without broad Docker access

Only hecate-bas runs the Docker client. Its private mount namespace binds the
selected Docker API socket and a fixed privileged pre-start command grants
only that broker account access to the socket. The reader/writer/Slack workers
can reach the broker socket, never the raw Docker API.

The broker authenticates callers using Linux peer credentials and permits only
the configured agent/controller inspection, lab network inspection, process
listing, bounded trace reads, hashing temporary lab files, and cleanup inside
the agent's /tmp. It pins execution to the inspected agent ID and refuses shell,
container start/run/copy, arbitrary filesystem access, and network modification.
Container environment credentials are removed from inspection results.
An unavailable broker fails closed; clients never fall back to raw Docker when
the broker socket is configured.

Existing approved-procedure and full sensor/controller preflight checks remain
mandatory. Broker access does not authorize new procedures or weaken a failed
lab profile. Keep the existing container resources and internal network.

## Verify after migration

Check all four system services and their effective User, Groups, NoNewPrivileges,
ProtectHome, ProtectSystem, and writable paths. Confirm that the former desktop
Slack unit is disabled, all three workers can use the shared workspace, the
reader cannot read writer credentials or the operator's .ssh/.kube/.docker
directories, and workers cannot modify /opt/hecate.

Run the doctor and a reviewed, bounded read-only integration check under each
appropriate role. Confirm ordinary drafting, publication, Slack operations,
and approved lab preflight before relying on unattended operation. This
repository's tests exercise policy, path races, request pinning, and failure
handling; a successful static/unit test is not proof of installed-host isolation.

## Input boundaries

Public report fetches resolve and validate all addresses for every redirect,
connect to a checked numeric IP, preserve the original Host/TLS name, disable
ambient proxy configuration, strip credentials across origins, and bound
uncompressed bytes. Compressed responses that ignore Accept-Encoding: identity
are refused. Configured private integrations continue using their separate
clients; public-report fetching never permits private endpoints.

Automatic pivot values are typed and quoted. Controls, query pipeline
operators, and user-supplied wildcards are refused, invalid pivots never reach
a provider, and SQL substring searches do not interpret entity wildcards.
Hunt identifiers and artifact paths reject traversal and symlinks. On POSIX,
descriptor-relative reads/replacements remain inside pinned workspace
directories even if a parent path is replaced during an operation.

Service migration does not fix the existing dependency backlog, TLS settings
of separately configured integrations, or Slack user/channel authorization.
