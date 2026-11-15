#!/usr/bin/env bash
# Install the dedicated-account service profile after its preflight checks.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec /usr/bin/python3 "$repo_root/scripts/install-isolated-services.py" "$@"
