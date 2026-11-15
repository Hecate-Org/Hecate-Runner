#!/usr/bin/env bash
# Install the dedicated-account service profile after its preflight checks.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -eq 0 ]]; then
    exec "$repo_root/scripts/setup-services.sh"
fi

exec /usr/bin/python3 "$repo_root/scripts/install-isolated-services.py" "$@"

