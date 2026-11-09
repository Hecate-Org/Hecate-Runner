#!/usr/bin/env bash
# Install hecate-runner systemd units.
#
# Usage: sudo ./scripts/install-systemd.sh
#
# Idempotent — safe to re-run after editing the units.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="/etc/systemd/system"

echo "==> Installing hecate-runner systemd units from $REPO_ROOT/systemd"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

bash "$REPO_ROOT/scripts/retire-legacy-services.sh"
install -m 0644 "$REPO_ROOT/systemd/hecate-runner-daemon.service" "$UNIT_DIR/hecate-runner-daemon.service"
install -m 0644 "$REPO_ROOT/systemd/hecate-runner-maintenance.service" "$UNIT_DIR/hecate-runner-maintenance.service"

echo "==> Reloading systemd"
systemctl daemon-reload

echo
echo "==> Installed. Next steps:"
echo "   sudo systemctl enable --now hecate-runner-maintenance.service"
echo "   sudo systemctl enable --now hecate-runner-daemon.service"
echo "   sudo systemctl status hecate-runner-daemon.service hecate-runner-maintenance.service"
echo "   sudo journalctl -u hecate-runner-daemon.service -f  # follow logs"
echo "   uv run hecate-runner run  # optional manual single cycle; no legacy timer"
echo
echo "   CTI polling needs no units of its own: with HECATE_RUNNER_CTI_PROVIDER=multi"
echo "   (or otx/rss/misp) the orchestrator pulls from each source inline every cycle."
echo "   To stage CTI into the file queue by hand instead, run one of:"
echo "   uv run hecate-runner otx-poll | rss-poll | misp-poll"
