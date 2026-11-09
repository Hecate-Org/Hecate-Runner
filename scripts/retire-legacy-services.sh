#!/usr/bin/env bash
# Retire only the superseded oneshot orchestrator and hourly timer.
# The resident daemon, maintenance, user services and firewall stay running.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: bash scripts/retire-legacy-services.sh" >&2
    exit 1
fi

if systemctl is-active --quiet hecate-runner-orchestrator.service; then
    echo "The legacy orchestrator is executing a cycle; let it finish before retiring it." >&2
    exit 1
fi

backup="/var/backups/hecate-retired-systemd/$(date -u +%Y%m%dT%H%M%SZ)"
units=(hecate-runner-orchestrator.timer hecate-runner-orchestrator.service)
for unit in "${units[@]}"; do
    fragment="/etc/systemd/system/$unit"
    if [[ -e $fragment || -L $fragment || -d $fragment.d ]]; then
        install -d -m 0700 "$backup"
        systemctl disable --now "$unit"
        for path in "$fragment" "$fragment.d"; do
            if [[ -e $path || -L $path ]]; then
                cp -a -- "$path" "$backup/"
                rm -rf -- "$path"
            fi
        done
    fi
done

# Remove the exact obsolete conflict without replacing locally customized
# daemon settings. Otherwise systemd retains a not-found timer dependency.
daemon=/etc/systemd/system/hecate-runner-daemon.service
if [[ -f $daemon ]] && grep -qx 'Conflicts=hecate-runner-orchestrator.timer' "$daemon"; then
    install -d -m 0700 "$backup"
    cp -a -- "$daemon" "$backup/"
    sed -i '/^Conflicts=hecate-runner-orchestrator\.timer$/d' "$daemon"
fi

systemctl daemon-reload
for unit in "${units[@]}"; do
    systemctl reset-failed "$unit" 2>/dev/null || true
done
echo "Legacy orchestration units retired. Existing unit files, if present, were saved under $backup."
systemctl list-unit-files 'hecate*' --no-pager
