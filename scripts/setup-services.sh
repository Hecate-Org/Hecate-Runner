#!/usr/bin/env bash
# Guided setup for Hecate isolated systemd background services.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
runner_root="$(cd "$script_dir/.." && pwd)"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Set up and install isolated Hecate systemd services.

Options:
  --runtime-stage PATH  Pre-built standalone runtime stage directory (skips build step)
  --core PATH           Path to Hecate-Core checkout (default: sibling ../Hecate-Core)
  --workspace PATH      Path to workspace repository (default: \$HECATE_WORKSPACE or ../Hecate-Public)
  --env-dir PATH        Path to environment directory with role .env files (default: /etc/hecate or deploy/service-env)
  --docker-socket PATH  Path to Docker Unix socket (default: /run/docker.sock or /var/run/docker.sock)
  --operator USER       Desktop operator username (default: \$SUDO_USER or \$USER)
  --check               Validate inputs and configuration without installing
  -h, --help            Show this help message
EOF
    exit "${1:-0}"
}

runtime_stage=""
core_dir=""
workspace_dir=""
env_dir=""
docker_sock=""
operator_user=""
check_only=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runtime-stage)
            runtime_stage="$2"
            shift 2
            ;;
        --core)
            core_dir="$2"
            shift 2
            ;;
        --workspace)
            workspace_dir="$2"
            shift 2
            ;;
        --env-dir)
            env_dir="$2"
            shift 2
            ;;
        --docker-socket)
            docker_sock="$2"
            shift 2
            ;;
        --operator)
            operator_user="$2"
            shift 2
            ;;
        --check)
            check_only=true
            shift
            ;;
        -h|--help)
            usage 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage 1
            ;;
    esac
done

# Resolve operator
if [[ -z "$operator_user" ]]; then
    operator_user="${SUDO_USER:-${USER:-$(id -un)}}"
fi

# Resolve Core checkout
if [[ -z "$core_dir" ]]; then
    if [[ -n "${HECATE_CORE:-}" && -d "$HECATE_CORE" ]]; then
        core_dir="$HECATE_CORE"
    elif [[ -d "$runner_root/../Hecate-Core" ]]; then
        core_dir="$runner_root/../Hecate-Core"
    else
        echo "Error: Could not locate Hecate-Core directory. Specify --core PATH." >&2
        exit 1
    fi
fi
core_dir="$(cd "$core_dir" && pwd)"

# Resolve Workspace
if [[ -z "$workspace_dir" ]]; then
    if [[ -n "${HECATE_WORKSPACE:-}" && -d "$HECATE_WORKSPACE" ]]; then
        workspace_dir="$HECATE_WORKSPACE"
    elif [[ -d "$runner_root/../Hecate-Public" ]]; then
        workspace_dir="$runner_root/../Hecate-Public"
    else
        echo "Error: Could not locate workspace directory. Specify --workspace PATH." >&2
        exit 1
    fi
fi
workspace_dir="$(cd "$workspace_dir" && pwd)"

# Resolve Docker socket
if [[ -z "$docker_sock" ]]; then
    if [[ -S "/run/docker.sock" ]]; then
        docker_sock="/run/docker.sock"
    elif [[ -S "/var/run/docker.sock" ]]; then
        docker_sock="/var/run/docker.sock"
    else
        echo "Error: Could not locate Docker socket. Specify --docker-socket PATH." >&2
        exit 1
    fi
fi

# Resolve environment directory
created_tmp_env=false
if [[ -z "$env_dir" ]]; then
    if [[ -d "/etc/hecate" && -f "/etc/hecate/reader.env" ]]; then
        env_dir="/etc/hecate"
    else
        # Staging template directory for first-time setup
        staged_env="$(mktemp -d /tmp/hecate-service-env-XXXXXX)"
        created_tmp_env=true
        chmod 0700 "$staged_env"
        for role in reader writer slack; do
            if [[ -f "$runner_root/deploy/service-env/${role}.env.example" ]]; then
                cp "$runner_root/deploy/service-env/${role}.env.example" "$staged_env/${role}.env"
                chmod 0600 "$staged_env/${role}.env"
            fi
        done
        env_dir="$staged_env"
        echo "[INFO] Initialized staging environment from templates at $staged_env"
        echo "       Review credentials in $staged_env before production deployment."
    fi
fi

cleanup() {
    if [[ "${created_tmp_stage:-false}" == true && -d "${runtime_stage:-}" ]]; then
        rm -rf "$runtime_stage"
    fi
    if [[ "$created_tmp_env" == true && -d "$env_dir" ]]; then
        rm -rf "$env_dir"
    fi
}
trap cleanup EXIT

echo "=== Hecate Service Setup Configuration ==="
echo "Operator:      $operator_user"
echo "Core Path:     $core_dir"
echo "Runner Path:   $runner_root"
echo "Workspace:     $workspace_dir"
echo "Env Dir:       $env_dir"
echo "Docker Socket: $docker_sock"
echo "Check Mode:    $check_only"
echo "=========================================="

# 1. Build runtime stage as non-root if not provided
if [[ -z "$runtime_stage" ]]; then
    runtime_stage="/tmp/hecate-runtime-setup-$$"
    created_tmp_stage=true
    echo ""
    echo "[1/2] Building isolated service runtime..."
    "$runner_root/scripts/prepare-service-runtime.sh" "$core_dir" "$runtime_stage"
else
    echo ""
    echo "[1/2] Using existing staged runtime at $runtime_stage..."
fi

# 2. Install services (requires root)
echo ""
echo "[2/2] Installing isolated systemd services..."
install_cmd=(
    /usr/bin/python3 "$runner_root/scripts/install-isolated-services.py"
    --runtime-stage "$runtime_stage"
    --workspace "$workspace_dir"
    --env-dir "$env_dir"
    --docker-socket "$docker_sock"
    --operator "$operator_user"
)

if [[ "$check_only" == true ]]; then
    install_cmd+=(--check)
fi

if [[ $EUID -eq 0 ]]; then
    "${install_cmd[@]}"
else
    echo "Elevating privileges with sudo to install systemd units and create dedicated users..."
    sudo "${install_cmd[@]}"
fi

echo ""
echo "Hecate service setup complete."
if [[ "$check_only" == false ]]; then
    echo "Check service status with:"
    echo "  systemctl status hecate-runner-daemon.service hecate-runner-maintenance.service hecate-slack-bot.service hecate-bas-broker.service"
fi
