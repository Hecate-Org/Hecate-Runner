#!/usr/bin/env bash
# Build the immutable service runtime as an ordinary user, never as root.
set -euo pipefail
if [[ $EUID -eq 0 ]]; then
    echo "Prepare the runtime as your normal account, then install it with sudo." >&2
    exit 1
fi
if [[ $# -ne 2 ]]; then
    echo "Usage: $0 CORE_CHECKOUT NEW_STAGE_DIRECTORY" >&2
    exit 2
fi
runner_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
core_root="$(cd "$1" && pwd)"
runtime_stage="$2"
if [[ -e "$runtime_stage" ]]; then
    echo "The stage directory must not already exist." >&2
    exit 1
fi
umask 077
mkdir -p "$runtime_stage"
runtime_stage="$(cd "$runtime_stage" && pwd)"
# Bundle the interpreter so services never need the operator's home directory.
uv python install 3.13 --install-dir "$runtime_stage/python"
runtime_python="$(find "$runtime_stage/python" -path '*/bin/python3.13' -type f -print -quit)"
if [[ -z "$runtime_python" ]]; then
    echo "Could not locate the staged Python interpreter." >&2
    exit 1
fi
uv venv --python "$runtime_python" "$runtime_stage/venv"
uv export --project "$runner_root" --frozen --no-dev --no-emit-local --no-emit-project \
    --format requirements.txt --output-file "$runtime_stage/requirements.txt" > /dev/null
# A few locked packages (such as sgmllib3k) have only source archives.
# Any required wheel build happens here as the unprivileged operator.
uv pip install --no-config --python "$runtime_stage/venv/bin/python" --require-hashes \
    --requirements "$runtime_stage/requirements.txt"
uv build --wheel --out-dir "$runtime_stage/wheels" "$core_root"
uv build --wheel --out-dir "$runtime_stage/wheels" "$runner_root"
uv pip install --no-config --python "$runtime_stage/venv/bin/python" --no-deps "$runtime_stage"/wheels/*.whl
"$runtime_stage/venv/bin/python" -I -c 'import hecate_agent.api, hecate_runner.cli; print("Service runtime imports passed")'
"$runtime_stage/venv/bin/python" -I - "$core_root" "$runner_root" "$runtime_stage" <<'PYTHON'
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from pathlib import Path

core, runner, stage = map(Path, sys.argv[1:])
def pin(root):
    if subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"]).strip():
        raise SystemExit(f"Commit source changes before preparing a pinned runtime: {root.name}")
    return {"commit": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
            "tree": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"], text=True).strip()}
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
manifest = {
    "schema": 1,
    "sources": {"core": pin(core), "runner": pin(runner)},
    "python": platform.python_version(),
    "uv_lock_sha256": sha(runner / "uv.lock"),
    "requirements_sha256": sha(stage / "requirements.txt"),
    "wheels": {p.name: sha(p) for p in sorted((stage / "wheels").glob("*.whl"))},
    "installed": {d.metadata["Name"]: d.version for d in importlib.metadata.distributions()},
}
(stage / "release-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PYTHON
echo "Prepared pinned runtime at $runtime_stage"
