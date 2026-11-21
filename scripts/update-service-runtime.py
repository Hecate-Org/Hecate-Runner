#!/usr/bin/env python3
"""Replace an installed isolated runtime without rerunning the account migration."""

from __future__ import annotations

import argparse
import fcntl
import grp
import importlib.util
import json
import os
import shlex
import stat
import subprocess
import time
from contextlib import suppress
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "isolated_installer", Path(__file__).with_name("install-isolated-services.py")
)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def installed_environment(role: str) -> dict[str, str]:
    path = Path("/etc/hecate") / f"{role}.env"
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != grp.getgrnam(f"hecate-{role}").gr_gid
        or stat.S_IMODE(info.st_mode) != 0o640
    ):
        raise ValueError(f"Unexpected ownership or permissions for {role}.env")
    result = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tokens = shlex.split(line)
        if len(tokens) != 1 or "=" not in tokens[0]:
            raise ValueError(f"Invalid installed configuration for {role}")
        name, value = tokens[0].split("=", 1)
        result[name] = value
    return result


def select_runtime(current: Path, target: Path) -> None:
    temporary = current.with_name(f".runtime-update-{os.getpid()}")
    temporary.symlink_to(target)
    try:
        os.replace(temporary, current)
    finally:
        temporary.unlink(missing_ok=True)


def check_service_canaries(unit: str, role: str, current: Path) -> None:
    """Offline checks in the running role's mount namespace; no model calls."""
    pid = installer.command(
        "/usr/bin/systemctl", "show", unit, "--property=MainPID", "--value"
    ).stdout.strip()
    if not pid.isdigit() or int(pid) <= 1:
        raise ValueError(f"No live process for {unit}")
    # Carry only nonsecret configuration from the actual process, including
    # shared reference settings supplied by systemd drop-ins.
    allowed = {"HOME", "HECATE_WORKSPACE", "HECATE_STIX_CACHE"}
    env = {}
    for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
        key, separator, value = item.partition(b"=")
        if separator and key.decode() in allowed:
            env[key.decode()] = value.decode()
    if not {"HOME", "HECATE_WORKSPACE"} <= env.keys():
        raise ValueError(f"Missing runtime environment for {unit}")
    env.update(PATH="/usr/bin:/bin", HECATE_SERVICE_ISOLATED="1", PYTHON_DOTENV_DISABLED="1")
    code = """
import os
import subprocess
import sys
from pathlib import Path
from hecate_runner.hecate_client import HecateClient, HecateError
from hecate_runner.subprocess_utils import run_process_group

cache = os.environ.get("HECATE_STIX_CACHE")
if cache:
    from hecate_agent.api import lookup_technique
    for tid, name in {"T1059.001": "PowerShell", "T1059.002": "AppleScript", "T1059.007": "JavaScript"}.items():
        assert lookup_technique(tid).get("name") == name
    for path in (Path(cache), Path(cache) / "enterprise-attack.json", Path(cache) / "enterprise-attack.sqlite3"):
        assert os.access(path, os.R_OK) and not os.access(path, os.W_OK)
client = HecateClient(Path(sys.executable), Path(os.environ["HECATE_WORKSPACE"]))
try:
    client._run_stage("readiness-probe", {}, 10)
except HecateError as exc:
    assert str(exc) == "readiness-probe API call failed in isolated worker"
else:
    raise RuntimeError("Worker accepted an unsupported operation")
try:
    run_process_group([sys.executable, "-I", "-c", "import time; time.sleep(30)"], timeout=0.1)
except subprocess.TimeoutExpired:
    pass
else:
    raise RuntimeError("Process deadline failed")
"""
    installer.command(
        "/usr/bin/nsenter",
        "--target",
        pid,
        "--mount",
        "--",
        "/usr/sbin/runuser",
        "-u",
        f"hecate-{role}",
        "--",
        str(current / "venv/bin/python"),
        "-I",
        "-c",
        code,
        env=env,
        cwd=current,
    )


def update(stage: Path) -> None:
    if os.geteuid() != 0:
        raise PermissionError("Runtime replacement requires sudo")
    os.umask(0o007)
    prefix = Path("/opt/hecate")
    if prefix.is_symlink() or prefix.stat().st_uid != 0 or prefix.stat().st_mode & 0o022:
        raise ValueError("Runtime prefix must be protected and administrator-owned")
    current = prefix / "runtime"
    if not current.is_symlink():
        raise ValueError("An isolated runtime must already be installed")
    previous = current.resolve()
    if not previous.is_relative_to(prefix / "releases"):
        raise ValueError("Current runtime is not a managed release")
    stage = stage.resolve()
    if not (stage / "venv/bin/python").is_file():
        raise ValueError("Prepared runtime is missing")
    envs = {role: installed_environment(role) for role in installer.ROLES}
    for unit, role in zip(installer.UNITS, (*installer.ROLES, "bas"), strict=True):
        installer.command("/usr/bin/systemctl", "is-active", unit)
        user = installer.command(
            "/usr/bin/systemctl", "show", unit, "--property=User", "--value"
        ).stdout.strip()
        if user != f"hecate-{role}":
            raise ValueError("Expected isolated service identities before a runtime update")
    stamp = time.strftime("%Y%m%dT%H%M%S")
    backup = Path("/var/backups/hecate-service-isolation") / f"runtime-{stamp}"
    backup.mkdir(mode=0o700)
    (backup / "previous-runtime.json").write_text(json.dumps({"runtime": str(previous)}))
    release = prefix / "releases" / f"{stamp}-runtime"
    phase = "runtime preparation"
    stopped = False
    try:
        installer.prepare_runtime(stage, release)
        for role in installer.ROLES:
            phase = f"{role} configuration preflight"
            installer.check_role_runtime(
                role, release, Path("/var/lib/hecate/workspace"), envs[role]
            )
        phase = "stopping isolated services"
        stopped = True
        installer.stop_existing_units(*installer.UNITS)
        select_runtime(current, release)
        phase = "starting updated services"
        installer.command("/usr/bin/systemctl", "start", "hecate-bas-broker", *installer.UNITS[:-1])
        time.sleep(3)
        for unit in installer.UNITS:
            installer.command("/usr/bin/systemctl", "is-active", unit)
        phase = "service-account worker and reference canaries"
        for unit, role in zip(installer.UNITS[:-1], installer.ROLES, strict=True):
            check_service_canaries(unit, role, current)
        phase = "publication outbox access verification"
        pid = installer.command(
            "/usr/bin/systemctl",
            "show",
            "hecate-runner-maintenance",
            "--property=MainPID",
            "--value",
        ).stdout.strip()
        if not pid.isdigit() or pid == "0":
            raise ValueError("Writer service has no live process")
        # Check only local SQLite access in the writer's real mount namespace.
        # This does not invoke a publisher client or send any remote request.
        code = (
            "import os; os.umask(0o007); "
            "from hecate_runner.config import Settings; "
            "from hecate_runner.github_publisher import outbox_for; "
            "from hecate_runner.misp_publisher import _connect; "
            "settings=Settings(); outbox_for(settings).summary(); "
            "context=_connect(settings); db=context.__enter__(); "
            "db.execute('SELECT count(*) FROM exports').fetchone(); "
            "context.__exit__(None,None,None)"
        )
        env = {
            **envs["writer"],
            "HOME": "/var/lib/hecate/homes/writer",
            "PATH": f"{current}/venv/bin:/usr/bin:/bin",
            "HECATE_SERVICE_ISOLATED": "1",
            "HECATE_STRICT_CREDENTIAL_ROLES": "1",
            "PYTHON_DOTENV_DISABLED": "1",
            "HECATE_WORKSPACE": "/var/lib/hecate/workspace",
        }
        installer.command(
            "/usr/bin/nsenter",
            "--target",
            pid,
            "--mount",
            "--",
            "/usr/sbin/runuser",
            "-u",
            "hecate-writer",
            "--",
            str(current / "venv/bin/python"),
            "-I",
            "-c",
            code,
            env=env,
            cwd=current,
        )
        print(
            "Updated isolated runtime active; role worker/reference canaries and outbox access verified."
        )
        print(f"Private recovery snapshot: {backup}")
    except Exception as failure:
        with suppress(OSError):
            installer.record_failure(backup, phase, failure)
        if stopped:
            with suppress(Exception):
                installer.stop_existing_units(*installer.UNITS)
            select_runtime(current, previous)
            installer.command(
                "/usr/bin/systemctl",
                "start",
                "hecate-bas-broker",
                *installer.UNITS[:-1],
                check=False,
            )
        raise RuntimeError(
            f"Runtime update failed during {phase}; prior runtime restoration attempted. "
            f"Private diagnostics: {backup}/failure.json"
        ) from None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-stage", type=Path, required=True)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise PermissionError("Runtime replacement requires sudo")
        fd = os.open(
            "/run/lock/hecate-runtime-update.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            update(args.runtime_stage)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
