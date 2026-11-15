#!/usr/bin/env python3
"""Install isolated workers after preparing a runtime and per-role environment files."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

ROLES = ("reader", "writer", "slack")
UNITS = (
    "hecate-runner-daemon",
    "hecate-runner-maintenance",
    "hecate-slack-bot",
    "hecate-bas-broker",
)
RESERVED = {
    "HOME",
    "PATH",
    "HECATE_WORKSPACE",
    "HECATE_BIN",
    "DOCKER_HOST",
    "HECATE_SERVICE_ISOLATED",
    "HECATE_STRICT_CREDENTIAL_ROLES",
    "HECATE_BAS_BROKER_SOCKET",
    "HECATE_ALLOW_UNSANDBOXED_EMULATION",
    "SPLUNK_TOKEN",
    "SPLUNK_API_TOKEN",
    "SPLUNK_PASSWORD",
}


def command(
    *args: str, check: bool = True, env: dict | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args), check=check, capture_output=True, text=True, timeout=120, env=env
    )


def read_environment(path: Path, role: str) -> dict[str, str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError(f"{role}.env must be a regular owner-only file")
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tokens = shlex.split(line, comments=False)
        if len(tokens) != 1 or "=" not in tokens[0]:
            raise ValueError(f"Invalid environment assignment in {role}.env")
        key, value = tokens[0].split("=", 1)
        if (
            not re.fullmatch(r"[A-Z][A-Z0-9_]*", key)
            or key in RESERVED
            or key.startswith(("PYTHON", "LD_", "DYLD_", "GIT_CONFIG_"))
            or any(char in value for char in "\r\n\x00")
        ):
            raise ValueError(f"Unsafe environment key in {role}.env: {key}")
        if role == "reader" and (
            key in {"SPLUNK_WRITE_TOKEN", "GITHUB_TOKEN", "MISP_OUTPUT_API_KEY", "SLACK_APP_TOKEN"}
            or "GITHUB_APP_PRIVATE_KEY" in key
            or "MISP_WRITE" in key
        ):
            raise ValueError(f"Writer credential is not allowed in reader.env: {key}")
        result[key] = value
    return result


def validate_environments(env_dir: Path) -> dict[str, dict[str, str]]:
    values = {role: read_environment(env_dir / f"{role}.env", role) for role in ROLES}
    if any(
        v.get("SPLUNK_HOST")
        or v.get("SPLUNK_URL")
        or v.get("HECATE_RUNNER_QUERY_PROVIDER") == "splunk"
        for v in values.values()
    ):
        reader = values["reader"].get("SPLUNK_READ_TOKEN")
        writer = values["writer"].get("SPLUNK_WRITE_TOKEN")
        if not reader or not writer or reader == writer:
            raise ValueError(
                "Configure distinct SPLUNK_READ_TOKEN and SPLUNK_WRITE_TOKEN credentials"
            )
    return values


def systemd_path(path: Path) -> str:
    value = str(path)
    if not path.is_absolute() or re.search(r"[^A-Za-z0-9_./:@-]", value):
        raise ValueError("Service paths must be absolute and contain no systemd metacharacters")
    return value


def prepare_runtime(stage: Path, release: Path) -> None:
    old = str(stage)
    shutil.copytree(stage, release, symlinks=True)
    for path in release.rglob("*"):
        if path.is_symlink():
            target = os.readlink(path)
            if target.startswith(old + "/"):
                path.unlink()
                path.symlink_to(str(release) + target[len(old) :])
            resolved = path.resolve()
            if not resolved.is_relative_to(release) and not str(resolved).startswith(
                ("/usr/", "/lib/")
            ):
                raise ValueError("Runtime symlink escapes the installed release")
            continue
        if path.is_file() and (path.parent == release / "venv/bin" or path.name == "pyvenv.cfg"):
            raw = path.read_bytes()
            if b"\0" not in raw:
                path.write_bytes(raw.replace(old.encode(), str(release).encode()))
        os.chown(path, 0, 0)
        os.chmod(path, 0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
    os.chown(release, 0, 0)
    os.chmod(release, 0o755)


def user_command(operator: str, *args: str, check: bool = True):
    uid = pwd.getpwnam(operator).pw_uid
    return command(
        "/usr/sbin/runuser",
        "-u",
        operator,
        "--",
        "/usr/bin/env",
        f"XDG_RUNTIME_DIR=/run/user/{uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
        "/usr/bin/systemctl",
        "--user",
        *args,
        check=check,
    )


def private_workspace_path(relative: Path) -> bool:
    return any(
        part in {".venv", "credentials", "secrets"}
        or part == ".env"
        or part.startswith(".env.")
        or part.endswith((".pem", ".key", ".p12", ".pfx"))
        for part in relative.parts
    )


def install(args) -> None:
    stage, workspace, env_dir = (
        path.resolve() for path in (args.runtime_stage, args.workspace, args.env_dir)
    )
    for path in (stage, workspace, env_dir, args.docker_socket, args.docker):
        systemd_path(path)
    if not (stage / "venv/bin/python").is_file() or not (stage / "python").is_dir():
        raise ValueError("Prepare a standalone service runtime first")
    if not workspace.is_dir() or not stat.S_ISSOCK(args.docker_socket.stat().st_mode):
        raise ValueError("Workspace and Docker API socket must exist")
    environments = validate_environments(env_dir)
    # Refuse an operator-data symlink rather than changing its target's permissions.
    for path in workspace.rglob("*"):
        if private_workspace_path(path.relative_to(workspace)):
            continue
        if path.is_symlink():
            raise ValueError("Remove workspace artifact symlinks before migration")
    retired_dropins = set(args.retire_dropin)
    for path in retired_dropins:
        if (
            path.parent.parent != Path("/etc/systemd/system")
            or path.parent.name not in {f"{unit}.service.d" for unit in UNITS}
            or path.is_symlink()
            or not path.is_file()
        ):
            raise ValueError("Only existing managed service drop-ins may be retired")
    if args.check:
        print("Migration inputs validated; no services or host permissions changed.")
        return
    if os.geteuid() != 0:
        raise PermissionError("Applying service isolation requires sudo")
    if not args.operator or args.operator == "root":
        raise ValueError("Specify the desktop operator account for the legacy Slack service")
    for binary in ("setfacl", "getfacl", "systemctl", "systemd-analyze", "runuser"):
        if shutil.which(binary) is None:
            raise ValueError(f"Required host tool is missing: {binary}")
    timestamp = time.strftime("%Y%m%dT%H%M%S")
    backup = Path("/var/backups/hecate-service-isolation") / timestamp
    backup.mkdir(parents=True, mode=0o700)
    os.chmod(backup.parent, 0o700)
    os.chmod(backup, 0o700)
    unit_root = Path("/etc/systemd/system")
    config_root = Path("/etc/hecate")
    prefix = Path("/opt/hecate")
    prefix.mkdir(parents=True, exist_ok=True)
    if prefix.is_symlink() or prefix.stat().st_uid != 0 or prefix.stat().st_mode & 0o022:
        raise ValueError("/opt/hecate must be administrator-owned and not group/world writable")
    (prefix / "releases").mkdir(exist_ok=True, mode=0o755)
    current = prefix / "runtime"
    old_runtime = os.readlink(current) if current.is_symlink() else None
    if current.exists() and not current.is_symlink():
        raise ValueError("/opt/hecate/runtime must be a managed release symlink")
    release = prefix / "releases" / timestamp
    prepare_runtime(stage, release)
    if command("/usr/bin/getent", "group", "hecate-data", check=False).returncode:
        command("/usr/sbin/groupadd", "--system", "hecate-data")
    for role in (*ROLES, "bas"):
        account = f"hecate-{role}"
        if command("/usr/bin/id", account, check=False).returncode:
            command(
                "/usr/sbin/useradd",
                "--system",
                "--user-group",
                "--groups",
                "hecate-data",
                "--home-dir",
                f"/var/lib/hecate/homes/{role}",
                "--shell",
                "/usr/sbin/nologin",
                account,
            )
        memberships = command("/usr/bin/id", "-nG", account).stdout.split()
        if set(memberships) - {account, "hecate-data"}:
            raise ValueError(f"Unexpected supplementary groups for {account}")
    if config_root.exists():
        shutil.copytree(config_root, backup / "configuration", symlinks=True)
    unit_source = Path(__file__).resolve().parents[1] / "systemd"
    old_active = {}
    old_enabled = {}
    permissions = []
    original_acl = command("/usr/bin/getfacl", "--absolute-names", str(args.docker_socket)).stdout
    (backup / "docker-socket.acl").write_text(original_acl)
    for unit in UNITS:
        source = unit_root / f"{unit}.service"
        if source.exists():
            shutil.copy2(source, backup / source.name)
        overrides = unit_root / f"{unit}.service.d"
        if overrides.exists():
            if any(
                path.name != "90-isolation.conf" and path not in retired_dropins
                for path in overrides.iterdir()
            ):
                raise ValueError("Review unmanaged systemd overrides before migration")
            shutil.copytree(overrides, backup / overrides.name)
        old_enabled[unit] = command(
            "/usr/bin/systemctl", "is-enabled", unit, check=False
        ).stdout.strip()
        old_active[unit] = (
            command("/usr/bin/systemctl", "is-active", unit, check=False).returncode == 0
        )
    old_slack = (
        user_command(args.operator, "is-active", "hecate-slack-bot", check=False).returncode == 0
    )
    snapshot = {
        "active": old_active,
        "enabled": old_enabled,
        "legacy_slack_active": old_slack,
        "old_runtime": old_runtime,
    }
    (backup / "previous-state.json").write_text(json.dumps(snapshot, indent=2))
    operator_in_data = "hecate-data" in command("/usr/bin/id", "-nG", args.operator).stdout.split()
    snapshot["operator_was_data_member"] = operator_in_data
    (backup / "previous-state.json").write_text(json.dumps(snapshot, indent=2))
    activated = False
    try:
        config_root.mkdir(exist_ok=True, mode=0o750)
        os.chmod(config_root, 0o711)
        homes = Path("/var/lib/hecate/homes")
        homes.mkdir(parents=True, exist_ok=True)
        for role in ROLES:
            home = homes / role
            home.mkdir(exist_ok=True, mode=0o700)
            os.chown(
                home, pwd.getpwnam(f"hecate-{role}").pw_uid, grp.getgrnam(f"hecate-{role}").gr_gid
            )
            os.chmod(home, 0o700)
            values = dict(environments[role])
            if "GITHUB_READ_TOKEN" in values:
                values["GITHUB_TOKEN"] = values.pop("GITHUB_READ_TOKEN")
            for key, value in list(values.items()):
                if "PRIVATE_KEY_PATH" in key and value:
                    source = Path(value)
                    if source.is_symlink() or not source.is_file():
                        raise ValueError("Private key paths must reference regular files")
                    destination = config_root / role / f"{key}.pem"
                    destination.parent.mkdir(exist_ok=True, mode=0o750)
                    os.chown(destination.parent, 0, grp.getgrnam(f"hecate-{role}").gr_gid)
                    shutil.copyfile(source, destination)
                    # The SDK requires mode 0600. Its root-owned parent and the
                    # service's read-only /etc mount prevent replacement/writes.
                    os.chown(
                        destination,
                        pwd.getpwnam(f"hecate-{role}").pw_uid,
                        grp.getgrnam(f"hecate-{role}").gr_gid,
                    )
                    os.chmod(destination, 0o600)
                    values[key] = str(destination)
            target = config_root / f"{role}.env"
            lines = [
                key + '="' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
                for key, value in sorted(values.items())
            ]
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write("\n".join(lines) + "\n")
            os.chown(target, 0, grp.getgrnam(f"hecate-{role}").gr_gid)
            os.chmod(target, 0o640)
        current.unlink(missing_ok=True)
        current.symlink_to(release)
        for role in ROLES:
            env = {
                "PATH": "/usr/bin:/bin",
                "HECATE_SERVICE_ISOLATED": "1",
                "PYTHON_DOTENV_DISABLED": "1",
                "HECATE_WORKSPACE": str(workspace),
                **environments[role],
            }
            command(
                "/usr/sbin/runuser",
                "-u",
                f"hecate-{role}",
                "--",
                str(current / "venv/bin/python"),
                "-I",
                "-c",
                "from hecate_runner.config import Settings; Settings()",
                env=env,
            )
        # Validate units before replacing any installed unit.
        command(
            "/usr/bin/systemd-analyze",
            "verify",
            *(str(unit_source / f"{unit}.service") for unit in UNITS),
        )
        activated = True
        command("/usr/bin/systemctl", "stop", "hecate-runner-daemon", "hecate-runner-maintenance")
        user_command(args.operator, "stop", "hecate-slack-bot", check=False)
        data_gid = grp.getgrnam("hecate-data").gr_gid
        if not operator_in_data:
            command("/usr/sbin/usermod", "--append", "--groups", "hecate-data", args.operator)
        for path in [workspace, *workspace.rglob("*")]:
            if path != workspace and private_workspace_path(path.relative_to(workspace)):
                continue
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode):
                raise ValueError("Unexpected workspace artifact type")
            permissions.append([str(path), info.st_gid, stat.S_IMODE(info.st_mode)])
            os.chown(path, -1, data_gid)
            os.chmod(
                path, 0o2770 if path.is_dir() else (stat.S_IMODE(info.st_mode) | 0o060) & ~0o6007
            )
        (backup / "workspace-permissions.json").write_text(json.dumps(permissions))
        Path("/var/lib/hecate/workspace").mkdir(exist_ok=True)
        for unit in UNITS:
            shutil.copyfile(unit_source / f"{unit}.service", unit_root / f"{unit}.service")
            os.chmod(unit_root / f"{unit}.service", 0o644)
            dropins = unit_root / f"{unit}.service.d"
            dropins.mkdir(exist_ok=True)
            for path in retired_dropins:
                if path.parent == dropins:
                    path.unlink()
            if unit == "hecate-bas-broker":
                text = (
                    "[Service]\n"
                    f"BindReadOnlyPaths={args.docker_socket}:/run/hecate-bas/docker.sock\n"
                    "ExecStartPre=\n"
                    f"ExecStartPre=+/usr/bin/setfacl -m u:hecate-bas:rw {args.docker_socket}\n"
                    f"Environment=HECATE_BAS_DOCKER_BIN={args.docker}\n"
                )
            else:
                text = f"[Service]\nBindPaths={workspace}:/var/lib/hecate/workspace\n"
            (dropins / "90-isolation.conf").write_text(text)
        command("/usr/bin/systemctl", "daemon-reload")
        command("/usr/bin/systemctl", "enable", "--now", "hecate-bas-broker", *UNITS[:-1])
        time.sleep(3)
        for unit in UNITS:
            command("/usr/bin/systemctl", "is-active", unit)
            expected = (
                "hecate-bas"
                if unit == "hecate-bas-broker"
                else f"hecate-{ROLES[UNITS.index(unit)]}"
            )
            actual = command(
                "/usr/bin/systemctl", "show", unit, "--property=User", "--value"
            ).stdout.strip()
            if actual != expected:
                raise RuntimeError("Service identity verification failed")
        user_command(args.operator, "disable", "hecate-slack-bot", check=False)
        print(f"Isolated services active. Private rollback snapshot: {backup}")
        if not operator_in_data:
            print("Open a new login session for operator access to newly created shared artifacts.")
    except Exception:
        if activated:
            command("/usr/bin/systemctl", "stop", *UNITS, check=False)
        for unit in UNITS:
            old = backup / f"{unit}.service"
            target = unit_root / f"{unit}.service"
            if old.exists():
                shutil.copyfile(old, target)
            elif activated:
                target.unlink(missing_ok=True)
            overrides = unit_root / f"{unit}.service.d"
            previous_overrides = backup / overrides.name
            if activated and overrides.exists():
                shutil.rmtree(overrides)
            if previous_overrides.exists():
                shutil.copytree(previous_overrides, overrides, dirs_exist_ok=True)
        if activated:
            # New artifacts belong to a worker. Preserve operator access if the
            # migration is rolled back and its data-group membership is removed.
            known_paths = {entry[0] for entry in permissions}
            worker_uids = {pwd.getpwnam(f"hecate-{role}").pw_uid for role in ROLES}
            for path in workspace.rglob("*"):
                if str(path) not in known_paths and path.lstat().st_uid in worker_uids:
                    os.chown(path, pwd.getpwnam(args.operator).pw_uid, -1, follow_symlinks=False)
            if not operator_in_data:
                command("/usr/bin/gpasswd", "--delete", args.operator, "hecate-data", check=False)
        for path, gid, mode in reversed(permissions):
            os.chown(path, -1, gid)
            os.chmod(path, mode)
        command("/usr/bin/setfacl", "--restore", str(backup / "docker-socket.acl"), check=False)
        current.unlink(missing_ok=True)
        if old_runtime:
            current.symlink_to(old_runtime)
        if config_root.exists():
            shutil.rmtree(config_root)
        if (backup / "configuration").exists():
            shutil.copytree(backup / "configuration", config_root, symlinks=True)
        command("/usr/bin/systemctl", "daemon-reload", check=False)
        if activated:
            for unit, state in old_enabled.items():
                if state in {"enabled", "enabled-runtime"}:
                    flags = ["--runtime"] if state == "enabled-runtime" else []
                    command("/usr/bin/systemctl", "enable", *flags, unit, check=False)
                else:
                    command("/usr/bin/systemctl", "disable", unit, check=False)
        for unit, active in old_active.items():
            if active:
                command("/usr/bin/systemctl", "start", unit, check=False)
        if old_slack:
            user_command(args.operator, "start", "hecate-slack-bot", check=False)
        raise RuntimeError(
            f"Service migration failed and restoration was attempted; inspect {backup}"
        ) from None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-stage", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--env-dir", type=Path, required=True)
    parser.add_argument("--docker-socket", type=Path, required=True)
    parser.add_argument("--docker", type=Path, default=Path("/usr/bin/docker"))
    parser.add_argument("--operator", default=os.environ.get("SUDO_USER", ""))
    parser.add_argument(
        "--retire-dropin",
        type=Path,
        action="append",
        default=[],
        help="Archive and remove a reviewed legacy service override (repeatable)",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Service isolation installation requires Linux")
    try:
        install(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        # Never emit subprocess output: it may include credential validation data.
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
