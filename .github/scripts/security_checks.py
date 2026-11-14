"""CI-only checks; never import the application or install audited dependencies."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import tomllib
from pathlib import Path


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, capture_output=True, text=True, timeout=300)


def base_file(ref: str, path: str) -> str | None:
    if not ref or set(ref) == {"0"}:
        return None
    commit = run(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"])
    if commit.returncode:
        raise RuntimeError("Cannot resolve the comparison commit")
    result = run(["git", "show", f"{commit.stdout.strip()}:{path}"])
    if result.returncode:
        if run(["git", "cat-file", "-e", f"{commit.stdout.strip()}:{path}"]).returncode:
            return None
        raise RuntimeError(f"Cannot read comparison file: {path}")
    return result.stdout


def secret_fingerprints(data: dict) -> set[tuple[str, str, str]]:
    return {
        (filename, row["type"], row["hashed_secret"])
        for filename, rows in data["results"].items()
        for row in rows
    }


def secrets(base_ref: str) -> int:
    # Never load plugins/filters from a PR-controlled baseline. The baseline
    # supplies only file/type/hash exceptions; scanning always uses fixed options.
    result = run(
        [
            "detect-secrets",
            "scan",
            "--no-verify",
            "--slim",
            "--exclude-files",
            r"^\.secrets\.baseline$",
            "--disable-filter",
            "detect_secrets.filters.allowlist.is_line_allowlisted",
        ]
    )
    if result.returncode:
        raise RuntimeError("Secret scanner failed")
    scanned = json.loads(result.stdout)
    baseline = base_file(base_ref, ".secrets.baseline")
    if baseline is None:
        baseline = Path(".secrets.baseline").read_text(encoding="utf-8")
    new = secret_fingerprints(scanned) - secret_fingerprints(json.loads(baseline))
    for filename, kind, _digest in sorted(new):
        # Scanner output and secret values are deliberately never printed.
        print(f"Unreviewed secret candidate: {filename} ({kind})")
    print(f"Secret scan: {len(new)} unreviewed candidates")
    return int(bool(new))


def requirement_batches(lock_text: str) -> list[list[str]]:
    packages: dict[str, set[str]] = {}
    for package in tomllib.loads(lock_text)["package"]:
        if "registry" not in package.get("source", {}):
            continue  # Local projects are source-scanned, never installed here.
        name, version = package["name"], package["version"]
        if not name or not version or any(c in name + version for c in "\r\n\x00"):
            raise ValueError("Invalid locked package")
        packages.setdefault(name, set()).add(version)
    if not packages:
        raise ValueError("Lockfile contains no registry packages")
    versions = {name: sorted(values) for name, values in packages.items()}
    # Universal uv locks may contain multiple versions of a package. Audit
    # every version without feeding duplicate names to pip-audit in one batch.
    return [
        [f"{name}=={values[i]}" for name, values in sorted(versions.items()) if i < len(values)]
        for i in range(max(map(len, versions.values())))
    ]


def audit_findings(data: dict) -> set[tuple[str, str, str]]:
    findings = set()
    for package in data["dependencies"]:
        if package.get("skip_reason"):
            raise RuntimeError(f"Dependency was not audited: {package['name']}")
        for advisory in package.get("vulns", []):
            findings.add(
                (package["name"].lower().replace("_", "-"), package["version"], advisory["id"])
            )
    return findings


def audit(lock_text: str, directory: Path, label: str) -> set[tuple[str, str, str]]:
    findings = set()
    for index, lines in enumerate(requirement_batches(lock_text)):
        requirements = directory / f"{label}-{index}.txt"
        report = directory / f"{label}-{index}.json"
        requirements.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = run(
            [
                "pip-audit",
                "--requirement",
                str(requirements),
                "--no-deps",
                "--disable-pip",
                "--strict",
                "--progress-spinner",
                "off",
                "--format",
                "json",
                "--desc",
                "off",
                "--output",
                str(report),
            ]
        )
        if result.returncode not in (0, 1) or not report.exists():
            raise RuntimeError("Dependency audit failed to produce a report")
        data = json.loads(report.read_text(encoding="utf-8"))
        batch = audit_findings(data)
        if result.returncode == 1 and not batch:
            raise RuntimeError("Dependency audit failed without advisory results")
        findings.update(batch)
    return findings


def dependencies(base_ref: str) -> int:
    current_lock = Path("uv.lock").read_text(encoding="utf-8")
    previous_lock = base_file(base_ref, "uv.lock")
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        current = audit(current_lock, directory, "current")
        if previous_lock == current_lock:
            previous = current
        elif previous_lock is not None:
            previous = audit(previous_lock, directory, "base")
        else:
            previous = set()
    blocking = current - previous
    mode = "new package/version/advisory matches" if previous_lock is not None else "full audit"
    report = {
        "mode": mode,
        "all_findings": sorted(current),
        "blocking_findings": sorted(blocking),
    }
    Path("dependency-audit.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Dependency audit: {len(current)} total; {len(blocking)} blocking ({mode})")
    for name, version, advisory in sorted(blocking):
        print(f"  {name} {version}: {advisory}")
    summary = os.getenv("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write(
                f"### Dependency audit\n\n{len(current)} total advisory matches; "
                f"{len(blocking)} blocking ({mode}).\n\n"
                "Full results are attached as dependency-audit.json. "
                "Existing matches remain visible; scheduled runs audit the full backlog.\n"
            )
    return int(bool(blocking))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("secrets", "dependencies"))
    parser.add_argument("--base-ref", default="")
    args = parser.parse_args()
    try:
        return secrets(args.base_ref) if args.check == "secrets" else dependencies(args.base_ref)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"Security check could not complete: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
