"""Freeze allowlisted verification outputs; never sweep a working directory."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import tarfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = (
    "backend",
    "frontend",
    "integrations",
    "policies",
    "infra",
    "scripts",
    "tools",
    "contracts",
    "docs",
    ".github",
)
ROOT_INPUTS = (
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "ruff.toml",
    ".gitignore",
    ".gitattributes",
    ".gitleaks.toml",
    ".dockerignore",
)
SKIP_DIRS = {
    "node_modules",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "test-results",
    "playwright-report",
    "output",
    ".local",
    ".git",
}
SOURCE_SUFFIXES = {
    ".py",
    ".ts",
    ".tsx",
    ".css",
    ".json",
    ".toml",
    ".txt",
    ".lock",
    ".rego",
    ".yml",
    ".yaml",
    ".html",
    ".md",
    ".conf",
    ".ps1",
    ".sh",
    ".svg",
    ".png",
    ".mjs",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_fingerprint(root: Path = ROOT) -> dict[str, str]:
    files = {}
    for name in ROOT_INPUTS:
        path = root / name
        if path.is_file() and not path.is_symlink():
            files[name] = sha(path.read_bytes())
    for directory in SOURCE_DIRS:
        for path in sorted((root / directory).rglob("*")):
            relative = path.relative_to(root)
            if path.is_symlink() or any(p in SKIP_DIRS for p in relative.parts):
                continue
            if (
                path.is_file()
                and (
                    path.suffix in SOURCE_SUFFIXES
                    or path.name in {"Dockerfile", "Caddyfile", ".dockerignore"}
                    or path.name.startswith("Dockerfile.")
                )
                and not path.name.startswith(".env")
            ):
                files[relative.as_posix()] = sha(path.read_bytes())
    return files


def junit_summary(path: Path) -> dict:
    # Only local reports produced by trusted tests; XML entity expansion is not enabled.
    if path.stat().st_size > 8_000_000:
        raise ValueError("Report exceeds size limit")
    document = ET.parse(path).getroot()
    cases = list(document.iter("testcase"))
    if not cases:
        raise ValueError("Report contains no test cases")
    checks = []
    for case in cases:
        failed = case.find("failure") is not None or case.find("error") is not None
        skipped = case.find("skipped") is not None
        checks.append(
            {
                "name": case.get("name", "unnamed"),
                "status": "failed" if failed else "skipped" if skipped else "passed",
            }
        )
    return {
        "total": len(checks),
        "passed": sum(c["status"] == "passed" for c in checks),
        "failed": sum(c["status"] == "failed" for c in checks),
        "skipped": sum(c["status"] == "skipped" for c in checks),
        "checks": checks,
    }


def git_value(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def freeze(report: Path, sbom: Path | None, destination: Path, origin: str, inputs: Path) -> Path:
    before = source_fingerprint()
    expected = json.loads(inputs.read_text(encoding="utf-8"))
    if expected != before:
        raise ValueError("Source changed since verification began; rerun checks")
    revision = git_value("rev-parse", "HEAD")
    dirty = bool(git_value("status", "--porcelain", "--untracked-files=all"))
    if origin == "ci" and (dirty or os.environ.get("GITHUB_ACTIONS") != "true"):
        raise ValueError("CI evidence requires a clean GitHub Actions checkout")
    summary = junit_summary(report)
    payloads = {"verification.json": json.dumps(summary, indent=2).encode()}
    if sbom is not None:
        bom = json.loads(sbom.read_text(encoding="utf-8"))
        if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6":
            raise ValueError("Expected CycloneDX 1.6 JSON SBOM")
        payloads["sbom.cdx.json"] = json.dumps(bom, indent=2).encode()
    manifest = {
        "schemaVersion": 1,
        "origin": origin,
        "repository": os.environ.get("GITHUB_REPOSITORY", "local"),
        "revision": revision,
        "dirty": dirty,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "runId": os.environ.get("GITHUB_RUN_ID"),
        "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "sourceInputs": before,
        "result": {k: v for k, v in summary.items() if k != "checks"},
        "limitations": [
            "Unit/integration scope is determined by the report; not a compliance certification.",
            "A local receipt is not CI provenance. Provider verification requires a connected run.",
        ],
        "files": {name: sha(data) for name, data in payloads.items()},
    }
    if before != source_fingerprint():
        raise ValueError("Source changed while evidence was collected")
    payloads["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode()
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / f"accessops-evidence-{revision[:12]}.tar.gz"
    if target.exists():
        raise ValueError("Evidence is frozen; choose a new output directory")
    # Only fixed member names and sanitized summaries, no logs/keys/environment.
    with tarfile.open(target, "w:gz") as archive:
        for name, data in sorted(payloads.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    target.with_suffix(target.suffix + ".sha256").write_text(
        f"{sha(target.read_bytes())}  {target.name}\n", encoding="utf-8"
    )
    return target


def verify_contents(path: Path) -> dict:
    if path.stat().st_size > 24_000_000:
        raise ValueError("Archive exceeds size limit")
    payloads = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if (
                not member.isfile()
                or len(name.parts) != 1
                or name.name not in {"manifest.json", "verification.json", "sbom.cdx.json"}
            ):
                raise ValueError("Unexpected archive entry")
            if member.size > 16_000_000 or member.name in payloads:
                raise ValueError("Invalid archive size or duplicate entry")
            file = archive.extractfile(member)
            if file is None:
                raise ValueError("Unreadable entry")
            payloads[member.name] = file.read()
    manifest = json.loads(payloads["manifest.json"])
    declared = manifest.get("files", {})
    if set(declared) != set(payloads) - {"manifest.json"}:
        raise ValueError("Manifest file set does not match archive")
    for name, digest in declared.items():
        if sha(payloads[name]) != digest:
            raise ValueError("Evidence hash mismatch")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    begin = sub.add_parser("begin")
    begin.add_argument("--output", type=Path, default=ROOT / "output" / "source-inputs.json")
    create = sub.add_parser("freeze")
    create.add_argument("--report", type=Path, required=True)
    create.add_argument("--sbom", type=Path)
    create.add_argument("--output", type=Path, default=ROOT / "output" / "evidence")
    create.add_argument("--origin", choices=("local", "ci"), default="local")
    create.add_argument("--inputs", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("archive", type=Path)
    args = parser.parse_args()
    if args.command == "begin":
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(source_fingerprint(), sort_keys=True), encoding="utf-8")
        print("Verification inputs recorded")
    elif args.command == "freeze":
        print(freeze(args.report, args.sbom, args.output, args.origin, args.inputs))
    else:
        manifest = verify_contents(args.archive)
        print(
            json.dumps(
                {
                    "contentHashesVerified": True,
                    "origin": manifest["origin"],
                    "revision": manifest["revision"],
                    "signatureVerified": False,
                    "note": "Verify detached attestation with trusted signer policy separately.",
                }
            )
        )


if __name__ == "__main__":
    main()
