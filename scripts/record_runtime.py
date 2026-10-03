"""Record allowlisted lab health, image IDs and runtime/host source hash equality.

Never inspects container environments, mounts, credential files, or raw logs.
The source label is unrecorded unless the runtime has a valid source commit.
"""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

from check_report import utc_now

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-f", "infra/compose.yml"]
SERVICES = {"app-db", "identity-db", "keycloak", "opa", "policy", "backend", "worker", "web"}


def command(arguments):
    result = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("Runtime inspection failed; private diagnostics omitted")
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(ROOT / "output/connected/runtime-source.json"))
    args = parser.parse_args()
    target = Path(args.output).resolve()
    relative_target = target.relative_to(ROOT)
    started_at = utc_now()
    raw = command(COMPOSE + ["ps", "--format", "json"])
    rows = (
        json.loads(raw) if raw.startswith("[") else [json.loads(line) for line in raw.splitlines()]
    )
    services = []
    for row in rows:
        name = row["Service"]
        if name not in SERVICES or row["Name"] != "accessops-" + name + "-1":
            raise RuntimeError("Unexpected container outside the AccessOps lab")
        image_id = command(["docker", "inspect", "--format", "{{.Image}}", row["Name"]])
        services.append(
            {
                "service": name,
                "state": row["State"],
                "health": row["Health"] or "not-configured",
                "image_id": image_id,
                "published_ports": [
                    {"address": port["URL"], "port": port["PublishedPort"]}
                    for port in row.get("Publishers", [])
                    if port["PublishedPort"]
                ],
            }
        )
    # This code reads only application Python source already copied into the
    # backend image. No .local files or environment contents are enumerated.
    probe = """import hashlib,json,os,re
from pathlib import Path
root=Path('/app')
files={str(path.relative_to(root)):hashlib.sha256(path.read_bytes()).hexdigest()
       for folder in ('backend','integrations','scripts')
       for path in sorted((root/folder).rglob('*.py')) if '__pycache__' not in path.parts}
revision=os.getenv('ACCESSOPS_SOURCE_COMMIT','')
print(json.dumps({'revision':revision if re.fullmatch(r'[0-9a-f]{40}',revision) else 'unrecorded','files_sha256':files}))
"""
    runtime = json.loads(command(COMPOSE + ["exec", "-T", "backend", "python", "-c", probe]))
    mismatches = []
    for name, digest in runtime["files_sha256"].items():
        path = ROOT / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            mismatches.append(name)
    host_sources = set()
    for folder in ("backend", "integrations", "scripts"):
        for directory, children, names in os.walk(ROOT / folder):
            children[:] = [name for name in children if name not in (".venv", "__pycache__")]
            for name in names:
                if name.endswith(".py"):
                    host_sources.add((Path(directory) / name).relative_to(ROOT).as_posix())
    mismatches.extend(sorted(host_sources - set(runtime["files_sha256"])))
    report = {
        "schema_version": 1,
        "origin": "connected",
        "started_at": started_at,
        "completed_at": utc_now(),
        "source_revision": runtime["revision"],
        "source_revision_origin": "runtime setting; not an attestation",
        "runtime_source_matches_host": not mismatches,
        "source_mismatches": mismatches,
        "runtime_files_sha256": runtime["files_sha256"],
        "services": sorted(services, key=lambda item: item["service"]),
        "limitations": [
            "This records current local container state, not a signed build provenance.",
            "Only backend Python source equality is checked; frontend static assets and image OS packages are separate scopes.",
        ],
    }
    target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "report": str(relative_target),
                "source_revision": runtime["revision"],
                "runtime_source_matches_host": not mismatches,
                "files": len(runtime["files_sha256"]),
                "services": len(services),
            },
            indent=2,
        )
    )
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
